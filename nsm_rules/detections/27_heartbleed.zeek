##! ============================================================================
##! [27] Heartbleed (OpenSSL CVE-2014-0160) — T1190 (2026-11 신규)
##!
##! TLS_Heartbleed
##!   - 하트비트 요청이 선언한 페이로드 길이가 실제 레코드보다 크면(과다 읽기 요청) 공격 시도.
##!     서버 응답이 요청보다 크면(서버 메모리가 응답에 실려 나감) 성공으로 본다.
##!   - 암호화된 하트비트(Heartleech 기본 동작, 핸드셰이크 뒤)는 내용을 못 보므로 레코드 길이로 본다:
##!     응답이 요청보다 heartbleed_enc_slack(32)바이트 넘게 크면 성공, 응답 없는 요청이
##!     heartbleed_unanswered(3)개를 넘으면 시도.
##!     기본 설정(SSL::disable_analyzer_after_detection=T)은 핸드셰이크 뒤 SSL 분석기를 떼어 내므로,
##!     서버가 ServerHello 에서 하트비트 확장(15)을 수락한 연결만 c$ssl$analyzer_id 를 지워 분석기를 남긴다
##!     (base/protocols/ssl/main.zeek 의 finish() 는 analyzer_id 가 있을 때만 떼어 낸다).
##!     하트비트를 켠 서버는 OpenSSL 1.1.0 이후 드물어 남는 분석기는 적다. 전역 옵션은 바꾸지 않는다
##!     (stock heartbleed.zeek 는 모든 TLS 에 대해 F 로 바꾼다).
##!   - Zeek 의 policy/protocols/ssl/heartbleed.zeek 와 같은 원리를 NSM 근거·탐지 요약 체계로 옮겼다
##!     (그 스크립트는 자체 notice 만 내서 NSM 상관·리포트와 이어지지 않는다).
##!   - 연결 단위로 상태를 모아 연결이 끝날 때 1건(시도 또는 성공).
##!
##! 상관 계약: notice $src = 공격 host(TLS 클라이언트), $dst = 대상 서버. 초기 침투 단계.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/ssl
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_heartbleed = T &redef;
    ## 암호화된 하트비트: 응답 레코드가 요청 레코드보다 이만큼(바이트) 넘게 크면 성공(MAC·패딩 차이 여유)
    const heartbleed_enc_slack = 32 &redef;
    ## 암호화된 하트비트: 응답 없는 요청이 이 수를 넘으면 시도
    const heartbleed_unanswered = 3 &redef;
}

type HeartbeatState: record {
    req_n:     count &default=0;
    resp_n:    count &default=0;
    last_req:  count &default=0;
    max_resp:  count &default=0;
    overread:  bool  &default=F;   # 선언 길이 > 실제 길이인 요청(평문)
    leak:      bool  &default=F;   # 요청보다 큰 응답
    enc:       bool  &default=F;   # 암호화된 하트비트를 봄
};

redef record connection += {
    nsm_hb: HeartbeatState &optional;
};

function hb_state(c: connection): HeartbeatState
    {
    if ( ! c?$nsm_hb )
        c$nsm_hb = HeartbeatState();
    return c$nsm_hb;
    }

event ssl_heartbeat(c: connection, is_client: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
    {
    if ( ! detect_heartbleed )
        return;
    local st = hb_state(c);
    if ( heartbeat_type == 1 )
        {
        ++st$req_n;
        st$last_req = length;
        local checklength = ( length < 3 + 16 ) ? length : length - 3 - 16;
        if ( payload_length > checklength )
            st$overread = T;
        }
    else if ( heartbeat_type == 2 )
        {
        ++st$resp_n;
        if ( length > st$max_resp )
            st$max_resp = length;
        if ( st$overread || ( st$last_req > 0 && length > st$last_req ) )
            st$leak = T;
        }
    }

# 서버가 하트비트 확장을 수락한 연결: 핸드셰이크 뒤에도 SSL 분석기를 남겨 암호화된 하트비트를 본다.
event ssl_extension(c: connection, is_client: bool, code: count, val: string)
    {
    if ( detect_heartbleed && ! is_client && code == 15 )
        hb_state(c);
    }

# base 의 finish(c, T)(priority -5)가 분석기를 떼기 전에 analyzer_id 를 지운다.
event ssl_established(c: connection) &priority=0
    {
    if ( c?$nsm_hb && c?$ssl && c$ssl?$analyzer_id )
        delete c$ssl$analyzer_id;
    }

# 하트비트 레코드(타입 24)만 본다. 분석기가 붙어 있는 동안(대부분 연결은 핸드셰이크까지) 레코드마다 온다.
event ssl_encrypted_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count)
    {
    if ( content_type != 24 || ! detect_heartbleed )
        return;
    local st = hb_state(c);
    st$enc = T;
    if ( is_client )
        {
        ++st$req_n;
        st$last_req = length;
        }
    else
        {
        ++st$resp_n;
        if ( length > st$max_resp )
            st$max_resp = length;
        if ( st$last_req > 0 && length > st$last_req + heartbleed_enc_slack )
            st$leak = T;
        }
    }

event connection_state_remove(c: connection)
    {
    if ( ! c?$nsm_hb )
        return;
    local st = c$nsm_hb;
    if ( ! ( st$overread || st$leak || ( st$enc && st$req_n > st$resp_n + heartbleed_unanswered ) ) )
        return;
    if ( NSM::exception_drop(TLS_Heartbleed, c) )
        return;

    local result = st$leak ? "success" : "attempt";
    local nid = cat(c$id$orig_h, c$id$resp_h, "heartbleed");
    if ( NSM::notice_suppressed(TLS_Heartbleed, nid) )
        return;
    local eid = cat(c$id$orig_h, "|heartbleed|", c$id$resp_h, "|", c$uid);
    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=TLS_Heartbleed,
        $technique="T1190",
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $uid=c$uid,
        $operation=fmt("tls_heartbleed_%s", result),
        $detail=fmt("result=%s requests=%d responses=%d last_request_len=%d max_response_len=%d overread_request=%s encrypted=%s port=%s",
                    result, st$req_n, st$resp_n, st$last_req, st$max_resp, st$overread, st$enc, c$id$resp_p)]);

    NOTICE([$note=TLS_Heartbleed,
            $conn=c,
            $msg=fmt("TLS Heartbleed %s: %s -> %s:%s (responses up to %d bytes)", result,
                     c$id$orig_h, c$id$resp_h, c$id$resp_p, st$max_resp),
            $sub=fmt("result=%s requests=%d responses=%d", result, st$req_n, st$resp_n),
            $identifier=nid,
            $suppress_for=1hr,
            $evidence_id=eid]);
    }
