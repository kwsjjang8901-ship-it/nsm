##! ============================================================================
##! [27] Heartbleed (OpenSSL CVE-2014-0160) — T1190 (2026-11 신규)
##!
##! TLS_Heartbleed
##!   - 하트비트 요청이 선언한 페이로드 길이가 실제 레코드보다 크면(과다 읽기 요청) 공격 시도.
##!     서버 응답이 요청보다 크면(서버 메모리가 응답에 실려 나감) 성공으로 본다.
##!   - 평문 하트비트만 본다. 공격 도구는 보통 핸드셰이크가 끝나기 전에 평문으로 보낸다.
##!     암호화된 하트비트는 Zeek 가 이벤트를 주지 않고(stock 스크립트는 레코드마다 오는 ssl_encrypted_data
##!     로 직접 만든다), 기본 설정(SSL::disable_analyzer_after_detection=T)에서는 핸드셰이크 뒤
##!     분석기가 떨어져 어차피 보이지 않으므로 다루지 않는다.
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
}

type HeartbeatState: record {
    req_n:     count &default=0;
    resp_n:    count &default=0;
    last_req:  count &default=0;
    max_resp:  count &default=0;
    overread:  bool  &default=F;   # 선언 길이 > 실제 길이인 요청(평문)
    leak:      bool  &default=F;   # 요청보다 큰 응답
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

event connection_state_remove(c: connection)
    {
    if ( ! c?$nsm_hb )
        return;
    local st = c$nsm_hb;
    if ( ! ( st$overread || st$leak ) )
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
        $detail=fmt("result=%s requests=%d responses=%d last_request_len=%d max_response_len=%d overread_request=%s port=%s",
                    result, st$req_n, st$resp_n, st$last_req, st$max_resp, st$overread, c$id$resp_p)]);

    NOTICE([$note=TLS_Heartbleed,
            $conn=c,
            $msg=fmt("TLS Heartbleed %s: %s -> %s:%s (responses up to %d bytes)", result,
                     c$id$orig_h, c$id$resp_h, c$id$resp_p, st$max_resp),
            $sub=fmt("result=%s requests=%d responses=%d", result, st$req_n, st$resp_n),
            $identifier=nid,
            $suppress_for=1hr,
            $evidence_id=eid]);
    }
