##! ============================================================================
##! [25] 식별 안 된 프로토콜의 외부 통신 — T1095 (2026-11 신규)
##!
##! Unknown_Protocol
##!   - 내부 -> 외부 TCP 연결 중 Zeek 가 프로토콜을 식별하지 못했고(c$service 비어 있음) 표준 포트가 아닌데,
##!     한 방향으로 unknown_proto_min_bytes 이상 보냈거나, unknown_proto_min_duration 이상 이어지며 양방향
##!     합계가 unknown_proto_min_bytes_long 이상이면 탐지한다.
##!   - Metasploit 역방향 셸(meterpreter reverse_tcp)·자체 프로토콜 RAT 처럼 HTTP·TLS·SSH 가 아닌 C2 채널.
##!     비표준 포트 룰(24)은 프로토콜이 식별돼야 보고, 암호화 C2(09)·비콘(07)은 TLS·HTTP 만 본다.
##!     (CIC-IDS2017 Thursday: 감염 PC -> 공격자 444/tcp, 서비스 미식별, 13MB. 같은 날 정상 트래픽에서 이 조건을
##!      넘는 (출발지, 목적지, 포트)는 0건)
##!   - 판정 시점: 연결 중 임계(ConnThreshold 바이트·시간)를 넘는 순간. 핸드셰이크가 캡처되지 않은 연결(OTH)이나
##!     임계 이벤트가 없던 연결은 연결 종료(connection_state_remove)에서 같은 조건으로 한 번 더 본다.
##!   - 단건 탐지, (출발지, 목적지, 포트) 단위 1시간 억제.
##!
##! 상관 계약: notice $src = 내부 출발지, $dst = 외부 목적지 (C2 단계).
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_unknown_protocol = T &redef;

    ## 한 방향 페이로드가 이 바이트 이상이면 탐지(역방향 셸의 파일 전송·화면 캡처, 자체 프로토콜 유출)
    ##   ConnThreshold 바이트 임계는 다른 룰과 같은 값이면 같은 이벤트를 공유하므로 10진 MB 로 둔다.
    const unknown_proto_min_bytes: count = 1000000 &redef;

    ## 이 시간 이상 이어지고 양방향 합계가 unknown_proto_min_bytes_long 이상이면 탐지(대화형 셸처럼 양은 적고 오래 감)
    const unknown_proto_min_duration = 30min &redef;
    const unknown_proto_min_bytes_long: count = 10000 &redef;

    ## 검사하지 않는 목적지 포트. 표준 포트의 미식별 트래픽(자체 암호화 앱·화상회의 등)은 양이 많아 뺀다.
    const unknown_proto_skip_ports: set[port] = {
        80/tcp, 443/tcp, 8080/tcp, 8443/tcp, 21/tcp, 22/tcp, 25/tcp, 53/tcp, 110/tcp, 143/tcp,
        465/tcp, 587/tcp, 853/tcp, 993/tcp, 995/tcp, 5223/tcp, 5228/tcp,
    } &redef;
}

redef record connection += {
    nsm_unk_watch:    bool &default=F;   # 임계를 걸어 둔 연결
    nsm_unk_reported: bool &default=F;   # 이미 판정해 근거·notice 를 낸 연결
};

function unk_candidate(c: connection): bool
    {
    return detect_unknown_protocol && get_port_transport_proto(c$id$resp_p) == tcp &&
           Site::is_local_addr(c$id$orig_h) && ! Site::is_local_addr(c$id$resp_h) &&
           c$id$resp_p !in unknown_proto_skip_ports;
    }

# 조건을 만족하면 근거·notice 를 낸다. reason = 어떤 조건으로 판정했는지
function unk_report(c: connection, reason: string)
    {
    if ( c$nsm_unk_reported || |c$service| > 0 || ! unk_candidate(c) )
        return;
    # 예외(예외 파일). 축: 목적지·포트·출발지. 사내 전용 프로그램·VPN·게임 서버 등
    if ( NSM::exception_drop(Unknown_Protocol, c) )
        return;
    c$nsm_unk_reported = T;

    local nid = cat(c$id$orig_h, c$id$resp_h, c$id$resp_p, "unknown-proto");
    if ( NSM::notice_suppressed(Unknown_Protocol, nid) )
        return;

    local eid = cat(c$id$orig_h, "|unknown-proto|", c$id$resp_h, "|", c$uid);
    local ob = c$orig$size;
    local rb = c$resp$size;
    # 바이트 임계(ConnThreshold)는 IP 바이트(헤더 포함)로 센다. 페이로드(orig_bytes)와 함께 남겨 숫자가 맞아 보이게 한다.
    local oib = c$orig?$num_bytes_ip ? c$orig$num_bytes_ip : 0;
    local rib = c$resp?$num_bytes_ip ? c$resp$num_bytes_ip : 0;
    local dur = network_time() - c$start_time;
    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=Unknown_Protocol,
        $technique="T1095",
        $src=c$id$orig_h,
        $dst=c$id$resp_h,
        $operation="unidentified_protocol_outbound",
        $uid=c$uid,
        $detail=fmt("port=%s %s orig_bytes=%d resp_bytes=%d orig_ip_bytes=%d resp_ip_bytes=%d duration=%s",
                    c$id$resp_p, reason, ob, rb, oib, rib, dur)]);

    NOTICE([$note=Unknown_Protocol,
            $conn=c,
            $msg=fmt("Unidentified protocol to external host: %s -> %s:%s (%s, sent %d / received %d bytes)",
                     c$id$orig_h, c$id$resp_h, c$id$resp_p, reason, ob, rb),
            $sub=fmt("port=%s %s", c$id$resp_p, reason),
            $identifier=nid,
            $suppress_for=1hr,
            $evidence_id=eid]);
    }

# 핸드셰이크가 보이지 않는 연결(OTH)도 잡도록 연결이 생길 때 임계를 건다.
event new_connection(c: connection)
    {
    if ( ! unk_candidate(c) )
        return;
    c$nsm_unk_watch = T;
    ConnThreshold::set_bytes_threshold(c, unknown_proto_min_bytes, T);
    ConnThreshold::set_bytes_threshold(c, unknown_proto_min_bytes, F);
    ConnThreshold::set_duration_threshold(c, unknown_proto_min_duration);
    }

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
    {
    if ( ! c$nsm_unk_watch || threshold != unknown_proto_min_bytes )
        return;
    unk_report(c, fmt("ip_bytes_%s>=%d", is_orig ? "sent" : "received", threshold));
    }

event ConnThreshold::duration_threshold_crossed(c: connection, threshold: interval, is_orig: bool)
    {
    if ( ! c$nsm_unk_watch || threshold != unknown_proto_min_duration )
        return;
    if ( c$orig$size + c$resp$size >= unknown_proto_min_bytes_long )
        unk_report(c, fmt("duration>=%s", threshold));
    }

# 임계 이벤트를 받지 못한 연결(캡처 손실로 크기만 seq 로 알게 된 경우 등)을 종료 때 한 번 더 본다.
event connection_state_remove(c: connection)
    {
    if ( c$nsm_unk_reported || ! unk_candidate(c) )
        return;
    if ( c$orig$size >= unknown_proto_min_bytes || c$resp$size >= unknown_proto_min_bytes )
        unk_report(c, fmt("payload_bytes>=%d(at_close)", unknown_proto_min_bytes));
    else if ( c$duration >= unknown_proto_min_duration && c$orig$size + c$resp$size >= unknown_proto_min_bytes_long )
        unk_report(c, fmt("duration>=%s(at_close)", unknown_proto_min_duration));
    }
