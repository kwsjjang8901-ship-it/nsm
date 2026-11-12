##! ============================================================================
##! [24] 비표준 포트 프로토콜 / 장기 외부 연결 — T1571 / T1572 (2026-11 신규)
##!
##! Nonstandard_Port
##!   - 내부 → 외부 연결에서 Zeek 가 프로토콜을 확인(analyzer_confirmation_info, DPD)했는데
##!     그 프로토콜의 표준 포트가 아니면 탐지한다. C2·터널이 방화벽 정책을 피하려고
##!     HTTP/TLS/SSH 를 임의 포트(4444, 8081, 2222 …)에서 쓰는 경우.
##!   - 대상 프로토콜과 표준 포트는 nonstd_port_standard 로 정의(기본: HTTP·SSL·SSH).
##!   - 단건 탐지, (src, dst, 포트, 프로토콜) 단위 1시간 suppress.
##!
##! Long_Connection
##!   - 내부 → 외부 TCP 연결이 long_conn_duration 이상 이어지면 탐지(ConnThreshold 로 연결 중 실시간).
##!     리버스 셸·터널·상시 C2 세션. 메신저·VPN·클라우드 동기화는 예외 목록으로 통제한다.
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
    ## 프로토콜(분석기 이름, 소문자)별 표준 포트. 여기 없는 프로토콜은 검사하지 않는다.
    const nonstd_port_standard: table[string] of set[port] = {
        ["http"] = set(80/tcp, 8080/tcp, 8000/tcp, 8008/tcp, 8888/tcp, 3128/tcp),
        ["ssl"]  = set(443/tcp, 8443/tcp, 993/tcp, 995/tcp, 465/tcp, 587/tcp, 636/tcp,
                                        853/tcp, 989/tcp, 990/tcp, 5061/tcp, 3389/tcp, 25/tcp, 143/tcp, 110/tcp),
        ["ssh"]  = set(22/tcp),
    } &redef;

    ## 예외 목적지(허용한 외부 서비스)·목적지 포트·출발지.
    const nonstd_port_allowed_dsts: set[subnet] = {} &redef;
    const nonstd_port_allowed_ports: set[port] = {} &redef;
    const nonstd_port_allowlist: set[subnet] = {} &redef;

    ## 장기 연결 기준 시간
    const long_conn_duration = 6hr &redef;

    ## 장기 연결 예외(VPN·메신저·클라우드 동기화 목적지, 목적지 포트, 출발지)
    const long_conn_allowed_dsts: set[subnet] = {} &redef;
    const long_conn_allowed_ports: set[port] = {} &redef;
    const long_conn_allowlist: set[subnet] = {} &redef;
}

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |nonstd_port_allowed_ports| > 0 )
        NSM::exception_add_legacy("legacy:nonstd_port_allowed_ports",
            [$scope=set("Nonstandard_Port"), $dst_port=nonstd_port_allowed_ports]);
    if ( |nonstd_port_allowed_dsts| > 0 )
        NSM::exception_add_legacy("legacy:nonstd_port_allowed_dsts",
            [$scope=set("Nonstandard_Port"), $dst=nonstd_port_allowed_dsts]);
    if ( |nonstd_port_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:nonstd_port_allowlist",
            [$scope=set("Nonstandard_Port"), $src=nonstd_port_allowlist]);
    if ( |long_conn_allowed_ports| > 0 )
        NSM::exception_add_legacy("legacy:long_conn_allowed_ports",
            [$scope=set("Long_Connection"), $dst_port=long_conn_allowed_ports]);
    if ( |long_conn_allowed_dsts| > 0 )
        NSM::exception_add_legacy("legacy:long_conn_allowed_dsts",
            [$scope=set("Long_Connection"), $dst=long_conn_allowed_dsts]);
    if ( |long_conn_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:long_conn_allowlist",
            [$scope=set("Long_Connection"), $src=long_conn_allowlist]);
    }

function nsm_outbound(c: connection): bool
    {
    return Site::is_local_addr(c$id$orig_h) && ! Site::is_local_addr(c$id$resp_h);
    }

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
    {
    if ( ! info?$c )
        return;
    local proto = to_lower(Analyzer::name(atype));
    if ( proto !in nonstd_port_standard )
        return;
    local c = info$c;
    if ( ! nsm_outbound(c) )
        return;
    local p = c$id$resp_p;
    if ( p in nonstd_port_standard[proto] )
        return;
    # 예외(예외 파일 + 기존 nonstd_port_allowed_ports·_allowed_dsts·_allowlist)
    if ( NSM::exception_drop(Nonstandard_Port, c) )
        return;

    local eid = cat(c$id$orig_h, "|nonstd-port|", c$id$resp_h, "|", c$uid);

    if ( NSM::evidence_is_new(eid, proto) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Nonstandard_Port,
            $technique="T1571",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation=fmt("%s_on_nonstandard_port", proto),
            $uid=c$uid,
            $detail=fmt("protocol=%s port=%s", proto, p)]);

    NOTICE([$note=Nonstandard_Port,
            $conn=c,
            $msg=fmt("%s on non-standard port to external host: %s -> %s:%s",
                     to_upper(proto), c$id$orig_h, c$id$resp_h, p),
            $sub=fmt("protocol=%s port=%s", proto, p),
            $identifier=cat(c$id$orig_h, c$id$resp_h, p, proto, "nonstd-port"),
            $suppress_for=1hr,
            $evidence_id=eid]);
    }

event connection_established(c: connection)
    {
    if ( ! nsm_outbound(c) )
        return;
    # 예외는 임계를 넘는 시점에 판정한다(그때는 서비스·SNI 등 축을 알 수 있다).
    ConnThreshold::set_duration_threshold(c, long_conn_duration);
    }

event ConnThreshold::duration_threshold_crossed(c: connection, threshold: interval, is_orig: bool)
    {
    if ( threshold != long_conn_duration || ! nsm_outbound(c) )
        return;
    # 예외(예외 파일 + 기존 long_conn_allowed_ports·_allowed_dsts·_allowlist). VPN·메신저·클라우드 동기화 등
    if ( NSM::exception_drop(Long_Connection, c) )
        return;

    local eid = cat(c$id$orig_h, "|long-conn|", c$id$resp_h, "|", c$uid);
    local ob = c$orig$size;
    local rb = c$resp$size;
    local svc = |c$service| > 0 ? join_string_set(c$service, ",") : "-";

    if ( NSM::evidence_is_new(eid, "duration") )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Long_Connection,
            $technique="T1572",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="long_external_connection",
            $uid=c$uid,
            $detail=fmt("duration>=%s port=%s service=%s orig_bytes=%d resp_bytes=%d",
                        threshold, c$id$resp_p, svc, ob, rb)]);

    NOTICE([$note=Long_Connection,
            $conn=c,
            $msg=fmt("Long-lived external connection: %s -> %s:%s open for %s or more",
                     c$id$orig_h, c$id$resp_h, c$id$resp_p, threshold),
            $sub=fmt("service=%s orig_bytes=%d resp_bytes=%d", svc, ob, rb),
            $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p, "long-conn"),
            $suppress_for=threshold,
            $evidence_id=eid]);
    }
