##! ============================================================================
##! [35] IOC 일치 (IOC_Match) — 위협 정보(IOC)의 IP·도메인·URL 과 일치하는 통신
##!
##! IOC 파일(ioc_file, TSV)을 Zeek Intel 프레임워크에 넣고, 센서가 본 값과 맞춰 본다.
##!   - IP  : 내부 -> 외부 연결의 목적지(대역 CIDR 포함). 연결 성립 때(TCP), 응답 없는 시도·UDP 는 연결 종료 때.
##!           외부 IOC 가 내부로 들어온 연결은 기본으로 보지 않는다(ioc_match_inbound, 인터넷 스캔이 대부분).
##!   - 도메인: DNS 조회 이름, TLS 접속 도메인(SNI), HTTP Host(프록시 CONNECT 대상 포함).
##!           하위 도메인도 맞춘다(IOC evil.example 은 a.evil.example 도 일치). 등록 도메인보다 위로는 올라가지 않는다.
##!   - URL : 평문 HTTP 요청의 호스트 + 경로. 쿼리 포함 전체와 쿼리를 뗀 것 둘 다 맞춘다.
##!           HTTPS 는 경로가 암호화돼 보이지 않으므로 URL IOC 의 호스트는 도메인 IOC 로도 넣어야 맞는다.
##!   - TLS 지문(JA3·JA4)은 IOC 로 쓰지 않는다. JA3 는 브라우저마다 바뀌고 정상 프로그램과 겹쳐 09 의 점수 재료로만 쓰고,
##!     JA4 는 FoxIO 라이선스·특허 문제로 제품에서 쓰지 않는다(rules/PACKAGES-README.md).
##!
##! IOC 파일 (TSV, 예외 파일과 같은 다시 읽기 방식: 바뀌면 재시작 없이 반영, 지운 줄은 IOC 에서 빠진다)
##!   #fields indicator  ioc_type  source  category  expires  desc
##!   ioc_type : ip | domain | url
##!   category : c2 | malware | phishing | scanner | - (근거에 남김)
##!   expires  : epoch 초 또는 - (지나면 일치로 치지 않는다)
##!
##! 판정은 Intel::match(standalone·매니저)에서 한다. 클러스터에서 워커는 값만 보고, 매니저가 IOC 전체 정보로 판정한다.
##! 예외는 판정 입구에서 exception_drop(건별). 축: 출발지·목적지·포트·도메인.
##!
##! 상관: 외부 연락(C2) 묶음. notice $src = 내부 host(들어온 연결이면 외부 IOC 주소), $dst = 연결 목적지
##!       (DNS 조회는 리졸버라서 비움).
##! ============================================================================

@load base/frameworks/intel
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./08_dns_tunneling

module NSM;

export {
    const detect_ioc_match = T &redef;
    ## IOC 파일 경로(TSV). 비우면 IOC 일치를 하지 않는다.
    const ioc_file = "" &redef;
    ## 외부 IOC 주소가 내부로 들어온 연결도 탐지(기본 끔: 인터넷 스캔이 대부분)
    const ioc_match_inbound = F &redef;
    ## DNS 조회 이름도 맞춘다(리졸버 dns_tunnel_resolvers 가 대신 묻는 조회는 뺀다)
    const ioc_match_dns = T &redef;
    ## 같은 (출발지, IOC) 억제 시간
    const suppress_ioc = 1hr &redef;

    redef enum Log::ID += { IOC_LOG };
    ## IOC 파일 적재 결과(nsm_ioc.log)
    type IocLogInfo: record {
        ts:        time   &log;
        kind:      string &log;            ##< summary | invalid | error
        indicator: string &log &optional;
        ioc_type:  string &log &optional;
        msg:       string &log &optional;
    };
}

redef record Intel::MetaData += {
    nsm_category: string &optional;
    nsm_expires:  time   &optional;
};

redef enum Intel::Where += {
    IOC_IN_CONN,        # 내부 -> 외부 연결 목적지(연결 성립, UDP 는 응답 있음)
    IOC_IN_CONN_ATTEMPT,# 내부 -> 외부 연결 시도(TCP 응답 없음·거부, UDP 응답 없음)
    IOC_IN_CONN_INBOUND,# 외부 -> 내부 연결 출발지
    IOC_IN_DNS,         # DNS 조회 이름
    IOC_IN_TLS_SNI,     # TLS 접속 도메인
    IOC_IN_HTTP_HOST,   # HTTP Host(프록시 CONNECT 대상 포함)
    IOC_IN_HTTP_URL,    # HTTP 호스트 + 경로
};

const ioc_wheres: set[Intel::Where] = {
    IOC_IN_CONN, IOC_IN_CONN_ATTEMPT, IOC_IN_CONN_INBOUND, IOC_IN_DNS, IOC_IN_TLS_SNI, IOC_IN_HTTP_HOST, IOC_IN_HTTP_URL,
};

const IOC_STREAM = "nsm-ioc";

# ---------------------------------------------------------------- 정규화

const ioc_scheme = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;

# "호스트:포트" 의 포트를 뗀다(IPv6 는 대괄호 형식만).
function ioc_strip_port(h: string): string
    {
    if ( /^[^:\[\]]+:[0-9]+$/ == h || /^\[.*\]:[0-9]+$/ == h )
        return sub(h, /:[0-9]+$/, "");
    return h;
    }

function ioc_norm_domain(d: string): string
    {
    local x = to_lower(strip(d));
    if ( |x| > 0 && x[|x| - 1:] == "." )
        x = x[:|x| - 1];
    return ioc_strip_port(x);
    }

## URL 을 "호스트/경로" 로: 스킴을 떼고 호스트는 소문자·포트 제거, 경로가 없으면 "/".
function ioc_norm_url(u: string): string
    {
    local x = sub(strip(u), ioc_scheme, "");
    local parts = split_string1(x, /\//);
    local host = ioc_norm_domain(split_string(parts[0], /@/)[|split_string(parts[0], /@/)| - 1]);
    local path = |parts| > 1 ? cat("/", parts[1]) : "/";
    return cat(host, path);
    }

# ---------------------------------------------------------------- IOC 파일 적재

type IocIdx: record {
    indicator: string;
    ioc_type:  string;
};
type IocVal: record {
    source:   string &optional;
    category: string &optional;
    expires:  time   &optional;
    desc:     string &optional;
};

global ioc_file_recs: table[string, string] of IocVal = table();
# 지금 Intel 에 넣어 둔 항목: (정규화 값, Intel 타입 이름) -> Item
global ioc_active: table[string, string] of Intel::Item = table();
global ioc_waiting_initial = F;

function ioc_log(kind: string, indicator: string, t: string, msg: string)
    {
    Log::write(IOC_LOG, IocLogInfo($ts=network_time(), $kind=kind, $indicator=indicator, $ioc_type=t, $msg=msg));
    }

## 파일 한 줄을 Intel 항목으로. 잘못된 줄이면 indicator 가 빈 항목.
function ioc_item(ind: string, t: string, v: IocVal): Intel::Item
    {
    local md = Intel::MetaData($source=v?$source && v$source != "" ? v$source : "nsm-ioc");
    if ( v?$desc )     md$desc = v$desc;
    if ( v?$category ) md$nsm_category = v$category;
    if ( v?$expires )  md$nsm_expires = v$expires;
    local x = strip(ind);
    switch ( to_lower(t) )
        {
        case "ip":
            if ( is_valid_ip(x) )
                return Intel::Item($indicator=x, $indicator_type=Intel::ADDR, $meta=md);
            if ( /^[0-9a-fA-F:.]+\/[0-9]+$/ == x && is_valid_ip(split_string1(x, /\//)[0]) )
                return Intel::Item($indicator=cat(to_subnet(x)), $indicator_type=Intel::SUBNET, $meta=md);
            break;
        case "domain":
            local d = ioc_norm_domain(x);
            if ( /^[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?)+$/ == d )
                return Intel::Item($indicator=d, $indicator_type=Intel::DOMAIN, $meta=md);
            break;
        case "url":
            if ( x != "" )
                return Intel::Item($indicator=ioc_norm_url(x), $indicator_type=Intel::URL, $meta=md);
            break;
        }
    return Intel::Item($indicator="", $indicator_type=Intel::ADDR, $meta=md);
    }

## 파일을 다 읽은 뒤 Intel 과 맞춘다: 새 줄은 넣고, 바뀐 줄은 다시 넣고, 지운 줄은 뺀다.
function ioc_sync()
    {
    local want: table[string, string] of Intel::Item = table();
    local invalid = 0;
    for ( [ind, t], v in ioc_file_recs )
        {
        local it = ioc_item(ind, t, v);
        if ( it$indicator == "" )
            {
            ++invalid;
            ioc_log("invalid", ind, t, "형식이 맞지 않아 뺌(ioc_type 은 ip·domain·url)");
            next;
            }
        want[it$indicator, cat(it$indicator_type)] = it;
        }
    local removed = 0;
    for ( [k, kt], old in ioc_active )
        if ( [k, kt] !in want )
            {
            Intel::remove(old, T);
            ++removed;
            }
    local added = 0;
    for ( [k, kt], it2 in want )
        {
        if ( [k, kt] !in ioc_active )
            ++added;
        Intel::insert(it2);
        }
    ioc_active = want;
    ioc_log("summary", "-", "-", fmt("active=%d added=%d removed=%d invalid=%d", |want|, added, removed, invalid));
    }

function ioc_reads_file(): bool
    {
    return detect_ioc_match && ioc_file != "" &&
           ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER );
    }

function ioc_release_wait()
    {
    if ( ioc_waiting_initial )
        {
        ioc_waiting_initial = F;
        continue_processing();
        }
    }

event ioc_input_error(desc: Input::TableDescription, message: string, level: Reporter::Level)
    {
    ioc_log("error", "-", "-", message);
    ioc_release_wait();
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( name != IOC_STREAM )
        return;
    ioc_sync();
    ioc_release_wait();
    }

event zeek_init() &priority=5
    {
    Log::create_stream(IOC_LOG, [$columns=IocLogInfo, $path="nsm_ioc"]);
    }

event zeek_init() &priority=-10
    {
    if ( ! ioc_reads_file() )
        return;
    # pcap 을 읽을 때는 IOC 를 다 넣을 때까지 패킷 처리를 멈춘다(실시간 센서는 멈추지 않음).
    if ( reading_traces() )
        {
        ioc_waiting_initial = T;
        suspend_processing();
        }
    Input::add_table([$source=ioc_file, $name=IOC_STREAM, $idx=IocIdx, $val=IocVal,
                      $destination=ioc_file_recs, $mode=Input::REREAD, $error_ev=ioc_input_error]);
    }

# ---------------------------------------------------------------- 값 보기(seen)

function ioc_seen_domain(name: string, w: Intel::Where, c: connection)
    {
    local d = ioc_norm_domain(name);
    if ( d == "" || is_valid_ip(d) )
        return;
    # 하위 도메인부터 등록 도메인까지: a.b.evil.example -> a.b.evil.example, b.evil.example, evil.example
    local stop = parent_domain(d);
    while ( T )
        {
        Intel::seen(Intel::Seen($indicator=d, $indicator_type=Intel::DOMAIN, $where=w, $conn=c));
        if ( d == stop || |split_string(d, /\./)| <= 2 )
            break;
        d = split_string1(d, /\./)[1];
        }
    }

global ioc_conn_checked: set[string] &create_expire=1day;

## established: 연결이 성립했나(TCP 3-way 완료, UDP 는 응답 있음)
function ioc_seen_conn(c: connection, established: bool)
    {
    if ( c$uid in ioc_conn_checked )
        return;
    add ioc_conn_checked[c$uid];
    if ( Site::is_local_addr(c$id$orig_h) && is_external(c$id$resp_h) )
        Intel::seen(Intel::Seen($host=c$id$resp_h, $where=established ? IOC_IN_CONN : IOC_IN_CONN_ATTEMPT, $conn=c));
    # 들어온 연결은 성립한 것만(응답 없는 스캔은 보지 않음)
    else if ( ioc_match_inbound && established && is_external(c$id$orig_h) && Site::is_local_addr(c$id$resp_h) )
        Intel::seen(Intel::Seen($host=c$id$orig_h, $where=IOC_IN_CONN_INBOUND, $conn=c));
    }

event connection_established(c: connection)
    {
    if ( detect_ioc_match )
        ioc_seen_conn(c, T);
    }

# 응답 없는 TCP 시도·UDP 는 연결이 끝날 때 본다(성립한 TCP 는 위에서 이미 봄).
event connection_state_remove(c: connection)
    {
    if ( ! detect_ioc_match )
        return;
    local tp = get_port_transport_proto(c$id$resp_p);
    if ( tp == tcp )
        ioc_seen_conn(c, F);
    else if ( tp == udp )
        ioc_seen_conn(c, c$resp$num_pkts > 0);
    delete ioc_conn_checked[c$uid];
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! detect_ioc_match || ! ioc_match_dns || query == "" )
        return;
    if ( ! Site::is_local_addr(c$id$orig_h) || c$id$orig_h in dns_tunnel_resolvers )
        return;
    ioc_seen_domain(query, IOC_IN_DNS, c);
    }

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
    {
    if ( ! detect_ioc_match || ! is_client || ! Site::is_local_addr(c$id$orig_h) )
        return;
    for ( _i, n in names )
        ioc_seen_domain(n, IOC_IN_TLS_SNI, c);
    }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    {
    if ( ! detect_ioc_match || ! is_orig || ! c?$http || ! Site::is_local_addr(c$id$orig_h) )
        return;
    local h = c$http;
    if ( h?$host && h$host != "" )
        ioc_seen_domain(h$host, IOC_IN_HTTP_HOST, c);
    if ( ! h?$uri || ( h?$method && h$method == "CONNECT" ) )
        return;
    local url = ioc_scheme in h$uri ? ioc_norm_url(h$uri)
                                    : ( h?$host ? ioc_norm_url(cat(h$host, h$uri)) : "" );
    if ( url == "" )
        return;
    Intel::seen(Intel::Seen($indicator=url, $indicator_type=Intel::URL, $where=IOC_IN_HTTP_URL, $conn=c));
    local noq = split_string1(url, /\?/)[0];
    if ( noq != url )
        Intel::seen(Intel::Seen($indicator=noq, $indicator_type=Intel::URL, $where=IOC_IN_HTTP_URL, $conn=c));
    }

# ---------------------------------------------------------------- 판정

function ioc_where_name(w: Intel::Where): string
    {
    switch ( w )
        {
        case IOC_IN_CONN:         return "conn";
        case IOC_IN_CONN_ATTEMPT: return "conn";
        case IOC_IN_CONN_INBOUND: return "conn_inbound";
        case IOC_IN_DNS:          return "dns_query";
        case IOC_IN_TLS_SNI:      return "tls_sni";
        case IOC_IN_HTTP_HOST:    return "http_host";
        case IOC_IN_HTTP_URL:     return "http_url";
        }
    return "-";
    }

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
    {
    if ( ! detect_ioc_match || s$where !in ioc_wheres || ! s?$conn )
        return;
    local c = s$conn;

    # 만료된 IOC 는 빼고, 남은 것 중 하나를 대표로 근거에 쓴다(IP 는 주소·대역 중 더 좁은 쪽이 먼저 오도록 ADDR 우선).
    local best: Intel::Item;
    local have = F;
    for ( it in items )
        {
        if ( it$meta?$nsm_expires && it$meta$nsm_expires < network_time() )
            next;
        if ( ! have || ( it$indicator_type == Intel::ADDR && best$indicator_type != Intel::ADDR ) )
            {
            best = it;
            have = T;
            }
        }
    if ( ! have )
        return;

    local inbound = s$where == IOC_IN_CONN_INBOUND;
    local src = c$id$orig_h;
    local kind = best$indicator_type == Intel::URL ? "url"
               : ( best$indicator_type == Intel::DOMAIN ? "domain" : "ip" );
    # 실제로 본 값: 하위 도메인으로 맞았으면 원래 이름을 남긴다
    local seen_val = s?$indicator ? s$indicator : ( s?$host ? cat(s$host) : "-" );
    if ( s$where == IOC_IN_DNS && c?$dns && c$dns?$query )
        seen_val = c$dns$query;
    else if ( s$where == IOC_IN_TLS_SNI && c?$ssl && c$ssl?$server_name )
        seen_val = c$ssl$server_name;
    else if ( s$where == IOC_IN_HTTP_HOST && c?$http && c$http?$host )
        seen_val = ioc_norm_domain(c$http$host);
    local status = "request";
    if ( s$where == IOC_IN_CONN || inbound )
        status = "established";
    else if ( s$where == IOC_IN_CONN_ATTEMPT )
        status = "attempt";
    else if ( s$where == IOC_IN_DNS )
        status = "lookup";

    if ( NSM::exception_drop(IOC_Match, c) )
        return;

    local nid = cat(src, "|ioc|", best$indicator);
    if ( NSM::notice_suppressed(IOC_Match, nid) )
        return;

    local cat_s = best$meta?$nsm_category ? best$meta$nsm_category : "-";
    local desc = best$meta?$desc ? best$meta$desc : "-";
    local host = kind == "ip" ? "" : cat(" host=", split_string1(best$indicator, /\//)[0]);
    local eid = cat(src, "|ioc|", best$indicator, "|", c$uid);
    local detail = fmt("ioc=%s type=%s seen=%s where=%s status=%s source=%s category=%s desc=%s%s",
                       best$indicator, kind, seen_val, ioc_where_name(s$where), status,
                       best$meta$source, cat_s, desc, host);

    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=IOC_Match,
        $technique="T1071",
        $src=src,
        $dst=c$id$resp_h,
        $uid=c$uid,
        $operation=cat("ioc_", kind),
        $detail=detail]);

    local n = Notice::Info($note=IOC_Match,
                           $src=src,
                           $uid=c$uid,
                           $msg=fmt("IOC match (%s): %s %s %s [%s, %s]", kind, src,
                                    inbound ? "<-" : "->", best$indicator, ioc_where_name(s$where), status),
                           $sub=fmt("ioc=%s type=%s where=%s status=%s source=%s category=%s",
                                    best$indicator, kind, ioc_where_name(s$where), status, best$meta$source, cat_s),
                           $identifier=nid,
                           $suppress_for=suppress_ioc,
                           $evidence_id=eid);
    # DNS 조회의 연결 상대는 리졸버라 피해 대상으로 쓰지 않는다.
    if ( s$where != IOC_IN_DNS )
        n$dst = c$id$resp_h;
    NOTICE(n);
    }
