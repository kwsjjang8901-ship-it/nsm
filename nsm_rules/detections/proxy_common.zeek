##! ============================================================================
##! 명시적 프록시 인식 (탐지 아님, 유출 룰 10·12·14 공용)
##!
##! PC 에 프록시가 설정된 환경(PAC·WPAD 포함)에서는 PC 의 웹 연결이 모두 프록시(예: 3128/tcp)로 간다.
##! Zeek 에 보이는 목적지는 프록시라서, 프록시가 내부 대역(local_nets)에 있으면 "외부로 나간 연결"로
##! 보이지 않는다. 실제 목적지는 연결의 첫 요청에 평문으로 있다.
##!   - HTTPS: "CONNECT 호스트:포트". 성공(200)하면 Zeek 가 같은 연결의 나머지를 TLS 로 해석해 SNI 도 보인다.
##!   - HTTP : 절대 URL("POST http://호스트/경로").
##!
##! 프록시 학습(오탐·회피 방지를 위해 좁게 잡는다)
##!   - 내부 PC 의 CONNECT 에 2xx 로 답하고, 이어서 같은 연결에서 TLS 접속 시작(ClientHello)이 보인
##!     (주소, 포트)만 프록시로 배운다. 외부 스캐너가 내부 웹서버로 보내는 CONNECT·절대 URL 탐색, 거부(4xx)된
##!     CONNECT, 그리고 어떤 요청에도 200 으로 답하는 장비(프린터·NAS 등 임베디드 웹서버)에 점검 장비가 CONNECT 만
##!     보내고 끝낸 경우로는 배우지 않는다. 진짜 프록시를 쓰는 PC 는 CONNECT 뒤에 바로 HTTPS 접속을 이어 간다.
##!     (TLS 가 아닌 터널, 예: CONNECT 뒤 SSH 는 배우지 않는다. 그런 프록시는 proxy_servers 로 지정)
##!   - 절대 URL 만으로는 배우지 않는다(웹서버도 절대 URL 을 받는다). 배운 프록시로 가는 평문 HTTP 는 프록시 경유로 본다.
##!   - 배운 프록시나 proxy_servers 로 가는 TCP 연결은 "프록시를 거친 외부 연결"로 본다. 첫 요청을 못 본
##!     연결(캡처 전부터 열려 있던 연결 등)도 포함하며, 그때는 실제 목적지 이름을 모른다.
##!   - 클러스터에서는 한 워커가 배운 프록시와 쓴 PC 를 모든 노드에 알려 같은 표를 갖는다(main.zeek share_learned).
##!
##! 프록시가 출발지인 외부 전송(프록시 -> 인터넷 구간)은 같은 업로드를 PC -> 프록시 구간에서 이미 보므로
##! 유출 탐지에서 뺀다(exfil_skip_proxy_source). 다만 출발지 제외는 탐지를 없애는 쪽이라 더 엄격하게,
##! proxy_servers 에 있거나 서로 다른 내부 PC proxy_source_min_clients(3)대 이상의 CONNECT 에 2xx 로
##! 답한 프록시만 뺀다(개발자 PC 의 디버깅 프록시 같은 것을 띄워 유출을 숨기는 것을 막는다).
##! 미러링이 프록시 바깥 구간만 보는 환경이면 CONNECT 를 못 봐 배우지 못하므로 이 제외도 일어나지 않는다.
##!
##! HTTPS 로 프록시에 붙는 방식(PC-프록시 구간도 TLS)은 CONNECT 가 암호화돼 인식하지 못한다.
##! ============================================================================

@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site
@load ./main

module NSM;

export {
    ## 고객이 아는 프록시 주소. 이 주소로 가는 TCP 연결은 프록시 경유로 보고, 이 주소가 출발지인 외부 전송은 뺀다.
    const proxy_servers: set[addr] = {} &redef;
    ## 내부 PC 의 CONNECT 에 2xx 로 답한 (주소, 포트)를 프록시로 배운다
    const proxy_learn = T &redef;
    ## 배운 프록시를 기억하는 시간(마지막으로 쓰인 뒤)
    const proxy_learn_expire = 24hr &redef;
    ## 프록시가 출발지인 외부 전송은 유출 탐지(10·12·14)에서 뺀다
    const exfil_skip_proxy_source = T &redef;
    ## 배운 프록시를 출발지 제외 대상으로 볼 최소 내부 PC 수(서로 다른 CONNECT 성공 클라이언트)
    const proxy_source_min_clients = 3 &redef;

    ## C2·AI 계열 룰의 프록시 인식(프록시를 거친 연결도 실제 목적지 기준으로 판정).
    ## 고객 프록시 환경 측정(2026-11, 1.4시간)에서 33·24·09 는 새 오탐이 거의 없었고, 07·30 은 흔한 OS·SaaS
    ## 주기 통신(업데이트·원격 측정·연결 확인)이 많아 기본 끔. 켤 때는 docs/examples/exceptions.proxy-beacon.tsv 를 함께 쓴다.
    const proxy_aware_ai = T &redef;          ##< 33 AI 업로드·서버의 AI 접속
    const proxy_aware_nonstd = T &redef;      ##< 24 비표준 포트(CONNECT 대상 포트로 판정)
    const proxy_aware_enc_c2 = T &redef;      ##< 09 수상한 암호화 통신(터널 안 TLS)
    const proxy_aware_beacon = F &redef;      ##< 07·30 주기 접속

    ## 프록시 경유 연결의 실제 목적지
    type ProxyDest: record {
        name: string &default="";             ##< 호스트 이름 또는 주소(소문자, 포트 제외)
        p:    count  &default=0;              ##< 목적지 포트(CONNECT 대상 포트, 절대 URL 포트, 없으면 443·80)
    };

    ## 이 연결이 프록시를 거친 외부 연결인가(배운 프록시 또는 proxy_servers 로 가는 TCP 연결)
    global conn_via_proxy: function(c: connection): bool;
    ## 프록시 경유 연결의 실제 목적지 호스트(CONNECT 대상·절대 URL 호스트, 포트 제외). 모르면 ""
    global proxy_target: function(c: connection): string;
    ## 출발지 제외 대상 프록시인가(proxy_servers, 또는 내부 PC proxy_source_min_clients 대 이상이 쓰는 배운 프록시)
    global is_proxy_host: function(a: addr): bool;
    ## 유출 룰 입구 조건: 내부 출발지(프록시 제외) -> 외부 목적지 또는 프록시 경유
    global exfil_outbound: function(c: connection): bool;
    ## 목적지 이름: SNI > 프록시 요청 대상 > HTTP Host. 없으면 ""
    global conn_dest_name: function(c: connection): string;
    ## 근거 detail 에 붙일 프록시 정보(" via_proxy=주소:포트", 프록시가 아니면 "")
    global proxy_detail: function(c: connection): string;
    ## 프록시 경유 연결의 실제 목적지(이름·포트). 프록시가 아니거나 첫 요청을 못 봤으면 빈 값
    global proxy_dest: function(c: connection): ProxyDest;
    ## C2·AI 계열 룰이 쓸 프록시 경유 목적지 이름. 목적지를 모르거나, 프록시 자신이거나, 내부 주소면 ""
    ##   (목적지를 모르는 연결을 프록시 하나로 묶으면 주기·누적 판정이 오탐을 낸다)
    global proxy_c2_dest: function(c: connection): string;
    ## 프록시 터널이 확인됨(CONNECT 2xx 뒤 TLS 시작). 이 시점에 그 (주소, 포트)를 배운 뒤 발생한다.
    global proxy_tunnel_confirmed: event(c: connection);
}

global proxy_learned: set[addr, port] &read_expire=proxy_learn_expire;
# 배운 프록시별 CONNECT 에 성공한 내부 PC(최대 proxy_source_min_clients 대까지만 기억)
global proxy_clients: table[addr] of set[addr] &read_expire=proxy_learn_expire;

const abs_uri = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;

# 프록시 (주소, 포트)와 그 프록시로 CONNECT 에 성공한 내부 PC 를 기억한다
function proxy_add(p: addr, pp: port, client: addr)
    {
    add proxy_learned[p, pp];
    if ( p !in proxy_clients )
        proxy_clients[p] = set();
    if ( |proxy_clients[p]| < proxy_source_min_clients )
        add proxy_clients[p][client];
    }

# 터널이 확인된 프록시를 배운다
function proxy_learn_tunnel(p: addr, pp: port, client: addr)
    {
    proxy_add(p, pp, client);
    # 클러스터: 다른 워커의 PC 도 같은 프록시를 쓰므로 배운 프록시와 쓴 PC 를 공유한다
    NSM::share_learned("proxy", p, pp, client);
    }

# CONNECT 가 2xx 로 성공한 연결(uid). 이어서 TLS 가 시작되면 프록시로 배운다.
global proxy_connect_ok: set[string] &create_expire=10min;

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( ! proxy_learn || code < 200 || code >= 300 )
        return;
    if ( ! c?$http || ! c$http?$method || c$http$method != "CONNECT" )
        return;
    if ( ! Site::is_local_addr(c$id$orig_h) )
        return;
    add proxy_connect_ok[c$uid];
    }

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
                       client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
    {
    if ( c$uid !in proxy_connect_ok )
        return;
    delete proxy_connect_ok[c$uid];
    proxy_learn_tunnel(c$id$resp_h, c$id$resp_p, c$id$orig_h);
    event NSM::proxy_tunnel_confirmed(c);
    }

event NSM::learned_shared(kind: string, a: addr, p: port, b: addr)
    {
    if ( kind == "proxy" && proxy_learn )
        proxy_add(a, p, b);
    }

event connection_state_remove(c: connection)
    {
    delete proxy_connect_ok[c$uid];
    }

function conn_via_proxy(c: connection): bool
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return F;
    return c$id$resp_h in proxy_servers || [c$id$resp_h, c$id$resp_p] in proxy_learned;
    }

function is_proxy_host(a: addr): bool
    {
    if ( a in proxy_servers )
        return T;
    return a in proxy_clients && |proxy_clients[a]| >= proxy_source_min_clients;
    }

# "호스트:포트" 의 포트를 뗀다. IPv6 는 대괄호 형식만 다룬다("[::1]:443").
function strip_host_port(h: string): string
    {
    if ( /^[^:\[\]]+:[0-9]+$/ == h || /^\[.*\]:[0-9]+$/ == h )
        return sub(h, /:[0-9]+$/, "");
    return h;
    }

function proxy_target(c: connection): string
    {
    if ( ! conn_via_proxy(c) || ! c?$http || ! c$http?$method )
        return "";
    if ( c$http$method == "CONNECT" && c$http?$uri && c$http$uri != "" )
        return to_lower(strip_host_port(c$http$uri));
    if ( c$http?$host && c$http$host != "" )
        return to_lower(strip_host_port(c$http$host));
    if ( c$http?$uri )
        {
        # 절대 URL 에서 호스트: scheme://[userinfo@]host[:port]/...
        local rest = sub(c$http$uri, abs_uri, "");
        local hp = split_string1(rest, /\//)[0];
        local at = split_string(hp, /@/);
        return to_lower(strip_host_port(at[|at| - 1]));
        }
    return "";
    }

function exfil_outbound(c: connection): bool
    {
    if ( ! Site::is_local_addr(c$id$orig_h) )
        return F;
    if ( exfil_skip_proxy_source && is_proxy_host(c$id$orig_h) )
        return F;
    return is_external(c$id$resp_h) || conn_via_proxy(c);
    }

function conn_dest_name(c: connection): string
    {
    if ( c?$ssl && c$ssl?$server_name && c$ssl$server_name != "" )
        return to_lower(c$ssl$server_name);
    local t = proxy_target(c);
    if ( t != "" )
        return t;
    if ( c?$http && c$http?$host && c$http$host != "" )
        return to_lower(strip_host_port(c$http$host));
    return "";
    }

function proxy_detail(c: connection): string
    {
    if ( ! conn_via_proxy(c) )
        return "";
    return fmt(" via_proxy=%s:%s", c$id$resp_h, port_to_count(c$id$resp_p));
    }

function proxy_dest(c: connection): ProxyDest
    {
    local d = ProxyDest();
    if ( ! conn_via_proxy(c) || ! c?$http || ! c$http?$method )
        return d;
    d$name = proxy_target(c);
    if ( d$name == "" )
        return d;
    local hp = "";
    if ( c$http$method == "CONNECT" && c$http?$uri )
        hp = c$http$uri;
    else if ( c$http?$host )
        hp = c$http$host;
    if ( /:[0-9]+$/ in hp )
        d$p = to_count(split_string(hp, /:/)[|split_string(hp, /:/)| - 1]);
    else
        d$p = c$http$method == "CONNECT" ? 443 : 80;
    return d;
    }

function proxy_c2_dest(c: connection): string
    {
    local d = proxy_dest(c);
    if ( d$name == "" )
        return "";
    local n = sub(sub(d$name, /^\[/, ""), /\]$/, "");
    if ( is_valid_ip(n) )
        {
        local a = to_addr(n);
        if ( a == c$id$resp_h || Site::is_local_addr(a) || a in proxy_servers )
            return "";
        }
    return d$name;
    }
