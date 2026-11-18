##! ============================================================================
##! 명시적 프록시 인식 (탐지 아님, 유출 룰 10·12·14 공용)
##!
##! PC 에 프록시가 설정된 환경(PAC·WPAD 포함)에서는 PC 의 웹 연결이 모두 프록시(예: 3128/tcp)로 간다.
##! Zeek 에 보이는 목적지는 프록시라서, 프록시가 내부 대역(local_nets)에 있으면 "외부로 나간 연결"로
##! 보이지 않는다. 실제 목적지는 연결의 첫 요청에 평문으로 있다.
##!   - HTTPS: "CONNECT 호스트:포트". 성공(200)하면 Zeek 가 같은 연결의 나머지를 TLS 로 해석해 SNI 도 보인다.
##!   - HTTP : 절대 URL("POST http://호스트/경로").
##! 이 요청이 보이는 연결은 내부·외부 판단과 상관없이 "프록시를 거친 외부 연결"로 본다.
##!
##! CONNECT·절대 URL 을 받은 (주소, 포트)는 프록시로 배운다. 캡처 전부터 열려 있던 연결처럼 첫 요청을
##! 못 본 연결도 배운 프록시(또는 proxy_servers)로 가면 프록시 경유로 본다(실제 목적지 이름은 모른다).
##! 배운 내용은 워커마다 따로 갖는다(같은 PC-프록시 쌍은 보통 같은 워커로 간다).
##!
##! 프록시가 출발지인 외부 전송(프록시 -> 인터넷 구간)은 같은 업로드를 PC -> 프록시 구간에서 이미 보므로
##! 유출 탐지에서 뺀다(exfil_skip_proxy_source). 미러링이 프록시 바깥 구간만 보는 환경이면 프록시를
##! 배우지 못하므로(CONNECT 를 못 봄) 이 제외도 일어나지 않는다. proxy_servers 를 지정한 경우만 예외.
##!
##! HTTPS 로 프록시에 붙는 방식(PC-프록시 구간도 TLS)은 CONNECT 가 암호화돼 인식하지 못한다.
##! ============================================================================

@load base/protocols/http
@load base/protocols/ssl
@load base/utils/site
@load ./main

module NSM;

export {
    ## 고객이 아는 프록시 주소. 이 주소로 가는 TCP 연결은 첫 요청을 못 봐도 프록시 경유로 본다.
    const proxy_servers: set[addr] = {} &redef;
    ## CONNECT·절대 URL 요청을 받은 (주소, 포트)를 프록시로 배운다
    const proxy_learn = T &redef;
    ## 배운 프록시를 기억하는 시간(마지막으로 쓰인 뒤)
    const proxy_learn_expire = 24hr &redef;
    ## 프록시가 출발지인 외부 전송은 유출 탐지(10·12·14)에서 뺀다
    const exfil_skip_proxy_source = T &redef;

    ## HTTP 요청이 프록시 요청인가(CONNECT 또는 절대 URL)
    global is_proxy_request: function(method: string, uri: string): bool;
    ## 이 연결이 프록시를 거친 외부 연결인가(CONNECT·절대 URL, 배운 프록시, proxy_servers)
    global conn_via_proxy: function(c: connection): bool;
    ## 프록시 요청의 실제 목적지 호스트(포트 제외). 첫 요청을 못 봤으면 ""
    global proxy_target: function(c: connection): string;
    ## 이 주소가 프록시인가(proxy_servers 또는 배운 프록시)
    global is_proxy_host: function(a: addr): bool;
    ## 유출 룰 입구 조건: 내부 출발지(프록시 제외) -> 외부 목적지 또는 프록시 경유
    global exfil_outbound: function(c: connection): bool;
    ## 목적지 이름: SNI > 프록시 요청 대상 > HTTP Host. 없으면 ""
    global conn_dest_name: function(c: connection): string;
    ## 근거 detail 에 붙일 프록시 정보(" via_proxy=주소:포트", 프록시가 아니면 "")
    global proxy_detail: function(c: connection): string;
}

global proxy_learned: set[addr, port] &read_expire=proxy_learn_expire;
global proxy_hosts_learned: set[addr] &read_expire=proxy_learn_expire;

const abs_uri = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;

function is_proxy_request(method: string, uri: string): bool
    {
    return method == "CONNECT" || abs_uri in uri;
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( ! proxy_learn || ! is_proxy_request(method, original_URI) )
        return;
    add proxy_learned[c$id$resp_h, c$id$resp_p];
    add proxy_hosts_learned[c$id$resp_h];
    }

# 연결에 남은 HTTP 요청(마지막 요청)이 프록시 요청인가
function conn_proxy_request(c: connection): bool
    {
    if ( ! c?$http || ! c$http?$method )
        return F;
    return is_proxy_request(c$http$method, c$http?$uri ? c$http$uri : "");
    }

function conn_via_proxy(c: connection): bool
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return F;
    if ( conn_proxy_request(c) )
        return T;
    if ( c$id$resp_h in proxy_servers )
        return T;
    return [c$id$resp_h, c$id$resp_p] in proxy_learned;
    }

function is_proxy_host(a: addr): bool
    {
    return a in proxy_servers || a in proxy_hosts_learned;
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
    if ( ! conn_proxy_request(c) )
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
