##! ============================================================================
##! 인증 맥락 — 확산 근거에 "어떤 계정으로" 를 붙이기 위한 최근 인증 기록
##!
##!   - NTLM 인증(ntlm_authenticate): (출발지, 목적지) -> 사용자. 같은 대상에 쓴 계정이라 정확하다.
##!   - Kerberos TGS 응답(krb_tgs_response): (출발지, 서비스 종류) -> 클라이언트.
##!       서비스 티켓은 DC 에서 받으므로 목적지를 알 수 없다. 확산 룰은 프로토콜에 맞는 종류
##!       (SMB=cifs, WinRM=http·wsman, RDP=termsrv, DCOM=rpcss·host)로 "그 시간 출발지가 그 종류 티켓을
##!       받은 계정" 을 찾는다(대상별 정확도는 NTLM 보다 낮다).
##!   - 내부 출발지만 기록한다(NTLM 은 목적지도 내부일 때만). 실패한 인증도 기록된다(시도한 계정).
##!
##! 클러스터: 티켓 요청(DC 로 가는 연결)과 확산·원격 실행 연결은 서로 다른 워커가 볼 수 있다.
##!   각 워커는 새 (출발지, 키, 계정) 조합을 자기 표에 넣고 auth_ctx_resend 마다 한 번만 매니저로 보낸다.
##!   매니저는 표에 새로 들어간 조합만 모든 워커에 다시 알린다(auth_ctx_to_workers). 그래서 매니저에서 판정하는
##!   확산 룰(06·15·16·20·21)과 워커에서 판정하는 연결 단위 룰(23·31·34)이 단독 실행과 같은 계정을 찾는다.
##! ============================================================================

@load base/frameworks/cluster
@load base/protocols/ntlm
@load base/protocols/krb
@load base/utils/site
@load ./main

module NSM;

export {
    ## 기록을 유지하는 시간(확산 집계 창보다 길게)
    const auth_ctx_expire = 30min &redef;
    ## 같은 (출발지, 키, 계정)을 다시 보내지 않는 시간(워커 -> 매니저 전송량 억제)
    const auth_ctx_resend = 5min &redef;
    ## 키마다 남기는 계정 수(최근 것 우선이 아니라 먼저 본 것)
    const auth_ctx_max_accounts = 3 &redef;
    ## 클러스터: 매니저가 받은 인증 맥락을 워커에도 알린다(워커에서 판정하는 23·31·34 의 근거 계정).
    ##   전송량은 (출발지, 서비스 종류, 계정) 새 조합 수 × 워커 수. 아주 큰 망에서 매니저 부하가 문제면 F
    const auth_ctx_to_workers = T &redef;
    ## 기록할 Kerberos 서비스 종류(SPN 의 '/' 앞, 소문자). drsuapi GUID 는 DCSync 용
    const auth_krb_classes: set[string] = {
        "cifs", "http", "wsman", "termsrv", "rpcss", "host", "ldap", "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
    } &redef;

    ## 출발지가 목적지에 쓴 NTLM 계정, 없으면 klasses 종류의 Kerberos 티켓 계정. 쉼표 구분, 없으면 "".
    global auth_accounts: function(src: addr, dst: addr, klasses: set[string]): string;

    global auth_ctx_ntlm: event(src: addr, dst: addr, who: string);
    global auth_ctx_krb: event(src: addr, klass: string, who: string);
}

global auth_ntlm: table[addr, addr] of set[string] &create_expire=auth_ctx_expire;
global auth_krb: table[addr, string] of set[string] &create_expire=auth_ctx_expire;
global auth_sent: set[string] &create_expire=auth_ctx_resend;

# 새로 넣었으면 T
function auth_add(s: set[string], who: string): bool
    {
    if ( who in s || |s| >= auth_ctx_max_accounts )
        return F;
    add s[who];
    return T;
    }

# 받은 노드는 표에 넣는다. 매니저는 새로 들어간 조합만 워커에 다시 알린다(워커는 다시 보내지 않는다)
event NSM::auth_ctx_ntlm(src: addr, dst: addr, who: string)
    {
    if ( [src, dst] !in auth_ntlm )
        auth_ntlm[src, dst] = set();
    local added = auth_add(auth_ntlm[src, dst], who);
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
    if ( added && auth_ctx_to_workers )
        Cluster::publish(Cluster::worker_topic, NSM::auth_ctx_ntlm, src, dst, who);
@endif
    }

event NSM::auth_ctx_krb(src: addr, klass: string, who: string)
    {
    if ( [src, klass] !in auth_krb )
        auth_krb[src, klass] = set();
    local added = auth_add(auth_krb[src, klass], who);
@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
    if ( added && auth_ctx_to_workers )
        Cluster::publish(Cluster::worker_topic, NSM::auth_ctx_krb, src, klass, who);
@endif
    }

function auth_send_ntlm(src: addr, dst: addr, who: string)
    {
    local k = cat("n|", src, "|", dst, "|", who);
    if ( k in auth_sent )
        return;
    add auth_sent[k];
    event NSM::auth_ctx_ntlm(src, dst, who);   # 이 노드의 표
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
    Cluster::publish(Cluster::manager_topic, NSM::auth_ctx_ntlm, src, dst, who);
@endif
    }

function auth_send_krb(src: addr, klass: string, who: string)
    {
    local k = cat("k|", src, "|", klass, "|", who);
    if ( k in auth_sent )
        return;
    add auth_sent[k];
    event NSM::auth_ctx_krb(src, klass, who);   # 이 노드의 표
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
    Cluster::publish(Cluster::manager_topic, NSM::auth_ctx_krb, src, klass, who);
@endif
    }

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! request?$user_name || request$user_name == "" )
        return;
    if ( ! Site::is_local_addr(c$id$orig_h) || ! Site::is_local_addr(c$id$resp_h) )
        return;
    local who = to_lower(request$user_name);
    if ( request?$domain_name && request$domain_name != "" )
        who = cat(to_lower(request$domain_name), "\\", who);
    auth_send_ntlm(c$id$orig_h, c$id$resp_h, who);
    }

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( ! Site::is_local_addr(c$id$orig_h) || msg$client_name == "" )
        return;
    local spn = to_lower(msg$ticket$service_name);
    local parts = split_string1(spn, /\//);
    if ( |parts| < 2 || parts[0] !in auth_krb_classes )
        return;
    local who = to_lower(msg$client_name);
    if ( msg?$client_realm && msg$client_realm != "" )
        who = cat(who, "@", to_lower(msg$client_realm));
    auth_send_krb(c$id$orig_h, parts[0], who);
    }

function auth_accounts(src: addr, dst: addr, klasses: set[string]): string
    {
    local out: vector of string = vector();
    local seen: set[string] = set();
    if ( [src, dst] in auth_ntlm )
        for ( w in auth_ntlm[src, dst] )
            if ( w !in seen )
                {
                add seen[w];
                out += w;
                }
    if ( |out| == 0 )
        for ( k in klasses )
            if ( [src, k] in auth_krb )
                for ( w in auth_krb[src, k] )
                    if ( w !in seen )
                        {
                        add seen[w];
                        out += w;
                        }
    sort(out, function(a: string, b: string): int { return strcmp(a, b); });
    return join_string_vec(out, ",");
    }
