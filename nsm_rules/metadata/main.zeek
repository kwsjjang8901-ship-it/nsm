##! ============================================================================
##! 메타데이터 선별 전송 (T1) — docs/METADATA_EXPORT_PLAN.md
##!
##!   탐지 결과(T0) 외에 조사·헌팅에 필요한 프로토콜 메타데이터를 골라 별도 경로
##!   (meta_path_prefix, 기본 /log/zeek/meta/)에 JSON 으로 남긴다. 수집 에이전트가 이 경로를
##!   Manager 로 보낸다.
##!
##!   스트림마다 "nsm_meta" 로그 필터를 하나 더 붙인다.
##!     - include  : 조사에 쓰는 필드만 남긴다(meta_export_streams 의 fields)
##!     - policy 훅: 범위(scope) → 스트림별 조건 → 중복 억제 → 분당 상한 순으로 판정하고,
##!                  탈락한 행은 이 필터로 쓰지 않는다(직렬화·로거 전송·디스크 쓰기 없음).
##!   판정은 Log::write 를 부르는 노드(클러스터에서는 워커)에서 일어난다.
##!
##!   원본 스트림 처리
##!     - keep_log_streams 에 있는 스트림: default 필터(원본)를 그대로 둔다.
##!     - 없는 스트림: filter_log 가 끈 스트림을 다시 켜고 default 필터를 지운다.
##!       meta_keep_raw_local = T 면 default 필터를 지우지 않고 meta_raw_path_prefix + Zeek 기본 이름(conn, dns …)으로 보낸다(T2).
##!
##!   요약 모드(MetaSpec$summary = T): 행을 보내지 않고 노드 메모리에서 묶어 주기마다 요약 행을 쓴다.
##!     - conn → flow_summary.log : (출발지, 목적지, 목적지 포트, 프로토콜)별, meta_flow_interval(10분)
##!     - dns  → dns_summary.log  : (출발지, 등록 도메인)별, meta_dns_interval(1시간). 유형·결과는 필드로 모은다
##!       질의 이름이 매번 다른 트래픽(DGA·터널링·CDN)도 도메인 하나로 묶이도록 등록 도메인 단위로 센다.
##!     - http 의 User-Agent → http_ua_summary.log : (출발지, User-Agent)별, meta_ua_interval(24시간).
##!       http 행에는 User-Agent 를 싣지 않는다(행 크기의 큰 부분).
##!
##!   meta_export_stats.log : meta_stats_interval 마다 스트림별 보냄·요약·탈락 건수(노드별).
##!
##!   탐지 경로(notice·nsm_detection·evidence)는 이 모듈과 무관하게 그대로 기록된다.
##! ============================================================================

@load base/frameworks/logging
@load base/utils/site
@load base/protocols/conn
@load base/protocols/krb
@load base/protocols/ntlm
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/rdp
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/dns
@load policy/misc/capture-loss
@load policy/misc/stats
@load ../rules/filter_log
@load ../detections/main             # domain_matches
@load ../detections/08_dns_tunneling # dns_tunnel_resolvers(내부 재귀 리졸버)

module NSM;

export {
    redef enum Log::ID += { META_STATS_LOG, META_FLOW_LOG, META_DNS_LOG, META_UA_LOG };

    ## 행을 고르는 범위(연결 방향 기준). 연결 정보가 없는 로그(상태 로그)는 범위와 무관하게 통과한다.
    type MetaScope: enum {
        META_ALL,                ##< 방향 제한 없음
        META_BOUNDARY,           ##< 내부 <-> 외부
        META_ADMIN_INTERNAL,     ##< 내부 -> 내부, 목적지 포트가 meta_admin_ports
        META_BOUNDARY_OR_ADMIN,  ##< 위 둘 중 하나
    };

    ## 스트림별 선별 전송 설정
    type MetaSpec: record {
        name:       string;                   ##< 출력 이름(meta_path_prefix 뒤에 붙음)
        fields:     set[string] &optional;    ##< 남길 필드(없으면 전체). id 는 "id.orig_h" 처럼 적는다
        scope:      MetaScope &default=META_ALL;
        dedup:      interval &default=0secs;  ##< 같은 중복 키를 다시 보내지 않는 기간(0 = 끔)
        rate_limit: count &default=0;         ##< 노드별 분당 최대 행 수(0 = 무제한)
        summary:    bool &default=F;          ##< T: 행 대신 요약 로그로 묶음(Conn::LOG, DNS::LOG 만 지원)
    };

    ## 전체 토글
    const meta_export_enable = T &redef;

    ## 출력 경로 앞부분. "/log/zeek/meta/" 면 /log/zeek/meta/kerberos.log 처럼 쓴다.
    const meta_path_prefix = "/log/zeek/meta/" &redef;

    ## T2: 선별 대상 스트림의 원본을 센서 로컬에 남길지, 남길 경로 앞부분
    const meta_keep_raw_local = F &redef;
    const meta_raw_path_prefix = "/hdd_tmp/log/zeek/" &redef;

    ## 내부 관리·인증 포트(META_ADMIN_INTERNAL 범위)
    const meta_admin_ports: set[port] = {
        22/tcp, 88/tcp, 88/udp, 135/tcp, 139/tcp, 389/tcp, 389/udp, 445/tcp, 636/tcp,
        3268/tcp, 3269/tcp, 3389/tcp, 5985/tcp, 5986/tcp,
    } &redef;

    ## smb_files 에서 남길 동작(읽기·열기·닫기는 양이 많아 제외)
    const meta_smb_file_actions: set[SMB::Action] = {
        SMB::FILE_WRITE, SMB::FILE_RENAME, SMB::FILE_DELETE,
    } &redef;

    ## dce_rpc 에서 남길 인터페이스(dce_rpc.log 의 endpoint 이름, 대소문자 무시).
    ##   이름은 Zeek base/protocols/dce-rpc/consts.zeek 기준(ISystemActivator = IRemoteSCMActivator).
    const meta_dce_rpc_endpoints: set[string] = {
        "drsuapi",                                  # 디렉터리 복제(DCSync)
        "svcctl", "atsvc", "itaskschedulerservice", # 원격 서비스·작업 생성(PsExec, schtasks)
        "winreg",                                   # 원격 레지스트리
        "iremotescmactivator",                      # 원격 COM 객체 생성(DCOM, wmiexec 시작)
        "iwbemlevel1login", "iwbemservices",        # 원격 WMI
        "samr", "lsarpc",                           # 계정·그룹 열거
        "netlogon",                                 # Zerologon 등
        "efsrpc",                                   # PetitPotam 강제 인증
    } &redef;

    ## ssl·http(SNI·Host)·dns(질의)에서 뺄 도메인(접미사 일치). 업데이트·CDN·텔레메트리 등.
    const meta_domain_allowlist: set[string] = {} &redef;

    ## 요약 로그 주기와 노드당 최대 키 수(넘으면 그 시점에 내보내고 새로 시작)
    const meta_flow_interval = 30min &redef;
    const meta_dns_interval = 1hr &redef;
    const meta_ua_interval = 24hr &redef;

    ## http 의 User-Agent 를 (출발지, User-Agent)별 요약 로그로 보낼지
    const meta_ua_summary = T &redef;
    const meta_summary_max_keys = 100000 &redef;

    ## dns_summary 에 남길 응답·표본 이름 최대 개수, 고유 이름을 셀 최대 개수(넘으면 unique_names_capped)
    const meta_dns_max_answers = 3 &redef;
    const meta_dns_max_samples = 3 &redef;
    const meta_dns_max_unique = 1000 &redef;

    ## 출발지 하나가 한 주기에 만드는 dns_summary 도메인 행 상한. 넘는 도메인은 domain="(other)" 한 행에
    ## 묶는다(DGA·대량 조회 host 가 요약 로그를 키우지 않게).
    const meta_dns_max_domains_per_src = 100 &redef;

    ## 스트림별 설정. 여기 있는 스트림만 선별 전송한다.
    const meta_export_streams: table[Log::ID] of MetaSpec = {
        [KRB::LOG] = [$name="kerberos",
                      $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                  "request_type", "client", "service", "success", "error_msg", "cipher")],
        [NTLM::LOG] = [$name="ntlm",
                       $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                   "username", "domainname", "hostname", "success")],
        [SMB::MAPPING_LOG] = [$name="smb_mapping",
                              $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                          "path", "share_type"),
                              $dedup=1hr],
        [SMB::FILES_LOG] = [$name="smb_files",
                            $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                        "action", "path", "name", "prev_name", "size"),
                            $dedup=10min],
        [DCE_RPC::LOG] = [$name="dce_rpc",
                          $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                      "endpoint", "operation"),
                          $dedup=10min],
        [RDP::LOG] = [$name="rdp",
                      $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                  "cookie", "security_protocol", "result")],
        [SSH::LOG] = [$name="ssh",
                      $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                  "auth_success", "auth_attempts", "direction", "client", "server")],
        [SSL::LOG] = [$name="ssl", $scope=META_BOUNDARY, $dedup=24hr,
                      $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                  "version", "cipher", "server_name", "established", "ja3")],
        # URL 은 쿼리 문자열을 뺀 uri_path 만 보낸다(개인정보).
        [HTTP::LOG] = [$name="http", $scope=META_BOUNDARY, $dedup=10min,
                       $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                   "method", "host", "uri_path", "status_code",
                                   "request_body_len", "response_body_len")],
        # 양이 큰 conn·dns 는 요약 로그로 보낸다.
        [Conn::LOG] = [$name="flow_summary", $scope=META_BOUNDARY_OR_ADMIN, $summary=T],
        [DNS::LOG]  = [$name="dns_summary", $summary=T],
        # 센서 상태
        [CaptureLoss::LOG] = [$name="capture_loss"],
        [Stats::LOG]       = [$name="stats"],
        [Reporter::LOG]    = [$name="reporter"],
    } &redef;

    ## 중복 억제 상태: 항목 수 상한(넘으면 새 키는 억제하지 않고 보낸다).
    ##   항목은 각자의 억제 기간(스트림 dedup)이 끝나면 지워지고, 만료 여부는 meta_dedup_check_interval 마다 확인한다.
    const meta_dedup_max_entries = 200000 &redef;
    const meta_dedup_check_interval = 10min &redef;

    ## meta_export_stats.log 기록 주기
    const meta_stats_interval = 5min &redef;

    type MetaStats: record {
        ts:             time    &log;
        node:           string  &log;   ##< 기록한 노드(standalone 은 "zeek")
        stream:         string  &log;   ##< MetaSpec 의 name
        sent:           count   &log &default=0;
        dropped_scope:  count   &log &default=0;   ##< 범위 밖
        dropped_filter: count   &log &default=0;   ##< 스트림별 조건(동작·인터페이스 등) 탈락
        dropped_dedup:  count   &log &default=0;   ##< 중복 억제
        dropped_rate:   count   &log &default=0;   ##< 분당 상한 초과
        summarized:     count   &log &default=0;   ##< 요약 로그로 묶은 행
    };

    ## flow_summary.log
    type FlowSummary: record {
        ts:         time   &log;            ##< 주기 안 첫 연결 시작 시각
        node:       string &log;
        orig_h:     addr   &log;
        resp_h:     addr   &log;
        resp_p:     port   &log;
        proto:      transport_proto &log;
        service:    string &log &optional;  ##< 관측된 서비스(쉼표 구분)
        conns:      count  &log &default=0;
        orig_bytes: count  &log &default=0;
        resp_bytes: count  &log &default=0;
        states:     string &log &optional;  ##< 연결 상태별 건수(예: SF:12,S0:3)
        sample_uid: string &log &optional;  ##< 대표 연결 uid. 원본 conn 로그가 남을 때만(T2 또는 keep_log_streams 에 Conn::LOG)
        svc_set:    set[string] &default=set();
        state_cnt:  table[string] of count &default=table();
    };

    ## dns_summary.log
    type DnsSummary: record {
        ts:           time   &log;
        ts_end:       time   &log;
        node:         string &log;
        orig_h:       addr   &log;
        domain:       string &log;                  ##< 등록 도메인(parent_domain, co.kr 등 2단계 접미사 처리)
        qtypes:       string &log &optional;        ##< 관측된 질의 유형(쉼표 구분, 예: A,AAAA,HTTPS)
        rcodes:       string &log &optional;        ##< 결과별 질의 수(예: NOERROR:12,NXDOMAIN:1)
        queries:      count  &log &default=0;       ##< 질의 수
        unique_names: count  &log &default=0;       ##< 고유 질의 이름 수
        unique_names_capped: bool &log &optional;   ##< 참일 때만 기록: meta_dns_max_unique 에 닿아 그 뒤는 세지 않음
        sample_names: vector of string &log;        ##< 처음 관측한 질의 이름(최대 meta_dns_max_samples)
        answers:      vector of string &log &optional;  ##< 처음 관측한 응답(최대 meta_dns_max_answers)
        sample_uid:   string &log &optional;  ##< 대표 uid. 원본 dns 로그가 남을 때만(T2 또는 keep_log_streams 에 DNS::LOG)
        names:        set[string] &default=set();
        qtype_set:    set[string] &default=set();
        rcode_cnt:    table[string] of count &default=table();
    };

    ## http_ua_summary.log
    type UaSummary: record {
        ts:         time   &log;            ##< 주기 안 첫 요청 시각
        ts_end:     time   &log;            ##< 주기 안 마지막 요청 시각
        node:       string &log;
        orig_h:     addr   &log;
        user_agent: string &log;
        requests:   count  &log &default=0; ##< 선별 대상(범위·조건 통과) http 요청 수(중복 억제 전)
        hosts:      count  &log &default=0; ##< 고유 Host 수(100개까지 셈)
        sample_host: string &log &optional;
        host_set:   set[string] &default=set();
    };

    ## 한 행의 판정 재료. 스트림마다 meta_extract 가 채운다.
    type MetaRow: record {
        cid:  conn_id &optional;   ##< 연결 4-튜플(없으면 범위 판정 생략)
        keep: bool &default=T;     ##< 스트림별 조건 통과 여부
        key:  string &default="";  ##< 중복 억제 키(빈 문자열이면 억제하지 않음)
    };
}

redef NSM::keep_log_streams += { NSM::META_STATS_LOG };

## http: 쿼리 문자열을 뺀 경로(선별 전송용). 원본 http.log 를 남기는 환경에서는 그 로그에도 열이 생긴다.
redef record HTTP::Info += {
    uri_path: string &log &optional;
};

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string,
                   version: string) &priority=4
    {
    if ( ! c?$http )
        return;
    local parts = split_string1(original_URI, /\?/);
    c$http$uri_path = parts[0];
    }

# ---------------------------------------------------------------- 상태

# 값 = 억제가 끝나는 시각. 확인 시점에 아직 남았으면 남은 시간만큼 더 둔다(스트림마다 억제 기간이 다르다).
function meta_dedup_expire(t: table[string] of time, k: string): interval
    {
    local left = t[k] - network_time();
    return left > 0secs ? left : 0secs;
    }

global meta_dedup: table[string] of time &create_expire=meta_dedup_check_interval
                                         &expire_func=meta_dedup_expire;
global meta_rate_bucket: count = 0;
global meta_rate_count: table[string] of count = table();
global meta_counters: table[string] of MetaStats = table();

function meta_counter(name: string): MetaStats
    {
    if ( name !in meta_counters )
        meta_counters[name] = MetaStats($ts=network_time(), $node=peer_description, $stream=name);
    return meta_counters[name];
    }

# ---------------------------------------------------------------- 판정

function meta_in_scope(scope: MetaScope, cid: conn_id): bool
    {
    if ( scope == META_ALL )
        return T;
    local ol = Site::is_local_addr(cid$orig_h);
    local rl = Site::is_local_addr(cid$resp_h);
    local boundary = ol != rl;
    local admin = ol && rl && cid$resp_p in meta_admin_ports;
    switch ( scope )
        {
        case META_BOUNDARY:
            return boundary;
        case META_ADMIN_INTERNAL:
            return admin;
        case META_BOUNDARY_OR_ADMIN:
            return boundary || admin;
        default:
            return T;
        }
    }

function meta_cid_key(cid: conn_id): string
    {
    return cat(cid$orig_h, ">", cid$resp_h);
    }

## 스트림별 판정 재료. 새 스트림을 선별 전송하려면 여기에 추가한다.
function meta_extract(id: Log::ID, rec: any): MetaRow
    {
    local r: MetaRow;

    if ( rec is Conn::Info )
        {
        local cn = rec as Conn::Info;
        r$cid = cn$id;
        r$key = cat(meta_cid_key(cn$id), ":", cn$id$resp_p);
        }
    else if ( rec is KRB::Info )
        r$cid = (rec as KRB::Info)$id;
    else if ( rec is NTLM::Info )
        r$cid = (rec as NTLM::Info)$id;
    else if ( rec is SMB::TreeInfo )
        {
        local tr = rec as SMB::TreeInfo;
        r$cid = tr$id;
        r$key = cat(tr$id$orig_h, ">", tr$id$resp_h, "|", tr?$path ? to_lower(tr$path) : "-");
        }
    else if ( rec is SMB::FileInfo )
        {
        local fi = rec as SMB::FileInfo;
        r$cid = fi$id;
        r$keep = fi?$action && fi$action in meta_smb_file_actions;
        r$key = cat(meta_cid_key(fi$id), "|", fi$action, "|",
                    fi?$path ? to_lower(fi$path) : "-", "|", fi?$name ? to_lower(fi$name) : "-");
        }
    else if ( rec is DCE_RPC::Info )
        {
        local dr = rec as DCE_RPC::Info;
        r$cid = dr$id;
        r$keep = dr?$endpoint && to_lower(dr$endpoint) in meta_dce_rpc_endpoints;
        r$key = cat(meta_cid_key(dr$id), "|", dr?$endpoint ? dr$endpoint : "-", "|",
                    dr?$operation ? dr$operation : "-");
        }
    else if ( rec is SSL::Info )
        {
        local sl = rec as SSL::Info;
        r$cid = sl$id;
        local sni = sl?$server_name ? to_lower(sl$server_name) : "";
        r$keep = ! domain_matches(sni, meta_domain_allowlist);
        r$key = cat(sl$id$orig_h, "|", sni, "|", sl?$ja3 ? sl$ja3 : "-");
        }
    else if ( rec is HTTP::Info )
        {
        local hp = rec as HTTP::Info;
        r$cid = hp$id;
        local host = hp?$host ? to_lower(hp$host) : "";
        r$keep = ! domain_matches(host, meta_domain_allowlist);
        r$key = cat(hp$id$orig_h, "|", host, "|", hp?$method ? hp$method : "-", "|",
                    hp?$uri_path ? hp$uri_path : "-", "|", hp?$status_code ? cat(hp$status_code) : "-");
        }
    else if ( rec is DNS::Info )
        {
        local dn = rec as DNS::Info;
        r$cid = dn$id;
        local q = dn?$query ? to_lower(dn$query) : "";
        local ql = |q|;
        r$keep = q != ""
                 && dn$id$orig_h !in dns_tunnel_resolvers          # 리졸버가 대신 묻는 질의(중복)
                 && ! ( ql >= 13 && q[ql - 13 :] == ".in-addr.arpa" )
                 && ! ( ql >= 9 && q[ql - 9 :] == ".ip6.arpa" )
                 && ! domain_matches(q, meta_domain_allowlist);
        }
    else if ( rec is RDP::Info )
        r$cid = (rec as RDP::Info)$id;
    else if ( rec is SSH::Info )
        r$cid = (rec as SSH::Info)$id;

    return r;
    }

# ---------------------------------------------------------------- 요약

# 원본 conn·dns 로그가 남는지(T2 이거나 keep_log_streams 에 있음). 남을 때만 요약에 sample_uid 를 붙인다.
global meta_flow_raw = F;
global meta_dns_raw = F;

global meta_flows: table[string] of FlowSummary = table();
global meta_dns: table[string] of DnsSummary = table();
global meta_dns_src_domains: table[addr] of count = table();

## 이름순으로 쉼표로 잇는다(출력이 실행마다 같도록)
function meta_join_sorted(ss: set[string]): string
    {
    local v: vector of string = vector();
    for ( x in ss )
        v += x;
    sort(v, strcmp);
    return join_string_vec(v, ",");
    }

## "A:3,B:1" 같은 건수 문자열(이름순)
function meta_count_str(t: table[string] of count): string
    {
    local ks: set[string] = set();
    for ( k in t )
        add ks[k];
    local out = "";
    for ( _i, k2 in split_string(meta_join_sorted(ks), /,/) )
        out = out == "" ? fmt("%s:%d", k2, t[k2]) : fmt("%s,%s:%d", out, k2, t[k2]);
    return out;
    }

function meta_flush_flows()
    {
    for ( _k, fs in meta_flows )
        {
        if ( |fs$svc_set| > 0 )
            fs$service = meta_join_sorted(fs$svc_set);
        if ( |fs$state_cnt| > 0 )
            fs$states = meta_count_str(fs$state_cnt);
        Log::write(META_FLOW_LOG, fs);
        }
    meta_flows = table();
    }

function meta_flush_dns()
    {
    for ( _k, ds in meta_dns )
        {
        if ( |ds$qtype_set| > 0 )
            ds$qtypes = meta_join_sorted(ds$qtype_set);
        if ( |ds$rcode_cnt| > 0 )
            ds$rcodes = meta_count_str(ds$rcode_cnt);
        Log::write(META_DNS_LOG, ds);
        }
    meta_dns = table();
    meta_dns_src_domains = table();
    }

global meta_ua: table[string] of UaSummary = table();

function meta_flush_ua()
    {
    for ( _k, us in meta_ua )
        Log::write(META_UA_LOG, us);
    meta_ua = table();
    }

## http 행(범위·조건 통과, 중복 억제 전)의 User-Agent 를 (출발지, User-Agent)별로 센다.
function meta_summarize_ua(hp: HTTP::Info)
    {
    if ( ! hp?$user_agent || hp$user_agent == "" )
        return;
    local k = cat(hp$id$orig_h, "|", hp$user_agent);
    if ( k !in meta_ua )
        {
        if ( |meta_ua| >= meta_summary_max_keys )
            meta_flush_ua();
        meta_ua[k] = UaSummary($ts=hp$ts, $ts_end=hp$ts, $node=peer_description,
                               $orig_h=hp$id$orig_h, $user_agent=hp$user_agent);
        }
    local us = meta_ua[k];
    if ( hp$ts < us$ts ) us$ts = hp$ts;
    if ( hp$ts > us$ts_end ) us$ts_end = hp$ts;
    ++us$requests;
    if ( hp?$host && hp$host !in us$host_set && |us$host_set| < 100 )
        {
        add us$host_set[hp$host];
        us$hosts = |us$host_set|;
        if ( ! us?$sample_host )
            us$sample_host = hp$host;
        }
    }

function meta_summarize(rec: any)
    {
    if ( rec is Conn::Info )
        {
        local cn = rec as Conn::Info;
        local k = cat(cn$id$orig_h, "|", cn$id$resp_h, "|", cn$id$resp_p);
        if ( k !in meta_flows )
            {
            if ( |meta_flows| >= meta_summary_max_keys )
                meta_flush_flows();
            meta_flows[k] = FlowSummary($ts=cn$ts, $node=peer_description,
                                        $orig_h=cn$id$orig_h, $resp_h=cn$id$resp_h, $resp_p=cn$id$resp_p,
                                        $proto=cn$proto);
            if ( meta_flow_raw )
                meta_flows[k]$sample_uid = cn$uid;
            }
        local fs = meta_flows[k];
        if ( cn$ts < fs$ts ) fs$ts = cn$ts;
        ++fs$conns;
        if ( cn?$orig_bytes ) fs$orig_bytes += cn$orig_bytes;
        if ( cn?$resp_bytes ) fs$resp_bytes += cn$resp_bytes;
        if ( cn?$service )
            for ( _si, sv in split_string(cn$service, /,/) )
                add fs$svc_set[sv];
        local cs = cn?$conn_state ? cn$conn_state : "-";
        fs$state_cnt[cs] = ( cs in fs$state_cnt ? fs$state_cnt[cs] : 0 ) + 1;
        }
    else if ( rec is DNS::Info )
        {
        local dn = rec as DNS::Info;
        local q = to_lower(dn$query);
        local dom = parent_domain(q);
        local qt = dn?$qtype_name ? dn$qtype_name : "-";
        local rc = dn?$rcode_name ? dn$rcode_name : "-";
        local src = dn$id$orig_h;
        local dk = cat(src, "|", dom);
        if ( dk !in meta_dns )
            {
            local nd = src in meta_dns_src_domains ? meta_dns_src_domains[src] : 0;
            if ( nd >= meta_dns_max_domains_per_src )
                {
                dom = "(other)";
                dk = cat(src, "|", dom);
                }
            else
                meta_dns_src_domains[src] = nd + 1;
            }
        if ( dk !in meta_dns )
            {
            if ( |meta_dns| >= meta_summary_max_keys )
                meta_flush_dns();
            meta_dns[dk] = DnsSummary($ts=dn$ts, $ts_end=dn$ts, $node=peer_description,
                                      $orig_h=dn$id$orig_h, $domain=dom, $sample_names=vector());
            if ( meta_dns_raw )
                meta_dns[dk]$sample_uid = dn$uid;
            }
        local ds = meta_dns[dk];
        if ( dn$ts < ds$ts ) ds$ts = dn$ts;
        if ( dn$ts > ds$ts_end ) ds$ts_end = dn$ts;
        ++ds$queries;
        if ( qt != "-" )
            add ds$qtype_set[qt];
        ds$rcode_cnt[rc] = ( rc in ds$rcode_cnt ? ds$rcode_cnt[rc] : 0 ) + 1;
        if ( q !in ds$names )
            {
            if ( |ds$names| < meta_dns_max_unique )
                {
                add ds$names[q];
                ds$unique_names = |ds$names|;
                if ( |ds$sample_names| < meta_dns_max_samples )
                    ds$sample_names += q;
                }
            else
                ds$unique_names_capped = T;
            }
        if ( ! ds?$answers && dn?$answers && |dn$answers| > 0 )
            {
            local av: vector of string = vector();
            for ( i in dn$answers )
                {
                if ( |av| >= meta_dns_max_answers )
                    break;
                av += dn$answers[i];
                }
            ds$answers = av;
            }
        }
    }

event meta_ua_tick()
    {
    meta_flush_ua();
    schedule meta_ua_interval { meta_ua_tick() };
    }

event meta_flow_tick()
    {
    meta_flush_flows();
    schedule meta_flow_interval { meta_flow_tick() };
    }

event meta_dns_tick()
    {
    meta_flush_dns();
    schedule meta_dns_interval { meta_dns_tick() };
    }

hook meta_policy(rec: any, id: Log::ID, filter: Log::Filter)
    {
    if ( id !in meta_export_streams )
        break;
    local spec = meta_export_streams[id];
    local st = meta_counter(spec$name);
    local row = meta_extract(id, rec);

    # 1) 범위(가장 싸고, 가장 많이 거른다)
    if ( row?$cid && ! meta_in_scope(spec$scope, row$cid) )
        {
        ++st$dropped_scope;
        break;
        }

    # 2) 스트림별 조건
    if ( ! row$keep )
        {
        ++st$dropped_filter;
        break;
        }

    # http 의 User-Agent 는 행에 싣지 않고 (출발지, User-Agent)별로 따로 센다(중복 억제 전)
    if ( id == HTTP::LOG && meta_ua_summary && rec is HTTP::Info )
        meta_summarize_ua(rec as HTTP::Info);

    # 요약 모드: 행은 보내지 않고 묶는다
    if ( spec$summary )
        {
        meta_summarize(rec);
        ++st$summarized;
        break;
        }

    # 3) 중복 억제
    if ( spec$dedup > 0secs && row$key != "" )
        {
        local dk = cat(spec$name, "|", row$key);
        local now = network_time();
        if ( dk in meta_dedup && meta_dedup[dk] > now )
            {
            ++st$dropped_dedup;
            break;
            }
        if ( |meta_dedup| < meta_dedup_max_entries || dk in meta_dedup )
            meta_dedup[dk] = now + spec$dedup;
        }

    # 4) 분당 상한
    if ( spec$rate_limit > 0 )
        {
        local bucket = double_to_count(floor(time_to_double(network_time()) / 60.0));
        if ( bucket != meta_rate_bucket )
            {
            meta_rate_bucket = bucket;
            meta_rate_count = table();
            }
        local n = spec$name in meta_rate_count ? meta_rate_count[spec$name] : 0;
        if ( n >= spec$rate_limit )
            {
            ++st$dropped_rate;
            break;
            }
        meta_rate_count[spec$name] = n + 1;
        }

    ++st$sent;
    }

# ---------------------------------------------------------------- 통계

function meta_flush_stats()
    {
    for ( name, st in meta_counters )
        {
        if ( st$sent + st$dropped_scope + st$dropped_filter + st$dropped_dedup + st$dropped_rate
             + st$summarized == 0 )
            next;
        st$ts = network_time();
        Log::write(META_STATS_LOG, st);
        }
    meta_counters = table();
    }

event meta_stats_tick()
    {
    meta_flush_stats();
    schedule meta_stats_interval { meta_stats_tick() };
    }

event zeek_done()
    {
    if ( ! meta_export_enable )
        return;
    meta_flush_flows();
    meta_flush_dns();
    meta_flush_ua();
    meta_flush_stats();
    }

# ---------------------------------------------------------------- 필터 설치

event zeek_init() &priority=5
    {
    Log::create_stream(META_STATS_LOG, [$columns=MetaStats, $path="meta_export_stats"]);
    Log::create_stream(META_FLOW_LOG, [$columns=FlowSummary, $path="flow_summary"]);
    Log::create_stream(META_DNS_LOG, [$columns=DnsSummary, $path="dns_summary"]);
    Log::create_stream(META_UA_LOG, [$columns=UaSummary, $path="http_ua_summary"]);
    }

# filter_log(우선순위 -1)가 끄지 않도록 대상 스트림을 알린다(스트림은 우선순위 5 에서 만들어진다).
event zeek_init() &priority=0
    {
    if ( ! meta_export_enable )
        return;
    for ( id in meta_export_streams )
        if ( id in Log::active_streams )
            add keep_enabled_streams[id];
    add keep_enabled_streams[META_FLOW_LOG];
    add keep_enabled_streams[META_DNS_LOG];
    add keep_enabled_streams[META_UA_LOG];
    }

# filter_log(우선순위 -1)가 스트림을 정리한 뒤에 실행한다.
event zeek_init() &priority=-2
    {
    if ( ! meta_export_enable )
        {
        Log::disable_stream(META_STATS_LOG);
        return;
        }

    # 통계 로그도 선별 로그와 같은 경로를 따른다(log_paths 에 직접 지정했으면 그 값을 존중).
    if ( META_STATS_LOG !in log_paths )
        change_log_path(META_STATS_LOG, meta_path_prefix + "meta_export_stats");
    change_log_path(META_FLOW_LOG, meta_path_prefix + "flow_summary");
    change_log_path(META_DNS_LOG, meta_path_prefix + "dns_summary");
    change_log_path(META_UA_LOG, meta_path_prefix + "http_ua_summary");
    local want_flow = F;
    local want_dns = F;
    meta_flow_raw = meta_keep_raw_local || Conn::LOG in keep_log_streams;
    meta_dns_raw = meta_keep_raw_local || DNS::LOG in keep_log_streams;

    if ( create_log_dirs )
        {
        local d = log_dir_of(meta_path_prefix + "x");
        if ( d != "" )
            mkdir_p(d);
        if ( meta_keep_raw_local )
            {
            local rd = log_dir_of(meta_raw_path_prefix + "x");
            if ( rd != "" )
                mkdir_p(rd);
            }
        }

    for ( id, spec in meta_export_streams )
        {
        if ( id !in keep_enabled_streams )
            next;   # 로드되지 않은 스트림

        if ( id !in keep_log_streams )
            {
            # 원래 꺼질 스트림: 원본(default) 출력은 지우거나 T2 경로로 보낸다.
            # 원본은 Zeek 기본 이름(conn, dns …)으로 쓴다. 선별 로그 이름(flow_summary 등)을 쓰면
            # 요약 로그와 이름이 겹쳐 헷갈린다.
            if ( meta_keep_raw_local )
                {
                local st = Log::active_streams[id];
                change_log_path(id, meta_raw_path_prefix + ( st?$path ? st$path : spec$name ));
                }
            else
                Log::remove_filter(id, "default");
            }

        if ( spec$summary )
            {
            if ( id == Conn::LOG )
                want_flow = T;
            else if ( id == DNS::LOG )
                want_dns = T;
            else
                Reporter::warning(fmt("NSM metadata: %s 는 요약 모드를 지원하지 않습니다", spec$name));
            }

        local f = Log::Filter($name="nsm_meta",
                              # 요약 모드 필터는 행을 쓰지 않는다(경로는 요약 로그와 겹치지 않게만)
                              $path=meta_path_prefix + spec$name + ( spec$summary ? "_rows" : "" ),
                              $policy=meta_policy,
                              $config=table(["use_json"] = "T"));
        if ( spec?$fields )
            f$include = spec$fields;
        Log::add_filter(id, f);
        }

    if ( ! want_flow )
        Log::disable_stream(META_FLOW_LOG);
    else
        schedule meta_flow_interval { meta_flow_tick() };
    if ( ! want_dns )
        Log::disable_stream(META_DNS_LOG);
    else
        schedule meta_dns_interval { meta_dns_tick() };
    if ( ! meta_ua_summary || HTTP::LOG !in meta_export_streams )
        Log::disable_stream(META_UA_LOG);
    else
        schedule meta_ua_interval { meta_ua_tick() };

    schedule meta_stats_interval { meta_stats_tick() };
    }
