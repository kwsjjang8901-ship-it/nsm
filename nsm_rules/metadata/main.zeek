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
##!       meta_keep_raw_local = T 면 default 필터를 지우지 않고 meta_raw_path_prefix 로 보낸다(T2).
##!
##!   meta_export_stats.log : meta_stats_interval 마다 스트림별 보냄·탈락 건수(노드별).
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
@load policy/misc/capture-loss
@load policy/misc/stats
@load ../rules/filter_log

module NSM;

export {
    redef enum Log::ID += { META_STATS_LOG };

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
        # 센서 상태
        [CaptureLoss::LOG] = [$name="capture_loss"],
        [Stats::LOG]       = [$name="stats"],
        [Reporter::LOG]    = [$name="reporter"],
    } &redef;

    ## 중복 억제 상태: 항목 수 상한(넘으면 새 키는 억제하지 않고 보낸다)과 최대 보관 시간
    const meta_dedup_max_entries = 200000 &redef;
    const meta_dedup_expire = 1hr &redef;

    ## meta_export_stats.log 기록 주기
    const meta_stats_interval = 1min &redef;

    type MetaStats: record {
        ts:             time    &log;
        node:           string  &log;   ##< 기록한 노드(standalone 은 "zeek")
        stream:         string  &log;   ##< MetaSpec 의 name
        sent:           count   &log &default=0;
        dropped_scope:  count   &log &default=0;   ##< 범위 밖
        dropped_filter: count   &log &default=0;   ##< 스트림별 조건(동작·인터페이스 등) 탈락
        dropped_dedup:  count   &log &default=0;   ##< 중복 억제
        dropped_rate:   count   &log &default=0;   ##< 분당 상한 초과
    };

    ## 한 행의 판정 재료. 스트림마다 meta_extract 가 채운다.
    type MetaRow: record {
        cid:  conn_id &optional;   ##< 연결 4-튜플(없으면 범위 판정 생략)
        keep: bool &default=T;     ##< 스트림별 조건 통과 여부
        key:  string &default="";  ##< 중복 억제 키(빈 문자열이면 억제하지 않음)
    };
}

redef NSM::keep_log_streams += { NSM::META_STATS_LOG };
redef NSM::log_paths += { [NSM::META_STATS_LOG] = "/log/zeek/meta/meta_export_stats" };

# ---------------------------------------------------------------- 상태

global meta_dedup: table[string] of time &create_expire=meta_dedup_expire;
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
    else if ( rec is RDP::Info )
        r$cid = (rec as RDP::Info)$id;
    else if ( rec is SSH::Info )
        r$cid = (rec as SSH::Info)$id;

    return r;
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
        if ( st$sent + st$dropped_scope + st$dropped_filter + st$dropped_dedup + st$dropped_rate == 0 )
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
    if ( meta_export_enable )
        meta_flush_stats();
    }

# ---------------------------------------------------------------- 필터 설치

event zeek_init() &priority=5
    {
    Log::create_stream(META_STATS_LOG, [$columns=MetaStats, $path="meta_export_stats"]);
    }

# filter_log(우선순위 -1)가 끄지 않도록 대상 스트림을 알린다(스트림은 우선순위 5 에서 만들어진다).
event zeek_init() &priority=0
    {
    if ( ! meta_export_enable )
        return;
    for ( id in meta_export_streams )
        if ( id in Log::active_streams )
            add keep_enabled_streams[id];
    }

# filter_log(우선순위 -1)가 스트림을 정리한 뒤에 실행한다.
event zeek_init() &priority=-2
    {
    if ( ! meta_export_enable )
        {
        Log::disable_stream(META_STATS_LOG);
        return;
        }

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
            if ( meta_keep_raw_local )
                change_log_path(id, meta_raw_path_prefix + spec$name);
            else
                Log::remove_filter(id, "default");
            }

        local f = Log::Filter($name="nsm_meta",
                              $path=meta_path_prefix + spec$name,
                              $policy=meta_policy,
                              $config=table(["use_json"] = "T"));
        if ( spec?$fields )
            f$include = spec$fields;
        Log::add_filter(id, f);
        }

    schedule meta_stats_interval { meta_stats_tick() };
    }
