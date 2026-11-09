##! ============================================================================
##! 로그 출력 필터 — 운영에서 남길 로그 스트림과 출력 경로를 한 곳에서 관리한다.
##!
##!   - keep_log_streams 에 없는 스트림은 모두 비활성화한다(디스크·전송량 절감).
##!   - log_paths 에 지정된 스트림은 출력 경로를 바꾼다(없으면 Zeek 기본 경로).
##!   - 두 값 모두 &redef 이므로 고객 환경 설정(nsm_config_custom.zeek)에서 조정한다.
##!       예) 자산 식별(asset-id) 머지 후:
##!           redef NSM::keep_log_streams += { AssetID::LOG };
##!       예) evidence 의 uid 로 원본을 조인해야 하는 환경:
##!           redef NSM::keep_log_streams += { Conn::LOG, DNS::LOG, SSL::LOG };
##!
##!   ※ reporter.log 는 스크립트 런타임 에러/경고 확인용으로 기본 유지한다.
##!   ※ 이 파일은 __load__.zeek 의 맨 마지막에 로드된다.
##! ============================================================================

@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/reporter
@load policy/misc/capture-loss
@load policy/misc/loaded-scripts
@load policy/misc/stats
@load ../detections/detection_log
@load ../detections/evidence_log

module NSM;

redef Log::default_rotation_interval = 4hr;

export {
    ## 활성 상태로 남길 로그 스트림. 여기 없는 스트림은 zeek_init 에서 비활성화된다.
    const keep_log_streams: set[Log::ID] = {
        NSM::DETECTION_LOG,
        NSM::EVIDENCE_LOG,
        Notice::LOG,
        CaptureLoss::LOG,
        LoadedScripts::LOG,
        Stats::LOG,
        Reporter::LOG,
    } &redef;

    ## 스트림별 출력 경로(확장자 제외). 지정하지 않은 스트림은 Zeek 기본 경로를 쓴다.
    const log_paths: table[Log::ID] of string = {
        [NSM::DETECTION_LOG]  = "/log/zeek/nsm_detection",
        [NSM::EVIDENCE_LOG]   = "/log/zeek/evidence",
        [Notice::LOG]         = "/hdd_tmp/log/zeek/notice",
        [CaptureLoss::LOG]    = "/hdd_tmp/log/zeek/capture_loss",
        [LoadedScripts::LOG]  = "/hdd_tmp/log/zeek/loadedscripts",
        [Stats::LOG]          = "/hdd_tmp/log/zeek/stats",
        [Reporter::LOG]       = "/hdd_tmp/log/zeek/reporter",
    } &redef;

    ## log_paths 의 상위 디렉터리를 zeek_init 에서 생성할지 여부.
    ##   배포 스크립트/패키지에서 디렉터리를 만드는 환경이면 F 로 둔다.
    const create_log_dirs = T &redef;
}

## 경로 문자열에서 디렉터리 부분("/a/b/c" -> "/a/b")을 돌려준다. 없으면 "".
function log_dir_of(path: string): string
    {
    local parts = split_string(path, /\//);
    if ( |parts| <= 1 )
        return "";
    local dirs: vector of string = vector();
    local i = 0;
    while ( i < |parts| - 1 )
        {
        dirs[|dirs|] = parts[i];
        ++i;
        }
    return join_string_vec(dirs, "/");
    }

## default 필터의 다른 속성($policy 등)은 유지하고 경로만 바꾼다.
function change_log_path(id: Log::ID, path: string)
    {
    local f = Log::get_filter(id, "default");
    if ( f$name == Log::no_filter$name )
        f = Log::Filter($name="default");
    Log::remove_filter(id, "default");
    f$path = path;
    Log::add_filter(id, f);
    }

function filter_log()
    {
    local ids: set[Log::ID];
    for ( id in Log::active_streams )
        add ids[id];

    for ( id in ids )
        if ( id !in keep_log_streams )
            Log::disable_stream(id);

    if ( create_log_dirs )
        {
        local dirs: set[string];
        for ( pid in log_paths )
            {
            local d = log_dir_of(log_paths[pid]);
            if ( d != "" )
                add dirs[d];
            }
        for ( dd in dirs )
            system(fmt("mkdir -p %s", safe_shell_quote(dd)));
        }

    for ( kid in keep_log_streams )
        {
        if ( kid !in ids )
            next;   # 로드되지 않은(존재하지 않는) 스트림
        if ( kid in log_paths )
            change_log_path(kid, log_paths[kid]);
        }
    }

event zeek_init() &priority=-1
    {
    filter_log();
    }
