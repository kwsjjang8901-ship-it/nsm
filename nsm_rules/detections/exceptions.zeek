##! ============================================================================
##! 탐지 예외 엔진 (docs/EXCEPTION_ENGINE_REVIEW.md, E1)
##!
##!   예외를 룰 코드가 아니라 데이터(예외 파일)로 관리한다.
##!     - 예외 파일: Input Framework(ASCII/TSV)로 읽고 파일이 바뀌면 다시 읽는다(재시작 불필요).
##!       교체는 임시 파일에 쓴 뒤 이름 바꾸기로 한다. 같은 초 안의 제자리 덮어쓰기는 감지되지 않는다(수정 시각 초 단위).
##!       클러스터에서는 매니저(또는 standalone)만 파일을 읽고 워커·프록시로 배포한다.
##!     - 기존 redef 예외 목록(*_allowlist)은 룰 파일이 exception_add_legacy 로 등록한다(drop).
##!
##!   판정 지점은 룰 입구 한 곳이다. 룰은 지금 allowlist 를 검사하던 자리에서
##!       if ( NSM::exception_drop(Encrypted_C2, c) ) return;          # 건별 룰
##!       if ( NSM::exception_drop_agg(SSH_Lateral, c) ) return;       # 집계형 룰(SumStats 관측 직전)
##!   를 부른다. 근거(evidence)가 notice 보다 먼저 기록되므로 notice 시점에 버리면 근거만 남는다.
##!
##!   처리(disposition)
##!     - drop(기본): 룰 입구에서 거른다. notice·근거·탐지 요약을 남기지 않는다(기존 allowlist 와 같음).
##!     - suppress  : 탐지는 그대로 진행하고, notice·탐지 요약에 exception_id·disposition 을 붙인다.
##!                   Manager 는 이 탐지로 알림을 올리지 않는다. 판정은 Notice::policy 에서 notice 의
##!                   필드(src·dst·포트, $conn 이 있으면 SNI 등)로 한다.
##!                   집계형 룰에서 목적지 쪽 축이 있는 suppress 예외는 drop 으로 동작한다
##!                   (집계된 notice 하나에 예외 경로와 아닌 경로가 섞이기 때문).
##!
##!   예외 로그(nsm_exception.log): 적재 결과(loaded·rejected·expired)와 주기별 적중 수(hits).
##!     적중 수는 drop 이면 "예외에 걸린 관측(연결·이벤트) 수", suppress 면 "표시한 notice 수"다.
##! ============================================================================

@load base/frameworks/notice
@load base/frameworks/input
@load base/frameworks/cluster
@load ./main

module NSM;

export {
    redef enum Log::ID += { EXCEPTION_LOG };

    ## 예외 파일 경로(TSV, Input Framework ASCII 형식). 빈 문자열이면 파일을 읽지 않는다.
    ##   형식은 docs/SRS.md "예외 파일" 절. Manager 가 YAML 을 검증·변환해 배포한다.
    const exception_file = "" &redef;

    ## 적중 수(hits)를 예외 로그에 쓰는 주기. 적중이 없는 예외는 쓰지 않는다.
    const exception_stats_interval = 1hr &redef;

    ## src·dst 대역만 있는 예외에서 허용하는 가장 넓은 접두사 길이(IPv4). 더 넓으면 거부한다.
    const exception_min_prefix = 16 &redef;

    ## 예외 파일 한 행(색인 id 제외). 집합 축은 비어 있거나 없으면(-, (empty)) 조건이 없는 것이다.
    type ExceptionRec: record {
        scope:       set[string];             ##< notice 이름(SSH_Lateral) 또는 묶음(group:lateral)
        src:         set[subnet] &optional;   ##< 출발지 대역
        dst:         set[subnet] &optional;   ##< 목적지 대역
        dst_port:    set[port]   &optional;   ##< 목적지 포트(443/tcp 형식)
        service:     set[string] &optional;   ##< Zeek 서비스 이름(ssl, ssh, rdp …)
        domain:      set[string] &optional;   ##< SNI·HTTP Host·DNS 질의. 하위 도메인 포함
        ja4:         set[string] &optional;   ##< JA4(TLS 클라이언트). JA4 패키지가 없으면 맞지 않는다
        disposition: string      &optional;   ##< drop(기본) 또는 suppress
        reason:      string      &optional;   ##< 사유(파일 예외는 필수)
        owner:       string      &optional;   ##< 작성자(파일 예외는 필수)
        expires:     time        &optional;   ##< 만료 시각(epoch 초). 지나면 적용하지 않는다
        ref:         string      &optional;   ##< 근거 알림(detection_id)
    };

    ## 판정 재료. 룰 입구에서는 연결로, notice 시점에는 notice 필드로 채운다.
    type ExceptionCtx: record {
        src:      addr        &optional;
        dst:      addr        &optional;
        dst_port: port        &optional;
        services: set[string] &optional;
        domain:   string      &optional;
        ja4:      string      &optional;
    };

    ## 예외 로그 한 행.
    type ExceptionLogInfo: record {
        ts:           time   &log;
        node:         string &log;
        kind:         string &log;            ##< loaded, rejected, expired, hits, error(파일 읽기 오류)
        exception_id: string &log;
        disposition:  string &log &optional;
        scope:        string &log &optional;
        hits:         count  &log &optional;  ##< 주기 안 적중 수(kind=hits)
        last_hit:     time   &log &optional;
        msg:          string &log &optional;  ##< 거부 이유, 출처(file, legacy) 등
    };

    ## 예외 묶음 이름 -> notice 종류. 상관 모듈(correlation_killchain)이 corr_*_notes 로 채운다.
    global exception_groups: table[string] of set[Notice::Type] = table() &redef;

    ## 룰 입구 판정(건별 룰). drop 예외에 맞으면 T. 룰은 바로 반환한다.
    global exception_drop: function(note: Notice::Type, c: connection): bool;
    ## 룰 입구 판정(집계형 룰, 관측 직전). 목적지 쪽 축이 있는 suppress 예외도 drop 으로 본다.
    global exception_drop_agg: function(note: Notice::Type, c: connection): bool;
    ## 연결 없이 판정할 때(DNS 집계 등). agg 의미는 위와 같다.
    global exception_drop_ctx: function(note: Notice::Type, ctx: ExceptionCtx, agg: bool): bool;

    ## 적중을 세지 않고 맞는 drop 예외 id 만 돌려준다(없으면 ""). 여러 탐지가 한 집계를 공유하는 룰용.
    global exception_peek: function(note: Notice::Type, ctx: ExceptionCtx, agg: bool): string;
    ## exception_peek 으로 찾은 예외의 적중을 1 센다.
    global exception_count: function(id: string);

    ## 기존 redef 예외 목록 등록(룰 파일의 zeek_init 에서). 항상 drop, 검증 생략.
    global exception_add_legacy: function(id: string, r: ExceptionRec);

    ## 예외 목록 배포(매니저 -> 워커·프록시).
    global exception_update: event(recs: table[string] of ExceptionRec);

    redef record Notice::Info += {
        exception_id: string &optional &log;  ##< suppress 예외에 맞은 경우 예외 id
        disposition:  string &optional &log;  ##< suppressed
    };
}

## 색인에 들어가는 예외 하나.
type ExcEntry: record {
    id:       string;
    r:        ExceptionRec;
    suppress: bool;
    dst_side: bool;   ##< 목적지 쪽 축(dst·dst_port·service·domain·ja4)이 있음
};

global exc_legacy: table[string] of ExceptionRec = table();
global exc_file_recs: table[string] of ExceptionRec = table();   # Input 대상(매니저·standalone)
global exc_active: table[string] of ExceptionRec = table();      # 배포받거나 읽은 파일 예외
global exc_index: table[Notice::Type] of vector of ExcEntry = table();
global exc_hits: table[string] of count = table();
global exc_last_hit: table[string] of time = table();
global exc_disp: table[string] of string = table();
global exc_waiting_initial = F;
global exc_expired_reported: set[string] = set();

const EXC_STREAM = "nsm-exceptions";

function axis_s(r: ExceptionRec, which: string): bool
    {
    switch ( which )
        {
        case "service": return r?$service && |r$service| > 0;
        case "domain":  return r?$domain  && |r$domain|  > 0;
        case "ja4":     return r?$ja4     && |r$ja4|     > 0;
        }
    return F;
    }

function has_src(r: ExceptionRec): bool { return r?$src && |r$src| > 0; }
function has_dst(r: ExceptionRec): bool { return r?$dst && |r$dst| > 0; }
function has_port(r: ExceptionRec): bool { return r?$dst_port && |r$dst_port| > 0; }

function dst_side(r: ExceptionRec): bool
    {
    return has_dst(r) || has_port(r) || axis_s(r, "service") || axis_s(r, "domain") || axis_s(r, "ja4");
    }

function disp_of(r: ExceptionRec): string
    {
    return r?$disposition ? to_lower(r$disposition) : "drop";
    }

function scope_str(r: ExceptionRec): string
    {
    local v: vector of string = vector();
    for ( s in r$scope )
        v += s;
    sort(v, strcmp);
    return join_string_vec(v, ",");
    }

function exc_log(kind: string, id: string, r: ExceptionRec, msg: string)
    {
    local l = ExceptionLogInfo($ts=network_time(), $node=peer_description, $kind=kind,
                               $exception_id=id, $disposition=disp_of(r), $scope=scope_str(r));
    if ( msg != "" )
        l$msg = msg;
    Log::write(EXCEPTION_LOG, l);
    }

## 범위 문자열 하나 -> notice 종류 집합. 모르는 이름이면 빈 집합.
function resolve_scope(tok: string): set[Notice::Type]
    {
    local out: set[Notice::Type] = set();
    if ( starts_with(tok, "group:") )
        {
        local g = to_lower(tok[6:]);
        if ( g in exception_groups )
            out = copy(exception_groups[g]);
        return out;
        }
    local name = starts_with(tok, "NSM::") ? tok : cat("NSM::", tok);
    local v = lookup_ID(name);
    if ( type_name(v) == "Notice::Type" )
        add out[v as Notice::Type];
    return out;
    }

## 파일 예외 검증. 문제가 있으면 이유, 없으면 빈 문자열.
function validate(r: ExceptionRec): string
    {
    if ( |r$scope| == 0 )
        return "scope 없음";
    for ( tok in r$scope )
        if ( |resolve_scope(tok)| == 0 )
            return fmt("알 수 없는 scope: %s", tok);
    local d = disp_of(r);
    if ( d != "drop" && d != "suppress" )
        return fmt("알 수 없는 disposition: %s", d);
    if ( ! r?$reason || r$reason == "" )
        return "reason 없음";
    if ( ! r?$owner || r$owner == "" )
        return "owner 없음";
    if ( ! has_src(r) && ! dst_side(r) )
        return "조건(축)이 하나도 없음";
    if ( has_port(r) )
        for ( p in r$dst_port )
            if ( get_port_transport_proto(p) == unknown_transport )
                return fmt("포트에 프로토콜이 없음: %s (443/tcp 형식)", p);
    # 대역 축만 있는 예외는 너무 넓으면 거부한다.
    if ( ! has_port(r) && ! axis_s(r, "service") && ! axis_s(r, "domain") && ! axis_s(r, "ja4") )
        {
        local nets: set[subnet] = set();
        if ( has_src(r) ) for ( s1 in r$src ) add nets[s1];
        if ( has_dst(r) ) for ( s2 in r$dst ) add nets[s2];
        for ( sn in nets )
            if ( is_v4_subnet(sn) && subnet_width(sn) < exception_min_prefix )
                return fmt("대역이 너무 넓음: %s (/%d 보다 넓음)", sn, exception_min_prefix);
        }
    return "";
    }

## 색인 다시 만들기: legacy + 파일 예외. report=T 면 적재 결과를 로그에 쓴다(파일을 읽는 노드만).
function rebuild_index(report: bool)
    {
    local idx: table[Notice::Type] of vector of ExcEntry = table();
    local disp: table[string] of string = table();
    local srcs: table[string] of ExceptionRec = table();
    local origin: table[string] of string = table();

    for ( lid, lr in exc_legacy )
        { srcs[lid] = lr; origin[lid] = "legacy"; }
    for ( fid, fr in exc_active )
        {
        if ( fid in srcs )
            {
            if ( report )
                exc_log("rejected", fid, fr, "id 가 기존 설정(legacy) 예외와 겹침");
            next;
            }
        local why = validate(fr);
        if ( why != "" )
            {
            if ( report )
                exc_log("rejected", fid, fr, why);
            next;
            }
        srcs[fid] = fr; origin[fid] = "file";
        }

    # pcap 을 읽기 전(network_time = 0)에는 벽시계로 만료를 본다.
    local now = network_time() != 0.0 ? network_time() : current_time();
    for ( id, r in srcs )
        {
        if ( r?$expires && r$expires < now )
            {
            if ( report && id !in exc_expired_reported )
                {
                exc_log("expired", id, r, origin[id]);
                add exc_expired_reported[id];
                }
            next;
            }
        local e = ExcEntry($id=id, $r=r, $suppress=(disp_of(r) == "suppress"), $dst_side=dst_side(r));
        disp[id] = disp_of(r);
        for ( tok in r$scope )
            for ( nt in resolve_scope(tok) )
                {
                if ( nt !in idx )
                    idx[nt] = vector();
                idx[nt] += e;
                }
        if ( report )
            exc_log("loaded", id, r, origin[id]);
        }
    exc_index = idx;
    exc_disp = disp;
    }

function ctx_of_conn(c: connection): ExceptionCtx
    {
    local x = ExceptionCtx($src=c$id$orig_h, $dst=c$id$resp_h, $dst_port=c$id$resp_p);
    if ( |c$service| > 0 )
        {
        local sv: set[string] = set();
        for ( s in c$service )
            add sv[to_lower(s)];
        x$services = sv;
        }
    if ( c?$ssl && c$ssl?$server_name && c$ssl$server_name != "" )
        x$domain = c$ssl$server_name;
    else if ( c?$http && c$http?$host && c$http$host != "" )
        x$domain = c$http$host;
    else if ( c?$dns && c$dns?$query && c$dns$query != "" )
        x$domain = c$dns$query;
    local j = get_ja4(c);
    if ( j != "" )
        x$ja4 = j;
    return x;
    }

function entry_matches(e: ExcEntry, x: ExceptionCtx): bool
    {
    local r = e$r;
    if ( r?$expires && r$expires < network_time() )
        return F;
    if ( has_src(r) && ( ! x?$src || x$src !in r$src ) )
        return F;
    if ( has_dst(r) && ( ! x?$dst || x$dst !in r$dst ) )
        return F;
    if ( has_port(r) && ( ! x?$dst_port || x$dst_port !in r$dst_port ) )
        return F;
    if ( axis_s(r, "service") )
        {
        if ( ! x?$services )
            return F;
        local hit = F;
        for ( s in x$services )
            if ( s in r$service )
                { hit = T; break; }
        if ( ! hit )
            return F;
        }
    if ( axis_s(r, "domain") && ( ! x?$domain || ! domain_matches(x$domain, r$domain) ) )
        return F;
    if ( axis_s(r, "ja4") && ( ! x?$ja4 || x$ja4 !in r$ja4 ) )
        return F;
    return T;
    }

function count_hit(id: string)
    {
    exc_hits[id] = ( id in exc_hits ? exc_hits[id] : 0 ) + 1;
    exc_last_hit[id] = network_time();
    }

function exception_peek(note: Notice::Type, ctx: ExceptionCtx, agg: bool): string
    {
    if ( note !in exc_index )
        return "";
    for ( _i, e in exc_index[note] )
        {
        if ( e$suppress && ! ( agg && e$dst_side ) )
            next;
        if ( entry_matches(e, ctx) )
            return e$id;
        }
    return "";
    }

function exception_count(id: string)
    {
    count_hit(id);
    }

function exception_drop_ctx(note: Notice::Type, ctx: ExceptionCtx, agg: bool): bool
    {
    if ( note !in exc_index )
        return F;
    local id = exception_peek(note, ctx, agg);
    if ( id == "" )
        return F;
    count_hit(id);
    return T;
    }

function exception_drop(note: Notice::Type, c: connection): bool
    {
    if ( note !in exc_index )
        return F;
    return exception_drop_ctx(note, ctx_of_conn(c), F);
    }

function exception_drop_agg(note: Notice::Type, c: connection): bool
    {
    if ( note !in exc_index )
        return F;
    return exception_drop_ctx(note, ctx_of_conn(c), T);
    }

function exception_add_legacy(id: string, r: ExceptionRec)
    {
    r$disposition = "drop";
    if ( ! r?$reason )
        r$reason = "기존 redef 설정";
    if ( ! r?$owner )
        r$owner = "config";
    exc_legacy[id] = r;
    }

# suppress: notice 필드로 판정해 표시한다. 중복 묶기(-5)·탐지 요약(-6)보다 먼저.
hook Notice::policy(n: Notice::Info) &priority=-4
    {
    if ( n$note !in exc_index || n?$disposition )
        return;
    local x: ExceptionCtx;
    if ( n?$conn )
        x = ctx_of_conn(n$conn);
    else
        {
        x = ExceptionCtx();
        if ( n?$src ) x$src = n$src;
        if ( n?$dst ) x$dst = n$dst;
        if ( n?$p )   x$dst_port = n$p;
        }
    for ( _i, e in exc_index[n$note] )
        {
        if ( ! e$suppress )
            next;
        if ( entry_matches(e, x) )
            {
            n$exception_id = e$id;
            n$disposition = "suppressed";
            delete n$actions[Notice::ACTION_ALARM];
            delete n$actions[Notice::ACTION_EMAIL];
            count_hit(e$id);
            return;
            }
        }
    }

# ---- 적중 통계 -------------------------------------------------------------

function flush_hits()
    {
    for ( id, h in exc_hits )
        {
        local l = ExceptionLogInfo($ts=network_time(), $node=peer_description, $kind="hits",
                                   $exception_id=id, $hits=h, $last_hit=exc_last_hit[id]);
        if ( id in exc_disp )
            l$disposition = exc_disp[id];
        Log::write(EXCEPTION_LOG, l);
        }
    exc_hits = table();
    }

## 적재 결과를 로그에 쓰는 노드: 예외 파일을 읽는 노드, 파일이 없으면 매니저·standalone.
function reports(): bool
    {
    return ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER;
    }

## 실행 중에 만료된 예외가 있으면 색인에서 빼고(적재 노드는 expired 를 기록) 다시 만든다.
function check_expiry()
    {
    for ( _nt, v in exc_index )
        for ( _i, e in v )
            if ( e$r?$expires && e$r$expires < network_time() )
                {
                rebuild_index(F);
                if ( reports() && e$id !in exc_expired_reported )
                    {
                    exc_log("expired", e$id, e$r, "실행 중 만료");
                    add exc_expired_reported[e$id];
                    }
                return;
                }
    }

event exception_stats_tick()
    {
    check_expiry();
    flush_hits();
    schedule exception_stats_interval { exception_stats_tick() };
    }

event zeek_done()
    {
    flush_hits();
    }

# ---- 예외 파일 읽기·배포 ------------------------------------------------------

type ExcIdx: record {
    id: string;
};

function reads_file(): bool
    {
    return exception_file != "" &&
           ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER );
    }

function release_initial_wait()
    {
    if ( exc_waiting_initial )
        {
        exc_waiting_initial = F;
        continue_processing();
        }
    }

# 파일이 없으면 경고(WARNING)로 오고, 리더는 파일이 생길 때까지 기다린다. 처음 대기는 어느 수준이든 푼다.
event exception_input_error(desc: Input::TableDescription, message: string, level: Reporter::Level)
    {
    Log::write(EXCEPTION_LOG, ExceptionLogInfo($ts=network_time(), $node=peer_description, $kind="error",
                                               $exception_id="-", $msg=message));
    release_initial_wait();
    }

event Input::end_of_data(name: string, source: string)
    {
    if ( name != EXC_STREAM )
        return;
    exc_active = copy(exc_file_recs);
    rebuild_index(T);
@if ( Cluster::is_enabled() )
    Cluster::publish(Cluster::worker_topic, NSM::exception_update, exc_active);
    Cluster::publish(Cluster::proxy_topic, NSM::exception_update, exc_active);
@endif
    release_initial_wait();
    }

event NSM::exception_update(recs: table[string] of ExceptionRec)
    {
    exc_active = recs;
    rebuild_index(F);
    }

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
# 늦게 붙은 워커·프록시에도 현재 목록을 보낸다.
event Cluster::node_up(name: string, id: string)
    {
    if ( exception_file != "" )
        Cluster::publish(Cluster::node_topic(name), NSM::exception_update, exc_active);
    }
@endif

event zeek_init() &priority=5
    {
    Log::create_stream(EXCEPTION_LOG, [$columns=ExceptionLogInfo, $path="nsm_exception"]);
    }

# 룰 파일의 zeek_init(우선순위 0)이 legacy 예외를 등록한 뒤 색인을 만든다.
event zeek_init() &priority=-10
    {
    # 파일을 읽는 노드는 파일을 다 읽은 뒤(end_of_data) legacy 와 함께 한 번에 기록한다.
    rebuild_index(reports() && ! reads_file());
    schedule exception_stats_interval { exception_stats_tick() };

    if ( ! reads_file() )
        return;

    # pcap 을 읽을 때는 예외 파일을 다 읽을 때까지 패킷 처리를 멈춘다(첫 패킷부터 예외 적용).
    #   실시간 센서는 멈추지 않는다(파일이 없거나 늦어도 탐지는 계속).
    if ( reading_traces() )
        {
        exc_waiting_initial = T;
        suspend_processing();
        }
    Input::add_table([$source=exception_file, $name=EXC_STREAM, $idx=ExcIdx, $val=ExceptionRec,
                      $destination=exc_file_recs, $mode=Input::REREAD,
                      $error_ev=exception_input_error]);
    }
