##! ============================================================================
##! 증적(Evidence) 전용 로그 스트림
##!
##! 설계 의도
##!   - notice.log = "탐지됐다"(dedup 된 인덱스), evidence.log = 그 탐지의 근거 레코드.
##!   - 둘은 evidence_id 로 연결한다.
##!       * 단일 연결 탐지     -> evidence_id = uid (연결 그 자체가 key)
##!       * 집계형(SumStats) 탐지 -> evidence_id = 그룹키로 결정적 계산한 합성 문자열
##!   - DC-3 컨텍스트(WHO/WHAT/WHEN/WHERE/HOW)를 구조화 컬럼으로 직접 설계.
##!   - 원본(conn/dce_rpc/smb/kerberos/dns)·추출 파일은 uid/fuid 로 다시 조인.
##!
##! 적재 시점 (2026-09 개정)
##!   - 단일 연결형 : notice 발화 지점에서 1건.
##!   - 집계형      : threshold_crossed / epoch_result(=탐지 시점)에서 표본 근거를
##!                   적재한다. evidence_id 를 그 자리에서 1회만 생성해 notice 와
##!                   같은 값을 쓰므로, 관측 시점과 탐지 시점의 time_bucket 이
##!                   어긋나 조회가 깨지던 문제가 구조적으로 제거된다.
##!   - 반드시 write_evidence() 를 NOTICE() 보다 먼저 호출한다
##!     (detection_log 가 evidence_count 를 그 시점에 읽는다).
##! ============================================================================

@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/sumstats
@load ./main

module NSM;

export {
    redef enum Log::ID += { EVIDENCE_LOG };

    ## 증적 1행의 스키마. 모든 필드 &log 이며, 알 수 없는 값은 생략(&optional).
    type EvidenceInfo: record {
        ts:          time         &log;            # WHEN
        evidence_id: string       &log;            # 상관 key (notice 와 공유)
        note:        Notice::Type &log &optional;  # 어떤 탐지에서 나온 근거인지
        rule:        string       &log &optional;  # note 에서 NSM:: 를 뺀 값(nsm_detection 의 rule 과 같음). 자동
        killchain_stage: string   &log &optional;  # 킬체인 단계명(note 로 매핑, detection_log 와 동일 체계)
        technique:   string       &log &optional;  # WHAT  (ATT&CK 기법코드)
        account:     string       &log &optional;  # WHO   (가능할 때만)
        ## account 를 나눈 값(소문자). domain\user 와 user@realm 을 같은 모양으로 맞춘다.
        ##   account 가 쉼표로 여러 개면 첫 번째 계정. 도메인이 없으면 user_name 만 둔다.
        ##   user_domain_type: 도메인에 점이 있으면 dns(Kerberos realm·FQDN), 없으면 netbios.
        user_name:        string  &log &optional;
        user_domain:      string  &log &optional;
        user_domain_type: string  &log &optional;
        src:         addr         &log &optional;  # WHERE (출발)
        dst:         addr         &log &optional;  # WHERE (대상)
        operation:   string       &log &optional;  # HOW   (행위/오퍼레이션)
        uid:         string       &log &optional;  # 연결 조인 key (conn.log 등)
        ## 근거 연결(uid)의 포트·프로토콜과 Community ID. 룰이 uid 자리에 NSM::conn_ref(c) 를 넘기면 자동으로 채운다.
        ##   src_port·dst_port 는 근거의 src·dst 방향(src 가 연결의 응답 쪽이면 뒤바꿔 맞춘다).
        ##   community_id 는 방향과 무관한 연결 식별자(Community ID v1, base64, seed=community_id_seed). 다른 제품과 연결 단위로 잇는 키.
        src_port:     count       &log &optional;
        dst_port:     count       &log &optional;
        proto:        string      &log &optional;  # tcp | udp | icmp
        community_id: string      &log &optional;
        ## detail 에서 뽑아 올린 공통 값(룰이 직접 넣으면 그 값을 쓴다).
        ##   dst_name: 목적지 이름(sni > host > name > DNS 상위 도메인 parent > query). 소문자, 포트·끝 점 제거, IP 주소는 넣지 않음
        ##   proxy   : 거쳐 간 프록시 주소:포트(via_proxy=)
        ##   bytes   : 출발지가 보낸 바이트(orig_bytes > conn_upload > sum_bytes)
        ##   window_s: 집계 창(초, window=)
        dst_name:    string       &log &optional;
        proxy:       string       &log &optional;
        bytes:       count        &log &optional;
        window_s:    double       &log &optional;
        fuid:        string       &log &optional;  # 파일 조인 key (files.log 등)
        parent_id:   vector of string &log &optional;  # 상관 행이 묶는 하위 evidence_id
        detail:      string       &log &optional;  # 부가 컨텍스트
    };

    ## notice <-> evidence 연결 컬럼. (attack 컬럼과 동일한 확장 패턴)
    redef record Notice::Info += {
        evidence_id: string &optional &log;
    };

    ## 증적 1건 기록 헬퍼.
    global write_evidence: function(ev: EvidenceInfo);

    ## 근거의 uid 자리에 넣는 연결 참조: "uid~orig_h~orig_p~resp_h~resp_p~proto".
    ##   uid 와 함께 연결의 5-tuple 을 실어, SumStats 표본으로 다른 노드(매니저)에 넘어가도
    ##   write_evidence 가 포트·프로토콜·community_id 를 채울 수 있다. 기록되는 uid 는 앞부분만.
    global conn_ref: function(c: connection): string;
    ## 연결 참조(또는 uid)에서 uid 만
    global ref_uid: function(ref: string): string;

    ## Community ID seed(다른 제품과 맞춰야 함, 기본 0)
    const community_id_seed = 0 &redef;

    ## evidence_id 별 실제 기록 건수. detection 의 evidence_count 산출에 사용한다.
    ##   evidence_id 에 time_bucket 이 포함되므로 창이 바뀌면 자연히 새 키가 된다.
    ##   메모리 보호를 위해 일정 시간 뒤 만료시킨다.
    const evidence_count_expire = 2hr &redef;
    global evidence_counts: table[string] of count
        &create_expire=evidence_count_expire &default=0;

    ## evidence_id 의 누적 기록 건수(없으면 0).
    global evidence_count_of: function(eid: string): count;

    ## 계정 문자열을 (사용자, 도메인, 도메인 종류)로 나눈 값.
    type AccountParts: record {
        user:        string;
        domain:      string &default="";
        domain_type: string &default="";   # dns | netbios | ""(도메인 없음)
    };

    ## "dom\user", "user@realm", "user" 를 나눈다(소문자, 앞뒤 공백 제거).
    global split_account: function(acct: string): AccountParts;

    ## detection 요약 칸(accounts·dst_names·relays)에 싣는 최대 개수.
    const evidence_summary_max = 5 &redef;

    ## evidence_id 들의 근거에서 모은 값(정렬, 최대 evidence_summary_max 개).
    ##   accounts : account 칸(쉼표로 여러 개면 나눠서)
    ##   names    : detail 의 host=·sni=·name=·parent=(없으면 query=) 값. 소문자, 포트·끝 점 제거, IP 는 뺀다
    ##   relays   : detail 의 via_proxy= 값(프록시 주소:포트)
    global evidence_accounts_of: function(eids: vector of string): vector of string;
    global evidence_names_of:    function(eids: vector of string): vector of string;
    global evidence_relays_of:   function(eids: vector of string): vector of string;

    ## evidence_id 별 이미 적재한 항목 집합(중복 적재 방지).
    ##   threshold_series 는 한 창에서 임계치마다 재발화하므로, 같은 표본이
    ##   여러 번 들어와 evidence_count 가 부풀지 않도록 걸러낸다.
    global evidence_seen: table[string] of set[string]
        &create_expire=evidence_count_expire;

    ## (eid, item) 이 처음이면 T 를 돌려주고 기록한다. 두 번째부터는 F.
    global evidence_is_new: function(eid: string, item: string): bool;

    ## 집계형 룰의 근거용 대표 연결(uid) 표본.
    ##   고유 수를 세는 스트림과 따로 두고("목적지|uid"), (스트림, 출발지, 목적지)마다 창(win) 안에서
    ##   처음 본 연결 하나만 관측한다. 탐지 시점에 ev_uids 로 목적지 -> uid 표를 만든다.
    ##   관측과 판정 노드가 달라도(클러스터: 워커 관측, 매니저 판정) SumStats 가 표본을 모은다.
    global ev_observe: function(stream: string, src: addr, dst: addr, uid: string, win: interval);
    global ev_uids: function(result: SumStats::Result, stream: string): table[string] of string;
    ## 표에 없으면 "" (write_evidence 가 빈 uid 는 기록하지 않는다)
    global ev_uid: function(uids: table[string] of string, dst: string): string;
}

# evidence_id 별 요약 값(detection 의 accounts·dst_names·relays). evidence_counts 와 같은 수명.
#   한 evidence_id 에 값이 아주 많아도 메모리가 늘지 않도록 summary_keep 개까지만 둔다.
const summary_keep = 32;
global ev_accounts: table[string] of set[string] &create_expire=evidence_count_expire;
global ev_names:    table[string] of set[string] &create_expire=evidence_count_expire;
global ev_relays:   table[string] of set[string] &create_expire=evidence_count_expire;

# 근거용 표본 중복 관측 방지(창 단위 키). 창이 바뀌면 키가 달라 다시 관측된다.
global ev_observed: set[string] &create_expire=30min;

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::EVIDENCE_LOG, [$columns=EvidenceInfo, $path="evidence"]);
    }

function split_account(acct: string): AccountParts
    {
    local a = to_lower(strip(acct));
    local r = AccountParts($user=a);
    local p: string_vec;
    if ( /\\/ in a )
        {
        p = split_string1(a, /\\/);
        r$user = p[1];
        r$domain = p[0];
        }
    else if ( /@/ in a )
        {
        p = split_string1(a, /@/);
        r$user = p[0];
        r$domain = p[1];
        }
    if ( r$domain != "" )
        r$domain_type = ( /\./ in r$domain ) ? "dns" : "netbios";
    return r;
    }

function summary_add(t: table[string] of set[string], eid: string, v: string)
    {
    if ( v == "" || v == "-" )
        return;
    if ( eid !in t )
        t[eid] = set();
    if ( |t[eid]| < summary_keep )
        add t[eid][v];
    }

# detail 의 이름 값 정규화. 이름이 아니면 "".
function summary_name(v: string): string
    {
    local n = to_lower(v);
    if ( n == "" || n == "-" || is_valid_ip(n) || /^\[/ in n )
        return "";
    # host 헤더의 포트(name:8080). 콜론이 하나일 때만(IPv6 주소는 위에서 걸러짐)
    if ( /^[^:]+:[0-9]+$/ in n )
        n = split_string1(n, /:/)[0];
    while ( |n| > 0 && n[-1] == "." )
        n = n[:-1];
    return ( n == "" || is_valid_ip(n) ) ? "" : n;
    }

function summary_collect(ev: EvidenceInfo)
    {
    local eid = ev$evidence_id;
    if ( ev?$account )
        for ( _i, a in split_string(ev$account, /,/) )
            summary_add(ev_accounts, eid, to_lower(strip(a)));
    if ( ! ev?$detail )
        return;
    local query = "";
    local has_parent = F;
    for ( _j, tok in split_string(ev$detail, / +/) )
        {
        if ( /=/ !in tok )
            next;
        local kv = split_string1(tok, /=/);
        switch ( kv[0] ) {
        case "host", "sni", "name", "parent":
            if ( kv[0] == "parent" )
                has_parent = T;
            summary_add(ev_names, eid, summary_name(kv[1]));
            break;
        case "query":
            query = kv[1];
            break;
        case "via_proxy":
            summary_add(ev_relays, eid, kv[1]);
            break;
        }
        }
    # DNS 터널링은 긴 질의 대신 상위 도메인(parent)을 쓴다. 상위가 없으면 질의 그대로(DGA).
    if ( query != "" && ! has_parent )
        summary_add(ev_names, eid, summary_name(query));
    }

function summary_of(t: table[string] of set[string], eids: vector of string): vector of string
    {
    local all: set[string] = set();
    for ( _i, eid in eids )
        if ( eid in t )
            for ( v in t[eid] )
                add all[v];
    local out: vector of string = vector();
    for ( v in all )
        out += v;
    sort(out, function(a: string, b: string): int { return strcmp(a, b); });
    if ( |out| > evidence_summary_max )
        out = out[:evidence_summary_max];
    return out;
    }

function evidence_accounts_of(eids: vector of string): vector of string
    { return summary_of(ev_accounts, eids); }

function evidence_names_of(eids: vector of string): vector of string
    { return summary_of(ev_names, eids); }

function evidence_relays_of(eids: vector of string): vector of string
    { return summary_of(ev_relays, eids); }

function conn_ref(c: connection): string
    {
    return fmt("%s~%s~%d~%s~%d~%s", c$uid, c$id$orig_h, port_to_count(c$id$orig_p),
               c$id$resp_h, port_to_count(c$id$resp_p), get_port_transport_proto(c$id$resp_p));
    }

function ref_uid(ref: string): string
    {
    return ( /~/ in ref ) ? split_string1(ref, /~/)[0] : ref;
    }

# uid 자리의 연결 참조를 풀어 uid·포트·프로토콜·community_id 를 채운다.
function apply_conn_ref(ev: EvidenceInfo)
    {
    local p = split_string(ev$uid, /~/);
    ev$uid = p[0];
    if ( |p| != 6 || ! is_valid_ip(p[1]) || ! is_valid_ip(p[3]) )
        return;
    local oh = to_addr(p[1]);
    local rh = to_addr(p[3]);
    local op = to_count(p[2]);
    local rp = to_count(p[4]);
    local tp: transport_proto;
    switch ( p[5] ) {
    case "tcp":  tp = tcp;  break;
    case "udp":  tp = udp;  break;
    case "icmp": tp = icmp; break;
    default:     return;
    }
    if ( ! ev?$src_port && ! ev?$dst_port )
        {
        # 근거의 src 가 연결의 응답 쪽이면(예: 응답자가 공격자) 방향을 맞춘다
        if ( ev?$src && ev$src == rh && ev$src != oh )
            {
            ev$src_port = rp;
            ev$dst_port = op;
            }
        else
            {
            ev$src_port = op;
            ev$dst_port = rp;
            }
        }
    if ( ! ev?$proto )
        ev$proto = p[5];
    if ( ! ev?$community_id )
        ev$community_id = community_id_v1([$orig_h=oh, $orig_p=count_to_port(op, tp),
                                           $resp_h=rh, $resp_p=count_to_port(rp, tp)],
                                          community_id_seed);
    }

# Zeek interval 표기("10.0 mins", "1.0 hr", "30.0 secs")를 초로
function interval_text_s(num: string, unit: string): double
    {
    local v = to_double(num);
    if ( /^min/ in unit )
        return v * 60.0;
    if ( /^hr/ in unit )
        return v * 3600.0;
    if ( /^day/ in unit )
        return v * 86400.0;
    return v;
    }

# detail 의 key=value 에서 공통 값을 필드로 올린다(룰이 이미 채운 필드는 그대로).
function detail_fields(ev: EvidenceInfo)
    {
    local d = ev$detail;
    local kv: table[string] of string = table();
    for ( _i, tok in split_string(d, / +/) )
        {
        if ( /=/ !in tok )
            next;
        local x = split_string1(tok, /=/);
        if ( x[0] !in kv )
            kv[x[0]] = x[1];
        }

    if ( ! ev?$dst_name )
        for ( _j, k in vector("sni", "host", "name", "parent", "query") )
            if ( k in kv )
                {
                local nm = summary_name(kv[k]);
                if ( nm != "" )
                    {
                    ev$dst_name = nm;
                    break;
                    }
                }

    if ( ! ev?$proxy && "via_proxy" in kv && kv["via_proxy"] != "" )
        ev$proxy = kv["via_proxy"];

    if ( ! ev?$bytes )
        for ( _k, bk in vector("orig_bytes", "conn_upload", "sum_bytes") )
            if ( bk in kv && /^[0-9]+$/ in kv[bk] )
                {
                ev$bytes = to_count(kv[bk]);
                break;
                }

    if ( ! ev?$window_s && /window=[0-9.]+ [a-z]+/ in d )
        {
        local w = split_string1(find_last(d, /window=[0-9.]+ [a-z]+/), /=/)[1];
        local wp = split_string1(w, / /);
        ev$window_s = interval_text_s(wp[0], wp[1]);
        }
    }

function write_evidence(ev: EvidenceInfo)
    {
    if ( ev?$note && ev$note in NSM::disabled_notes )     # 룰 정책으로 끈 룰
        return;
    # killchain_stage 미지정 시 note 로 자동 매핑(detection_log 와 동일 체계).
    if ( ! ev?$killchain_stage && ev?$note )
        {
        local stg = NSM::killchain_stage_of(ev$note);
        if ( stg != "" )
            ev$killchain_stage = stg;
        }
    # 값이 없는 선택 필드는 빈 문자열 대신 필드 없음으로 남긴다(uid·계정 조회 결과가 없을 때)
    if ( ev?$uid && /~/ in ev$uid )
        apply_conn_ref(ev);
    if ( ev?$uid && ev$uid == "" )
        delete ev$uid;
    if ( ev?$note && ! ev?$rule )
        ev$rule = sub(cat(ev$note), /^NSM::/, "");
    if ( ev?$detail )
        detail_fields(ev);
    if ( ev?$account && ev$account == "" )
        delete ev$account;
    if ( ev?$account && ! ev?$user_name )
        {
        local ap = split_account(split_string1(ev$account, /,/)[0]);
        if ( ap$user != "" )
            {
            ev$user_name = ap$user;
            if ( ap$domain != "" )
                {
                ev$user_domain = ap$domain;
                ev$user_domain_type = ap$domain_type;
                }
            }
        }

    # evidence_id 별 실제 기록 건수 누적(detection 의 evidence_count 산출용)
    if ( ev$evidence_id != "" )
        {
        ++evidence_counts[ev$evidence_id];
        summary_collect(ev);
        }

    Log::write(NSM::EVIDENCE_LOG, ev);
    }

function evidence_count_of(eid: string): count
    {
    return ( eid in evidence_counts ) ? evidence_counts[eid] : 0;
    }

function evidence_is_new(eid: string, item: string): bool
    {
    if ( eid !in evidence_seen )
        evidence_seen[eid] = set();
    if ( item in evidence_seen[eid] )
        return F;
    add evidence_seen[eid][item];
    return T;
    }

function ev_observe(stream: string, src: addr, dst: addr, uid: string, win: interval)
    {
    local k = cat(stream, "|", src, "|", dst, "|", time_bucket(win));
    if ( k in ev_observed )
        return;
    add ev_observed[k];
    SumStats::observe(stream, [$host=src], [$str=cat(dst, "|", uid)]);
    }

function ev_uids(result: SumStats::Result, stream: string): table[string] of string
    {
    local out: table[string] of string = table();
    if ( stream !in result || ! result[stream]?$samples )
        return out;
    for ( i in result[stream]$samples )
        {
        local o = result[stream]$samples[i];
        if ( ! o?$str )
            next;
        local p = split_string(o$str, /\|/);
        if ( |p| == 2 && p[0] !in out )
            out[p[0]] = p[1];
        }
    return out;
    }

function ev_uid(uids: table[string] of string, dst: string): string
    {
    return ( dst in uids ) ? uids[dst] : "";
    }
