@load base/frameworks/notice
@load base/utils/site
@load ./main
@load ./attack_mapping
@load ./evidence_log   # evidence_count_of (evidence_id 별 실제 근거 건수) 참조
@load ./notice_aggregation   # dup_count 참조
@load ./exceptions           # exception_id / disposition 참조

module NSM;

export {
    redef enum Log::ID += { DETECTION_LOG };

    type DetectionInfo: record {
        ts:               time   &log;
        detection_id:     string &log;
        diagnosis:        string &log;
        ## 탐지를 낸 룰(notice 이름에서 NSM:: 를 뺀 값, 상관 탐지는 Correlated_KillChain).
        ##   Manager 의 룰 정책·예외 화면과 잇는 키. diagnosis 는 표시용 분류다.
        rule:             string &log &optional;
        techniques:       vector of string &log &optional;   # ATT&CK 기법(상관은 체인 순서)
        category:         string &log;
        killchain_stages: vector of string &log &optional;   # 킬체인 단계(상관은 체인 순서)
        severity:         string &log;
        ## severity 의 숫자 값(OCSF severity_id 척도): 단독 1(Information), 상관 3(Suspicious 를 Medium 자리에).
        ##   다른 제품 이벤트와 같은 척도로 정렬·비교할 때 쓴다.
        severity_id:      count  &log &optional;
        first_seen:       time   &log &optional;
        last_seen:        time   &log &optional;
        attacker:         addr   &log &optional;
        attacker_subnet:  subnet &log &optional;
        victims:          vector of string &log &optional;   # 피해 host(최대 chain_max_victims)
        victim_count:     count  &log &optional;             # 피해 host 전체 수(victims 가 잘려도 실제 수)
        ## 근거(evidence)에서 모은 요약(정렬, 최대 NSM::evidence_summary_max 개). 없으면 칸 없음.
        ##   accounts : 관련 계정(근거의 account)
        ##   dst_names: 목적지 이름(근거 detail 의 host·sni·name·DNS 상위 도메인)
        ##   relays   : 거쳐 간 프록시(주소:포트)
        accounts:         vector of string &log &optional;
        dst_names:        vector of string &log &optional;
        relays:           vector of string &log &optional;
        evidence_count:   count  &log &default=0;
        evidence_ids:     vector of string &log &optional;
        disposition:      string &log &optional;   # suppress 예외에 맞은 탐지: suppressed(Manager 는 알림 안 함)
        exception_id:     string &log &optional;   # 맞은 예외 id
        ## 같은 공격이 이어져 나온 탐지를 묶는 사건 id(그 사건의 첫 탐지 detection_id)와 몇 번째인지.
        ##   occurrence > 1 은 진행 중인 같은 사건의 갱신: Manager 는 새 알림 없이 사건의 횟수·마지막 시각을 갱신한다.
        ##   first_seen 은 사건의 첫 탐지 시각이다.
        incident_id:      string &log &optional;
        occurrence:       count  &log &optional;
        ## 상관 탐지만: 같은 체인(detection_id)의 갱신 번호(1부터). 행마다 갈래를 합친 체인 전체를 담으므로
        ##   Manager 는 detection_id 별 revision 이 가장 큰 행을 쓴다. 상관 행은 incident_id = detection_id,
        ##   occurrence = revision 으로도 채워 단독 탐지와 같은 사건 규칙으로 처리할 수 있다.
        revision:         count  &log &optional;
        ## 상관 탐지만: 체인을 이루는 단독 탐지의 detection_id(처음 본 순서). evidence_ids 에서 체인 자신의 근거 id 를 뺀 것.
        member_detection_ids: vector of string &log &optional;
    };

    ## 같은 (탐지 종류, 공격자, 피해 host)의 탐지가 이 간격 안에 다시 나오면 같은 사건으로 묶는다.
    ##   집계형 룰의 창(5분·10분)보다 길어야 창마다 나오는 탐지가 이어진다.
    const detection_continue_gap = 15min &redef;

    global write_detection: function(d: DetectionInfo);

    # 진단명은 main.zeek 의 rule_registry 에 있다(NSM::rule_diagnosis).


    global attacker_segment: function(a: addr): subnet;
}

# ATT&CK 기법 문자열("T1071.004, T1572" 처럼 쉼표·공백 구분)을 배열로
function technique_vec(s: string): vector of string
    {
    local out: vector of string = vector();
    for ( _i, t in split_string(s, /[ ]*,[ ]*/) )
        if ( t != "" )
            out += t;
    return out;
    }

# 근거 요약(accounts·dst_names·relays)을 채운다. 값이 없으면 칸을 비워 둔다.
function fill_summaries(d: DetectionInfo, eids: vector of string)
    {
    local v = NSM::evidence_accounts_of(eids);
    if ( |v| > 0 )
        d$accounts = v;
    v = NSM::evidence_names_of(eids);
    if ( |v| > 0 )
        d$dst_names = v;
    v = NSM::evidence_relays_of(eids);
    if ( |v| > 0 )
        d$relays = v;
    }

function write_detection(d: DetectionInfo)
    {
    if ( ! d?$severity_id )
        d$severity_id = ( d$category == "Correlated" ) ? 3 : 1;
    # 단일 탐지는 근거와 같은 노드에서 기록되므로 여기서 요약을 채운다.
    #   상관 탐지는 단계마다 실어 온 요약을 correlation_killchain 이 채운다(클러스터에서 근거가 다른 노드에 있다).
    if ( d$category != "Correlated" && d?$evidence_ids && |d$evidence_ids| > 0 )
        fill_summaries(d, d$evidence_ids);
    Log::write(NSM::DETECTION_LOG, d);
    }

function attacker_segment(a: addr): subnet
    {
    if ( a in Site::local_nets_table )
        return Site::local_nets_table[a];
    return ( is_v4_addr(a) ) ? mask_addr(a, 24) : mask_addr(a, 64);
    }

type OngoingIncident: record {
    incident_id: string;
    first_seen:  time;
    occurrences: count &default=1;
};

## (탐지 종류|공격자|피해 host) -> 진행 중인 사건. 마지막 탐지 후 detection_continue_gap 이 지나면 끝난 사건.
##   클러스터에서는 탐지를 낸 노드별 상태다(집계형 탐지는 매니저가 내므로 한 곳에 모인다).
global ongoing_incidents: table[string] of OngoingIncident &write_expire=detection_continue_gap;

hook Notice::policy(n: Notice::Info) &priority=-6
    {
    if ( n$note == Correlated_KillChain )
        return;

    if ( n$note !in rule_registry )
        return;

    # 계약: notice.log 에 기록되는 notice 1건 = detection 1건.
    #   notice_aggregation(-5)이 묶은 중복 건은 ACTION_LOG 가 제거돼 있으므로 제외.
    if ( Notice::ACTION_LOG !in n$actions )
        return;
    #   첫 건이 이미 detection 으로 기록됐으므로 창 종료 시 나오는 요약 notice(dup_count)는 detection 을 추가하지 않는다.
    if ( n?$dup_count )
        return;

    local d: DetectionInfo;
    d$ts           = n$ts;
    if ( n?$evidence_id )
        d$detection_id = n$evidence_id;
    else
        d$detection_id = cat(n$note, "-", n$ts);
    d$diagnosis    = rule_registry[n$note]$diagnosis;
    d$rule         = sub(cat(n$note), /^NSM::/, "");
    d$category     = "Single";
    d$severity     = "Information";
    d$first_seen   = n$ts;
    d$last_seen    = n$ts;

    if ( rule_registry[n$note]$stage != "" )
        d$killchain_stages = vector(rule_registry[n$note]$stage);

    if ( n?$disposition )
        d$disposition = n$disposition;
    if ( n?$exception_id )
        d$exception_id = n$exception_id;

    if ( n?$attack )
        d$techniques = technique_vec(n$attack);
    else if ( rule_technique(n$note) != "" )
        d$techniques = technique_vec(rule_technique(n$note));

    if ( n?$src )
        {
        d$attacker        = n$src;
        d$attacker_subnet = attacker_segment(n$src);
        }
    # victims: 확산 룰(06/15/16)은 lm_targets(피해 host 집합)를 우선 사용하고,
    #   그 외에는 notice 의 dst 를 쓴다. 최대 chain_max_victims 개까지 표시(초과 생략).
    #   lm_targets 는 집합이라 순서가 없으므로 주소 순으로 정렬한다(같은 피해 집합이면 같은 배열).
    if ( n?$lm_targets && |n$lm_targets| > 0 )
        {
        local va: vector of addr = vector();
        for ( lv in n$lm_targets )
            va += lv;
        sort(va, function(a: addr, b: addr): int { return a < b ? -1 : ( a > b ? 1 : 0 ); });
        local vout: vector of string = vector();
        for ( _vi, av in va )
            {
            if ( |vout| >= chain_max_victims )
                break;
            vout += cat(av);
            }
        d$victims = vout;
        d$victim_count = |va|;
        }
    else if ( n?$dst )
        {
        d$victims = vector(cat(n$dst));
        d$victim_count = 1;
        }

    # evidence_count: evidence.log 에 실제 기록된 근거 행 수를 반영한다.
    #   (evidence_id 별 누적 카운터. 기록이 없으면 최소 1로 둔다)
    if ( n?$evidence_id )
        {
        local ec = NSM::evidence_count_of(n$evidence_id);
        d$evidence_count = ( ec > 0 ) ? ec : 1;
        }
    else
        d$evidence_count = 1;
    if ( n?$evidence_id )
        d$evidence_ids = vector(n$evidence_id);

    # 진행 중인 같은 사건이면 사건 id 를 이어 받고 횟수를 올린다.
    local ikey = cat(n$note, "|", d?$attacker ? cat(d$attacker) : "-", "|", d?$victims ? join_string_vec(d$victims, ",") : "-");
    if ( ikey in ongoing_incidents )
        {
        local inc = ongoing_incidents[ikey];
        inc$occurrences += 1;
        ongoing_incidents[ikey] = inc;          # 쓰기로 만료 시각을 늦춘다
        d$incident_id = inc$incident_id;
        d$occurrence  = inc$occurrences;
        d$first_seen  = inc$first_seen;
        }
    else
        {
        ongoing_incidents[ikey] = OngoingIncident($incident_id=d$detection_id, $first_seen=d$first_seen);
        d$incident_id = d$detection_id;
        d$occurrence  = 1;
        }

    write_detection(d);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::DETECTION_LOG, [$columns=DetectionInfo, $path="nsm_detection"]);
    }
