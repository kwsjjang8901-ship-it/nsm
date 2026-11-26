##! ============================================================================
##! Kill-chain 상관분석 — 확정 notice 를 단계 전이 규칙(chain_rules)으로 연결한다.
##!
##! 클러스터 동작 (2026-11 개정, 검토 H2)
##!   - Notice::log_notice 는 notice 를 기록한 노드에서만 발생한다. SumStats 룰(01/02/06/
##!     13/14/15/16)은 매니저에서, 연결 단위 룰(07/09/10/12)은 워커에서 notice 를 낸다.
##!     예전에는 각 노드가 자기 메모리(primes)로 상관해, 워커의 C2 -> 매니저의 확산 같은
##!     노드를 넘는 전이가 연결되지 않았다.
##!   - 이제 모든 노드는 notice 요약(CorrNotice)을 NSM::corr_notice 이벤트로 매니저에 보내고,
##!     상관(primes, 체인 생성, Correlated_KillChain notice)은 매니저 한 곳에서만 한다.
##!     standalone 에서는 같은 이벤트를 로컬로 처리한다(동작 동일).
##!   - 전이 시간창은 처리 노드의 현재 시각이 아니라 notice 의 발생 시각(ts)으로 판단한다
##!     (워커 -> 매니저 전달 지연이 판정에 영향을 주지 않도록).
##!   - 한계: 서로 다른 노드의 notice 가 전달 지연 때문에 발생 순서와 다르게 도착하면
##!     (수 초 이내의 근접 사건) 전이가 연결되지 않을 수 있다.
##! ============================================================================

@load base/frameworks/notice
@load base/frameworks/cluster
@load ./main
@load ./evidence_log
@load ./detection_log
@load ./notice_aggregation
@load ./attack_mapping
@load ./exceptions

module NSM;

export {
    type PivotKind: enum { SRC_TO_SRC, DST_TO_SRC };

    type Transition: record {
        from:   Notice::Type;
        to:     Notice::Type;
        pivot:  PivotKind;
        window: interval;
    };

    const chain_rules: vector of Transition = {
        # Recon -> C2 (같은 host)
        [$from=Port_Scan,       $to=HTTP_Beaconing,        $pivot=SRC_TO_SRC, $window=1hr],
        [$from=Port_Scan,       $to=Encrypted_C2,          $pivot=SRC_TO_SRC, $window=1hr],
        [$from=Host_Scan,       $to=HTTP_Beaconing,        $pivot=SRC_TO_SRC, $window=1hr],
        [$from=Host_Scan,       $to=Encrypted_C2,          $pivot=SRC_TO_SRC, $window=1hr],
        [$from=Port_Scan,       $to=DGA_Domain,            $pivot=SRC_TO_SRC, $window=1hr],
        [$from=Host_Scan,       $to=DGA_Domain,            $pivot=SRC_TO_SRC, $window=1hr],
        [$from=DGA_Domain,      $to=HTTP_Beaconing,        $pivot=SRC_TO_SRC, $window=1hr],
        [$from=DGA_Domain,      $to=Encrypted_C2,          $pivot=SRC_TO_SRC, $window=1hr],
        [$from=HTTP_Beaconing,  $to=SMB_Admin_Share,       $pivot=SRC_TO_SRC, $window=30min],
        [$from=Encrypted_C2,    $to=SMB_Admin_Share,       $pivot=SRC_TO_SRC, $window=30min],
        [$from=HTTP_Beaconing,  $to=RDP_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        [$from=Encrypted_C2,    $to=RDP_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        [$from=HTTP_Beaconing,  $to=SSH_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        [$from=Encrypted_C2,    $to=SSH_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        # DGA(C2) -> 확산: DGA 도 다른 C2(07/09)와 동일하게 확산으로 전이해야 한다.
        #   (누락 시 정찰->DGA 2단계에서 멈추고 확산이 이어지지 않는다)
        [$from=DGA_Domain,      $to=SMB_Admin_Share,       $pivot=SRC_TO_SRC, $window=30min],
        [$from=DGA_Domain,      $to=RDP_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        [$from=DGA_Domain,      $to=SSH_Lateral,           $pivot=SRC_TO_SRC, $window=30min],
        [$from=SMB_Admin_Share, $to=Exfil_Large_Transfer,  $pivot=DST_TO_SRC, $window=10min],
        [$from=SMB_Admin_Share, $to=Exfil_Volume_Aggregate,$pivot=DST_TO_SRC, $window=10min],
        [$from=RDP_Lateral,     $to=Exfil_Large_Transfer,  $pivot=DST_TO_SRC, $window=10min],
        [$from=RDP_Lateral,     $to=Exfil_Volume_Aggregate,$pivot=DST_TO_SRC, $window=10min],
        [$from=SSH_Lateral,     $to=Exfil_Large_Transfer,  $pivot=DST_TO_SRC, $window=10min],
        [$from=SSH_Lateral,     $to=Exfil_Volume_Aggregate,$pivot=DST_TO_SRC, $window=10min],
    } &redef;

    ## ------------------------------------------------------------------
    ## 단계 묶음 전이 (2026-11, 4단계 신규 탐지 반영)
    ##   묶음 A 의 어떤 탐지든 -> 묶음 B 의 어떤 탐지로 이어진다. zeek_init 에서 탐지 쌍으로 펼쳐
    ##   chain_rules 와 합친다(같은 from·to·pivot 이 겹치면 긴 window 를 쓴다).
    ##   묶음 집합을 redef 하면 반영되지만, chain_group_rules 를 함께 다시 정의해야 한다
    ##   (const 초기화 시점에 집합이 복사되기 때문).
    ## ------------------------------------------------------------------
    type GroupTransition: record {
        from:   set[Notice::Type];
        to:     set[Notice::Type];
        pivot:  PivotKind;
        window: interval;
    };

    const corr_recon_notes: set[Notice::Type] = { Port_Scan, Host_Scan, AD_Enumeration } &redef;
    ## 초기 침투(대상 = 침투당한 서버, notice 의 lm_targets). 이후 단계는 그 서버가 출발지가 된다.
    const corr_initial_notes: set[Notice::Type] = {
        SQL_Injection, Webshell_Access, Cross_Site_Scripting, TLS_Heartbleed, AI_Service_Exploit,
    } &redef;
    const corr_c2_notes: set[Notice::Type] = {
        HTTP_Beaconing, Encrypted_C2, DGA_Domain, DNS_Tunneling, Nonstandard_Port, Long_Connection, Unknown_Protocol,
        TLS_Beaconing, AI_API_From_Server, IOC_Match,
    } &redef;
    ## 자격증명 탈취 시도(출발지 = 공격 host)
    const corr_cred_notes: set[Notice::Type] = {
        NTLM_Spray, Kerberos_Spray, Kerberos_Bruteforce, Kerberoasting, ASREP_Roasting, Name_Poisoning,
        SSH_Bruteforce, FTP_Bruteforce, HTTP_Bruteforce, Machine_Account_Misuse,
        Coerced_Authentication, Remote_Registry_Dump,
    } &redef;
    ## 도메인 장악(자격증명 단계의 끝)
    const corr_domain_notes: set[Notice::Type] = { DCSync, Zerologon_Attempt } &redef;
    const corr_lateral_notes: set[Notice::Type] = {
        SMB_Admin_Share, RDP_Lateral, SSH_Lateral, WinRM_Lateral, DCOM_Lateral,
        Remote_Service_Creation, Remote_Task_Creation, Remote_WMI_Execution,
    } &redef;
    const corr_exfil_notes: set[Notice::Type] = {
        Exfil_Large_Transfer, Exfil_Volume_Aggregate, Exfil_DNS, Exfil_Web_Upload, Outbound_SMB, AI_Service_Upload,
    } &redef;
    const corr_impact_notes: set[Notice::Type] = { SMB_Ransomware } &redef;

    const chain_group_rules: vector of GroupTransition = {
        # 정찰 -> 초기 침투 (같은 공격 host)
        [$from=corr_recon_notes,   $to=corr_initial_notes, $pivot=SRC_TO_SRC, $window=1hr],
        # 초기 침투 -> 침투당한 서버에서 C2·자격증명 탈취·도메인 장악·확산 (대상 host 피벗)
        [$from=corr_initial_notes, $to=corr_c2_notes,      $pivot=DST_TO_SRC, $window=2hr],
        [$from=corr_initial_notes, $to=corr_cred_notes,    $pivot=DST_TO_SRC, $window=2hr],
        [$from=corr_initial_notes, $to=corr_domain_notes,  $pivot=DST_TO_SRC, $window=2hr],
        [$from=corr_initial_notes, $to=corr_lateral_notes, $pivot=DST_TO_SRC, $window=2hr],
        # 정찰 -> C2 / 자격증명 탈취 (같은 host)
        [$from=corr_recon_notes,   $to=corr_c2_notes,      $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_recon_notes,   $to=corr_cred_notes,    $pivot=SRC_TO_SRC, $window=1hr],
        # 정찰(AD 정보 수집 등) -> 도메인 장악·확산 (같은 host: BloodHound 로 경로를 찾은 뒤 이동)
        [$from=corr_recon_notes,   $to=corr_domain_notes,  $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_recon_notes,   $to=corr_lateral_notes, $pivot=SRC_TO_SRC, $window=1hr],
        # C2 -> 자격증명 탈취·도메인 장악·확산 (같은 host)
        [$from=corr_c2_notes,      $to=corr_cred_notes,    $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_c2_notes,      $to=corr_domain_notes,  $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_c2_notes,      $to=corr_lateral_notes, $pivot=SRC_TO_SRC, $window=30min],
        # 자격증명 탈취 -> 도메인 장악·확산 (같은 host)
        [$from=corr_cred_notes,    $to=corr_domain_notes,  $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_cred_notes,    $to=corr_lateral_notes, $pivot=SRC_TO_SRC, $window=1hr],
        [$from=corr_domain_notes,  $to=corr_lateral_notes, $pivot=SRC_TO_SRC, $window=1hr],
        # Zerologon 으로 DC 계정을 장악한 뒤 DCSync
        [$from=set(Zerologon_Attempt), $to=set(DCSync),    $pivot=SRC_TO_SRC, $window=1hr],
        # 확산 -> 피해 host 에서 유출·영향·추가 자격증명 탈취 (피해 host 피벗)
        [$from=corr_lateral_notes, $to=corr_exfil_notes,   $pivot=DST_TO_SRC, $window=10min],
        [$from=corr_lateral_notes, $to=corr_impact_notes,  $pivot=DST_TO_SRC, $window=30min],
        [$from=corr_lateral_notes, $to=corr_cred_notes,    $pivot=DST_TO_SRC, $window=1hr],
        [$from=corr_lateral_notes, $to=corr_domain_notes,  $pivot=DST_TO_SRC, $window=1hr],
        # 확산한 host 가 직접 파일 서버를 암호화
        [$from=corr_lateral_notes, $to=corr_impact_notes,  $pivot=SRC_TO_SRC, $window=30min],
        # 유출 후 암호화(이중 갈취)
        [$from=corr_exfil_notes,   $to=corr_impact_notes,  $pivot=SRC_TO_SRC, $window=1hr],
        # 외부로 NTLM 해시가 샌 host 가 이어서 C2 통신
        [$from=set(NTLM_Credential_Leak), $to=corr_c2_notes, $pivot=SRC_TO_SRC, $window=1hr],
    } &redef;

    const chain_max_expire = 2hr &redef;

    ## 상관에 필요한 notice 요약(노드 간 전달용).
    type CorrNotice: record {
        ts:          time;
        note:        Notice::Type;
        src:         addr;
        evidence_id: string   &default="";
        targets:     set[addr] &default=addr_set();
        ## 이 탐지 근거의 요약(nsm_detection 의 accounts·dst_names·relays). 근거를 쓴 노드에서 만들어
        ##   함께 보내므로, 클러스터에서도 상관 행이 모든 단계의 요약을 갖는다.
        accounts:    set[string] &default=string_set();
        names:       set[string] &default=string_set();
        relays:      set[string] &default=string_set();
    };

    ## notice 요약 전달 이벤트. 클러스터에서는 워커/매니저 모두 매니저로 보내고,
    ## 매니저(또는 standalone)에서만 처리한다.
    global corr_notice: event(cn: CorrNotice);
    # chain_max_victims 는 main.zeek 로 이동(detection_log 와 공용).

}

type ChainState: record {
    stages:     vector of Notice::Type;   # 밟아온 단계(순서)
    stage_ts:   vector of time;           # 각 단계 탐지 시각(stages 와 같은 순서)
    eids:       vector of string;         # 각 단계 evidence_id
    attacker:   addr   &default=0.0.0.0;  # 최초 기점 host
    started_at: time;
    expire_at:  time;                     # 이 prime 의 만료(전이별 window)
    chain_id:   string;
    victims:    set[addr];                # 각 단계에서 관측된 피해 host 누적
    accounts:   set[string];              # 각 단계 근거 요약 누적(detection 의 accounts·dst_names·relays)
    names:      set[string];
    relays:     set[string];
};

global primes: table[addr, Notice::Type] of ChainState &write_expire=chain_max_expire;

## 한 체인(chain_id)의 모든 갈래를 합친 상태. 탐지 요약(nsm_detection)은 이 값으로 쓴다.
##   한 체인은 피해 host 별(DST_TO_SRC)·다음 단계별로 갈라지는데, 갈래마다 다른 내용을 같은
##   detection_id 로 내면 Manager 가 덮어쓸 때 앞 갈래(예: 유출)가 사라진다. 그래서 갈래를 합친
##   전체를 내고 revision(1부터)을 붙인다. Manager 는 detection_id 별 revision 이 가장 큰 행을 쓴다.
type ChainAgg: record {
    revision:   count &default=0;
    attacker:   addr;
    started_at: time;
    last_seen:  time;
    notes:      vector of Notice::Type;   # 단계(중복 없음, 처음 본 시각 순)
    note_ts:    vector of time;           # 각 단계를 처음 본 시각
    eids:       vector of string;         # 구성 탐지 id(처음 본 순서, 중복 없음)
    victims:    set[addr];
    last_host:  addr;
    accounts:   set[string];
    names:      set[string];
    relays:     set[string];
};

## 갈래가 남아 있는 동안 유지한다. 합친 상태는 갈래(primes)를 만들 때마다 같이 갱신되므로
##   갈래보다 먼저 만료되지 않는다(같은 만료 시간, 마지막 쓰기가 더 늦음).
global chain_aggs: table[string] of ChainAgg &write_expire=chain_max_expire;

## 합친 상태의 구성 탐지 id 상한(긴 체인에서 메모리 보호)
const chain_agg_max_eids = 64;

## chain_rules + chain_group_rules 를 펼친 전이 색인: 출발 탐지 -> 전이 목록
global transitions_from: table[Notice::Type] of vector of Transition;

## 같은 (출발, 도착, pivot) 전이가 여러 규칙에 있으면 가장 긴 window 를 쓴다.
##   (Notice::Type 과 PivotKind 를 한 복합 색인에 섞으면 Zeek 9 가 경고하므로 문자열 키를 쓴다)
function merge_transition(best: table[string] of Transition, tr: Transition)
    {
    local k = cat(tr$from, "|", tr$to, "|", tr$pivot);
    if ( k !in best || best[k]$window < tr$window )
        best[k] = tr;
    }

event zeek_init() &priority=10
    {
    # 예외 엔진의 범위 묶음(group:<이름>)을 상관 단계 묶음과 같게 둔다(한 곳에서 관리).
    NSM::exception_groups["recon"]   = corr_recon_notes;
    NSM::exception_groups["c2"]      = corr_c2_notes;
    NSM::exception_groups["cred"]    = corr_cred_notes;
    NSM::exception_groups["domain"]  = corr_domain_notes;
    NSM::exception_groups["lateral"] = corr_lateral_notes;
    NSM::exception_groups["exfil"]   = corr_exfil_notes;
    NSM::exception_groups["impact"]  = corr_impact_notes;

    local best: table[string] of Transition = table();

    for ( i in chain_rules )
        merge_transition(best, chain_rules[i]);

    for ( j in chain_group_rules )
        {
        local g = chain_group_rules[j];
        for ( f in g$from )
            for ( t in g$to )
                {
                if ( f == t )
                    next;
                merge_transition(best, Transition($from=f, $to=t, $pivot=g$pivot, $window=g$window));
                }
        }

    for ( bk, tr in best )
        {
        if ( tr$from !in transitions_from )
            transitions_from[tr$from] = vector();
        local v = transitions_from[tr$from];
        v[|v|] = tr;
        }
    }

# 체인 표시용 기법 ID: 룰 레지스트리의 기법, 없으면 notice 이름
function stage_technique(n: Notice::Type): string
    {
    local t = rule_technique(n);
    return t != "" ? t : cat(n);
    }

global kc_counter: count = 0;
# 프로세스마다 다른 짧은 값. 재시작 직후 같은 초·같은 번호로 과거 체인 id 와 겹치지 않게 하고,
#   클러스터에서 여러 노드가 같은 id 를 만들지 않게 한다.
global kc_run: string = "";

event zeek_init()
    {
    kc_run = fmt("%06x", rand(0xffffff));
    }

function chain_tids(st: ChainState): string
    {
    local out = "";
    local i = 0; local n = |st$stages|;
    while ( i < n )
        {
        local t = stage_technique(st$stages[i]);
        out = i == 0 ? t : cat(out, "->", t);
        i += 1;
        }
    return out;
    }

# attack 필드용: 체인의 실제 기법을 중복 제거 후 쉼표로 연결한다.
#   chain_tids 는 "->" 로 흐름을 보여주는 sub 표시용, 이 함수는 attack 필드 표준(쉼표)용.
#   note→기법이 다대일일 수 있어(예: 여러 유출룰→T1041) 중복을 제거한다.
function chain_tids_csv(st: ChainState): string
    {
    local seen: set[string] = set();
    local parts: vector of string = vector();
    local i = 0; local n = |st$stages|;
    while ( i < n )
        {
        local t = stage_technique(st$stages[i]);
        if ( t !in seen )
            {
            add seen[t];
            parts[|parts|] = t;
            }
        i += 1;
        }
    return join_string_vec(parts, ",");
    }

function chain_names(st: ChainState): string
    {
    local out = "";
    local i = 0; local n = |st$stages|;
    while ( i < n )
        {
        out = i == 0 ? cat(st$stages[i]) : cat(out, "->", st$stages[i]);
        i += 1;
        }
    return out;
    }

function fresh_chain(note: Notice::Type, origin: addr, eid: string, ts: time): ChainState
    {
    kc_counter += 1;
    local eids: vector of string = vector();
    if ( eid != "" )
        eids[|eids|] = eid;
    local vic: set[addr] = set();
    local acc: set[string] = set();
    local nam: set[string] = set();
    local rel: set[string] = set();
    # chain_id: kc-<시작 epoch>-<프로세스 값>-<번호>. 재시작·노드가 달라도 겹치지 않게 프로세스 값을 넣는다.
    return [$stages=vector(note), $stage_ts=vector(ts), $eids=eids,
            $attacker=origin, $started_at=ts,
            $expire_at=ts, $chain_id=fmt("kc-%d-%s-%d", double_to_count(time_to_double(ts)), kc_run, kc_counter),
            $victims=vic, $accounts=acc, $names=nam, $relays=rel];
    }

# 체인 요약 누적. 오래 이어지는 체인에서 메모리가 늘지 않도록 칸마다 chain_summary_keep 개까지.
const chain_summary_keep = 32;

function absorb_set(dst: set[string], src: set[string])
    {
    for ( v in src )
        {
        if ( |dst| >= chain_summary_keep )
            return;
        add dst[v];
        }
    }

function chain_absorb(st: ChainState, cn: CorrNotice)
    {
    absorb_set(st$accounts, cn$accounts);
    absorb_set(st$names, cn$names);
    absorb_set(st$relays, cn$relays);
    }

# 정렬해 최대 NSM::evidence_summary_max 개
function summary_vec(s: set[string]): vector of string
    {
    local out: vector of string = vector();
    for ( v in s )
        out += v;
    sort(out, function(a: string, b: string): int { return strcmp(a, b); });
    if ( |out| > NSM::evidence_summary_max )
        out = out[:NSM::evidence_summary_max];
    return out;
    }


function stage_tag(note: Notice::Type): string
    {
    local st = killchain_stage_of(note);
    return st in stage_tags ? stage_tags[st] : cat(note);
    }

# evidence_ids 의 실제 기록 건수를 합산한다(단계 수가 아니라 근거 행 수).
function chain_evidence_count(eids: vector of string): count
    {
    local total = 0;
    for ( i in eids )
        {
        local c = NSM::evidence_count_of(eids[i]);
        total += ( c > 0 ) ? c : 1;
        }
    return total;
    }

# 단계 진행 순위(가장 많이 진행된 단계를 진단명 뒤쪽에 쓴다). 통합 리포트의 단계 순서와 같다.
const stage_rank: table[string] of count = {
    ["Recon"] = 1, ["InitialAccess"] = 2, ["C2"] = 3, ["CredentialAccess"] = 4,
    ["Lateral"] = 5, ["Exfil"] = 6, ["Impact"] = 7,
};

# 갈래 st 를 체인의 합친 상태에 넣고 revision 을 올린다.
function agg_merge(st: ChainState, last_host: addr, ts: time): ChainAgg
    {
    local agg: ChainAgg;
    if ( st$chain_id in chain_aggs )
        agg = chain_aggs[st$chain_id];
    else
        {
        local nv: vector of Notice::Type = vector();
        local tv: vector of time = vector();
        local ev: vector of string = vector();
        local vs: set[addr] = set();
        local s1: set[string] = set();
        local s2: set[string] = set();
        local s3: set[string] = set();
        agg = ChainAgg($attacker=st$attacker, $started_at=st$started_at, $last_seen=ts,
                       $notes=nv, $note_ts=tv, $eids=ev, $victims=vs, $last_host=last_host,
                       $accounts=s1, $names=s2, $relays=s3);
        }

    agg$revision += 1;
    if ( st$started_at < agg$started_at )
        agg$started_at = st$started_at;
    if ( ts >= agg$last_seen )
        {
        agg$last_seen = ts;
        agg$last_host = last_host;
        }

    # 단계: 처음 보는 단계를 시각 순 자리에 넣는다(같은 시각이면 뒤에).
    for ( i, n in st$stages )
        {
        local seen = F;
        for ( _j, an in agg$notes )
            if ( an == n )
                {
                seen = T;
                break;
                }
        if ( seen )
            next;
        local t = ( i < |st$stage_ts| ) ? st$stage_ts[i] : st$started_at;
        local pos = |agg$notes|;
        while ( pos > 0 && agg$note_ts[pos - 1] > t )
            pos -= 1;
        local nn: vector of Notice::Type = vector();
        local nt: vector of time = vector();
        for ( k, x in agg$notes )
            {
            if ( k == pos )
                {
                nn += n;
                nt += t;
                }
            nn += x;
            nt += agg$note_ts[k];
            }
        if ( pos == |agg$notes| )
            {
            nn += n;
            nt += t;
            }
        agg$notes = nn;
        agg$note_ts = nt;
        }

    for ( _e, eid in st$eids )
        {
        if ( eid == "" || |agg$eids| >= chain_agg_max_eids )
            next;
        local dup = F;
        for ( _f, x2 in agg$eids )
            if ( x2 == eid )
                {
                dup = T;
                break;
                }
        if ( ! dup )
            agg$eids += eid;
        }

    # 피해 host 에는 체인 출발지(공격자) 자신을 넣지 않는다(출발지에서 이어지는 단계의 last_host 는 출발지).
    for ( v in st$victims )
        if ( v != agg$attacker )
            add agg$victims[v];
    if ( last_host != agg$attacker )
        add agg$victims[last_host];
    absorb_set(agg$accounts, st$accounts);
    absorb_set(agg$names, st$names);
    absorb_set(agg$relays, st$relays);

    chain_aggs[st$chain_id] = agg;    # 다시 써서 만료 시각을 늦춘다
    return agg;
    }

# 진단명: NSM.Correlation.<첫 단계>.<가장 많이 진행된 단계>(같은 순위면 나중 단계)
function agg_diagnosis(agg: ChainAgg): string
    {
    local first = stage_tag(agg$notes[0]);
    local last = first;
    local best = 0;
    for ( _i, n in agg$notes )
        {
        local tg = stage_tag(n);
        local r = ( tg in stage_rank ) ? stage_rank[tg] : 0;
        if ( r >= best )
            {
            best = r;
            last = tg;
            }
        }
    return fmt("%s.%s.%s", rule_diagnosis(Correlated_KillChain), first, last);
    }

function agg_tids_vec(agg: ChainAgg): vector of string
    {
    local out: vector of string = vector();
    for ( _i, n in agg$notes )
        out += stage_technique(n);
    return out;
    }

# 킬체인 단계명: 처음 본 순서, 중복 없음(여러 탐지가 같은 단계면 한 번). techniques 는 탐지마다 하나.
function agg_stage_names(agg: ChainAgg): vector of string
    {
    local out: vector of string = vector();
    local seen: set[string] = set();
    for ( _i, n in agg$notes )
        {
        local nm = killchain_stage_of(n) != "" ? killchain_stage_of(n) : cat(n);
        if ( nm in seen )
            next;
        add seen[nm];
        out += nm;
        }
    return out;
    }

# 피해 host: 가장 최근 단계의 host 를 앞에, 나머지는 주소 순. 최대 chain_max_victims 개.
#   아직 피해 host 가 없으면(출발지에서만 이어진 단계들) 예전처럼 출발지를 표시한다.
function agg_victims_vec(agg: ChainAgg): vector of string
    {
    if ( |agg$victims| == 0 )
        return vector(cat(agg$attacker));
    local rest: vector of addr = vector();
    for ( v in agg$victims )
        if ( v != agg$last_host )
            rest += v;
    sort(rest, function(a: addr, b: addr): int { return a < b ? -1 : ( a > b ? 1 : 0 ); });
    local out: vector of string = vector();
    if ( agg$last_host in agg$victims )
        out += cat(agg$last_host);
    for ( _i, r in rest )
        {
        if ( |out| >= chain_max_victims )
            break;
        out += cat(r);
        }
    return out;
    }

# evidence_ids: 체인 요약 근거(chain_id) + 구성 탐지 id
function agg_evidence_ids(chain_id: string, agg: ChainAgg): vector of string
    {
    local out: vector of string = vector(chain_id);
    for ( _i, e in agg$eids )
        if ( e != chain_id )
            out += e;
    return out;
    }

function emit_chain(st: ChainState, last_host: addr, ts: time)
    {
    local len = |st$stages|;

    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=st$chain_id,
        $note=Correlated_KillChain,
        $technique=chain_tids(st),
        $src=st$attacker,
        $dst=last_host,
        $operation="killchain",
        $parent_id=st$eids,
        $detail=fmt("stages=%s len=%d last_host=%s", chain_names(st), len, last_host)]);

    NOTICE([$note=Correlated_KillChain,
            $src=st$attacker,
            $msg=fmt("Kill-chain(%d stages): %s | origin=%s last_host=%s",
                     len, chain_names(st), st$attacker, last_host),
            $sub=fmt("chain=%s chain_id=%s eids=%s",
                     chain_tids(st), st$chain_id, join_string_vec(st$eids, ",")),
            # 같은 체인이 피해 host 별(DST_TO_SRC)·마지막 단계별로 갈라질 수 있으므로 마지막 단계와 host 를 넣는다.
            #   (len 만 쓰면 두 번째 갈래 notice 가 억제되는데 detection 은 기록돼 notice 1 = detection 1 계약이 깨진다)
            $identifier=cat(st$chain_id, "|len", len, "|", st$stages[len-1], "|", last_host),
            $suppress_for=chain_max_expire,
            $attack=chain_tids_csv(st),
            $evidence_id=st$chain_id]);

    # 갈래를 합친 상태로 탐지 요약을 쓴다(chain 요약 근거를 적재한 뒤라 count 에 포함된다).
    local agg = agg_merge(st, last_host, ts);
    local all_eids = agg_evidence_ids(st$chain_id, agg);

    local d = NSM::DetectionInfo(
        $ts               = network_time(),
        $detection_id     = st$chain_id,
        $diagnosis        = agg_diagnosis(agg),
        $rule             = "Correlated_KillChain",
        $techniques       = agg_tids_vec(agg),
        $category         = "Correlated",
        $killchain_stages = agg_stage_names(agg),
        $severity         = "Suspicious",
        $severity_id      = 3,
        $first_seen       = agg$started_at,
        $last_seen        = agg$last_seen,
        $attacker         = agg$attacker,
        $attacker_subnet  = NSM::attacker_segment(agg$attacker),
        $victims          = agg_victims_vec(agg),
        $victim_count     = |agg$victims| > 0 ? |agg$victims| : 1,
        $evidence_count   = chain_evidence_count(all_eids),
        $evidence_ids     = all_eids,
        $revision         = agg$revision,
        # 같은 사건 묶기 규칙을 단독 탐지와 맞춘다: 사건 = 체인, 횟수 = 갱신 번호
        $incident_id      = st$chain_id,
        $occurrence       = agg$revision);
    if ( |agg$eids| > 0 )
        d$member_detection_ids = agg$eids;
    if ( |agg$accounts| > 0 )
        d$accounts = summary_vec(agg$accounts);
    if ( |agg$names| > 0 )
        d$dst_names = summary_vec(agg$names);
    if ( |agg$relays| > 0 )
        d$relays = summary_vec(agg$relays);
    NSM::write_detection(d);
    }

# 이미 걸린 대기(prime)가 아직 유효하고 새 체인보다 더 진행돼 있으면 덮어쓰지 않는다.
#   반복되는 정찰(포트 스캔 등)이 1단계짜리 새 체인으로, 이미 C2 까지 간 체인의 다음 단계 대기를 지우면
#   3단계 이상 체인이 쪼개진다. 같은 체인이면(갈래 갱신) 덮어쓴다.
function prime_keeps_existing(h: addr, to: Notice::Type, chain: ChainState, ts: time): bool
    {
    if ( [h, to] !in primes )
        return F;
    local old = primes[h, to];
    return old$expire_at >= ts && old$chain_id != chain$chain_id && |old$stages| > |chain$stages|;
    }

function prime_forward(note: Notice::Type, chain: ChainState, src: addr, dsts: set[addr], ts: time)
    {
    if ( note !in transitions_from )
        return;

    local rules = transitions_from[note];
    for ( idx in rules )
        {
        local rule = rules[idx];

        if ( rule$pivot == SRC_TO_SRC )
            {
            if ( prime_keeps_existing(src, rule$to, chain, ts) )
                next;
            local c1 = copy(chain);
            c1$expire_at = ts + rule$window;
            primes[src, rule$to] = c1;
            }
        else
            {
            for ( d in dsts )
                {
                if ( prime_keeps_existing(d, rule$to, chain, ts) )
                    next;
                local c2 = copy(chain);
                c2$expire_at = ts + rule$window;
                primes[d, rule$to] = c2;
                }
            }
        }
    }

## notice 1건을 상관 처리한다(매니저 또는 standalone 에서만 호출).
function corr_process(cn: CorrNotice)
    {
    local s   = cn$src;
    local m   = cn$note;
    local eid = cn$evidence_id;
    local dsts = cn$targets;

    local current: ChainState;
    local matched = F;

    if ( [s, m] in primes )
        {
        local st = primes[s, m];
        if ( cn$ts <= st$expire_at )
            {
            # 확장
            local ext = copy(st);
            ext$stages[|ext$stages|] = m;
            ext$stage_ts[|ext$stage_ts|] = cn$ts;
            if ( eid != "" )
                ext$eids[|ext$eids|] = eid;
            # 이 단계에서 관측된 피해 host 누적(확산 대상 등)
            for ( dv in dsts )
                add ext$victims[dv];
            chain_absorb(ext, cn);
            emit_chain(ext, s, cn$ts);
            current = ext;
            matched = T;
            }
        delete primes[s, m];
        }

    if ( ! matched )
        {
        current = fresh_chain(m, s, eid, cn$ts);
        for ( dv0 in dsts )
            add current$victims[dv0];
        chain_absorb(current, cn);
        }

    prime_forward(m, current, s, dsts, cn$ts);
    }

# notice 가 기록되는 노드(워커/매니저/standalone)에서 요약을 만들어 상관 처리 노드로 보낸다.
event Notice::log_notice(rec: Notice::Info)
    {
    if ( rec$note == Correlated_KillChain )
        return;
    if ( rec?$dup_count )
        return;
    # suppress 예외로 표시된 탐지는 상관에서 뺀다(drop 과 같음). 상관에 넣는 방안(E5)은 보류:
    #   대량 접속 서버에 suppress 를 걸면 피해 host 가 다음 단계 출발지로 등록돼 가짜 체인이 생길 수 있다.
    if ( rec?$disposition )
        return;
    if ( ! rec?$src )
        return;

    local cn = CorrNotice($ts=rec$ts, $note=rec$note, $src=rec$src);
    if ( rec?$evidence_id )
        {
        cn$evidence_id = rec$evidence_id;
        # 근거 요약은 근거를 쓴 이 노드에만 있으므로 여기서 실어 보낸다.
        local ev1 = vector(rec$evidence_id);
        for ( _i, a in NSM::evidence_accounts_of(ev1) )
            add cn$accounts[a];
        for ( _j, nm in NSM::evidence_names_of(ev1) )
            add cn$names[nm];
        for ( _k, r in NSM::evidence_relays_of(ev1) )
            add cn$relays[r];
        }
    if ( rec?$lm_targets )
        cn$targets = rec$lm_targets;

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
    Cluster::publish(Cluster::manager_topic, NSM::corr_notice, cn);
@else
    event NSM::corr_notice(cn);
@endif
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event NSM::corr_notice(cn: CorrNotice)
    {
    corr_process(cn);
    }
@endif
