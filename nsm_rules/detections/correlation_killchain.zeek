

@load base/frameworks/notice
@load ./main
@load ./evidence_log
@load ./detection_log
@load ./notice_aggregation

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

    const chain_max_expire = 2hr &redef;
    # chain_max_victims 는 main.zeek 로 이동(detection_log 와 공용).

    const stage_attack: table[Notice::Type] of string = {
        [Port_Scan]              = "T1046",
        [Host_Scan]              = "T1018",
        [HTTP_Beaconing]         = "T1071.001",
        [Encrypted_C2]           = "T1573",
        [DGA_Domain]             = "T1568.002",
        [SMB_Admin_Share]        = "T1021.002",
        [RDP_Lateral]            = "T1021.001",
        [SSH_Lateral]            = "T1021.004",
        [Exfil_Large_Transfer]   = "T1041",
        [Exfil_Volume_Aggregate] = "T1041",
    } &redef;
}

type ChainState: record {
    stages:     vector of Notice::Type;   # 밟아온 단계(순서)
    eids:       vector of string;         # 각 단계 evidence_id
    attacker:   addr   &default=0.0.0.0;  # 최초 기점 host
    started_at: time;
    expire_at:  time;                     # 이 prime 의 만료(전이별 window)
    chain_id:   string;
    victims:    set[addr];                # 각 단계에서 관측된 피해 host 누적
};

global primes: table[addr, Notice::Type] of ChainState &write_expire=chain_max_expire;

global kc_counter: count = 0;

function chain_tids(st: ChainState): string
    {
    local out = "";
    local i = 0; local n = |st$stages|;
    while ( i < n )
        {
        local t = st$stages[i] in stage_attack ? stage_attack[st$stages[i]] : cat(st$stages[i]);
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
        local t = st$stages[i] in stage_attack ? stage_attack[st$stages[i]] : cat(st$stages[i]);
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

function fresh_chain(note: Notice::Type, origin: addr, eid: string): ChainState
    {
    kc_counter += 1;
    local eids: vector of string = vector();
    if ( eid != "" )
        eids[|eids|] = eid;
    local vic: set[addr] = set();
    return [$stages=vector(note), $eids=eids,
            $attacker=origin, $started_at=network_time(),
            $expire_at=network_time(), $chain_id=cat("kc-", kc_counter),
            $victims=vic];
    }

const stage_tag_map: table[Notice::Type] of string = {
    [Port_Scan]              = "Recon",
    [Host_Scan]              = "Recon",
    [SQL_Injection]          = "InitialAccess",
    [Webshell_Access]        = "InitialAccess",
    [NTLM_Spray]             = "CredentialAccess",
    [HTTP_Beaconing]         = "C2",
    [DNS_Tunneling]          = "C2",
    [Encrypted_C2]           = "C2",
    [DGA_Domain]             = "C2",
    [SMB_Admin_Share]        = "Lateral",
    [Exfil_Large_Transfer]   = "Exfil",
    [Exfil_Volume_Aggregate] = "Exfil",
    [Exfil_DNS]              = "Exfil",
    [Exfil_Web_Upload]       = "Exfil",
} &redef;

function stage_tag(note: Notice::Type): string
    {
    return note in stage_tag_map ? stage_tag_map[note] : cat(note);
    }

function chain_stage_names(st: ChainState): string
    {
    local out = "";
    local i = 0; local n = |st$stages|;
    while ( i < n )
        {
        local nm = st$stages[i] in NSM::stage_name_map ?
                   NSM::stage_name_map[st$stages[i]] : cat(st$stages[i]);
        out = i == 0 ? nm : cat(out, "->", nm);
        i += 1;
        }
    return out;
    }

# 피해 host 목록 문자열 생성. last_host 를 앞에 두고 누적 victims 를 이어 붙이며
#   최대 chain_max_victims 개까지만 표시한다(초과분은 생략).
function victims_str(st: ChainState, last_host: addr): string
    {
    local out: vector of string = vector();
    local seen: set[addr] = set();

    # 마지막 단계의 host 를 우선 표시
    out[|out|] = cat(last_host);
    add seen[last_host];

    for ( v in st$victims )
        {
        if ( |out| >= chain_max_victims )
            break;
        if ( v in seen )
            next;
        add seen[v];
        out[|out|] = cat(v);
        }

    return join_string_vec(out, ",");
    }

# detection 의 evidence_ids 에 실릴 값들.
#   계약: 여기 실린 모든 id 는 evidence.log 에서 조회 가능해야 한다.
#   -> chain 자신의 요약 근거(chain_id)도 반드시 포함한다(기존 누락 지점).
function chain_evidence_ids(st: ChainState): vector of string
    {
    local out: vector of string = vector(st$chain_id);
    local seen: set[string] = set(st$chain_id);

    for ( i in st$eids )
        {
        if ( st$eids[i] == "" || st$eids[i] in seen )
            next;
        add seen[st$eids[i]];
        out[|out|] = st$eids[i];
        }
    return out;
    }

# 위 id 들의 실제 기록 건수를 합산한다(단계 수가 아니라 근거 행 수).
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

function emit_chain(st: ChainState, last_host: addr)
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
        $parent_id=join_string_vec(st$eids, ","),
        $detail=fmt("stages=%s len=%d last_host=%s", chain_names(st), len, last_host)]);

    NOTICE([$note=Correlated_KillChain,
            $src=st$attacker,
            $msg=fmt("Kill-chain(%d stages): %s | origin=%s last_host=%s",
                     len, chain_names(st), st$attacker, last_host),
            $sub=fmt("chain=%s chain_id=%s eids=%s",
                     chain_tids(st), st$chain_id, join_string_vec(st$eids, ",")),
            $identifier=cat(st$chain_id, "|len", len),
            $suppress_for=chain_max_expire,
            $attack=chain_tids_csv(st),
            $evidence_id=st$chain_id]);

    # chain 요약 근거를 적재한 뒤에 집계해야 count 에 포함된다.
    local all_eids = chain_evidence_ids(st);

    local first_note = st$stages[0];
    local last_note  = st$stages[len-1];
    local diag = fmt("%s.%s.%s", NSM::diagnosis_map[Correlated_KillChain],
                     stage_tag(first_note), stage_tag(last_note));

    NSM::write_detection([
        $ts               = network_time(),
        $detection_id     = st$chain_id,
        $diagnosis        = diag,
        $techniques       = chain_tids(st),
        $category         = "Correlated",
        $killchain_stages = chain_stage_names(st),
        $severity         = "Suspicious",
        $first_seen       = st$started_at,
        $last_seen        = network_time(),
        $attacker         = st$attacker,
        $attacker_subnet  = NSM::attacker_segment(st$attacker),
        $victims          = victims_str(st, last_host),
        $evidence_count   = chain_evidence_count(all_eids),
        $evidence_ids     = join_string_vec(all_eids, ",")]);
    }

function prime_forward(note: Notice::Type, chain: ChainState, src: addr, dsts: set[addr])
    {
    for ( idx in chain_rules )
        {
        local rule = chain_rules[idx];
        if ( rule$from != note )
            next;

        if ( rule$pivot == SRC_TO_SRC )
            {
            local c1 = copy(chain);
            c1$expire_at = network_time() + rule$window;
            primes[src, rule$to] = c1;
            }
        else   
            {
            for ( d in dsts )
                {
                local c2 = copy(chain);
                c2$expire_at = network_time() + rule$window;
                primes[d, rule$to] = c2;
                }
            }
        }
    }

event Notice::log_notice(rec: Notice::Info)
    {
    
    if ( rec$note == Correlated_KillChain )
        return;
    
    if ( rec?$dup_count )
        return;
    if ( ! rec?$src )
        return;

    local s   = rec$src;
    local m   = rec$note;
    local eid = rec?$evidence_id ? rec$evidence_id : "";

    local dsts: set[addr];
    if ( rec?$lm_targets )
        dsts = rec$lm_targets;

    local current: ChainState;
    local matched = F;

    if ( [s, m] in primes )
        {
        local st = primes[s, m];
        if ( network_time() <= st$expire_at )
            {
            # 확장
            local ext = copy(st);
            ext$stages[|ext$stages|] = m;
            if ( eid != "" )
                ext$eids[|ext$eids|] = eid;
            # 이 단계에서 관측된 피해 host 누적(확산 대상 등)
            for ( dv in dsts )
                add ext$victims[dv];
            emit_chain(ext, s);
            current = ext;
            matched = T;
            }
        delete primes[s, m];
        }

    if ( ! matched )
        {
        current = fresh_chain(m, s, eid);
        for ( dv0 in dsts )
            add current$victims[dv0];
        }

    prime_forward(m, current, s, dsts);
    }
