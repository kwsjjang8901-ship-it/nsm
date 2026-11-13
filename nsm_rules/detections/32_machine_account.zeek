##! ============================================================================
##! [32] 남의 머신 계정 사용(NTLM 릴레이·해시 전달) — T1557.001 (2026-11 신규)
##!
##! Machine_Account_Misuse
##!   - 머신 계정(host$)은 그 PC 자신만 쓴다. 한 IP 가 머신 계정 여러 개로 인증하면 NTLM 릴레이
##!     (ntlmrelayx: 강제 인증·포이즈닝으로 받은 다른 PC 의 인증을 대상 서버로 전달)나 탈취한 머신 계정
##!     해시 사용이다. 같은 (출발지)에서 machine_acct_epoch(10분) 안에 서로 다른 머신 계정이
##!     machine_acct_threshold(2)개 이상 인증하면 탐지한다.
##!   - 관측: NTLM AUTHENTICATE 의 사용자(끝이 $), Kerberos AS-REQ 의 클라이언트(끝이 $).
##!     계정은 "도메인 첫 레이블\계정"(소문자)으로 맞춰 NTLM(CORP)과 Kerberos(CORP.EXAMPLE)를 같은 것으로 센다.
##!   - 자산 식별(SPEC 4.6)이 같은 조건의 IP 를 식별 키에서 빼던 것을 탐지로 올렸다.
##!   - 정상 예외: NAT·프록시 뒤 여러 PC, 장애 조치 클러스터 노드(노드 계정 + 클러스터 이름 계정) →
##!     예외 엔진(출발지 축)으로 뺀다.
##!
##! 집계형: 출발지 키, 창 종료 시 판정. 상관 계약: notice $src = 계정을 쓴 host, $dst = 표본 인증 대상(자격증명 묶음).
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/ntlm
@load base/protocols/krb
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_machine_account_misuse = T &redef;
    const machine_acct_epoch = 10min &redef;
    ## 같은 출발지가 창 안에 쓴 서로 다른 머신 계정 수
    const machine_acct_threshold = 2 &redef;
    const machine_acct_num_samples = 10 &redef;
}

# "corp.example" -> "corp", "CORP" -> "corp"
function machine_acct_key(domain: string, user: string): string
    {
    local d = to_lower(split_string1(domain, /\./)[0]);
    local u = to_lower(user);
    return d == "" ? u : cat(d, "\\", u);
    }

function machine_acct_observe(c: connection, account: string, via: string)
    {
    if ( ! detect_machine_account_misuse )
        return;
    if ( NSM::exception_drop_agg(Machine_Account_Misuse, c) )
        return;
    local key: SumStats::Key = [$host=c$id$orig_h];
    SumStats::observe("nsm.machine_acct", key, [$str=account]);
    SumStats::observe("nsm.machine_acct.sample", key, [$str=cat(account, "|", c$uid, "|", c$id$resp_h, "|", via)]);
    }

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="nsm.machine_acct", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="nsm.machine_acct.sample", $apply=set(SumStats::SAMPLE), $num_samples=machine_acct_num_samples);
    SumStats::create([
        $name="nsm-detect-machine-account-misuse", $epoch=machine_acct_epoch, $reducers=set(r1, r2),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.machine_acct" !in result )
                return;
            local n = result["nsm.machine_acct"]$unique;
            if ( n < machine_acct_threshold )
                return;
            local src = key$host;
            local eid = cat(src, "|machine-acct|", time_bucket(machine_acct_epoch));
            local first_dst: addr = 0.0.0.0;
            local accts: vector of string = vector();
            if ( "nsm.machine_acct.sample" in result && result["nsm.machine_acct.sample"]?$samples )
                for ( i in result["nsm.machine_acct.sample"]$samples )
                    {
                    local o = result["nsm.machine_acct.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);      # "계정|uid|대상|경로"
                    if ( |p| < 4 )
                        next;
                    if ( first_dst == 0.0.0.0 )
                        first_dst = to_addr(p[2]);
                    if ( ! NSM::evidence_is_new(eid, p[0]) )
                        next;
                    accts += p[0];
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=Machine_Account_Misuse,
                        $technique="T1557.001",
                        $account=p[0],
                        $src=src,
                        $dst=to_addr(p[2]),
                        $uid=p[1],
                        $operation=fmt("%s_machine_account_auth", p[3]),
                        $detail=fmt("unique_machine_accounts=%d window=%s via=%s", n, machine_acct_epoch, p[3])]);
                    }
            NOTICE([$note=Machine_Account_Misuse,
                    $src=src,
                    $dst=first_dst,
                    $msg=fmt("%s authenticated with %d different machine accounts in %s (NTLM relay / pass-the-hash?)",
                             src, n, machine_acct_epoch),
                    $sub=fmt("machine_accounts=%d sample=%s", n, join_string_vec(accts, ",")),
                    $identifier=cat(src, "machine-acct", time_bucket(machine_acct_epoch)),
                    $suppress_for=machine_acct_epoch,
                    $evidence_id=eid]);
            }
    ]);
    }

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! request?$user_name || request$user_name == "" || request$user_name[-1] != "$" )
        return;
    machine_acct_observe(c, machine_acct_key(request?$domain_name ? request$domain_name : "", request$user_name), "ntlm");
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( ! msg?$client_name )
        return;
    local name = split_string1(msg$client_name, /@/)[0];
    if ( name == "" || /\// in name || name[-1] != "$" )
        return;
    machine_acct_observe(c, machine_acct_key(msg?$service_realm ? msg$service_realm : "", name), "kerberos");
    }
