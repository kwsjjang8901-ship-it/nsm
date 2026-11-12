##! ============================================================================
##! [17] Kerberos 패스워드 스프레이 / 무차별 대입 — T1110.003 / T1110.001 (2026-11 신규)
##!
##! 탐지 원리 (KDC 로 향한 AS 교환)
##!   - AS-REQ 의 계정(cname@realm)을 연결에 보관했다가 KRB-ERROR 가 인증 실패 코드면 1회 집계.
##!       KDC_ERR_PREAUTH_FAILED(24)      비밀번호 틀림
##!       KDC_ERR_C_PRINCIPAL_UNKNOWN(6)  없는 계정 (계정 목록 기반 스프레이)
##!       KDC_ERR_CLIENT_REVOKED(18)      잠김·비활성
##!       KDC_ERR_KEY_EXPIRED(23)         비밀번호 만료(비밀번호는 맞음)
##!     KDC_ERR_PREAUTH_REQUIRED(25) 는 정상 로그온 첫 단계라 세지 않는다.
##!   - 스프레이  : 출발지별 krb_spray_interval 안의 실패 "고유 계정" ≥ krb_spray_user_threshold
##!   - 무차별 대입: (출발지, 계정)별 비밀번호 실패(24·18) 횟수 ≥ krb_bruteforce_threshold
##!
##! AD 환경의 도메인 인증은 NTLM(05)보다 Kerberos 가 주류라, 05 와 함께 운영한다.
##!
##! 상관 계약: notice $src = 시도 출발지 (자격증명 접근 단계). KDC·계정은 근거(evidence)에 남긴다.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/krb
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const krb_spray_interval       = 10min &redef;  # 집계 윈도우(스프레이·무차별 대입 공용)
    const krb_spray_user_threshold = 10    &redef;  # 출발지별 인증 실패 고유 계정 수
    const krb_bruteforce_threshold = 20    &redef;  # (출발지, 계정)별 비밀번호 실패 횟수

    ## 내부(local_nets) KDC 로 향한 인증만 집계한다.
    const krb_spray_local_kdc_only = T &redef;

    ## 예외 출발지(계정 점검 도구, 인증 게이트웨이 등).
    const krb_spray_allowlist: set[subnet] = {} &redef;

    ## 스프레이로 세는 KRB-ERROR 코드.
    const krb_failure_codes: table[count] of string = {
        [6]  = "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        [18] = "KDC_ERR_CLIENT_REVOKED",
        [23] = "KDC_ERR_KEY_EXPIRED",
        [24] = "KDC_ERR_PREAUTH_FAILED",
    } &redef;

    ## 무차별 대입으로 세는 KRB-ERROR 코드(같은 계정의 비밀번호 실패·그 결과 잠김).
    const krb_bruteforce_codes: set[count] = { 18, 24 } &redef;
}

redef record connection += {
    ## 이 연결의 마지막 AS-REQ 계정(소문자 user@realm). 결과를 받으면 지운다.
    nsm_krb_as_client: string &optional;
};

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |krb_spray_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:krb_spray_allowlist",
            [$scope=set("Kerberos_Spray", "Kerberos_Bruteforce"), $src=krb_spray_allowlist]);
    }

function krb_spray_target(c: connection): bool
    {
    if ( krb_spray_local_kdc_only && ! Site::is_local_addr(c$id$resp_h) )
        return F;
    return T;
    }

function krb_principal(name: string, realm: string): string
    {
    return realm == "" ? to_lower(name) : cat(to_lower(name), "@", to_lower(realm));
    }

# 근거 표본 문자열 "계정|KDC|결과" -> evidence
function krb_spray_write_samples(eid: string, note: Notice::Type, technique: string, src: addr,
                                 samples: vector of SumStats::Observation, detail: string)
    {
    for ( i in samples )
        {
        if ( ! samples[i]?$str )
            next;
        local parts = split_string(samples[i]$str, /\|/);
        if ( |parts| < 3 || ! NSM::evidence_is_new(eid, parts[0]) )
            next;
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=note,
            $technique=technique,
            $account=parts[0],
            $src=src,
            $dst=to_addr(parts[1]),
            $uid=( |parts| > 3 ) ? parts[3] : "",
            $operation="kerberos_as_failure",
            $detail=fmt("result=%s %s", parts[2], detail)]);
        }
    }

event zeek_init()
    {
    # 스프레이: 고유 계정(str = 계정) / 근거 표본(str = "계정|KDC|결과")
    local r_users  = SumStats::Reducer($stream="nsm.krb_spray", $apply=set(SumStats::UNIQUE));
    local r_sample = SumStats::Reducer($stream="nsm.krb_spray.sample", $apply=set(SumStats::SAMPLE),
                                       $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-krb-spray",
        $epoch     = krb_spray_interval,
        $reducers  = set(r_users, r_sample),
        $threshold = krb_spray_user_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.krb_spray"]$unique + 0.0;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n   = result["nsm.krb_spray"]$unique;
            local num = result["nsm.krb_spray"]$num;
            local eid = cat(key$host, "|krb-spray|", time_bucket(krb_spray_interval));

            # 근거를 NOTICE 보다 먼저 적재한다(detection 의 evidence_count 산출 시점).
            if ( result["nsm.krb_spray.sample"]?$samples )
                krb_spray_write_samples(eid, Kerberos_Spray, "T1110.003", key$host,
                                        result["nsm.krb_spray.sample"]$samples,
                                        fmt("unique_failed_users=%d failures=%d window=%s",
                                            n, num, krb_spray_interval));

            NOTICE([$note=Kerberos_Spray,
                    $src=key$host,
                    $msg=fmt("Possible Kerberos password spray: %s failed pre-authentication for %d unique accounts in %s",
                             key$host, n, krb_spray_interval),
                    $sub=fmt("unique_failed_users=%d failures=%d", n, num),
                    $identifier=cat(key$host, "krb-spray"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);

    # 무차별 대입: key = (출발지, 계정), 실패 횟수 / 근거 표본 1개
    local r_fail = SumStats::Reducer($stream="nsm.krb_brute", $apply=set(SumStats::SUM));
    local r_one  = SumStats::Reducer($stream="nsm.krb_brute.sample", $apply=set(SumStats::SAMPLE),
                                     $num_samples=1);
    SumStats::create([
        $name      = "nsm-detect-krb-bruteforce",
        $epoch     = krb_spray_interval,
        $reducers  = set(r_fail, r_one),
        $threshold = krb_bruteforce_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.krb_brute"]$sum;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n   = double_to_count(result["nsm.krb_brute"]$sum);
            local eid = cat(key$host, "|krb-brute|", key$str, "|", time_bucket(krb_spray_interval));

            if ( result["nsm.krb_brute.sample"]?$samples )
                krb_spray_write_samples(eid, Kerberos_Bruteforce, "T1110.001", key$host,
                                        result["nsm.krb_brute.sample"]$samples,
                                        fmt("failures=%d window=%s", n, krb_spray_interval));

            NOTICE([$note=Kerberos_Bruteforce,
                    $src=key$host,
                    $msg=fmt("Possible Kerberos brute force: %s failed pre-authentication %d times for %s in %s",
                             key$host, n, key$str, krb_spray_interval),
                    $sub=fmt("account=%s failures=%d", key$str, n),
                    $identifier=cat(key$host, key$str, "krb-brute"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( ! msg?$client_name || msg$client_name == "" )
        return;
    if ( ! krb_spray_target(c) )
        return;

    c$nsm_krb_as_client = krb_principal(msg$client_name, msg?$service_realm ? msg$service_realm : "");
    }

event krb_as_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( c?$nsm_krb_as_client )
        delete c$nsm_krb_as_client;   # 성공
    }

event krb_error(c: connection, msg: KRB::Error_Msg)
    {
    if ( msg$error_code !in krb_failure_codes )
        return;   # PREAUTH_REQUIRED(25) 등 정상 흐름·TGS 오류는 제외

    local acct = "";
    if ( c?$nsm_krb_as_client )
        {
        acct = c$nsm_krb_as_client;
        delete c$nsm_krb_as_client;
        }
    else if ( msg?$client_name && krb_spray_target(c) )
        # 요청을 놓친 경우(비대칭 경로 등) 오류의 cname 을 쓴다
        acct = krb_principal(msg$client_name, msg?$client_realm ? msg$client_realm : "");

    if ( acct == "" )
        return;

    local src = c$id$orig_h;
    local result = krb_failure_codes[msg$error_code];
    local sample = cat(acct, "|", c$id$resp_h, "|", result, "|", c$uid);

    # 예외(예외 파일 + 기존 krb_spray_allowlist). 스프레이·무차별 대입을 따로 판정한다(범위가 다를 수 있음)
    local brute = msg$error_code in krb_bruteforce_codes;
    local skip_spray = NSM::exception_drop_agg(Kerberos_Spray, c);
    local skip_brute = brute && NSM::exception_drop_agg(Kerberos_Bruteforce, c);

    # 표본을 먼저 넣는다(임계 판정이 다음 observe 에서 즉시 일어날 수 있다).
    if ( ! skip_spray )
        {
        SumStats::observe("nsm.krb_spray.sample", [$host=src], [$str=sample]);
        SumStats::observe("nsm.krb_spray", [$host=src], [$str=acct]);
        }

    if ( brute && ! skip_brute )
        {
        SumStats::observe("nsm.krb_brute.sample", [$host=src, $str=acct], [$str=sample]);
        SumStats::observe("nsm.krb_brute", [$host=src, $str=acct], [$num=1]);
        }
    }
