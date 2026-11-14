##! ============================================================================
##! [18] Kerberoasting / AS-REP Roasting — T1558.003 / T1558.004 (2026-11 신규)
##!
##! Kerberoasting
##!   - 서비스 티켓(TGS-REP)의 티켓 암호화가 약한 암호(RC4 등)면, 그 서비스 계정 비밀번호를
##!     오프라인으로 깰 수 있다. 공격 도구는 RC4 를 요청해 여러 SPN 의 티켓을 한꺼번에 받는다.
##!   - 출발지별 krb_roast_interval 안에 약한 암호 서비스 티켓을 받은 "고유 SPN" ≥
##!     krb_roast_service_threshold 이면 탐지. AES 강제 환경에서는 RC4 티켓 자체가 드물다.
##!
##! AS-REP Roasting
##!   - 사전인증을 요구하지 않는 계정은 사전인증 없는 AS-REQ 에도 AS-REP 를 돌려주고,
##!     AS-REP 의 enc-part(사용자 키로 암호화)를 오프라인으로 깰 수 있다.
##!   - AS-REQ 에 PA-ENC-TIMESTAMP(2)·PA-FX-FAST(136)가 없는데 AS-REP 가 오고,
##!     enc-part 가 약한 암호면 탐지(계정마다 1건).
##!   - 정상 Windows 로그온은 사전인증 없는 첫 AS-REQ 에 PREAUTH_REQUIRED(25) 오류를 받으므로 해당 없음.
##!   - PKINIT(스마트카드) 사전인증은 Zeek 의 pa_data 벡터에 나타나지 않는다. 그래서 기본값은
##!     enc-part 가 약한 암호일 때만 탐지한다(asrep_require_weak_cipher).
##!
##! 상관 계약: notice $src = 티켓 요청 출발지 (자격증명 접근 단계), $dst = KDC.
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
    const krb_roast_interval          = 10min &redef;  # 집계 윈도우
    const krb_roast_service_threshold = 5     &redef;  # 출발지별 약한 암호 서비스 티켓의 고유 SPN 수

    ## 내부(local_nets) KDC 의 응답만 본다.
    const krb_roast_local_kdc_only = T &redef;

    ## 예외 출발지(레거시 RC4 서비스를 대량으로 쓰는 서버 등).
    const krb_roast_allowlist: set[subnet] = {} &redef;

    ## 오프라인 크래킹이 쉬운 암호(Kerberos etype).
    const krb_weak_ciphers: table[count] of string = {
        [1]  = "des-cbc-crc",
        [3]  = "des-cbc-md5",
        [23] = "rc4-hmac",
        [24] = "rc4-hmac-exp",
    } &redef;

    ## Kerberoasting 집계에서 제외할 서비스(TGT 갱신·비밀번호 변경 등 사용자 계정이 아닌 SPN).
    const krb_roast_excluded_services = /^(krbtgt|kadmin)\// &redef;

    ## AS-REP Roasting: T 면 enc-part 가 약한 암호일 때만 탐지(PKINIT 오탐 방지).
    const asrep_require_weak_cipher = T &redef;
}

redef record connection += {
    ## 이 연결의 마지막 AS-REQ 가 사전인증 없이 왔으면 그 계정(소문자 user@realm).
    nsm_krb_asreq_nopreauth: string &optional;
};

## 사전인증으로 인정하는 PA-DATA 유형: PA-ENC-TIMESTAMP(2), PA-FX-FAST(136, 사전인증이 FAST 안에 암호화됨)
const krb_preauth_padata: set[count] = { 2, 136 };

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |krb_roast_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:krb_roast_allowlist",
            [$scope=set("Kerberoasting", "ASREP_Roasting"), $src=krb_roast_allowlist]);
    }

function krb_roast_target(c: connection, note: Notice::Type): bool
    {
    if ( krb_roast_local_kdc_only && ! Site::is_local_addr(c$id$resp_h) )
        return F;
    # 예외(예외 파일 + 기존 krb_roast_allowlist). 집계 전 판정
    if ( NSM::exception_drop_agg(note, c) )
        return F;
    return T;
    }

event zeek_init()
    {
    # 고유 SPN(str = SPN) / 근거 표본(str = "SPN|KDC|암호|요청계정")
    local r_spn    = SumStats::Reducer($stream="nsm.krb_roast", $apply=set(SumStats::UNIQUE));
    local r_sample = SumStats::Reducer($stream="nsm.krb_roast.sample", $apply=set(SumStats::SAMPLE),
                                       $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-kerberoasting",
        $epoch     = krb_roast_interval,
        $reducers  = set(r_spn, r_sample),
        $threshold = krb_roast_service_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.krb_roast"]$unique + 0.0;
            },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n   = result["nsm.krb_roast"]$unique;
            local eid = cat(key$host, "|kerberoast|", time_bucket(krb_roast_interval));
            local kdc: addr = 0.0.0.0;

            # 근거를 NOTICE 보다 먼저 적재한다.
            local res = result["nsm.krb_roast.sample"];
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;
                    local p = split_string(res$samples[i]$str, /\|/);
                    if ( |p| < 4 )
                        next;
                    kdc = to_addr(p[1]);
                    if ( ! NSM::evidence_is_new(eid, p[0]) )
                        next;
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=Kerberoasting,
                        $technique="T1558.003",
                        $account=p[3],
                        $src=key$host,
                        $dst=kdc,
                        $uid=( |p| > 4 ) ? p[4] : "",
                        $operation="kerberos_tgs_weak_cipher",
                        $detail=fmt("service=%s cipher=%s unique_services=%d window=%s",
                                    p[0], p[2], n, krb_roast_interval)]);
                    }

            NOTICE([$note=Kerberoasting,
                    $src=key$host,
                    $dst=kdc,
                    $msg=fmt("Possible Kerberoasting: %s received weak-cipher (RC4/DES) service tickets for %d unique SPNs in %s",
                             key$host, n, krb_roast_interval),
                    $sub=fmt("unique_services=%d", n),
                    $identifier=cat(key$host, "kerberoast"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( msg$ticket$cipher !in krb_weak_ciphers )
        return;
    if ( krb_roast_excluded_services in to_lower(msg$ticket$service_name) )
        return;
    if ( ! krb_roast_target(c, Kerberoasting) )
        return;

    local spn = to_lower(msg$ticket$service_name);
    local who = cat(to_lower(msg$client_name), msg?$client_realm ? cat("@", to_lower(msg$client_realm)) : "");
    local src = c$id$orig_h;

    SumStats::observe("nsm.krb_roast.sample", [$host=src],
                      [$str=cat(spn, "|", c$id$resp_h, "|", krb_weak_ciphers[msg$ticket$cipher], "|", who, "|", c$uid)]);
    SumStats::observe("nsm.krb_roast", [$host=src], [$str=spn]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( c?$nsm_krb_asreq_nopreauth )
        delete c$nsm_krb_asreq_nopreauth;

    if ( ! msg?$client_name || msg$client_name == "" )
        return;

    if ( msg?$pa_data )
        for ( i in msg$pa_data )
            if ( msg$pa_data[i]$data_type in krb_preauth_padata )
                return;

    c$nsm_krb_asreq_nopreauth = msg?$service_realm
        ? cat(to_lower(msg$client_name), "@", to_lower(msg$service_realm))
        : to_lower(msg$client_name);
    }

event krb_as_response(c: connection, msg: KRB::KDC_Response)
    {
    if ( ! c?$nsm_krb_asreq_nopreauth )
        return;

    local acct = c$nsm_krb_asreq_nopreauth;
    delete c$nsm_krb_asreq_nopreauth;

    local weak = msg$enc_part$cipher in krb_weak_ciphers;
    if ( asrep_require_weak_cipher && ! weak )
        return;
    if ( ! krb_roast_target(c, ASREP_Roasting) )
        return;

    local cipher = weak ? krb_weak_ciphers[msg$enc_part$cipher] : cat(msg$enc_part$cipher);
    local eid = cat(c$id$orig_h, "|asrep|", acct, "|", c$uid);

    if ( NSM::evidence_is_new(eid, acct) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=ASREP_Roasting,
            $technique="T1558.004",
            $account=acct,
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="kerberos_as_rep_without_preauth",
            $uid=c$uid,
            $detail=fmt("enc_part_cipher=%s", cipher)]);

    NOTICE([$note=ASREP_Roasting,
            $conn=c,
            $msg=fmt("Possible AS-REP Roasting: %s got an AS-REP for %s without pre-authentication (enc-part %s)",
                     c$id$orig_h, acct, cipher),
            $sub=acct,
            $identifier=cat(c$id$orig_h, acct, "asrep"),
            $suppress_for=1hr,
            $evidence_id=eid]);
    }
