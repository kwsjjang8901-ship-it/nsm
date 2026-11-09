##! ============================================================================
##! [4] Credential Abuse (NTLM Spray) - 패스워드 스프레이
##!
##! 탐지 원리
##!   - 스프레이 = "소수의(보통 1개) 비밀번호 x 다수 계정" 시도.
##!   - 단일 src 가 윈도우 내 시도한 "고유 사용자명" 수를 SumStats UNIQUE 로 집계.
##!   - ntlm_authenticate 의 user_name(+domain) 을 정규화하여 관찰.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/ntlm
@load ./main
@load ./evidence_log

module NSM;

## 집계형 합성 증적 key (탐지 시점에서만 호출한다)
function ntlm_evidence_id(src: addr): string
    {
    return cat(src, "|ntlm-spray|", time_bucket(ntlm_interval));
    }

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.ntlm_spray",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-ntlm-spray",
        $epoch     = ntlm_interval,
        $reducers  = set(r),
        $threshold = ntlm_user_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.ntlm_spray"]$unique + 0.0;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res = result["nsm.ntlm_spray"];
            local n   = res$unique;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = ntlm_evidence_id(key$host);

            # 근거: 이 창에서 시도된 계정 표본. NOTICE 보다 먼저 적재해야
            #   detection 의 evidence_count 가 정확히 잡힌다.
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;

                    local acct = res$samples[i]$str;
                    if ( ! NSM::evidence_is_new(eid, acct) )
                        next;

                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=NTLM_Spray,
                        $technique="T1110.003",
                        $account=acct,
                        $src=key$host,
                        $operation="ntlm_authenticate",
                        $detail=fmt("unique_users=%d observed=%d window=%s",
                                    n, res$num, ntlm_interval)]);
                    }

            NOTICE([$note=NTLM_Spray,
                    $src=key$host,
                    $msg=fmt("Possible NTLM password spray: %s attempted %d unique accounts in %s",
                             key$host, n, ntlm_interval),
                    $sub=fmt("unique_users=%d", n),
                    $identifier=cat(key$host, "ntlm-spray"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! request?$user_name )
        return;

    # 도메인\사용자 형태로 정규화
    local user = request$user_name;
    if ( request?$domain_name && request$domain_name != "" )
        user = cat(request$domain_name, "\\", request$user_name);

    SumStats::observe("nsm.ntlm_spray", [$host=c$id$orig_h], [$str=user]);
    }
