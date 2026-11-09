##! ============================================================================
##! [9] DNS Tunneling - DNS 터널링(구조 기반)
##!
##! 탐지 원리
##!   - 터널링 = 한 부모도메인 아래 다수의 고유·긴·고엔트로피 서브도메인 인코딩.
##!   - (src,부모도메인) 별 고유 서브도메인 수를 SumStats UNIQUE 로 집계.
##!   - 긴 라벨/고엔트로피/TXT·NULL 레코드를 가중 신호로 사용해 오탐 억제.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dns
@load ./main
@load ./evidence_log

module NSM;

## 집계형 합성 증적 key (탐지 시점에서만 호출한다)
function dnstun_evidence_id(src: addr, parent: string): string
    {
    return cat(src, "|dns-tunnel|", parent, "|", time_bucket(dnstun_interval));
    }

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.dns_tunnel",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-dns-tunnel",
        $epoch     = dnstun_interval,
        $reducers  = set(r),
        $threshold = dnstun_unique_sub + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.dns_tunnel"]$unique + 0.0;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res = result["nsm.dns_tunnel"];
            local n   = res$unique;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = dnstun_evidence_id(key$host, key$str);

            # 근거: 터널 의심 질의 표본. NOTICE 보다 먼저 적재한다.
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;

                    local q = res$samples[i]$str;
                    if ( ! NSM::evidence_is_new(eid, q) )
                        next;

                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=DNS_Tunneling,
                        $technique="T1071.004",
                        $src=key$host,
                        $operation="dns_query",
                        $detail=fmt("query=%s parent=%s unique_sub=%d window=%s",
                                    q, key$str, n, dnstun_interval)]);
                    }

            NOTICE([$note=DNS_Tunneling,
                    $src=key$host,
                    $msg=fmt("DNS tunneling suspected: %s -> %s (%d unique subdomains in %s)",
                             key$host, key$str, n, dnstun_interval),
                    $sub=fmt("parent_domain=%s unique_subdomains=%d", key$str, n),
                    $identifier=cat(key$host, key$str),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    if ( query == "" )
        return;

    local parent = parent_domain(query);
    local sub = ( |query| > |parent| ) ? sub_bytes(query, 1, |query| - |parent| - 1) : "";

    local long_label   = |sub| >= dnstun_label_len;
    local high_entropy = (sub != "") && (find_entropy(sub)$entropy >= dnstun_entropy);
    local tunnel_rr    = (qtype == 16 || qtype == 10);  # 16=TXT, 10=NULL

    if ( long_label || high_entropy || tunnel_rr )
        {
        SumStats::observe("nsm.dns_tunnel",
                          [$host=c$id$orig_h, $str=parent],
                          [$str=query]);
        }
    }
