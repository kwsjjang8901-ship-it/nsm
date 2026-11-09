##! ============================================================================
##! [14] Exfiltration (Alt Proto) - DNS 터널 : 누적 인코딩 바이트 기준
##!
##! 탐지 원리
##!   - DNS 터널 유출은 qname 에 데이터를 인코딩하므로, (src,부모도메인) 단위로
##!     qname 길이(=인코딩 바이트)를 SUM 누적해 임계(기본 1MB) 초과 시 탐지.
##!   - [9] 가 "구조/형태" 라면 [14] 는 "누적 전송량" 관점(상호 보완).
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dns
@load ./main
@load ./evidence_log

module NSM;

## 집계형 합성 증적 key (탐지 시점에서만 호출한다)
function dnsexfil_evidence_id(src: addr, parent: string): string
    {
    return cat(src, "|dns-exfil|", parent, "|", time_bucket(dnsexfil_interval));
    }

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.dns_exfil",
                                $apply=set(SumStats::SUM, SumStats::SAMPLE),
                                $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-dns-exfil",
        $epoch     = dnsexfil_interval,
        $reducers  = set(r),
        $threshold = dnsexfil_bytes + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.dns_exfil"]$sum;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res   = result["nsm.dns_exfil"];
            local total = res$sum;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = dnsexfil_evidence_id(key$host, key$str);

            # 근거: 인코딩 페이로드로 의심되는 질의 표본. NOTICE 보다 먼저 적재.
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
                        $note=Exfil_DNS,
                        $technique="T1048.003",
                        $src=key$host,
                        $operation="dns_query",
                        $detail=fmt("query=%s parent=%s encoded_bytes=%.0f window=%s",
                                    q, key$str, total, dnsexfil_interval)]);
                    }

            NOTICE([$note=Exfil_DNS,
                    $src=key$host,
                    $msg=fmt("DNS-based exfiltration suspected: %s -> %s (~%.1f KB encoded in %s)",
                             key$host, key$str, total/1024.0, dnsexfil_interval),
                    $sub=fmt("parent_domain=%s encoded_bytes=%.0f", key$str, total),
                    $identifier=cat(key$host, key$str, "dns-exfil"),
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
    # 관측만 한다. 증적은 탐지 시점(threshold_crossed)에서 표본으로 적재한다.
    SumStats::observe("nsm.dns_exfil",
                      [$host=c$id$orig_h, $str=parent_domain(query)],
                      [$num=|query|, $str=query]);
    }
