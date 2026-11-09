##! ============================================================================
##! [16] DGA Detection - DGA 도메인 탐지 (높은 NXDOMAIN 비율 + 고엔트로피)
##!
##! 탐지 원리
##!   - DGA 멀웨어는 다수 알고리즘 생성 도메인을 조회 -> 대부분 미등록(NXDOMAIN).
##!   - (src) 단위로 전체 응답수/NXDOMAIN수/NXDOMAIN qname 평균 엔트로피를 집계.
##!   - nx 임계 초과 + (nx/total) 비율 임계 초과 + 평균 엔트로피 임계 초과(3중 게이트).
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dns
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_dga = T &redef;

    ## [A] 역방향 DNS 조회(in-addr.arpa / ip6.arpa) 제외.
    ##  역방향 조회는 숫자·점이 많아 엔트로피가 높게 나오지만 DGA 와 무관하다.
    ##  T 이면 total/nx 집계와 evidence 모두에서 제외한다.
    const dga_exclude_reverse_dns = T &redef;

    ## [B] evidence 를 남길 최소 엔트로피. 이 값 미만의 NXDOMAIN 은
    ##  판정 집계(nx/ratio/평균엔트로피)에는 포함하되 evidence 는 남기지 않는다.
    ##  -> 저엔트로피 정상 NXDOMAIN 의 evidence 폭증을 억제(판정 정확도는 불변).
    ##  기본은 판정 임계(dga_entropy)와 동일.
    const dga_evidence_min_entropy = dga_entropy &redef;

    ## 내부/신뢰 도메인 예외(부분매칭). 여기 매칭되는 조회는 집계·evidence 모두 제외.
    ##   내부 DNS·k8s·검색도메인 때문에 정상 조회가 NXDOMAIN 으로 잡히는 것을 막는다.
    ##   07/09 와 동일한 domain_matches 방식: 상위 도메인 하나로 하위 전체 매칭.
    ##   예) "ahnlab.com" -> *.ahnlab.com,  "localdomain" -> *.localdomain
    ##   ※ 집계(total/nx)에서도 빠지므로 NXDOMAIN 비율 정확도가 올라간다.
    const dga_allowlist_domains: set[string] = {} &redef;
}

## 집계형 합성 증적 key. 탐지 시점(threshold_crossed)에서만 호출한다.
##   관측 시점에 재계산하면 time_bucket 이 어긋나 notice 와 evidence 의
##   key 가 달라진다(2026-09 수정 이전의 결함).
function dga_evidence_id(src: addr): string
    {
    return cat(src, "|dga|", time_bucket(dga_interval));
    }

# [재설계] 엔트로피를 별도 테이블 대신 SumStats AVERAGE reducer 로 집계한다.
#   기존 dga_ent_tbl 방식은 SumStats(nx/total)와 만료·타이밍이 어긋나
#   epoch_result 시점에 avg_ent=0 으로 잡혀 미발화했다. 세 값을 같은 SumStats
#   창에서 집계하면 동기화 문제가 원천 제거된다.

event zeek_init()
    {
    if ( !detect_dga )
        return;

    local r_total = SumStats::Reducer($stream="nsm.dga.total",
                                      $apply=set(SumStats::SUM));
    # SUM: 판정용 NXDOMAIN 수 / SAMPLE: 근거로 남길 질의 표본
    #   (epoch_result 로 판정하므로 threshold 모호성 문제는 발생하지 않는다)
    local r_nx    = SumStats::Reducer($stream="nsm.dga.nx",
                                      $apply=set(SumStats::SUM, SumStats::SAMPLE),
                                      $num_samples=lm_num_samples);
    local r_ent   = SumStats::Reducer($stream="nsm.dga.ent",
                                      $apply=set(SumStats::AVERAGE));
    # [수정] reducer 가 2개(total, nx)일 때 $threshold 는 어느 스트림에 걸리는지
    #   모호해 threshold_crossed 가 호출되지 않는다(01/02 는 reducer 1개라 정상).
    #   -> epoch 종료 시 전체를 평가하는 $epoch_result 로 판정한다.
    #      DGA 는 원래 dga_interval(10min) 창 집계라 이 방식이 의미상으로도 맞다.
    SumStats::create([
        $name      = "nsm-detect-dga",
        $epoch     = dga_interval,
        $reducers  = set(r_total, r_nx, r_ent),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            # nx/total 스트림이 이 key 에 모두 있을 때만 평가
            if ( "nsm.dga.nx" !in result )
                return;
            local nx    = result["nsm.dga.nx"]$sum;
            if ( nx < dga_nxdomain_threshold )      # ① NXDOMAIN 수
                return;

            local total = ("nsm.dga.total" in result) ? result["nsm.dga.total"]$sum : nx;
            local ratio = (total > 0) ? nx / total : 0.0;
            if ( ratio < dga_ratio_threshold )      # ② 비율
                return;

            # 엔트로피 평균도 같은 SumStats 창에서 읽는다(별도 테이블 없음).
            local avg_ent = ("nsm.dga.ent" in result) ?
                            result["nsm.dga.ent"]$average : 0.0;
            if ( avg_ent < dga_entropy )            # ③ 평균 엔트로피
                return;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = dga_evidence_id(key$host);

            # 근거: 이 창에서 표본으로 잡힌 고엔트로피 NXDOMAIN 질의들.
            #   NOTICE 보다 먼저 적재해야 evidence_count 가 정확히 잡힌다.
            local rnx = result["nsm.dga.nx"];
            if ( rnx?$samples )
                for ( si in rnx$samples )
                    {
                    if ( ! rnx$samples[si]?$str )
                        next;   # 저엔트로피 질의는 $str 없이 관측 -> 근거 제외

                    local parts = split_string(rnx$samples[si]$str, /\|/);
                    if ( |parts| < 3 )
                        next;
                    if ( ! NSM::evidence_is_new(eid, parts[0]) )
                        next;

                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=DGA_Domain,
                        $technique="T1568.002",
                        $src=key$host,
                        $operation="dga_nxdomain",
                        $uid=parts[2],
                        $detail=fmt("query=%s entropy=%s rcode=NXDOMAIN",
                                    parts[0], parts[1])]);
                    }

            NOTICE([$note=DGA_Domain,
                    $src=key$host,
                    $msg=fmt("DGA activity suspected: %s (NXDOMAIN %.0f/%.0f = %.0f%%, avg entropy %.2f) in %s",
                             key$host, nx, total, ratio*100, avg_ent, dga_interval),
                    $sub=fmt("nxdomain=%.0f total=%.0f ratio=%.2f avg_entropy=%.2f",
                             nx, total, ratio, avg_ent),
                    $identifier=cat(key$host, "dga"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

## DNS 응답에서 rcode 확인 (is_orig=F 가 응답 방향)
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( !detect_dga )
        return;

    if ( is_orig )
        return;

    # [A] 역방향 DNS(in-addr.arpa / ip6.arpa)는 DGA 무관 -> 집계·evidence 모두 제외.
    if ( dga_exclude_reverse_dns && c?$dns && c$dns?$query )
        {
        local q = to_lower(c$dns$query);
        local ql = |q|;
        if ( ql >= 13 && q[ql - 13 :] == ".in-addr.arpa" )
            return;
        if ( ql >= 9 && q[ql - 9 :] == ".ip6.arpa" )
            return;
        }

    # 내부/신뢰 도메인 예외: 집계 전에 걸러 total/nx 비율에서 제외한다.
    if ( c?$dns && c$dns?$query &&
         NSM::domain_matches(c$dns$query, dga_allowlist_domains) )
        return;

    SumStats::observe("nsm.dga.total", [$host=c$id$orig_h], [$num=1]);

    if ( msg$rcode == 3 )   # NXDOMAIN
        {
        local qs = ( c?$dns && c$dns?$query ) ? c$dns$query : "";
        if ( qs == "" )
            {
            SumStats::observe("nsm.dga.nx", [$host=c$id$orig_h], [$num=1]);
            return;
            }

        local ent = find_entropy(qs)$entropy;

        # 관측만 한다. 증적은 탐지 시점(epoch_result)에서 표본으로 적재한다.
        #   [B] 저엔트로피 NXDOMAIN 은 집계엔 반영하되 $str 을 붙이지 않아
        #       근거 표본에서 제외한다(정상 NXDOMAIN 의 evidence 폭증 억제).
        if ( ent >= dga_evidence_min_entropy )
            SumStats::observe("nsm.dga.nx", [$host=c$id$orig_h],
                              [$num=1, $str=fmt("%s|%.2f|%s", qs, ent, c$uid)]);
        else
            SumStats::observe("nsm.dga.nx", [$host=c$id$orig_h], [$num=1]);

        # 엔트로피 평균은 별도 스트림(AVERAGE)으로 같은 창에서 집계한다.
        SumStats::observe("nsm.dga.ent", [$host=c$id$orig_h], [$dbl=ent]);
        }
    }
