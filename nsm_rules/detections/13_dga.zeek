##! ============================================================================
##! [13] DGA Detection - DGA 도메인 탐지 (높은 NXDOMAIN 비율 + 무작위형 등록 라벨)
##!
##! 탐지 원리
##!   - DGA 멀웨어는 다수 알고리즘 생성 도메인을 조회 -> 대부분 미등록(NXDOMAIN).
##!   - (src) 단위로 dga_interval 창에서 아래 3조건 AND (epoch 종료 시 판정)
##!       (1) NXDOMAIN 수                     >= dga_nxdomain_threshold
##!       (2) NXDOMAIN / 전체 응답            >= dga_ratio_threshold
##!       (3) NXDOMAIN 중 무작위형 라벨 비율  >= dga_like_ratio
##!
##! 무작위형(DGA형) 라벨 판정 (2026-11 개정)
##!   - 이전에는 qname 전체의 평균 Shannon 엔트로피 >= 4.0 이었다. 길이 n 인 문자열의
##!     엔트로피 최댓값은 log2(n) 이라, 일반 DGA 라벨(8~16자)은 4.0 에 거의 도달하지 못해
##!     미탐이 컸다(검토 H4). 또 qname 전체를 보면 CDN 서브도메인 같은 정상 무작위 문자열도 섞였다.
##!   - 이제 "등록 라벨"(registered_label: www.xk3f.com -> xk3f, a.b.xk3f.co.kr -> xk3f)만 보고,
##!     아래 신호의 점수 합이 dga_label_min_score 이상이면 무작위형으로 본다.
##!       * 모음(aeiouy) 비율 < dga_vowel_ratio_max           (+1)
##!       * 연속 자음 길이 >= dga_consonant_run_min             (+1)
##!       * 길이 정규화 엔트로피 >= dga_entropy_norm_min        (+1)  H / log2(min(n,36))
##!       * 숫자 비율 0.15 ~ 0.70 (영문·숫자 혼합)              (+1)
##!       * 길이 >= 16                                         (+1)
##!       * 16진수 문자만 + 숫자·문자 혼합, 길이 >= 8           (+2)
##!     길이 dga_min_label_len 미만 라벨(wpad, dc01 등)은 무작위형으로 보지 않는다.
##!   - 시뮬레이션(호스트당 NXDOMAIN 60건, 비율 0.5): 무작위 8자 이상 라벨 98.8% 이상 탐지,
##!     정상·오타·내부 이름 혼합 0%. 7자 이하 무작위 라벨은 판정력이 낮다(약 72%).
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
    ##  T 이면 total/nx 집계와 evidence 모두에서 제외한다.
    const dga_exclude_reverse_dns = T &redef;

    ## (폐기) evidence 최소 엔트로피. 이제 무작위형 라벨인 NXDOMAIN 만 evidence 로 남긴다.
    const dga_evidence_min_entropy = 4.0 &redef &deprecated="NSM::dga_evidence_min_entropy 는 더 이상 쓰이지 않습니다(무작위형 라벨만 evidence 로 적재)";

    ## 내부/신뢰 도메인 예외(부분매칭). 여기 매칭되는 조회는 집계·evidence 모두 제외.
    ##   예) "ahnlab.com" -> *.ahnlab.com,  "localdomain" -> *.localdomain
    const dga_allowlist_domains: set[string] = {} &redef;

    ## ---- 무작위형 라벨 판정 파라미터 ----
    const dga_min_label_len     = 6    &redef;  # 이보다 짧은 라벨은 무작위형으로 보지 않음
    const dga_label_min_score   = 2    &redef;  # 무작위형 판정 최소 점수
    const dga_vowel_ratio_max   = 0.25 &redef;  # 모음 비율 상한(미만이면 +1)
    const dga_consonant_run_min = 4    &redef;  # 연속 자음 길이(이상이면 +1)
    const dga_entropy_norm_min  = 0.90 &redef;  # 길이 정규화 엔트로피(이상이면 +1)

    ## 등록 라벨의 무작위성 점수(위 신호 합).
    global dga_label_score: function(label: string): count;

    ## qname 의 등록 라벨이 무작위형(DGA형)인지.
    global is_dga_like: function(qname: string): bool;
}

function dga_label_score(label: string): count
    {
    local n = |label|;
    if ( n < dga_min_label_len )
        return 0;

    local letters = 0;
    local vowels = 0;
    local digits = 0;
    local hexchars = 0;
    local run = 0;
    local maxrun = 0;
    local i = 0;

    while ( i < n )
        {
        local ch = label[i];
        ++i;
        if ( ch >= "0" && ch <= "9" )
            {
            ++digits;
            ++hexchars;
            run = 0;
            next;
            }
        if ( ch >= "a" && ch <= "z" )
            {
            ++letters;
            if ( ch <= "f" )
                ++hexchars;
            if ( ch in "aeiouy" )
                run = 0;
            else
                {
                ++run;
                if ( run > maxrun )
                    maxrun = run;
                }
            if ( ch in "aeiouy" )
                ++vowels;
            next;
            }
        run = 0;   # '-' 등 구분자
        }

    local sc = 0;
    if ( letters > 0 && ( vowels + 0.0 ) / letters < dga_vowel_ratio_max )
        ++sc;
    if ( maxrun >= dga_consonant_run_min )
        ++sc;
    local hmax = ln( n < 36 ? n + 0.0 : 36.0 ) / ln(2.0);
    if ( hmax > 0.0 && find_entropy(label)$entropy / hmax >= dga_entropy_norm_min )
        ++sc;
    local dr = ( digits + 0.0 ) / n;
    if ( dr >= 0.15 && dr <= 0.70 )
        ++sc;
    if ( n >= 16 )
        ++sc;
    if ( n >= 8 && hexchars == n && digits > 0 && digits < n )
        sc += 2;
    return sc;
    }

function is_dga_like(qname: string): bool
    {
    return dga_label_score(registered_label(qname)) >= dga_label_min_score;
    }

## 집계형 합성 증적 key. 탐지 시점(epoch_result)에서만 호출한다.
function dga_evidence_id(src: addr): string
    {
    return cat(src, "|dga|", time_bucket(dga_interval));
    }

event zeek_init()
    {
    if ( !detect_dga )
        return;

    local r_total = SumStats::Reducer($stream="nsm.dga.total",
                                      $apply=set(SumStats::SUM));
    # SUM: 판정용 NXDOMAIN 수 / SAMPLE: 근거로 남길 무작위형 질의 표본
    local r_nx    = SumStats::Reducer($stream="nsm.dga.nx",
                                      $apply=set(SumStats::SUM, SumStats::SAMPLE),
                                      $num_samples=lm_num_samples);
    # SUM: NXDOMAIN 중 무작위형 라벨 수
    local r_like  = SumStats::Reducer($stream="nsm.dga.like",
                                      $apply=set(SumStats::SUM));
    SumStats::create([
        $name      = "nsm-detect-dga",
        $epoch     = dga_interval,
        $reducers  = set(r_total, r_nx, r_like),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.dga.nx" !in result )
                return;
            local nx = result["nsm.dga.nx"]$sum;
            if ( nx < dga_nxdomain_threshold )      # ① NXDOMAIN 수
                return;

            local total = ("nsm.dga.total" in result) ? result["nsm.dga.total"]$sum : nx;
            local ratio = (total > 0) ? nx / total : 0.0;
            if ( ratio < dga_ratio_threshold )      # ② NXDOMAIN 비율
                return;

            local like = ("nsm.dga.like" in result) ? result["nsm.dga.like"]$sum : 0.0;
            local like_ratio = like / nx;
            if ( like_ratio < dga_like_ratio )      # ③ 무작위형 라벨 비율
                return;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = dga_evidence_id(key$host);

            # 근거: 이 창에서 표본으로 잡힌 무작위형 NXDOMAIN 질의들.
            #   NOTICE 보다 먼저 적재해야 evidence_count 가 정확히 잡힌다.
            local rnx = result["nsm.dga.nx"];
            if ( rnx?$samples )
                for ( si in rnx$samples )
                    {
                    if ( ! rnx$samples[si]?$str )
                        next;   # 무작위형이 아닌 질의는 $str 없이 관측 -> 근거 제외

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
                        $detail=fmt("query=%s label_score=%s rcode=NXDOMAIN",
                                    parts[0], parts[1])]);
                    }

            NOTICE([$note=DGA_Domain,
                    $src=key$host,
                    $msg=fmt("DGA activity suspected: %s (NXDOMAIN %.0f/%.0f = %.0f%%, DGA-like labels %.0f/%.0f = %.0f%%) in %s",
                             key$host, nx, total, ratio*100, like, nx, like_ratio*100, dga_interval),
                    $sub=fmt("nxdomain=%.0f total=%.0f ratio=%.2f dga_like=%.0f dga_like_ratio=%.2f",
                             nx, total, ratio, like, like_ratio),
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

    if ( msg$rcode != 3 )   # NXDOMAIN 만 아래 집계
        return;

    local qs = ( c?$dns && c$dns?$query ) ? c$dns$query : "";
    local score = ( qs != "" ) ? dga_label_score(registered_label(qs)) : 0;

    # 관측만 한다. 증적은 탐지 시점(epoch_result)에서 표본으로 적재한다.
    #   무작위형 질의만 $str 을 붙여 근거 표본으로 쓴다(정상 NXDOMAIN 의 evidence 폭증 억제).
    if ( score >= dga_label_min_score )
        {
        SumStats::observe("nsm.dga.nx", [$host=c$id$orig_h],
                          [$num=1, $str=fmt("%s|%d|%s", qs, score, c$uid)]);
        SumStats::observe("nsm.dga.like", [$host=c$id$orig_h], [$num=1]);
        }
    else
        SumStats::observe("nsm.dga.nx", [$host=c$id$orig_h], [$num=1]);
    }
