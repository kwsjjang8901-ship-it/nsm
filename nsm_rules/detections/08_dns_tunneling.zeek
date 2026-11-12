##! ============================================================================
##! [08] DNS Tunneling / DNS Exfiltration — 통합 판정 (2026-11 재작성, 이전 08 + 11)
##!
##! 탐지 원리
##!   - 터널링·유출 모두 "한 등록 도메인 아래 서브도메인에 데이터를 인코딩"한다.
##!     (src, 등록 도메인) 단위로 dnstun_interval 창에서 아래를 집계한다.
##!       * 전체 질의 수, 수상한 질의 수(→ 수상한 질의 비율)
##!       * 고유 서브도메인 수                         -> [터널링] DNS_Tunneling
##!       * 서브도메인 누적 바이트(인코딩 데이터량)     -> [유출]   Exfil_DNS
##!   - 수상한 질의 비율 >= dnstun_suspicious_ratio 일 때만 판정한다. CDN·클라우드처럼
##!     고유 서브도메인이 많아도 라벨이 짧거나 단어형이면 판정하지 않는다.
##!
##! 수상한 질의 (하나라도 해당)
##!   - TXT(16) / NULL(10) 레코드 질의
##!   - 서브도메인에 dnstun_label_len(40) 자 이상 라벨이 있음
##!   - dnstun_min_label_len(20) 자 이상 라벨이 무작위형(13 DGA 의 dga_label_score >=
##!     dga_label_min_score). hex·base32 인코딩 데이터가 여기에 해당한다.
##!
##! 오탐 통제
##!   - 등록 도메인은 parent_domain()(co.kr 등 2단계 공용 접미사 처리)으로 구한다(H5 해소).
##!   - 내부 출발지만(dnstun_local_only), 내부 재귀 리졸버 제외(dns_tunnel_resolvers),
##!     역방향 조회 제외, 도메인 예외(dns_tunnel_allowlist_domains: 기본 AV·스팸 평판 조회).
##!
##! 이전 구현과의 차이
##!   - 08: 신호 OR 로 관측해 TXT·고엔트로피 정상 조회가 섞였고 co.kr 이 한 부모로 묶였다.
##!   - 11: 모든 질의 길이를 합산해 정상 대량 조회도 누적됐고 1MB/5분은 과대했다.
##!   - 내장 함수와 이름이 겹치는 지역 변수(sub)로 로드 실패하던 문제도 없앴다.
##!
##! 상관 계약: notice $src = 감염 host (DNS_Tunneling: C2 단계, Exfil_DNS: 유출 단계).
##! 클러스터: SumStats 라 워커 관측 -> 매니저 판정으로 자동 안전.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dns
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./13_dga        # dga_label_score (라벨 무작위성 점수 공용)

module NSM;

export {
    const detect_dns_tunnel = T &redef;

    ## 내부 출발지만 집계.
    const dnstun_local_only = T &redef;

    ## 내부 재귀 리졸버(클라이언트 질의를 대신 외부로 보내는 DNS 서버). 출발지로 집계하지 않는다.
    ##   예) redef NSM::dns_tunnel_resolvers += { 10.0.0.53 };
    const dns_tunnel_resolvers: set[addr] = {} &redef;

    ## 도메인 예외(부분매칭). 서브도메인에 조회값을 인코딩하는 정상 서비스(AV 평판, DNSBL 등).
    const dns_tunnel_allowlist_domains: set[string] = {
        "sophosxl.net", "e5.sk",                                   # AV 평판 조회
        "spamhaus.org", "spamcop.net", "sorbs.net", "surbl.org",
        "uribl.com", "barracudacentral.org",                       # DNSBL
    } &redef;

    ## 질의 1건이 수상한지(서브도메인, 질의 타입).
    global dns_tunnel_query_suspicious: function(subdom: string, qtype: count): bool;
}

function dns_tunnel_query_suspicious(subdom: string, qtype: count): bool
    {
    if ( qtype == 16 || qtype == 10 )      # TXT, NULL
        return T;
    if ( subdom == "" )
        return F;

    local labels = split_string(subdom, /\./);
    for ( i in labels )
        {
        local lab = labels[i];
        if ( |lab| >= dnstun_label_len )
            return T;
        if ( |lab| >= dnstun_min_label_len && dga_label_score(lab) >= dga_label_min_score )
            return T;
        }
    return F;
    }

function dns_tunnel_eid(src: addr, kind: string, parent: string): string
    {
    return cat(src, "|", kind, "|", parent, "|", time_bucket(dnstun_interval));
    }

## 판정 시점 근거 적재(무작위·인코딩형 질의 표본).
function dns_tunnel_write_evidence(eid: string, note: Notice::Type, technique: string,
                                   src: addr, parent: string, rs: SumStats::ResultVal,
                                   detail: string)
    {
    if ( ! rs?$samples )
        return;
    for ( i in rs$samples )
        {
        if ( ! rs$samples[i]?$str )
            next;
        local q = rs$samples[i]$str;
        if ( ! NSM::evidence_is_new(eid, q) )
            next;
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=note,
            $technique=technique,
            $src=src,
            $operation="dns_query",
            $detail=fmt("query=%s parent=%s %s", q, parent, detail)]);
        }
    }

event zeek_init()
    {
    if ( ! detect_dns_tunnel )
        return;

    local r_total = SumStats::Reducer($stream="nsm.dnstun.total", $apply=set(SumStats::SUM));
    local r_susp  = SumStats::Reducer($stream="nsm.dnstun.susp",
                                      $apply=set(SumStats::SUM, SumStats::SAMPLE),
                                      $num_samples=lm_num_samples);
    local r_uniq  = SumStats::Reducer($stream="nsm.dnstun.uniq", $apply=set(SumStats::UNIQUE));
    local r_bytes = SumStats::Reducer($stream="nsm.dnstun.bytes", $apply=set(SumStats::SUM));

    SumStats::create([
        $name      = "nsm-detect-dns-tunnel",
        $epoch     = dnstun_interval,
        $reducers  = set(r_total, r_susp, r_uniq, r_bytes),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.dnstun.total" !in result || "nsm.dnstun.susp" !in result )
                return;

            local total = result["nsm.dnstun.total"]$sum;
            local rs    = result["nsm.dnstun.susp"];
            local susp  = rs$sum;
            local ratio = ( total > 0 ) ? susp / total : 0.0;
            if ( ratio < dnstun_suspicious_ratio )
                return;

            local uniq  = ( "nsm.dnstun.uniq" in result ) ? result["nsm.dnstun.uniq"]$unique : 0;
            local bytes = ( "nsm.dnstun.bytes" in result ) ? result["nsm.dnstun.bytes"]$sum : 0.0;
            local parent = key$str;
            local detail = fmt("total=%.0f suspicious=%.0f ratio=%.2f unique_sub=%d encoded_bytes=%.0f window=%s",
                               total, susp, ratio, uniq, bytes, dnstun_interval);

            # 한 탐지에만 걸리는 예외: (출발지, 등록 도메인) 기준으로 창 판정 때 거른다(근거 기록 전).
            local wx = NSM::ExceptionCtx($src=key$host, $domain=parent);

            # [터널링] 고유 서브도메인이 많다
            if ( uniq >= dnstun_unique_sub && ! NSM::exception_drop_ctx(DNS_Tunneling, wx, T) )
                {
                local eid_t = dns_tunnel_eid(key$host, "dns-tunnel", parent);
                dns_tunnel_write_evidence(eid_t, DNS_Tunneling, "T1071.004", key$host, parent, rs, detail);
                NOTICE([$note=DNS_Tunneling,
                        $src=key$host,
                        $msg=fmt("DNS tunneling suspected: %s -> %s (%d unique subdomains, %.0f%% suspicious) in %s",
                                 key$host, parent, uniq, ratio * 100, dnstun_interval),
                        $sub=fmt("parent_domain=%s %s", parent, detail),
                        $identifier=cat(key$host, parent, "dns-tunnel"),
                        $suppress_for=1hr,
                        $evidence_id=eid_t]);
                }

            # [유출] 서브도메인에 실린 데이터량이 많다
            if ( bytes >= dnsexfil_bytes && ! NSM::exception_drop_ctx(Exfil_DNS, wx, T) )
                {
                local eid_x = dns_tunnel_eid(key$host, "dns-exfil", parent);
                dns_tunnel_write_evidence(eid_x, Exfil_DNS, "T1048.003", key$host, parent, rs, detail);
                NOTICE([$note=Exfil_DNS,
                        $src=key$host,
                        $msg=fmt("DNS-based exfiltration suspected: %s -> %s (~%.1f KB encoded, %.0f%% suspicious) in %s",
                                 key$host, parent, bytes / 1024.0, ratio * 100, dnstun_interval),
                        $sub=fmt("parent_domain=%s %s", parent, detail),
                        $identifier=cat(key$host, parent, "dns-exfil"),
                        $suppress_for=1hr,
                        $evidence_id=eid_x]);
                }
            }
    ]);
    }

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |dns_tunnel_allowlist_domains| > 0 )
        NSM::exception_add_legacy("legacy:dns_tunnel_allowlist_domains",
            [$scope=set("DNS_Tunneling", "Exfil_DNS"), $domain=dns_tunnel_allowlist_domains]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! detect_dns_tunnel )
        return;
    if ( query == "" )
        return;

    local src = c$id$orig_h;
    if ( dnstun_local_only && ! Site::is_local_addr(src) )
        return;
    if ( src in dns_tunnel_resolvers )
        return;

    local q = to_lower(query);
    local ql = |q|;
    if ( ql >= 13 && q[ql - 13 :] == ".in-addr.arpa" )
        return;
    if ( ql >= 9 && q[ql - 9 :] == ".ip6.arpa" )
        return;
    # 예외(예외 파일 + 기존 dns_tunnel_allowlist_domains). 터널링·유출이 같은 집계를 쓰므로
    #   두 탐지 모두에 걸리는 예외만 질의 단위로 집계 전에 거른다. 한 탐지에만 걸리는 예외는 창 판정 때 거른다.
    local x = NSM::ExceptionCtx($src=src, $dst=c$id$resp_h, $dst_port=c$id$resp_p, $domain=q);
    local ex_t = NSM::exception_peek(DNS_Tunneling, x, T);
    local ex_x = NSM::exception_peek(Exfil_DNS, x, T);
    if ( ex_t != "" && ex_x != "" )
        {
        NSM::exception_count(ex_t);
        if ( ex_x != ex_t )
            NSM::exception_count(ex_x);
        return;
        }

    local parent = parent_domain(q);
    local subdom = ( |q| > |parent| ) ? sub_bytes(q, 1, |q| - |parent| - 1) : "";
    local key: SumStats::Key = [$host=src, $str=parent];

    SumStats::observe("nsm.dnstun.total", key, [$num=1]);
    SumStats::observe("nsm.dnstun.uniq",  key, [$str=subdom]);
    SumStats::observe("nsm.dnstun.bytes", key, [$num=|subdom|]);
    # 수상한 질의만 관측(표본 = 근거). 하나도 없으면 판정하지 않는다.
    if ( dns_tunnel_query_suspicious(subdom, qtype) )
        SumStats::observe("nsm.dnstun.susp", key, [$num=1, $str=q]);
    }
