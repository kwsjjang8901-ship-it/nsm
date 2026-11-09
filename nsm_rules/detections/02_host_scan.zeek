##! ============================================================================
##! [2] Host Scan (수평 스캔: 1 src -> 다수 dst, 동일 포트) - T1018
##!
##!   - (src, dst_port) 그룹별로 접근한 "고유 목적지 host 수"를 SumStats 로 집계.
##!     동일 포트를 여러 host 에 두드리는 수평 스윕(예: 445 스윕)을 잡는다.
##!   - evidence 는 확정 시점 요약 1행만.
##!
##! 상관 계약: notice $src = 스캐너 host (RECON 단계).
##! 클러스터: SumStats 라 자동 안전.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_host_scan = T &redef;
    const host_scan_local_only = T &redef;
    ## 기본은 비어 있음. redef NSM::host_scan_allowlist += { };
    const host_scan_allowlist: set[subnet] = {} &redef;

    ## 성공(established) 연결도 카운트할지. F 면 미응답/거부만 세어
    ## 프록시·모니터링 서버의 정상 fan-out 오탐을 억제.
    const host_scan_count_established = F &redef;

    ## 수평 스캔 집계에서 기본 제외할 포트(정상 클라이언트 fan-out 이 잦은 포트).
    ## 80/443/53 은 웹/DNS 정상 다중접속이 많아 스윕 오탐의 주원인 -> 기본 제외.
    ## 445/22/3389 등 관리 포트 스윕은 그대로 탐지된다.
    const host_scan_exclude_ports: set[port] = { 80/tcp, 443/tcp, 53/tcp, 53/udp } &redef;
}

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.host_scan",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=10);
    SumStats::create([
        $name     = "nsm-detect-host-scan",
        $epoch    = scan_interval,
        $reducers = set(r),
        $threshold = host_scan_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
                return result["nsm.host_scan"]$unique + 0.0;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res = result["nsm.host_scan"];
            local n_hosts = res$unique;

            local samples = "";
            if ( res?$samples )
                for ( i in res$samples )
                    if ( res$samples[i]?$str )
                        samples += fmt("%s ", res$samples[i]$str);
            samples = strip(samples);

            local scanner = key$host;
            local dport   = key$str;          # 대상 포트(문자열)
            local eid = cat(scanner, "|host-scan|", dport, "|", time_bucket(scan_interval));

            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=Host_Scan,
                $technique="T1018",
                $src=scanner,
                $operation="tcp_host_sweep",
                $detail=fmt("unique_hosts=%d port=%s sample=[%s] window=%s",
                            n_hosts, dport, samples, scan_interval)]);

            NOTICE([$note=Host_Scan,
                    $src=scanner,
                    $msg=fmt("Host scan (sweep): %s -> %d hosts on port %s in %s",
                             scanner, n_hosts, dport, scan_interval),
                    $sub=fmt("unique_hosts=%d port=%s sample=[%s]", n_hosts, dport, samples),
                    $identifier=cat(scanner, "host-scan", dport),
                    $suppress_for=scan_interval,
                    $evidence_id=eid]);
            }
    ]);
    }

function observe_host_scan(c: connection, failed: bool)
    {
    if ( ! detect_host_scan )
        return;
    if ( host_scan_local_only && ! Site::is_local_addr(c$id$orig_h) )
        return;
    if ( c$id$orig_h in host_scan_allowlist )
        return;
    if ( c$id$resp_p in host_scan_exclude_ports )
        return;
    if ( ! failed && ! host_scan_count_established )
        return;

    # (src, dst_port) 그룹에 목적지 host 를 관측 -> 고유 host 수 집계
    SumStats::observe("nsm.host_scan",
        [$host=c$id$orig_h, $str=cat(c$id$resp_p)],
        [$str=cat(c$id$resp_h)]);
    }

event connection_attempt(c: connection)     { observe_host_scan(c, T); }
event connection_rejected(c: connection)    { observe_host_scan(c, T); }
event connection_established(c: connection) { observe_host_scan(c, F); }
