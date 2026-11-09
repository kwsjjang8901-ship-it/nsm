##! ============================================================================
##! [1] Port Scan (수직 스캔: 1 src -> 1 dst, 다수 포트) - T1046
##!
##!   - (src,dst) 쌍별로 접근한 "고유 목적지 포트 수"를 SumStats 로 집계.
##!   - connection_attempt(미응답)·rejected(RST)·established(열린 포트) 모두 관측해
##!     실패/성공 포트를 폭넓게 카운트.
##!   - 트래픽량이 크므로 evidence 는 확정(threshold) 시점에 요약 1행만 적재.
##!
##! 상관 계약: notice $src = 스캐너 host (RECON 단계, SRC_TO_SRC 로 C2 에 연결).
##! 클러스터: SumStats 라 워커 관측 -> manager 집계로 자동 안전.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_port_scan = T &redef;

    ## 내부 출발지만 볼지(킬체인 recon = 내부 감염 host). 인터넷 배경 스캔 소음 차단.
    const port_scan_local_only = T &redef;

    ## 스캐너 예외(취약점/자산 스캐너 대역). 기본은 비어 있음.
    ## 운영/POC 에서 site 정책에 redef 로 추가:
    ##   redef NSM::port_scan_allowlist += {  };  # 예: 취약점 스캐너
    const port_scan_allowlist: set[subnet] = {} &redef;

    ## 성공(established) 연결도 스캔 카운트에 포함할지.
    ## F 로 두면 미응답(S0)·거부(REJ)만 세어 정상 다중포트 접속 오탐을 크게 줄임.
    const port_scan_count_established = F &redef;

    ## 스캔 집계에서 제외할 목적지 포트(정상 다중접속이 잦은 포트).
    const port_scan_exclude_ports: set[port] = {} &redef;
}

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.port_scan",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=10);
    SumStats::create([
        $name     = "nsm-detect-port-scan",
        $epoch    = scan_interval,
        $reducers = set(r),
        $threshold = port_scan_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
                return result["nsm.port_scan"]$unique + 0.0;
            },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res = result["nsm.port_scan"];
            local n_ports = res$unique;

            local samples = "";
            if ( res?$samples )
                for ( i in res$samples )
                    if ( res$samples[i]?$str )
                        samples += fmt("%s ", res$samples[i]$str);
            samples = strip(samples);

            local scanner = key$host;
            local target  = key$str;          # dst (문자열)
            local eid = cat(scanner, "|port-scan|", target, "|", time_bucket(scan_interval));

            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=Port_Scan,
                $technique="T1046",
                $src=scanner,
                $dst=to_addr(target),
                $operation="tcp_port_scan",
                $detail=fmt("unique_ports=%d target=%s sample=[%s] window=%s",
                            n_ports, target, samples, scan_interval)]);

            NOTICE([$note=Port_Scan,
                    $src=scanner,
                    $msg=fmt("Port scan: %s -> %s (%d unique ports in %s)",
                             scanner, target, n_ports, scan_interval),
                    $sub=fmt("unique_ports=%d sample=[%s]", n_ports, samples),
                    $identifier=cat(scanner, "port-scan", target),
                    $suppress_for=scan_interval,
                    $evidence_id=eid]);
            }
    ]);
    }

function observe_port_scan(c: connection, failed: bool)
    {
    if ( ! detect_port_scan )
        return;
    if ( port_scan_local_only && ! Site::is_local_addr(c$id$orig_h) )
        return;
    if ( c$id$orig_h in port_scan_allowlist )
        return;
    if ( c$id$resp_p in port_scan_exclude_ports )
        return;
    # 성공 연결 제외 옵션: 미응답/거부(failed)만 카운트
    if ( ! failed && ! port_scan_count_established )
        return;

    # (src,dst) 그룹에 목적지 포트를 관측 -> 고유 포트 수 집계
    SumStats::observe("nsm.port_scan",
        [$host=c$id$orig_h, $str=cat(c$id$resp_h)],
        [$str=cat(c$id$resp_p)]);
    }

event connection_attempt(c: connection)     { observe_port_scan(c, T); }  # SYN 미응답
event connection_rejected(c: connection)    { observe_port_scan(c, T); }  # RST 거부
event connection_established(c: connection) { observe_port_scan(c, F); }  # 열린 포트
