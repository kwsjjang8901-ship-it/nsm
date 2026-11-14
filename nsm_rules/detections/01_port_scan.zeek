##! ============================================================================
##! [1] Port Scan (수직 스캔: 1 src -> 1 dst, 다수 포트) - T1046
##!
##!   - (src,dst) 쌍별로 접근한 "고유 목적지 포트 수"를 SumStats 로 집계.
##!   - connection_attempt(미응답)·rejected(RST)·established(열린 포트) 모두 관측해
##!     실패/성공 포트를 폭넓게 카운트.
##!   - SYN 없는 TCP 탐침(FIN·NULL·Xmas·ACK·Window)과 UDP 스캔도 연결 종료 때 센다(2026-11).
##!     (CIC-IDS2017 Friday 방화벽 해제 구간의 nmap -sF·-sX·-sN·-sA·-sW·-sU 를 놓치던 것 보완)
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
@load ./exceptions

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

    ## SYN 없이 보내는 TCP 탐침(FIN·NULL·Xmas·ACK·Window 스캔)과 UDP 스캔도 센다.
    const port_scan_count_nosyn = T &redef;
    const port_scan_count_udp = T &redef;
    ## UDP traceroute(33434~33534)는 스캔이 아니다.
    const port_scan_udp_skip_low = 33434 &redef;
    const port_scan_udp_skip_high = 33534 &redef;
}

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.port_scan", $apply=set(SumStats::UNIQUE));
    # 표본은 "포트(탐침 종류)"로 남긴다: syn_noreply·rejected·nosyn·udp
    local rs = SumStats::Reducer($stream="nsm.port_scan.sample", $apply=set(SumStats::SAMPLE),
                                 $num_samples=lm_num_samples);
    SumStats::create([
        $name     = "nsm-detect-port-scan",
        $epoch    = scan_interval,
        $reducers = set(r, rs),
        $threshold = port_scan_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
                return result["nsm.port_scan"]$unique + 0.0;
            },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local res = result["nsm.port_scan"];
            local n_ports = res$unique;

            local samples = "";
            if ( "nsm.port_scan.sample" in result && result["nsm.port_scan.sample"]?$samples )
                for ( i in result["nsm.port_scan.sample"]$samples )
                    if ( result["nsm.port_scan.sample"]$samples[i]?$str )
                        samples += fmt("%s ", result["nsm.port_scan.sample"]$samples[i]$str);
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
                    $dst=to_addr(target),   # 대상 host -> detection victims, 상관 DST 피벗에 사용
                    $msg=fmt("Port scan: %s -> %s (%d unique ports in %s)",
                             scanner, target, n_ports, scan_interval),
                    $sub=fmt("unique_ports=%d sample=[%s]", n_ports, samples),
                    $identifier=cat(scanner, "port-scan", target),
                    $suppress_for=scan_interval,
                    $evidence_id=eid]);
            }
    ]);
    }

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |port_scan_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:port_scan_allowlist",
            [$scope=set("Port_Scan"), $src=port_scan_allowlist]);
    if ( |port_scan_exclude_ports| > 0 )
        NSM::exception_add_legacy("legacy:port_scan_exclude_ports",
            [$scope=set("Port_Scan"), $dst_port=port_scan_exclude_ports]);
    }

function observe_port_scan(c: connection, failed: bool, kind: string)
    {
    if ( ! detect_port_scan )
        return;
    if ( port_scan_local_only && ! Site::is_local_addr(c$id$orig_h) )
        return;
    # 예외(예외 파일 + 기존 port_scan_allowlist·port_scan_exclude_ports). 집계 전 판정
    if ( NSM::exception_drop_agg(Port_Scan, c) )
        return;
    # 성공 연결 제외 옵션: 미응답/거부(failed)만 카운트
    if ( ! failed && ! port_scan_count_established )
        return;

    # (src,dst) 그룹에 목적지 포트를 관측 -> 고유 포트 수 집계
    local key: SumStats::Key = [$host=c$id$orig_h, $str=cat(c$id$resp_h)];
    SumStats::observe("nsm.port_scan", key, [$str=cat(c$id$resp_p)]);
    SumStats::observe("nsm.port_scan.sample", key, [$str=fmt("%s(%s)", c$id$resp_p, kind)]);
    }

event connection_attempt(c: connection)     { observe_port_scan(c, T, "syn_noreply"); }  # SYN 미응답
event connection_rejected(c: connection)    { observe_port_scan(c, T, "rejected"); }     # RST 거부
event connection_established(c: connection) { observe_port_scan(c, F, "established"); }  # 열린 포트

# SYN 없는 TCP 탐침(nmap -sF·-sN·-sX·-sA·-sW)과 UDP 스캔(-sU). 연결 이벤트가 없으므로 연결이 끝날 때 본다.
#   TCP: 출발지 SYN 이 없고(history 에 'S' 없음) 출발지 RST 도 없고('R', 뒤집힘 '^' 없음) 출발지 패킷 2개 이하·
#        양쪽 페이로드 0. 데이터가 오가는
#        캡처 시작 전 연결(중간부터 보인 연결)은 페이로드가 있어 빠진다.
#   UDP: 응답 패킷 없음(닫힌 포트는 ICMP 도달 불가, 막힌 포트는 무응답), 출발지 패킷 2개 이하.
event connection_state_remove(c: connection)
    {
    local proto = get_port_transport_proto(c$id$resp_p);
    if ( proto == tcp && port_scan_count_nosyn )
        {
        if ( "S" in c$history || c$orig$size > 0 || c$resp$size > 0 || c$orig$num_pkts > 2 )
            return;
        # 출발지가 RST 를 보냈거나(R) Zeek 가 방향을 뒤집은(^) 연결은 탐침이 아니라 응답이다.
        #   캡처 손실로 스캐너의 SYN 이 빠지면 피해 host 의 RST 응답만 남아 피해 host 가 스캐너의
        #   임시 포트를 두드린 것처럼 보인다(CIC-IDS2017 Friday). FIN·NULL·Xmas·ACK 탐침은 출발지 RST 가 없다.
        if ( "R" in c$history || "^" in c$history )
            return;
        observe_port_scan(c, T, "nosyn");
        }
    else if ( proto == udp && port_scan_count_udp )
        {
        local pn = port_to_count(c$id$resp_p);
        if ( pn >= port_scan_udp_skip_low && pn <= port_scan_udp_skip_high )
            return;
        if ( c$resp$num_pkts > 0 || c$orig$num_pkts > 2 )
            return;
        observe_port_scan(c, T, "udp");
        }
    }
