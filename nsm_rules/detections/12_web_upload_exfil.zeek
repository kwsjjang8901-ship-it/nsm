##! ============================================================================
##! [12] Web/Cloud Upload Exfiltration - T1567.002
##!
##!   - 클라우드 스토리지/협업 서비스(main.zeek 의 cloud_hosts)로의 대용량 업로드.
##!   - 암호화(HTTPS)라 본문은 못 보므로 "식별 가능한 목적지(SNI/HTTP Host/프록시 CONNECT 대상)
##!     + 업로드 바이트(orig_bytes)"로 추론한다.
##!   - 집계형: 한 내부 host 가 한 클라우드 서비스(등록 도메인, 예: dropboxapi.com)로
##!     webupload_epoch(기본 1시간) 안에 올린 바이트 합계가 webupload_bytes(50MB) 를 넘으면 탐지.
##!     클라우드 클라이언트는 파일을 여러 연결·조각(S3 multipart 8MB 등)으로 나눠 올리고, 천천히
##!     올리면 1분 합계(14번)에도 닿지 않으므로 연결 하나가 아니라 서비스별 누적으로 본다.
##!     연결 하나로 임계를 넘는 업로드도 그대로 탐지된다(합계에 포함).
##!     바이트는 연결이 끝날 때 더한다(장시간 진행 중인 업로드는 10·14번이 먼저 본다).
##!     창은 고정 구간(epoch)이라, 경계에 걸친 업로드는 두 창으로 나뉠 수 있다.
##!   - 명시적 프록시를 거친 업로드(PC -> 프록시, CONNECT)도 본다(proxy_common.zeek). 목적지 이름은
##!     CONNECT 뒤 TLS 의 SNI, 없으면 CONNECT 대상. 첫 요청을 못 본 프록시 연결은 이름을 몰라 세지 않는다.
##!     (프록시 학습 조건은 proxy_common.zeek: 내부 PC 의 CONNECT 에 2xx 로 답한 주소만)
##!
##!   ※ 10/14(일반 대용량 유출)와 겹칠 수 있으나, 12 는 "어느 서비스로"가 식별되는
##!     경우로 한정되어 컨텍스트가 다르다. 동일 전송에 함께 뜰 수 있으며, 위험도/상관
##!     단계에서 정리한다(웹서비스 유출이 더 구체적 근거).
##!
##! 상관 계약: notice $src = 유출 host (EXFIL 단계).
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./proxy_common

module NSM;

export {
    const detect_web_upload = T &redef;

    ## 누적 창. 한 (출발지, 클라우드 서비스)로 이 시간 안에 올린 바이트 합계를 본다
    const webupload_epoch = 1hr &redef;

    ## 정상 대용량 업로드 예외(사내 승인 클라우드 계정 대역 등).
    const web_upload_allowlist: set[subnet] = {} &redef;
}

event zeek_init()
    {
    if ( |web_upload_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:web_upload_allowlist",
            [$scope=set("Exfil_Web_Upload"), $dst=web_upload_allowlist]);

    local r1 = SumStats::Reducer($stream="nsm.webupload", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="nsm.webupload.sample", $apply=set(SumStats::SAMPLE), $num_samples=5);
    SumStats::create([
        $name="nsm-detect-web-upload", $epoch=webupload_epoch, $reducers=set(r1, r2),
        $threshold=webupload_bytes + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = { return result["nsm.webupload"]$sum; },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local svc = key$str;
            local total = double_to_count(result["nsm.webupload"]$sum);
            local n = result["nsm.webupload"]$num;
            local mb = total / (1024.0 * 1024.0);
            local eid = cat(src, "|web-upload|", svc, "|", time_bucket(webupload_epoch));
            # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
            local nid = cat(src, "web-upload", svc);
            if ( NSM::notice_suppressed(Exfil_Web_Upload, nid) )
                return;
            local dst: addr = 0.0.0.0;
            local name = "";
            if ( "nsm.webupload.sample" in result && result["nsm.webupload.sample"]?$samples )
                for ( i in result["nsm.webupload.sample"]$samples )
                    {
                    local o = result["nsm.webupload.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);       # "uid|목적지|이름|바이트|프록시 여부"
                    if ( |p| < 5 )
                        next;
                    if ( name == "" )
                        name = p[2];
                    # 프록시를 거쳤으면 목적지 주소는 프록시라 피해 대상으로 쓰지 않는다
                    if ( dst == 0.0.0.0 && p[4] == "" )
                        dst = to_addr(p[1]);
                    if ( ! NSM::evidence_is_new(eid, p[0]) )
                        next;
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=Exfil_Web_Upload,
                        $src=src,
                        $dst=to_addr(p[1]),
                        $uid=p[0],
                        $operation="cloud_upload",
                        $detail=fmt("service=%s host=%s conn_upload=%s total_upload=%d conns=%d window=%s%s",
                                    svc, p[2], p[3], total, n, webupload_epoch, p[4])]);
                    }

            local nt = Notice::Info($note=Exfil_Web_Upload,
                    $src=src,
                    $msg=fmt("Web/cloud upload exfil suspected: %s -> %s (%.1f MB in %s, %d conns)",
                             src, name != "" ? name : svc, mb, webupload_epoch, n),
                    $sub=fmt("service=%s upload_mb=%.1f conns=%d", svc, mb, n),
                    $identifier=nid,
                    $suppress_for=suppress_web_upload,
                    $evidence_id=eid);
            if ( dst != 0.0.0.0 )
                nt$dst = dst;
            NOTICE(nt);
            }
    ]);
    }

event connection_state_remove(c: connection)
    {
    if ( ! detect_web_upload || c$orig$size == 0 )
        return;
    if ( ! exfil_outbound(c) )
        return;

    # 목적지 서비스 식별: SNI(TLS) > 프록시 CONNECT 대상 > HTTP Host
    local name = conn_dest_name(c);
    if ( name == "" || cloud_hosts !in name )  # 식별 안 되거나 클라우드 서비스 아님
        return;

    # 예외(예외 파일 + 기존 web_upload_allowlist). 축: 목적지, 도메인(SNI·Host) 등. 집계 전에 거른다
    if ( NSM::exception_drop_agg(Exfil_Web_Upload, c) )
        return;

    local svc = parent_domain(name);
    local key: SumStats::Key = [$host=c$id$orig_h, $str=svc];
    # 표본을 먼저 넣는다: 합계를 넣는 순간 임계를 넘으면 그 연결도 근거에 남도록
    SumStats::observe("nsm.webupload.sample", key,
                      [$str=cat(NSM::conn_ref(c), "|", c$id$resp_h, "|", name, "|", c$orig$size, "|", proxy_detail(c))]);
    SumStats::observe("nsm.webupload", key, [$num=c$orig$size]);
    }
