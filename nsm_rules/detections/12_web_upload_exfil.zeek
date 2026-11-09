##! ============================================================================
##! [12] Web/Cloud Upload Exfiltration - T1567.002
##!
##!   - 클라우드 스토리지/협업 서비스(main.zeek 의 cloud_hosts)로의 대용량 업로드.
##!   - 암호화(HTTPS)라 본문은 못 보므로 "식별 가능한 목적지(SNI/HTTP Host)
##!     + 업로드 바이트(orig_bytes)"로 추론한다.
##!   - 단일 연결 기준(집계 아님) -> 교차 상태가 없어 워커 로컬이라도 안전.
##!
##!   ※ 10/14(일반 대용량 유출)와 겹칠 수 있으나, 12 는 "어느 서비스로"가 식별되는
##!     경우로 한정되어 컨텍스트가 다르다. 동일 전송에 함께 뜰 수 있으며, 위험도/상관
##!     단계에서 정리한다(웹서비스 유출이 더 구체적 근거).
##!
##! 상관 계약: notice $src = 유출 host (EXFIL 단계).
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_web_upload = T &redef;

    ## 정상 대용량 업로드 예외(사내 승인 클라우드 계정 대역 등).
    const web_upload_allowlist: set[subnet] = {} &redef;
}

event connection_state_remove(c: connection)
    {
    if ( ! detect_web_upload )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    if ( ! Site::is_local_addr(orig) || ! is_external(resp) )
        return;
    if ( resp in web_upload_allowlist )
        return;
    if ( c$orig$size <= webupload_bytes )   # 업로드 바이트 임계 미달
        return;

    # 목적지 서비스 식별: SNI(TLS) 우선, 없으면 HTTP Host
    local svc = "";
    if ( c?$ssl && c$ssl?$server_name )
        svc = c$ssl$server_name;
    else if ( c?$http && c$http?$host )
        svc = c$http$host;

    if ( svc == "" || cloud_hosts !in svc )  # 식별 안 되거나 클라우드 서비스 아님
        return;

    local mb = c$orig$size / (1024.0 * 1024.0);
    local eid = cat(orig, "|web-upload|", resp, "|", time_bucket(1hr));

    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=Exfil_Web_Upload,
        $technique="T1567.002",
        $src=orig,
        $dst=resp,
        $operation="cloud_upload",
        $uid=c$uid,
        $detail=fmt("service=%s upload=%.1fMB (orig_bytes=%d)", svc, mb, c$orig$size)]);

    NOTICE([$note=Exfil_Web_Upload,
            $conn=c,
            $src=orig,
            $msg=fmt("Web/cloud upload exfil suspected: %s -> %s (%.1f MB)", orig, svc, mb),
            $sub=fmt("service=%s upload_mb=%.1f", svc, mb),
            $identifier=cat(orig, resp, "web-upload"),
            $suppress_for=suppress_web_upload,
            $evidence_id=eid]);
    }
