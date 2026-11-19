##! ============================================================================
##! [13] Exfiltration (C2) - 대량 전송 : 외부로 100MB+ 업로드  (단일 연결형)
##!
##! 탐지 원리
##!   - 연결 종료(connection_state_remove) 시 originator 페이로드(c$orig$size)를
##!     검사. 내부->외부 방향이며 임계(기본 100MB) 초과 전송이면 유출 의심.
##!   - 명시적 프록시를 거친 연결(PC -> 배운 프록시·proxy_servers)도 외부로 본다(proxy_common.zeek).
##!     프록시가 출발지인 연결(프록시 -> 인터넷)은 같은 전송을 PC 쪽에서 보므로 뺀다.
##!
##! 증적(Evidence) 연동  ※ 단일 연결형
##!   - 연결 하나로 탐지가 끝나므로 evidence_id = <src>|large-transfer|<dst>|<uid>
##!     (uid 를 끝에 붙여 연결 단위 유일성 확보 + 다른 룰과 형식 일관).
##!   - notice·evidence 가 동일 uid 를 들고 가, conn.log 원본까지 바로 조인된다.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./proxy_common

module NSM;

export {
    const detect_large_transfer_exfil = T &redef;
}

event connection_state_remove(c: connection)
    {
    if ( !detect_large_transfer_exfil )
        return;

    if ( c$orig$size > exfil_bytes_threshold && exfil_outbound(c) )
        {
        # 예외(예외 파일). 백업·동기화처럼 허용한 대용량 전송은 목적지·도메인 축으로 뺀다.
        if ( NSM::exception_drop(Exfil_Large_Transfer, c) )
            return;

        local mb = c$orig$size / (1024.0 * 1024.0);
        # service 는 버전에 따라 set[string] 이므로 cat() 으로 안전하게 문자열화.
        local svc = (c?$conn && c$conn?$service) ? cat(c$conn$service) : "-";
        # 프록시를 거쳤으면 실제 목적지 이름과 프록시를 근거에 남긴다
        local name = conn_dest_name(c);
        local px = proxy_detail(c);
        local extra = ( name != "" ? cat(" host=", name) : "" ) + px;

        # 단일 연결 탐지. 다른 룰과 형식 통일: <src>|large-transfer|<dst>|<uid>
        #   uid 를 끝에 유지해 연결 단위 유일성은 그대로 확보(집계형의 time_bucket 대체).
        local eid = cat(c$id$orig_h, "|large-transfer|", c$id$resp_h, "|", c$uid);

        # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
        local nid = cat(c$id$orig_h, c$id$resp_h, "large-exfil");
        if ( NSM::notice_suppressed(Exfil_Large_Transfer, nid) )
            return;

        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Exfil_Large_Transfer,
            $technique="T1041",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="outbound_bulk_transfer",
            $uid=c$uid,
            $detail=fmt("orig_bytes=%d service=%s %.1fMB%s", c$orig$size, svc, mb, extra)]);

        NOTICE([$note=Exfil_Large_Transfer,
                $conn=c,
                $src=c$id$orig_h,
                $msg=fmt("Large outbound transfer (exfil?): %s -> %s %.1f MB service=%s%s",
                         c$id$orig_h, c$id$resp_h, mb, svc, extra),
                $sub=fmt("orig_size=%d service=%s%s", c$orig$size, svc, extra),
                $identifier=nid,
                $suppress_for=suppress_large_exfil,
                $evidence_id=eid]);
        }
    }
