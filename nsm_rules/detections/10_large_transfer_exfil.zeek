##! ============================================================================
##! [13] Exfiltration (C2) - 대량 전송 : 외부로 100MB+ 업로드  (단일 연결형)
##!
##! 탐지 원리
##!   - 연결 종료(connection_state_remove) 시 originator 페이로드(c$orig$size)를
##!     검사. 내부->외부 방향이며 임계(기본 100MB) 초과 전송이면 유출 의심.
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

module NSM;

export {
    const detect_large_transfer_exfil = T &redef;
}

event connection_state_remove(c: connection)
    {
    if ( !detect_large_transfer_exfil )
        return;

    if ( Site::is_local_addr(c$id$orig_h) &&
         is_external(c$id$resp_h) &&
         c$orig$size > exfil_bytes_threshold )
        {
        local mb = c$orig$size / (1024.0 * 1024.0);
        # service 는 버전에 따라 set[string] 이므로 cat() 으로 안전하게 문자열화.
        local svc = (c?$conn && c$conn?$service) ? cat(c$conn$service) : "-";

        # 단일 연결 탐지. 다른 룰과 형식 통일: <src>|large-transfer|<dst>|<uid>
        #   uid 를 끝에 유지해 연결 단위 유일성은 그대로 확보(집계형의 time_bucket 대체).
        local eid = cat(c$id$orig_h, "|large-transfer|", c$id$resp_h, "|", c$uid);

        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Exfil_Large_Transfer,
            $technique="T1041",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="outbound_bulk_transfer",
            $uid=c$uid,
            $detail=fmt("orig_bytes=%d service=%s %.1fMB", c$orig$size, svc, mb)]);

        NOTICE([$note=Exfil_Large_Transfer,
                $conn=c,
                $src=c$id$orig_h,
                $msg=fmt("Large outbound transfer (exfil?): %s -> %s %.1f MB service=%s",
                         c$id$orig_h, c$id$resp_h, mb, svc),
                $sub=fmt("orig_size=%d service=%s", c$orig$size, svc),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "large-exfil"),
                $suppress_for=suppress_large_exfil,
                $evidence_id=eid]);
        }
    }
