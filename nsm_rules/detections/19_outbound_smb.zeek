##! ============================================================================
##! [19] 외부향 SMB / NTLM 자격증명 유출 — T1048 / T1187 (2026-11 신규)
##!
##! 탐지 원리
##!   - Outbound_SMB : 내부 호스트가 외부(공인) 주소의 SMB(445/139)와 TCP 연결을 "성립"시킴.
##!       기업망에서 외부 SMB 는 경계에서 막혀야 하는 정책 위반이며, 데이터 유출 경로가 된다.
##!       SYN 만 나가고 막힌 시도는 세지 않는다(connection_established 기준).
##!   - NTLM_Credential_Leak : 내부 호스트가 외부 서버에 NTLM AUTHENTICATE 를 보냄.
##!       강제 인증(문서·바로가기의 UNC 경로, 피싱 메일 등)으로 NetNTLM 해시가 외부로 나가
##!       오프라인 크래킹·릴레이에 쓰인다. SMB 외에 NTLM 을 실어 나르는 프로토콜(DCE-RPC 등)도 포함.
##!   - 둘 다 단건 탐지. (src, dst[, 계정]) 단위로 suppress.
##!
##! 상관 계약: notice $src = 내부 출발지, $dst = 외부 서버.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/ntlm
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    ## SMB 서비스 포트
    const outbound_smb_ports: set[port] = { 445/tcp, 139/tcp } &redef;

    ## 예외 출발지(외부 파일 공유가 허용된 장비 등).
    const outbound_smb_allowlist: set[subnet] = {} &redef;

    ## 예외 목적지(업무상 허용한 외부 SMB/NTLM 서버, 예: 협력사 파일 서버·클라우드 파일 공유).
    const outbound_smb_allowed_dsts: set[subnet] = {} &redef;
}

function outbound_smb_target(c: connection, note: Notice::Type): bool
    {
    if ( ! Site::is_local_addr(c$id$orig_h) || Site::is_local_addr(c$id$resp_h) )
        return F;
    # 예외(예외 파일 + 기존 outbound_smb_allowlist·outbound_smb_allowed_dsts)
    if ( NSM::exception_drop(note, c) )
        return F;
    return T;
    }

event zeek_init()
    {
    if ( |outbound_smb_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:outbound_smb_allowlist",
            [$scope=set("Outbound_SMB", "NTLM_Credential_Leak"), $src=outbound_smb_allowlist]);
    if ( |outbound_smb_allowed_dsts| > 0 )
        NSM::exception_add_legacy("legacy:outbound_smb_allowed_dsts",
            [$scope=set("Outbound_SMB", "NTLM_Credential_Leak"), $dst=outbound_smb_allowed_dsts]);
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p !in outbound_smb_ports || ! outbound_smb_target(c, Outbound_SMB) )
        return;

    local eid = cat(c$id$orig_h, "|outbound-smb|", c$id$resp_h, "|", c$uid);

    if ( NSM::evidence_is_new(eid, "conn") )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Outbound_SMB,
            $technique="T1048",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="smb_outbound_connection",
            $uid=c$uid,
            $detail=fmt("port=%s", c$id$resp_p)]);

    NOTICE([$note=Outbound_SMB,
            $conn=c,
            $msg=fmt("Outbound SMB connection to external host: %s -> %s:%s",
                     c$id$orig_h, c$id$resp_h, c$id$resp_p),
            $identifier=cat(c$id$orig_h, c$id$resp_h, "outbound-smb"),
            $suppress_for=1hr,
            $evidence_id=eid]);
    }

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! outbound_smb_target(c, NTLM_Credential_Leak) )
        return;

    local user = request?$user_name ? request$user_name : "";
    if ( user == "" )
        return;   # 익명 인증은 해시가 없다
    if ( request?$domain_name && request$domain_name != "" )
        user = cat(request$domain_name, "\\", user);

    local eid = cat(c$id$orig_h, "|ntlm-leak|", c$id$resp_h, "|", c$uid);

    if ( NSM::evidence_is_new(eid, user) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=NTLM_Credential_Leak,
            $technique="T1187",
            $account=user,
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="ntlm_authenticate_external",
            $uid=c$uid,
            $detail=fmt("port=%s workstation=%s", c$id$resp_p,
                        request?$workstation ? request$workstation : "-")]);

    NOTICE([$note=NTLM_Credential_Leak,
            $conn=c,
            $msg=fmt("NTLM credentials sent to external host: %s -> %s:%s (account %s)",
                     c$id$orig_h, c$id$resp_h, c$id$resp_p, user),
            $sub=user,
            $identifier=cat(c$id$orig_h, c$id$resp_h, to_lower(user), "ntlm-leak"),
            $suppress_for=1hr,
            $evidence_id=eid]);
    }
