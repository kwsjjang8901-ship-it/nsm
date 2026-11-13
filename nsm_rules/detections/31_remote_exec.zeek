##! ============================================================================
##! [31] 단일 대상 원격 실행 — T1569.002 / T1053.005 / T1047 (2026-11 신규)
##!
##! 확산 룰(06 SMB 관리 공유 2대, 20 WinRM·DCOM 3대)은 여러 대를 노려야 탐지된다. PsExec·schtasks·wmiexec 로
##! 서버 한 대만 노리면 보이지 않았다. 원격 실행에 쓰는 DCE-RPC 호출 자체를 1건으로 탐지한다.
##!
##! Remote_Service_Creation (T1569.002) — svcctl CreateService*(PsExec, impacket smbexec·psexec, sc \\host create)
##! Remote_Task_Creation    (T1053.005) — atsvc NetrJobAdd, ITaskSchedulerService SchRpcRegisterTask(at, schtasks /s)
##! Remote_WMI_Execution    (T1047)     — IWbemServices ExecMethod*(wmic /node process call create, wmiexec)
##!
##!   - 호출 이름은 Zeek 기본 DCE-RPC 스크립트가 응답 시점(dce_rpc_response priority 5)에 바인드 정보로 채운
##!     c$dce_rpc$endpoint·operation 을 쓴다. SMB 명명된 파이프(\svcctl, \atsvc)와 TCP(동적 포트) 모두 해당.
##!     WMI 는 보통 패킷 암호화(packet privacy)지만 인터페이스(바인드)와 opnum 은 평문이라 보인다.
##!   - 조회성 호출(OpenSCManager, ExecQuery 등)은 보지 않는다.
##!   - 내부 -> 내부만. 관리 서버(SCCM·백업·배포 도구)는 예외 엔진(출발지 축)으로 뺀다.
##!
##! 단건: (출발지, 대상, 종류) 단위 1시간 억제. 상관 계약: notice $src = 실행한 host, $lm_targets = 대상 host(확산 묶음).
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/dce-rpc
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./auth_context

module NSM;

export {
    const detect_remote_exec = T &redef;
    const remote_exec_service_ops: set[string] = {
        "CreateServiceW", "CreateServiceA", "CreateServiceWOW64W", "CreateServiceWOW64A", "CreateWowService",
    } &redef;
    const remote_exec_task_ops: set[string, string] = {
        ["atsvc", "NetrJobAdd"], ["ITaskSchedulerService", "SchRpcRegisterTask"],
    } &redef;
    const remote_exec_wmi_ops: set[string] = { "ExecMethod", "ExecMethodAsync" } &redef;
}

function remote_exec_account(c: connection, kerb_prefixes: set[string]): string
    {
    if ( c?$ntlm && c$ntlm?$username && c$ntlm$username != "" )
        return to_lower(c$ntlm?$domainname && c$ntlm$domainname != "" ? cat(c$ntlm$domainname, "\\", c$ntlm$username) : c$ntlm$username);
    return NSM::auth_accounts(c$id$orig_h, c$id$resp_h, kerb_prefixes);
    }

function remote_exec_report(c: connection, note: Notice::Type, technique: string, kind: string, kerb: set[string])
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    if ( NSM::exception_drop(note, c) )
        return;
    local nid = cat(src, dst, kind);
    if ( NSM::notice_suppressed(note, nid) )
        return;
    local op = c$dce_rpc$operation;
    local ep = c$dce_rpc$endpoint;
    local pipe = c$dce_rpc?$named_pipe ? c$dce_rpc$named_pipe : "-";
    local eid = cat(src, "|", kind, "|", dst, "|", c$uid);
    if ( NSM::evidence_is_new(eid, op) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=note,
            $technique=technique,
            $src=src,
            $dst=dst,
            $uid=c$uid,
            $account=remote_exec_account(c, kerb),
            $operation=fmt("%s::%s", ep, op),
            $detail=fmt("endpoint=%s operation=%s port=%s pipe=%s", ep, op, c$id$resp_p, pipe)]);
    NOTICE([$note=note,
            $conn=c,
            $msg=fmt("Remote %s on %s from %s (%s::%s)", kind, dst, src, ep, op),
            $sub=fmt("%s::%s", ep, op),
            $identifier=nid,
            $suppress_for=1hr,
            $lm_targets=set(dst),
            $evidence_id=eid]);
    }

# Zeek 기본 스크립트가 priority 5 에서 endpoint·operation 을 채우고, -5 에서 로그를 쓴다.
event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=0
    {
    if ( ! detect_remote_exec || ! c?$dce_rpc || ! c$dce_rpc?$endpoint || ! c$dce_rpc?$operation )
        return;
    if ( ! Site::is_local_addr(c$id$orig_h) || ! Site::is_local_addr(c$id$resp_h) )
        return;
    local ep = c$dce_rpc$endpoint;
    local op = c$dce_rpc$operation;
    if ( ep == "svcctl" && op in remote_exec_service_ops )
        remote_exec_report(c, Remote_Service_Creation, "T1569.002", "service_creation", set("cifs", "host", "rpcss"));
    else if ( [ep, op] in remote_exec_task_ops )
        remote_exec_report(c, Remote_Task_Creation, "T1053.005", "task_creation", set("cifs", "host", "rpcss"));
    else if ( ep == "IWbemServices" && op in remote_exec_wmi_ops )
        remote_exec_report(c, Remote_WMI_Execution, "T1047", "wmi_execution", set("rpcss", "host"));
    }
