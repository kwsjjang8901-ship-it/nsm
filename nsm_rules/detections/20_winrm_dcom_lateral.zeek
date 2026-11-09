##! ============================================================================
##! [20] WinRM / DCOM 내부 확산 — T1021.006 / T1021.003 (2026-11 신규)
##!
##! 탐지 원리 (15 RDP·16 SSH 와 같은 fan-out 구조)
##!   - 한 내부 출발지가 lm_mgmt_epoch 안에 원격 실행 채널로 접속한 "고유 내부 목적지" 수가
##!     임계 이상이면 확산으로 판정한다(epoch_result, 창당 1건).
##!   - WinRM_Lateral : WinRM(5985 HTTP / 5986 HTTPS) TCP 연결 성립
##!       PowerShell Remoting, evil-winrm, CrackMapExec winrm 등
##!   - DCOM_Lateral  : DCE-RPC ISystemActivator(000001a0-...-46) RemoteCreateInstance(opnum 4)
##!       원격 COM 객체 생성. MMC20.Application·ShellWindows 를 이용한 원격 실행(dcomexec),
##!       원격 WMI(wmiexec)도 이 호출로 시작한다.
##!
##! 오탐 통제: 관리 서버(SCCM·모니터링·Ansible·점프 서버)는 원격 관리를 대량으로 하므로
##!   lm_mgmt_allowlist 에 등록하는 것이 핵심이다. 내부 -> 내부만 본다.
##!
##! 상관 계약: notice $src = 확산 기점 host, $lm_targets = 피해 host 집합.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dce-rpc
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const lm_mgmt_epoch = 5min &redef;          # 집계 윈도우
    const winrm_lm_threshold = 3 &redef;         # WinRM 고유 목적지 수
    const dcom_lm_threshold  = 3 &redef;         # DCOM 원격 객체 생성 고유 목적지 수

    ## WinRM 포트
    const winrm_ports: set[port] = { 5985/tcp, 5986/tcp } &redef;

    ## 관리 인프라 출발지 예외(SCCM·모니터링·Ansible·점프 서버 등). 오탐 통제 핵심.
    const lm_mgmt_allowlist: set[subnet] = {} &redef;
}

redef record connection += {
    ## ISystemActivator 로 바인드된 (fid, ctx_id)
    nsm_dcom_ctx: set[count, count] &optional;
};

const isystemactivator_uuid = "000001a0-0000-0000-c000-000000000046";
const remote_create_instance_opnum = 4;

function lm_mgmt_target(c: connection): bool
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    if ( ! Site::is_local_addr(src) || ! Site::is_local_addr(dst) || src == dst )
        return F;
    return src !in lm_mgmt_allowlist;
    }

## epoch_result 공통 처리: 임계 이상이면 표본(목적지)마다 근거 1행 + NOTICE 1건
function lm_mgmt_report(note: Notice::Type, technique: string, operation: string, label: string,
                        tag: string, threshold: count, key: SumStats::Key, res: SumStats::ResultVal)
    {
    local n = res$unique;
    if ( n < threshold )
        return;

    local eid = cat(key$host, "|", tag, "|", time_bucket(lm_mgmt_epoch));
    local targets: set[addr] = set();
    local shown = "";

    if ( res?$samples )
      for ( i in res$samples )
        {
        if ( ! res$samples[i]?$str )
            next;
        local dst = to_addr(res$samples[i]$str);
        if ( dst in targets )
            next;
        add targets[dst];
        shown += fmt("%s ", dst);

        # 근거를 NOTICE 보다 먼저 적재한다(detection 의 evidence_count 산출 시점).
        if ( NSM::evidence_is_new(eid, cat(dst)) )
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=note,
                $technique=technique,
                $src=key$host,
                $dst=dst,
                $operation=operation,
                $detail=fmt("unique_dst=%d window=%s", n, lm_mgmt_epoch)]);
        }

    NOTICE([$note=note,
            $src=key$host,
            $msg=fmt("%s lateral movement: %s -> %d unique hosts in %s", label, key$host, n, lm_mgmt_epoch),
            $sub=fmt("unique_dst=%d sample=[%s]", n, shown),
            $identifier=cat(key$host, tag, time_bucket(lm_mgmt_epoch)),
            $suppress_for=lm_mgmt_epoch,
            $evidence_id=eid,
            $lm_targets=targets]);
    }

event zeek_init()
    {
    # UNIQUE + SAMPLE 를 한 스트림에 둔다(str = 목적지 주소 하나라 섞일 값이 없다).
    local r_winrm = SumStats::Reducer($stream="nsm.winrm_lm", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                      $num_samples=lm_num_samples);
    SumStats::create([
        $name         = "nsm-detect-winrm-lateral",
        $epoch        = lm_mgmt_epoch,
        $reducers     = set(r_winrm),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.winrm_lm" in result )
                lm_mgmt_report(WinRM_Lateral, "T1021.006", "winrm_connect", "WinRM", "winrm-lm",
                               winrm_lm_threshold, key, result["nsm.winrm_lm"]);
            }
    ]);

    local r_dcom = SumStats::Reducer($stream="nsm.dcom_lm", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                     $num_samples=lm_num_samples);
    SumStats::create([
        $name         = "nsm-detect-dcom-lateral",
        $epoch        = lm_mgmt_epoch,
        $reducers     = set(r_dcom),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.dcom_lm" in result )
                lm_mgmt_report(DCOM_Lateral, "T1021.003", "dcom_remote_create_instance", "DCOM", "dcom-lm",
                               dcom_lm_threshold, key, result["nsm.dcom_lm"]);
            }
    ]);
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p !in winrm_ports || ! lm_mgmt_target(c) )
        return;
    SumStats::observe("nsm.winrm_lm", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
    }

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
    {
    if ( uuid_to_string(uuid) != isystemactivator_uuid )
        return;
    if ( ! c?$nsm_dcom_ctx )
        c$nsm_dcom_ctx = set();
    add c$nsm_dcom_ctx[fid, ctx_id];
    }

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if ( opnum != remote_create_instance_opnum || ! c?$nsm_dcom_ctx || [fid, ctx_id] !in c$nsm_dcom_ctx )
        return;
    if ( ! lm_mgmt_target(c) )
        return;
    SumStats::observe("nsm.dcom_lm", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
    }
