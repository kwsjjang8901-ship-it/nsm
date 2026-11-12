##! ============================================================================
##! [23] DCSync — T1003.006 (2026-11 신규)
##!
##! 탐지 원리
##!   - DCSync(mimikatz lsadump::dcsync, impacket secretsdump)는 DC 인 척 디렉터리 복제 API
##!     DRSUAPI(e3514235-4b06-11d1-ab04-00c04fc2dcd2)의 DRSGetNCChanges(opnum 3)를 호출해
##!     계정 비밀번호 해시(krbtgt 포함)를 가져간다.
##!   - 정상적으로 이 호출을 하는 것은 다른 DC 뿐이다. "DC 가 아닌" 출발지의 DRSGetNCChanges 는
##!     단건으로 탐지한다(고신뢰).
##!   - DRSUAPI 는 동적 RPC 포트를 쓰지만 Zeek 의 DCE-RPC DPD 서명으로 포트와 무관하게 해석된다.
##!     패킷 프라이버시로 스텁이 암호화돼도 바인드의 인터페이스 UUID 와 요청의 opnum 은 평문이다.
##!
##! DC 판정
##!   - dcsync_domain_controllers (배포 설정에 기록, 권장)
##!   - dcsync_learn_dcs = T 이면 Kerberos 응답(AS-REP/TGS-REP)을 보낸 내부 host 를 DC 로 학습한다.
##!     (클러스터에서는 워커별로 학습하므로 고정 목록을 함께 쓰는 것이 좋다)
##!   - Azure AD Connect·ADFS 동기화 서버처럼 복제 권한을 정상적으로 쓰는 서버는 dcsync_allowlist.
##!
##! 상관 계약: notice $src = 복제를 요청한 출발지, $dst = 대상 DC.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/dce-rpc
@load base/protocols/krb
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./auth_context

module NSM;

export {
    ## 도메인 컨트롤러 주소(배포 설정에 기록).
    const dcsync_domain_controllers: set[addr] = {} &redef;

    ## Kerberos 응답을 보낸 내부 host 를 DC 로 학습할지.
    const dcsync_learn_dcs = T &redef;

    ## 복제 권한을 정상적으로 쓰는 서버(Azure AD Connect 등).
    const dcsync_allowlist: set[subnet] = {} &redef;

    ## 학습된 DC(조회용).
    global dcsync_learned_dcs: set[addr] = set();
}

redef record connection += {
    ## DRSUAPI 로 바인드된 (fid, ctx_id)
    nsm_drsuapi_ctx: set[count, count] &optional;
};

const drsuapi_uuid = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";
const drs_get_nc_changes_opnum = 3;

# 복제를 요청한 계정: 같은 연결의 NTLM 인증(c$ntlm), 없으면 같은 대상 NTLM·drsuapi·ldap 티켓 계정.
#   클러스터 워커에서는 auth_context 표가 비어 있어(매니저에 모음) 같은 연결의 NTLM 만 쓰인다.
function dcsync_account(c: connection): string
    {
    if ( c?$ntlm && c$ntlm?$username && c$ntlm$username != "" )
        return to_lower(c$ntlm?$domainname && c$ntlm$domainname != "" ? cat(c$ntlm$domainname, "\\", c$ntlm$username) : c$ntlm$username);
    return NSM::auth_accounts(c$id$orig_h, c$id$resp_h, set("e3514235-4b06-11d1-ab04-00c04fc2dcd2", "ldap"));
    }

function dcsync_is_dc(a: addr): bool
    {
    return a in dcsync_domain_controllers || a in dcsync_learned_dcs;
    }

function dcsync_learn(c: connection)
    {
    if ( dcsync_learn_dcs && Site::is_local_addr(c$id$resp_h) && c$id$resp_h !in dcsync_learned_dcs )
        add dcsync_learned_dcs[c$id$resp_h];
    }

event zeek_init()
    {
    if ( |dcsync_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:dcsync_allowlist",
            [$scope=set("DCSync"), $src=dcsync_allowlist]);
    }

event krb_as_response(c: connection, msg: KRB::KDC_Response)
    {
    dcsync_learn(c);
    }

event krb_tgs_response(c: connection, msg: KRB::KDC_Response)
    {
    dcsync_learn(c);
    }

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count)
    {
    if ( uuid_to_string(uuid) != drsuapi_uuid )
        return;
    if ( ! c?$nsm_drsuapi_ctx )
        c$nsm_drsuapi_ctx = set();
    add c$nsm_drsuapi_ctx[fid, ctx_id];
    }

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if ( opnum != drs_get_nc_changes_opnum || ! c?$nsm_drsuapi_ctx || [fid, ctx_id] !in c$nsm_drsuapi_ctx )
        return;

    local src = c$id$orig_h;
    if ( dcsync_is_dc(src) )
        return;
    # 예외(예외 파일 + 기존 dcsync_allowlist): Azure AD Connect 등 복제 권한을 정상적으로 쓰는 서버
    if ( NSM::exception_drop(DCSync, c) )
        return;

    local eid = cat(src, "|dcsync|", c$id$resp_h, "|", c$uid);

    # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
    local nid = cat(src, c$id$resp_h, "dcsync");
    if ( NSM::notice_suppressed(DCSync, nid) )
        return;

    if ( NSM::evidence_is_new(eid, "DRSGetNCChanges") )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=DCSync,
            $technique="T1003.006",
            $src=src,
            $dst=c$id$resp_h,
            $operation="drsuapi_DRSGetNCChanges",
            $uid=c$uid,
            $account=dcsync_account(c),
            $detail=fmt("port=%s target_is_known_dc=%s stub_len=%d",
                        c$id$resp_p, dcsync_is_dc(c$id$resp_h), stub_len)]);

    NOTICE([$note=DCSync,
            $conn=c,
            $msg=fmt("Possible DCSync: non-DC host %s requested directory replication (DRSGetNCChanges) from %s",
                     src, c$id$resp_h),
            $identifier=nid,
            $suppress_for=1hr,
            $evidence_id=eid]);
    }
