##! ============================================================================
##! [34] AD 공격(DCE-RPC) — 강제 인증·원격 레지스트리 하이브 저장·Zerologon·AD 정보 수집 (2026-11 신규)
##!
##! 23 DCSync·31 원격 실행과 같이 Zeek 기본 DCE-RPC 스크립트가 응답 시점(dce_rpc_response priority 5)에
##! 채운 c$dce_rpc$endpoint·operation 으로 판정한다. 바인드의 인터페이스와 요청의 opnum 은 패킷 암호화
##! (packet privacy)여도 평문이라, SMB 명명된 파이프와 TCP(동적 포트) 모두 보인다. 인자(대상 경로 등)는 보지 않는다.
##!
##! Coerced_Authentication (T1187) — 대상 서버가 공격자에게 인증하도록 만드는 호출(NTLM 릴레이의 앞단).
##!   PetitPotam(efsrpc·efsrpc2 의 모든 호출), PrinterBug(spoolss RpcRemoteFindFirstPrinterChangeNotification[Ex]),
##!   DFSCoerce(netdfs NetrDfsAddStdRoot·RemoveStdRoot), ShadowCoerce(FileServerVssAgent IsPathShadowCopied·IsPathSupported).
##!   spoolss 알림 등록은 클라이언트 -> 프린트 서버에서 정상이라, 기본은 대상이 DC(23 의 DC 목록·학습)일 때만 본다.
##! Remote_Registry_Dump (T1003.002) — winreg BaseRegSaveKey[Ex]: 레지스트리 하이브(SAM·SECURITY·SYSTEM)를 원격으로
##!   파일로 저장(impacket secretsdump·reg save \\host). 정상 원격 관리에서는 드물다.
##! Zerologon_Attempt (T1210) — netlogon NetrServerAuthenticate* 가 한 (출발지, 대상)에서 zerologon_epoch(1분) 안
##!   zerologon_threshold(20)회 이상. 정상 보안 채널 수립은 1~2회, Zerologon(CVE-2020-1472)은 수백~수천 회 시도한다.
##! AD_Enumeration (T1087.002) — BloodHound/SharpHound 의 세션·로컬 관리자 수집처럼 한 출발지가 ad_enum_epoch(5분)
##!   안 서로 다른 host ad_enum_threshold(10)대 이상에 srvsvc NetrSessionEnum·wkssvc NetrWkstaUserEnum·
##!   samr SamrGetMembersInAlias 를 호출. DC 한 대에 대한 계정 조회(net user /domain)는 정상 관리에서도 흔해 보지 않는다.
##!   Windows LDAP 는 보통 서명·암호화돼 검색 필터가 보이지 않으므로 LDAP 는 쓰지 않는다.
##!
##! 대상은 내부 host 만(출발지는 내외부 모두). 관리 서버·백업 도구·인벤토리 도구는 예외 엔진(출발지 축)으로 뺀다.
##! 상관 계약: notice $src = 호출한 host, $dst = 대상(집계형은 표본 대상).
##!   묶음: AD_Enumeration = 정찰, Coerced_Authentication·Remote_Registry_Dump = 자격증명, Zerologon_Attempt = 도메인 장악.
##! ============================================================================

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dce-rpc
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./auth_context
@load ./23_dcsync

module NSM;

export {
    const detect_coerced_auth = T &redef;
    const detect_remote_registry_dump = T &redef;
    const detect_zerologon = T &redef;
    const detect_ad_enumeration = T &redef;

    ## 강제 인증 호출 (인터페이스, 호출)
    const coerce_ops: set[string, string] = {
        ["spoolss", "RpcRemoteFindFirstPrinterChangeNotification"],
        ["spoolss", "RpcRemoteFindFirstPrinterChangeNotificationEx"],
        ["netdfs", "NetrDfsAddStdRoot"], ["netdfs", "NetrDfsRemoveStdRoot"], ["netdfs", "NetrDfsAddStdRootForced"],
        ["FileServerVssAgent", "IsPathShadowCopied"], ["FileServerVssAgent", "IsPathSupported"],
    } &redef;
    ## 모든 호출을 강제 인증으로 보는 인터페이스(원격 EFS: efsrpc 는 \efsrpc, efsrpc2 는 \lsarpc 파이프로 바인드)
    const coerce_any_op_endpoints: set[string] = { "efsrpc", "efsrpc2" } &redef;
    ## T 면 spoolss 호출은 대상이 DC 일 때만 본다(프린트 서버로 가는 알림 등록은 정상)
    const coerce_spoolss_dc_only = T &redef;

    const registry_dump_ops: set[string] = { "BaseRegSaveKey", "BaseRegSaveKeyEx" } &redef;

    const zerologon_ops: set[string] = {
        "NetrServerAuthenticate", "NetrServerAuthenticate2", "NetrServerAuthenticate3",
    } &redef;
    const zerologon_epoch = 1min &redef;
    const zerologon_threshold = 20 &redef;

    ## AD 정보 수집 호출 (인터페이스, 호출)
    const ad_enum_ops: set[string, string] = {
        ["srvsvc", "NetrSessionEnum"], ["wkssvc", "NetrWkstaUserEnum"], ["samr", "SamrGetMembersInAlias"],
    } &redef;
    const ad_enum_epoch = 5min &redef;
    ## 창 안에 위 호출을 받은 서로 다른 host 수
    const ad_enum_threshold = 10 &redef;
    const ad_enum_num_samples = 10 &redef;
}

# 호출한 계정: 같은 연결의 NTLM 인증, 없으면 같은 대상으로 받은 티켓(cifs·host·rpcss)의 계정.
function ad_attack_account(c: connection): string
    {
    if ( c?$ntlm && c$ntlm?$username && c$ntlm$username != "" )
        return to_lower(c$ntlm?$domainname && c$ntlm$domainname != "" ? cat(c$ntlm$domainname, "\\", c$ntlm$username) : c$ntlm$username);
    return NSM::auth_accounts(c$id$orig_h, c$id$resp_h, set("cifs", "host", "rpcss"));
    }

# 단건(강제 인증·하이브 저장): (출발지, 대상, 종류) 1시간 억제
function ad_attack_report(c: connection, note: Notice::Type, technique: string, kind: string)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    if ( NSM::exception_drop(note, c) )
        return;
    local nid = cat(src, dst, kind);
    if ( NSM::notice_suppressed(note, nid) )
        return;
    local ep = c$dce_rpc$endpoint;
    local op = c$dce_rpc$operation;
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
            $account=ad_attack_account(c),
            $operation=fmt("%s::%s", ep, op),
            $detail=fmt("endpoint=%s operation=%s port=%s pipe=%s dst_is_dc=%s", ep, op, c$id$resp_p, pipe,
                        dcsync_is_dc(dst) ? "T" : "F")]);
    NOTICE([$note=note,
            $conn=c,
            $msg=fmt("%s: %s -> %s (%s::%s)", kind, src, dst, ep, op),
            $sub=fmt("%s::%s", ep, op),
            $identifier=nid,
            $suppress_for=1hr,
            $evidence_id=eid]);
    }

event zeek_init()
    {
    # Zerologon: (출발지, 대상)별 인증 호출 수
    local zr = SumStats::Reducer($stream="nsm.zerologon", $apply=set(SumStats::SUM));
    local zs = SumStats::Reducer($stream="nsm.zerologon.sample", $apply=set(SumStats::SAMPLE), $num_samples=3);
    SumStats::create([
        $name="nsm-detect-zerologon", $epoch=zerologon_epoch, $reducers=set(zr, zs),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.zerologon"]$sum;
            },
        $threshold=zerologon_threshold + 0.0,
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local dst = to_addr(key$str);
            local n = double_to_count(result["nsm.zerologon"]$sum);
            local eid = cat(src, "|zerologon|", dst, "|", time_bucket(zerologon_epoch));
            local uids: vector of string = vector();
            local uid_seen: set[string] = set();
            local op = "-";
            if ( "nsm.zerologon.sample" in result && result["nsm.zerologon.sample"]?$samples )
                for ( i in result["nsm.zerologon.sample"]$samples )
                    {
                    local o = result["nsm.zerologon.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string1(o$str, /\|/);     # "uid|호출"
                    if ( p[0] !in uid_seen )
                        {
                        add uid_seen[p[0]];
                        uids += p[0];
                        }
                    if ( |p| > 1 )
                        op = p[1];
                    }
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=Zerologon_Attempt,
                $technique="T1210",
                $src=src,
                $dst=dst,
                $uid=|uids| > 0 ? uids[0] : "",
                $operation=fmt("netlogon::%s", op),
                $detail=fmt("netlogon_auth_calls=%d window=%s dst_is_dc=%s sample_uids=%s", n, zerologon_epoch,
                            dcsync_is_dc(dst) ? "T" : "F", join_string_vec(uids, ","))]);
            NOTICE([$note=Zerologon_Attempt,
                    $src=src,
                    $dst=dst,
                    $msg=fmt("Possible Zerologon: %s made %d netlogon authentication calls to %s in %s", src, n, dst, zerologon_epoch),
                    $sub=fmt("netlogon_auth_calls=%d", n),
                    $identifier=cat(src, "zerologon", dst),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);

    # AD 정보 수집: 출발지별 호출을 받은 고유 host 수
    local er = SumStats::Reducer($stream="nsm.ad_enum", $apply=set(SumStats::UNIQUE));
    local es = SumStats::Reducer($stream="nsm.ad_enum.sample", $apply=set(SumStats::SAMPLE), $num_samples=ad_enum_num_samples);
    SumStats::create([
        $name="nsm-detect-ad-enumeration", $epoch=ad_enum_epoch, $reducers=set(er, es),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.ad_enum"]$unique + 0.0;
            },
        $threshold=ad_enum_threshold + 0.0,
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local n = result["nsm.ad_enum"]$unique;
            local eid = cat(src, "|ad-enum|", time_bucket(ad_enum_epoch));
            local first_dst: addr = 0.0.0.0;
            local ops: set[string] = set();
            if ( "nsm.ad_enum.sample" in result && result["nsm.ad_enum.sample"]?$samples )
                for ( i in result["nsm.ad_enum.sample"]$samples )
                    {
                    local o = result["nsm.ad_enum.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);      # "대상|인터페이스::호출|uid|계정"
                    if ( |p| < 4 )
                        next;
                    local d = to_addr(p[0]);
                    if ( first_dst == 0.0.0.0 )
                        first_dst = d;
                    add ops[p[1]];
                    if ( ! NSM::evidence_is_new(eid, p[0]) )
                        next;
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=AD_Enumeration,
                        $technique="T1087.002",
                        $src=src,
                        $dst=d,
                        $uid=p[2],
                        $account=p[3],
                        $operation=p[1],
                        $detail=fmt("unique_hosts=%d window=%s", n, ad_enum_epoch)]);
                    }
            local opv: vector of string = vector();
            for ( x in ops )
                opv += x;
            NOTICE([$note=AD_Enumeration,
                    $src=src,
                    $dst=first_dst,
                    $msg=fmt("AD enumeration: %s queried sessions/local groups on %d hosts in %s (BloodHound/SharpHound?)",
                             src, n, ad_enum_epoch),
                    $sub=fmt("unique_hosts=%d ops=%s", n, join_string_vec(sort(opv, strcmp), ",")),
                    $identifier=cat(src, "ad-enum"),
                    $suppress_for=ad_enum_epoch,
                    $evidence_id=eid]);
            }
    ]);
    }

# Zeek 기본 스크립트가 priority 5 에서 endpoint·operation 을 채우고, -5 에서 로그를 쓴다.
event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=0
    {
    if ( ! c?$dce_rpc || ! c$dce_rpc?$endpoint || ! c$dce_rpc?$operation )
        return;
    if ( ! Site::is_local_addr(c$id$resp_h) )
        return;
    local ep = c$dce_rpc$endpoint;
    local op = c$dce_rpc$operation;
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( detect_coerced_auth && ( ep in coerce_any_op_endpoints || [ep, op] in coerce_ops ) )
        {
        if ( ep == "spoolss" && coerce_spoolss_dc_only && ! dcsync_is_dc(dst) )
            return;
        ad_attack_report(c, Coerced_Authentication, "T1187", "coerced_auth");
        }
    else if ( detect_remote_registry_dump && ep == "winreg" && op in registry_dump_ops )
        ad_attack_report(c, Remote_Registry_Dump, "T1003.002", "registry_dump");
    else if ( detect_zerologon && ep == "netlogon" && op in zerologon_ops )
        {
        if ( NSM::exception_drop_agg(Zerologon_Attempt, c) )
            return;
        local zk: SumStats::Key = [$host=src, $str=cat(dst)];
        SumStats::observe("nsm.zerologon", zk, [$num=1]);
        SumStats::observe("nsm.zerologon.sample", zk, [$str=cat(c$uid, "|", op)]);
        }
    else if ( detect_ad_enumeration && [ep, op] in ad_enum_ops )
        {
        if ( NSM::exception_drop_agg(AD_Enumeration, c) )
            return;
        local ek: SumStats::Key = [$host=src];
        SumStats::observe("nsm.ad_enum", ek, [$str=cat(dst)]);
        SumStats::observe("nsm.ad_enum.sample", ek,
                          [$str=cat(dst, "|", ep, "::", op, "|", c$uid, "|", ad_attack_account(c))]);
        }
    }
