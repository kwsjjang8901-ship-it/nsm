@load base/frameworks/notice
@load base/utils/site
@load ./main
@load ./attack_mapping
@load ./evidence_log   # evidence_count_of (evidence_id 별 실제 근거 건수) 참조
@load ./notice_aggregation   # dup_count / dedup_emit_first 참조
@load ./exceptions           # exception_id / disposition 참조

module NSM;

export {
    redef enum Log::ID += { DETECTION_LOG };

    type DetectionInfo: record {
        ts:               time   &log;
        detection_id:     string &log;
        diagnosis:        string &log;
        techniques:       string &log &optional;
        category:         string &log;
        killchain_stages: string &log &optional;
        severity:         string &log;
        first_seen:       time   &log &optional;
        last_seen:        time   &log &optional;
        attacker:         addr   &log &optional;
        attacker_subnet:  subnet &log &optional;
        victims:          string &log &optional;
        evidence_count:   count  &log &default=0;
        evidence_ids:     string &log &optional;
        disposition:      string &log &optional;   # suppress 예외에 맞은 탐지: suppressed(Manager 는 알림 안 함)
        exception_id:     string &log &optional;   # 맞은 예외 id
        ## 같은 공격이 이어져 나온 탐지를 묶는 사건 id(그 사건의 첫 탐지 detection_id)와 몇 번째인지.
        ##   occurrence > 1 은 진행 중인 같은 사건의 갱신: Manager 는 새 알림 없이 사건의 횟수·마지막 시각을 갱신한다.
        ##   first_seen 은 사건의 첫 탐지 시각이다.
        incident_id:      string &log &optional;
        occurrence:       count  &log &optional;
    };

    ## 같은 (탐지 종류, 공격자, 피해 host)의 탐지가 이 간격 안에 다시 나오면 같은 사건으로 묶는다.
    ##   집계형 룰의 창(5분·10분)보다 길어야 창마다 나오는 탐지가 이어진다.
    const detection_continue_gap = 15min &redef;

    global write_detection: function(d: DetectionInfo);

    const diagnosis_map: table[Notice::Type] of string = {
        [Port_Scan]              = "NSM.Recon.PortScan",
        [Host_Scan]              = "NSM.Recon.HostScan",
        [SQL_Injection]          = "NSM.WebAttack.SqlInjection",
        [Webshell_Access]        = "NSM.WebAttack.Webshell",
        [NTLM_Spray]             = "NSM.CredentialAccess.NtlmSpray",
        [Kerberos_Spray]         = "NSM.CredentialAccess.KerberosSpray",
        [Kerberos_Bruteforce]    = "NSM.CredentialAccess.KerberosBruteforce",
        [Kerberoasting]          = "NSM.CredentialAccess.Kerberoasting",
        [ASREP_Roasting]         = "NSM.CredentialAccess.AsrepRoasting",
        [NTLM_Credential_Leak]   = "NSM.CredentialAccess.NtlmCredentialLeak",
        [Outbound_SMB]           = "NSM.Exfiltration.OutboundSmb",
        [WinRM_Lateral]          = "NSM.LateralMovement.WinrmAccess",
        [DCOM_Lateral]           = "NSM.LateralMovement.DcomExec",
        [SMB_Ransomware]         = "NSM.Impact.SmbRansomware",
        [Name_Poisoning]         = "NSM.CredentialAccess.NamePoisoning",
        [DCSync]                 = "NSM.CredentialAccess.DcSync",
        [Nonstandard_Port]       = "NSM.C2.NonstandardPort",
        [Long_Connection]        = "NSM.C2.LongConnection",
        [Unknown_Protocol]       = "NSM.C2.UnknownProtocol",
        [SSH_Bruteforce]         = "NSM.CredentialAccess.SshBruteforce",
        [FTP_Bruteforce]         = "NSM.CredentialAccess.FtpBruteforce",
        [TLS_Heartbleed]         = "NSM.WebAttack.Heartbleed",
        [Cross_Site_Scripting]   = "NSM.WebAttack.Xss",
        [HTTP_Bruteforce]        = "NSM.CredentialAccess.HttpBruteforce",
        [TLS_Beaconing]          = "NSM.C2.TlsBeaconing",
        [Remote_Service_Creation] = "NSM.LateralMovement.RemoteService",
        [Remote_Task_Creation]   = "NSM.LateralMovement.RemoteTask",
        [Remote_WMI_Execution]   = "NSM.LateralMovement.RemoteWmi",
        [Machine_Account_Misuse] = "NSM.CredentialAccess.MachineAccountMisuse",
        [AI_Service_Upload]      = "NSM.Exfiltration.AiServiceUpload",
        [AI_API_From_Server]     = "NSM.C2.AiApiFromServer",
        [AI_Service_Exploit]     = "NSM.WebAttack.AiServiceExploit",
        [SMB_Admin_Share]        = "NSM.LateralMovement.SmbAccess",
        [RDP_Lateral]            = "NSM.LateralMovement.RdpAccess",
        [SSH_Lateral]            = "NSM.LateralMovement.SshAccess",
        [HTTP_Beaconing]         = "NSM.C2.HttpBeaconing",
        [DNS_Tunneling]          = "NSM.C2.DnsTunneling",
        [Encrypted_C2]           = "NSM.C2.EncryptedChannel",
        [Exfil_Large_Transfer]   = "NSM.Exfiltration.LargeTransfer",
        [Exfil_Volume_Aggregate] = "NSM.Exfiltration.VolumeAggregate",
        [Exfil_DNS]              = "NSM.Exfiltration.DnsTunnel",
        [Exfil_Web_Upload]       = "NSM.Exfiltration.WebUpload",
        [DGA_Domain]             = "NSM.C2.DgaDomain",
        [Correlated_KillChain]   = "NSM.Correlation",
    } &redef;

    # stage_name_map 은 main.zeek 로 이동(evidence_log 와 공용). NSM::stage_name_map 사용.

    global attacker_segment: function(a: addr): subnet;
}

function write_detection(d: DetectionInfo)
    {
    Log::write(NSM::DETECTION_LOG, d);
    }

function attacker_segment(a: addr): subnet
    {
    if ( a in Site::local_nets_table )
        return Site::local_nets_table[a];
    return ( is_v4_addr(a) ) ? mask_addr(a, 24) : mask_addr(a, 64);
    }

type OngoingIncident: record {
    incident_id: string;
    first_seen:  time;
    occurrences: count &default=1;
};

## (탐지 종류|공격자|피해 host) -> 진행 중인 사건. 마지막 탐지 후 detection_continue_gap 이 지나면 끝난 사건.
##   클러스터에서는 탐지를 낸 노드별 상태다(집계형 탐지는 매니저가 내므로 한 곳에 모인다).
global ongoing_incidents: table[string] of OngoingIncident &write_expire=detection_continue_gap;

hook Notice::policy(n: Notice::Info) &priority=-6
    {
    if ( n$note == Correlated_KillChain )
        return;

    if ( n$note !in diagnosis_map )
        return;

    # 계약: notice.log 에 기록되는 notice 1건 = detection 1건.
    #   notice_aggregation(-5)이 묶은 중복 건은 ACTION_LOG 가 제거돼 있으므로 제외.
    if ( Notice::ACTION_LOG !in n$actions )
        return;
    #   emit_first 모드에서는 첫 건이 이미 detection 으로 기록됐으므로
    #   창 종료 시 나오는 요약 notice(dup_count)는 detection 을 추가하지 않는다.
    #   (보류 모드에서는 요약 notice 가 유일한 기록이므로 그대로 남긴다)
    if ( n?$dup_count && NSM::dedup_emit_first )
        return;

    local d: DetectionInfo;
    d$ts           = n$ts;
    if ( n?$evidence_id )
        d$detection_id = n$evidence_id;
    else
        d$detection_id = cat(n$note, "-", n$ts);
    d$diagnosis    = diagnosis_map[n$note];
    d$category     = "Single";
    d$severity     = "Information";
    d$first_seen   = n$ts;
    d$last_seen    = n$ts;

    if ( n$note in stage_name_map )
        d$killchain_stages = stage_name_map[n$note];

    if ( n?$disposition )
        d$disposition = n$disposition;
    if ( n?$exception_id )
        d$exception_id = n$exception_id;

    if ( n?$attack )
        d$techniques = n$attack;
    else if ( n$note in NSM::attack_map )
        d$techniques = NSM::attack_map[n$note];

    if ( n?$src )
        {
        d$attacker        = n$src;
        d$attacker_subnet = attacker_segment(n$src);
        }
    # victims: 확산 룰(06/15/16)은 lm_targets(피해 host 집합)를 우선 사용하고,
    #   그 외에는 notice 의 dst 를 쓴다. 최대 chain_max_victims 개까지 표시(초과 생략).
    if ( n?$lm_targets && |n$lm_targets| > 0 )
        {
        local vout: vector of string = vector();
        for ( lv in n$lm_targets )
            {
            if ( |vout| >= chain_max_victims )
                break;
            vout[|vout|] = cat(lv);
            }
        d$victims = join_string_vec(vout, ",");
        }
    else if ( n?$dst )
        d$victims = cat(n$dst);

    # evidence_count: evidence.log 에 실제 기록된 근거 행 수를 반영한다.
    #   (evidence_id 별 누적 카운터. 기록이 없으면 최소 1로 둔다)
    if ( n?$evidence_id )
        {
        local ec = NSM::evidence_count_of(n$evidence_id);
        d$evidence_count = ( ec > 0 ) ? ec : 1;
        }
    else
        d$evidence_count = 1;
    if ( n?$evidence_id )
        d$evidence_ids = n$evidence_id;

    # 진행 중인 같은 사건이면 사건 id 를 이어 받고 횟수를 올린다.
    local ikey = cat(n$note, "|", d?$attacker ? cat(d$attacker) : "-", "|", d?$victims ? d$victims : "-");
    if ( ikey in ongoing_incidents )
        {
        local inc = ongoing_incidents[ikey];
        inc$occurrences += 1;
        ongoing_incidents[ikey] = inc;          # 쓰기로 만료 시각을 늦춘다
        d$incident_id = inc$incident_id;
        d$occurrence  = inc$occurrences;
        d$first_seen  = inc$first_seen;
        }
    else
        {
        ongoing_incidents[ikey] = OngoingIncident($incident_id=d$detection_id, $first_seen=d$first_seen);
        d$incident_id = d$detection_id;
        d$occurrence  = 1;
        }

    write_detection(d);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::DETECTION_LOG, [$columns=DetectionInfo, $path="nsm_detection"]);
    }
