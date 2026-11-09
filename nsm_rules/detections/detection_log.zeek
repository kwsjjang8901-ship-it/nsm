@load base/frameworks/notice
@load base/utils/site
@load ./main
@load ./attack_mapping
@load ./evidence_log   # evidence_count_of (evidence_id 별 실제 근거 건수) 참조

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
    };

    global write_detection: function(d: DetectionInfo);

    const diagnosis_map: table[Notice::Type] of string = {
        [Port_Scan]              = "NSM.Recon.PortScan",
        [Host_Scan]              = "NSM.Recon.HostScan",
        [SQL_Injection]          = "NSM.WebAttack.SqlInjection",
        [Webshell_Access]        = "NSM.WebAttack.Webshell",
        [NTLM_Spray]             = "NSM.CredentialAccess.NtlmSpray",
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

hook Notice::policy(n: Notice::Info) &priority=-6
    {
    if ( n$note == Correlated_KillChain )
        return;

    if ( n$note !in diagnosis_map )
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

    write_detection(d);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::DETECTION_LOG, [$columns=DetectionInfo, $path="nsm_detection"]);
    }
