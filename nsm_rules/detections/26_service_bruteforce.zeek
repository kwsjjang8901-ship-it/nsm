##! ============================================================================
##! [26] SSH·FTP 무차별 대입 — T1110.001 (2026-11 신규)
##!
##! SSH_Bruteforce
##!   - 같은 출발지 -> 목적지로 svc_bf_epoch(5분) 안에 인증이 성공하지 않은 SSH 세션이 ssh_bf_threshold(20)회 이상.
##!     SSH 는 암호화라 계정·비밀번호는 못 본다. 버전 교환이 끝난 세션(c$ssh$client·server)만 세고, Zeek 의
##!     인증 추정(c$ssh$auth_success)이 성공(T)인 세션은 뺀다. 추정이 안 된 세션(값 없음)은 센다.
##!     (patator·hydra 는 시도마다 연결을 새로 열어 짧은 세션이 대량으로 생긴다. CIC-IDS2017 Tuesday SSH-Patator)
##! FTP_Bruteforce
##!   - 같은 출발지 -> 목적지로 5분 안에 FTP 로그인 실패 응답(530)이 ftp_bf_threshold(10)회 이상. 시도한 계정(USER)을 근거에 남긴다.
##!
##! 집계형: (출발지, 목적지) 키, 창 종료 시 판정(창당 1건). 예외는 관측 전에 판정(exception_drop_agg).
##! 상관 계약: notice $src = 공격 host, $dst = 대상 서버. 자격증명 탈취 묶음.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/ssh
@load base/protocols/ftp
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_ssh_bruteforce = T &redef;
    const detect_ftp_bruteforce = T &redef;
    const svc_bf_epoch = 5min &redef;
    ## 같은 (출발지, 목적지)에서 인증이 성공하지 않은 SSH 세션 수
    const ssh_bf_threshold = 20 &redef;
    ## 같은 (출발지, 목적지)에서 FTP 530(로그인 실패) 응답 수
    const ftp_bf_threshold = 10 &redef;
    const svc_bf_num_samples = 10 &redef;
}

function svc_bf_report(note: Notice::Type, tag: string, operation: string, threshold: count,
                       key: SumStats::Key, result: SumStats::Result, s_sum: string, s_sample: string, s_user: string)
    {
    if ( s_sum !in result )
        return;
    local n = double_to_count(result[s_sum]$sum);
    if ( n < threshold )
        return;
    local src = key$host;
    local dst = to_addr(key$str);
    local users = ( s_user != "" && s_user in result ) ? result[s_user]$unique : 0;
    local eid = cat(src, "|", tag, "|", dst, "|", time_bucket(svc_bf_epoch));

    if ( s_sample in result && result[s_sample]?$samples )
        for ( i in result[s_sample]$samples )
            {
            local o = result[s_sample]$samples[i];
            if ( ! o?$str )
                next;
            local p = split_string(o$str, /\|/);       # "계정|uid|부가"
            if ( |p| < 3 || ! NSM::evidence_is_new(eid, cat(p[0], "|", p[2])) )
                next;
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=note,
                $technique="T1110.001",
                $account=( p[0] == "-" ) ? "" : p[0],
                $src=src,
                $dst=dst,
                $uid=p[1],
                $operation=operation,
                $detail=( users > 0 ) ? fmt("failures=%d unique_users=%d window=%s %s", n, users, svc_bf_epoch, p[2])
                                      : fmt("failures=%d window=%s %s", n, svc_bf_epoch, p[2])]);
            }

    NOTICE([$note=note,
            $src=src,
            $dst=dst,
            $msg=fmt("%s brute force: %s -> %s, %d failed attempts in %s", to_upper(tag), src, dst, n, svc_bf_epoch),
            $sub=( users > 0 ) ? fmt("failures=%d unique_users=%d", n, users) : fmt("failures=%d", n),
            $identifier=cat(src, dst, tag, time_bucket(svc_bf_epoch)),
            $suppress_for=svc_bf_epoch,
            $evidence_id=eid]);
    }

event zeek_init()
    {
    local r_ssh = SumStats::Reducer($stream="nsm.ssh_bf", $apply=set(SumStats::SUM));
    local r_ssh_s = SumStats::Reducer($stream="nsm.ssh_bf.sample", $apply=set(SumStats::SAMPLE), $num_samples=svc_bf_num_samples);
    SumStats::create([
        $name="nsm-detect-ssh-bruteforce", $epoch=svc_bf_epoch, $reducers=set(r_ssh, r_ssh_s),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            svc_bf_report(SSH_Bruteforce, "ssh", "ssh_auth_not_successful", ssh_bf_threshold,
                          key, result, "nsm.ssh_bf", "nsm.ssh_bf.sample", "");
            }
    ]);

    local r_ftp = SumStats::Reducer($stream="nsm.ftp_bf", $apply=set(SumStats::SUM));
    local r_ftp_s = SumStats::Reducer($stream="nsm.ftp_bf.sample", $apply=set(SumStats::SAMPLE), $num_samples=svc_bf_num_samples);
    local r_ftp_u = SumStats::Reducer($stream="nsm.ftp_bf.user", $apply=set(SumStats::UNIQUE));
    SumStats::create([
        $name="nsm-detect-ftp-bruteforce", $epoch=svc_bf_epoch, $reducers=set(r_ftp, r_ftp_s, r_ftp_u),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            svc_bf_report(FTP_Bruteforce, "ftp", "ftp_login_failure", ftp_bf_threshold,
                          key, result, "nsm.ftp_bf", "nsm.ftp_bf.sample", "nsm.ftp_bf.user");
            }
    ]);
    }

# SSH: 버전 교환이 끝났고 인증 성공으로 추정되지 않은 세션을 연결이 끝날 때 센다.
event connection_state_remove(c: connection)
    {
    if ( ! detect_ssh_bruteforce || ! c?$ssh || ! c$ssh?$client || ! c$ssh?$server )
        return;
    if ( c$ssh?$auth_success && c$ssh$auth_success )
        return;
    if ( NSM::exception_drop_agg(SSH_Bruteforce, c) )
        return;
    local key: SumStats::Key = [$host=c$id$orig_h, $str=cat(c$id$resp_h)];
    SumStats::observe("nsm.ssh_bf.sample", key, [$str=cat("-|", c$uid, "|client=", c$ssh$client)]);
    SumStats::observe("nsm.ssh_bf", key, [$num=1]);
    }

# FTP: 530 응답(로그인 실패). USER 로 보낸 계정을 근거에 남긴다.
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=-5
    {
    if ( ! detect_ftp_bruteforce || code != 530 || ! c?$ftp )
        return;
    if ( NSM::exception_drop_agg(FTP_Bruteforce, c) )
        return;
    local user = ( c$ftp?$user && c$ftp$user != "<unknown>" ) ? to_lower(c$ftp$user) : "-";
    local key: SumStats::Key = [$host=c$id$orig_h, $str=cat(c$id$resp_h)];
    SumStats::observe("nsm.ftp_bf.sample", key, [$str=cat(user, "|", c$uid, "|reply=530")]);
    SumStats::observe("nsm.ftp_bf.user", key, [$str=user]);
    SumStats::observe("nsm.ftp_bf", key, [$num=1]);
    }
