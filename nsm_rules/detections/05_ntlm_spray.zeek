##! ============================================================================
##! [05] NTLM 패스워드 스프레이 — T1110.003 (2026-11 재작성 후 활성화)
##!
##! 탐지 원리
##!   - 스프레이 = "소수의(보통 1개) 비밀번호 x 다수 계정" 시도.
##!   - 단일 출발지가 ntlm_interval 안에 "인증에 실패한 고유 계정" 수를 SumStats UNIQUE 로 집계,
##!     ntlm_user_threshold 이상이면 탐지.
##!
##! 실패 판정 (Zeek 9.0.1 소스 확인)
##!   - ntlm.log 의 success 는 SPNEGO negState(gssapi_neg_result)로만 채워진다. 그런데 SMB 서버는
##!     로그온 실패 시 보안 버퍼 없이 오류 상태(STATUS_LOGON_FAILURE 등)만 돌려주므로
##!     SMB 실패는 대부분 success 가 비어 있다. 그래서 두 경로로 판정한다.
##!       1) SMB2/SMB1 세션 설정 응답의 상태 코드가 ntlm_failure_statuses 에 있음
##!       2) SPNEGO negState = reject(2)  (SMB 외 프로토콜 포함)
##!   - 연결의 마지막 NTLM AUTHENTICATE 계정을 보관했다가 실패 응답이 오면 1회 집계한다.
##!
##! 이전 구현과의 차이
##!   - 성공/실패 구분 없이 AUTHENTICATE 계정을 모두 세던 것을 실패만 세도록 변경
##!     (터미널 서버·프록시·파일 서버처럼 많은 사용자가 정상 인증하는 출발지 오탐 제거).
##!   - 계정명 대소문자 정규화(같은 계정을 대소문자만 바꿔 시도해도 1개로 셈).
##!   - 대상은 내부 서버로 한정, 예외 출발지(ntlm_spray_allowlist) 추가.
##!
##! 상관 계약: notice $src = 스프레이 출발지 (자격증명 접근 단계). 대상 서버는 근거(evidence)에 남긴다.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/ntlm
@load base/protocols/smb
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    ## 내부(local_nets) 서버로 향한 인증만 집계한다.
    const ntlm_spray_local_servers_only = T &redef;

    ## 예외 출발지(인증 프록시, VDI/터미널 게이트웨이, 계정 점검 도구 등).
    const ntlm_spray_allowlist: set[subnet] = {} &redef;

    ## 인증 실패로 보는 SMB NTSTATUS. 비밀번호가 맞아도 나오는 상태(만료·변경 필요·잠김 등)도
    ## 스프레이 결과이므로 포함한다.
    const ntlm_failure_statuses: table[count] of string = {
        [0xC000006D] = "STATUS_LOGON_FAILURE",
        [0xC000006A] = "STATUS_WRONG_PASSWORD",
        [0xC0000064] = "STATUS_NO_SUCH_USER",
        [0xC000006E] = "STATUS_ACCOUNT_RESTRICTION",
        [0xC000006F] = "STATUS_INVALID_LOGON_HOURS",
        [0xC0000070] = "STATUS_INVALID_WORKSTATION",
        [0xC0000071] = "STATUS_PASSWORD_EXPIRED",
        [0xC0000072] = "STATUS_ACCOUNT_DISABLED",
        [0xC0000193] = "STATUS_ACCOUNT_EXPIRED",
        [0xC0000224] = "STATUS_PASSWORD_MUST_CHANGE",
        [0xC0000234] = "STATUS_ACCOUNT_LOCKED_OUT",
        [0xC000015B] = "STATUS_LOGON_TYPE_NOT_GRANTED",
    } &redef;
}

redef record connection += {
    ## 이 연결에서 마지막으로 AUTHENTICATE 한, 아직 결과를 모르는 계정(정규화된 domain\user).
    nsm_ntlm_pending: string &optional;
};

const ntlm_smb2_session_setup = 0x01;
const ntlm_smb1_session_setup_andx = 0x73;

# 집계형 합성 증적 key (탐지 시점에서만 호출한다)
function ntlm_evidence_id(src: addr): string
    {
    return cat(src, "|ntlm-spray|", time_bucket(ntlm_interval));
    }

event zeek_init()
    {
    # 고유 계정 수(str = 계정) / 근거 표본(str = "계정|대상서버|결과")
    local r_users = SumStats::Reducer($stream="nsm.ntlm_spray", $apply=set(SumStats::UNIQUE));
    local r_sample = SumStats::Reducer($stream="nsm.ntlm_spray.sample", $apply=set(SumStats::SAMPLE),
                                       $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-ntlm-spray",
        $epoch     = ntlm_interval,
        $reducers  = set(r_users, r_sample),
        $threshold = ntlm_user_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.ntlm_spray"]$unique + 0.0;
            },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n   = result["nsm.ntlm_spray"]$unique;
            local num = result["nsm.ntlm_spray"]$num;
            local res = result["nsm.ntlm_spray.sample"];

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = ntlm_evidence_id(key$host);

            # 근거: 이 창에서 실패한 계정 표본("domain\user|대상서버|상태").
            #   NOTICE 보다 먼저 적재해야 detection 의 evidence_count 가 정확히 잡힌다.
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;

                    local parts = split_string(res$samples[i]$str, /\|/);
                    if ( |parts| < 3 )
                        next;
                    if ( ! NSM::evidence_is_new(eid, parts[0]) )
                        next;

                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=NTLM_Spray,
                        $technique="T1110.003",
                        $account=parts[0],
                        $src=key$host,
                        $dst=to_addr(parts[1]),
                        $uid=( |parts| > 3 ) ? parts[3] : "",
                        $operation="ntlm_auth_failure",
                        $detail=fmt("result=%s unique_failed_users=%d failures=%d window=%s",
                                    parts[2], n, num, ntlm_interval)]);
                    }

            NOTICE([$note=NTLM_Spray,
                    $src=key$host,
                    $msg=fmt("Possible NTLM password spray: %s failed authentication for %d unique accounts in %s",
                             key$host, n, ntlm_interval),
                    $sub=fmt("unique_failed_users=%d failures=%d", n, num),
                    $identifier=cat(key$host, "ntlm-spray"),
                    $suppress_for=1hr,
                    $evidence_id=eid]);
            }
    ]);
    }

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |ntlm_spray_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:ntlm_spray_allowlist",
            [$scope=set("NTLM_Spray"), $src=ntlm_spray_allowlist]);
    }

function ntlm_spray_target(c: connection): bool
    {
    if ( ntlm_spray_local_servers_only && ! Site::is_local_addr(c$id$resp_h) )
        return F;
    # 예외(예외 파일 + 기존 ntlm_spray_allowlist): 인증 프록시·VDI 게이트웨이 등. 집계 전 판정
    if ( NSM::exception_drop_agg(NTLM_Spray, c) )
        return F;
    return T;
    }

# 보관해 둔 계정의 인증 실패를 1회 집계한다.
function ntlm_failed(c: connection, result: string)
    {
    if ( ! c?$nsm_ntlm_pending )
        return;

    local acct = c$nsm_ntlm_pending;
    delete c$nsm_ntlm_pending;

    # 표본을 먼저 넣는다. 임계 판정은 고유 계정 스트림 observe 에서 즉시 일어날 수 있어(Zeek 8),
    #   순서가 반대면 임계를 넘긴 마지막 실패가 근거 표본에서 빠진다.
    SumStats::observe("nsm.ntlm_spray.sample", [$host=c$id$orig_h],
                      [$str=cat(acct, "|", c$id$resp_h, "|", result, "|", c$uid)]);
    SumStats::observe("nsm.ntlm_spray", [$host=c$id$orig_h], [$str=acct]);
    }

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
    {
    if ( ! request?$user_name || request$user_name == "" )
        return;   # 익명(null session)
    if ( ! ntlm_spray_target(c) )
        return;

    # domain\user 로 정규화(Windows 계정명은 대소문자 구분 없음)
    local user = to_lower(request$user_name);
    if ( request?$domain_name && request$domain_name != "" )
        user = cat(to_lower(request$domain_name), "\\", user);

    c$nsm_ntlm_pending = user;
    }

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
    {
    if ( is_orig || hdr$command != ntlm_smb2_session_setup || ! c?$nsm_ntlm_pending )
        return;

    if ( hdr$status in ntlm_failure_statuses )
        ntlm_failed(c, ntlm_failure_statuses[hdr$status]);
    else if ( hdr$status == 0 )
        delete c$nsm_ntlm_pending;   # 성공
    }

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
    {
    if ( is_orig || hdr$command != ntlm_smb1_session_setup_andx || ! c?$nsm_ntlm_pending )
        return;

    if ( hdr$status in ntlm_failure_statuses )
        ntlm_failed(c, ntlm_failure_statuses[hdr$status]);
    else if ( hdr$status == 0 )
        delete c$nsm_ntlm_pending;
    }

# SPNEGO 결과: 0 accept-completed, 1 accept-incomplete, 2 reject
event gssapi_neg_result(c: connection, state: count)
    {
    if ( ! c?$nsm_ntlm_pending )
        return;

    if ( state == 2 )
        ntlm_failed(c, "SPNEGO_REJECT");
    else if ( state == 0 )
        delete c$nsm_ntlm_pending;
    }
