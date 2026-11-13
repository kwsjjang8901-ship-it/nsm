##! ============================================================================
##! [29] 웹 로그인 무차별 대입 — T1110.001 (2026-11 신규)
##!
##! HTTP_Bruteforce
##!   - 폼 로그인: 같은 출발지가 내부 웹서버의 같은 경로로 svc_bf_epoch(5분) 안에 비밀번호형 파라미터
##!     (password·passwd·pwd 등) 값을 web_bf_threshold(20)가지 이상 바꿔 보냈으면 탐지.
##!     URI 쿼리(GET 로그인, CIC-IDS2017 Thursday DVWA brute)와 POST 본문(폼 인코딩·JSON)을 본다.
##!     정상 사용자·자동화는 같은 비밀번호를 반복하므로 "서로 다른 값의 수"로 센다.
##!   - HTTP Basic 인증: 같은 출발지 -> 서버로 5분 안에 Basic 인증 헤더를 보낸 요청의 401 응답이
##!     web_bf_basic_threshold(20)회 이상. NTLM·Negotiate 의 정상 401(챌린지)은 c$http$username 이
##!     채워지지 않아 세지 않는다.
##!   - 비밀번호 값은 기록하지 않는다. 고유 수는 값의 MD5 로만 센다. 근거에는 계정(사용자명 파라미터,
##!     Basic 사용자명)·경로·시도 수만 남긴다.
##!
##! 집계형: (출발지, 서버|경로) 키, 창 종료 시 판정(창당 1건). 예외는 관측 전에 판정(exception_drop_agg).
##! 상관 계약: notice $src = 공격 host, $dst = 대상 웹서버. 자격증명 탈취 묶음.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/http
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./web_common
@load ./26_service_bruteforce

module NSM;

export {
    const detect_http_bruteforce = T &redef;
    ## 같은 (출발지, 서버, 경로)에서 창 안에 나온 서로 다른 비밀번호 값 수
    const web_bf_threshold = 20 &redef;
    ## 같은 (출발지, 서버)에서 창 안에 Basic 인증이 실패(401)한 수
    const web_bf_basic_threshold = 20 &redef;
    ## 비밀번호로 보는 파라미터 이름(소문자, 정확히 일치)
    const web_bf_password_params: set[string] = {
        "password", "passwd", "pass", "pwd", "pw", "passw", "passwort", "userpassword", "user_password",
        "j_password", "login_password", "loginpassword", "log_pass", "user_pass", "txtpassword",
    } &redef;
    ## 계정으로 보는 파라미터 이름(근거 표시용)
    const web_bf_user_params: set[string] = {
        "username", "user", "userid", "user_id", "login", "loginid", "login_id", "email", "uname",
        "j_username", "log", "usr", "user_name", "txtusername",
    } &redef;
}

# JSON 본문의 "password": "..." 형태
const web_bf_json_pw = /\"(password|passwd|pwd|pass|passw|userpassword|user_password|login_password)\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/;
const web_bf_json_user = /\"(username|user|userid|user_id|login|loginid|email|uname|user_name)\"[[:space:]]*:[[:space:]]*\"[^\"]*\"/;

function web_bf_path(c: connection): string
    {
    if ( ! c?$http || ! c$http?$uri )
        return "/";
    local p = split_string1(c$http$uri, /\?/);
    return |p| > 0 && p[0] != "" ? p[0] : "/";
    }

# key=value&... 에서 비밀번호·계정 값을 찾는다. 반환: [비밀번호 값 또는 "", 계정 또는 ""]
function web_bf_parse_form(s: string): vector of string
    {
    local pw = "";
    local user = "";
    for ( i, kv in split_string(s, /&/) )
        {
        local p = split_string1(kv, /=/);
        if ( |p| < 2 )
            next;
        local k = to_lower(unescape_URI(gsub(p[0], /\+/, " ")));
        local v = unescape_URI(gsub(p[1], /\+/, " "));
        if ( k in web_bf_password_params && pw == "" )
            pw = v;
        else if ( k in web_bf_user_params && user == "" )
            user = to_lower(v);
        }
    return vector(pw, user);
    }

function web_bf_json_value(s: string, pat: pattern): string
    {
    local m = find_all_ordered(s, pat);
    if ( |m| == 0 )
        return "";
    local p = split_string1(m[0], /:[[:space:]]*\"/);
    if ( |p| < 2 )
        return "";
    return sub(p[1], /\"$/, "");
    }

function web_bf_observe(c: connection, pw: string, user: string, where: string)
    {
    if ( pw == "" )
        return;
    if ( web_attack_local_servers_only && ! Site::is_local_addr(c$id$resp_h) )
        return;
    if ( NSM::exception_drop_agg(HTTP_Bruteforce, c) )
        return;
    local key: SumStats::Key = [$host=c$id$orig_h, $str=cat(c$id$resp_h, "|", web_bf_path(c))];
    SumStats::observe("nsm.http_bf.form", key, [$num=1]);
    SumStats::observe("nsm.http_bf.form.pw", key, [$str=md5_hash(pw)]);
    if ( user != "" )
        SumStats::observe("nsm.http_bf.form.user", key, [$str=user]);
    SumStats::observe("nsm.http_bf.form.sample", key,
                      [$str=cat(user == "" ? "-" : user, "|", c$uid, "|", where, " ",
                                c?$http && c$http?$method ? c$http$method : "-")]);
    }

function web_bf_report(kind: string, threshold: count, key: SumStats::Key, result: SumStats::Result,
                       s_sum: string, s_uniq: string, s_user: string, s_sample: string)
    {
    if ( s_sum !in result )
        return;
    local n = double_to_count(result[s_sum]$sum);
    local u = ( s_uniq != "" && s_uniq in result ) ? result[s_uniq]$unique : n;
    if ( u < threshold )
        return;
    local src = key$host;
    local kp = split_string1(key$str, /\|/);
    local dst = to_addr(kp[0]);
    local path = |kp| > 1 ? kp[1] : "-";
    local users = ( s_user in result ) ? result[s_user]$unique : 0;
    local eid = cat(src, "|http-bf|", dst, "|", kind, "|", time_bucket(svc_bf_epoch));
    local what = kind == "form" ? fmt("attempts=%d unique_passwords=%d", n, u)
                                : fmt("basic_auth_failures=%d", n);
    local op = kind == "form" ? "http_login_password_variation" : "http_basic_auth_failure";

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
                $note=HTTP_Bruteforce,
                $technique="T1110.001",
                $account=( p[0] == "-" ) ? "" : p[0],
                $src=src,
                $dst=dst,
                $uid=p[1],
                $operation=op,
                $detail=fmt("%s unique_users=%d path=%s window=%s %s", what, users, path, svc_bf_epoch, p[2])]);
            }

    NOTICE([$note=HTTP_Bruteforce,
            $src=src,
            $dst=dst,
            $msg=fmt("HTTP login brute force: %s -> %s %s, %s in %s", src, dst, path, what, svc_bf_epoch),
            $sub=fmt("%s path=%s", what, path),
            $identifier=cat(src, dst, "http-bf", kind, time_bucket(svc_bf_epoch)),
            $suppress_for=svc_bf_epoch,
            $evidence_id=eid]);
    }

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="nsm.http_bf.form", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="nsm.http_bf.form.pw", $apply=set(SumStats::UNIQUE));
    local r3 = SumStats::Reducer($stream="nsm.http_bf.form.user", $apply=set(SumStats::UNIQUE));
    local r4 = SumStats::Reducer($stream="nsm.http_bf.form.sample", $apply=set(SumStats::SAMPLE), $num_samples=svc_bf_num_samples);
    SumStats::create([
        $name="nsm-detect-http-bruteforce-form", $epoch=svc_bf_epoch, $reducers=set(r1, r2, r3, r4),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            web_bf_report("form", web_bf_threshold, key, result,
                          "nsm.http_bf.form", "nsm.http_bf.form.pw", "nsm.http_bf.form.user", "nsm.http_bf.form.sample");
            }
    ]);

    local b1 = SumStats::Reducer($stream="nsm.http_bf.basic", $apply=set(SumStats::SUM));
    local b2 = SumStats::Reducer($stream="nsm.http_bf.basic.user", $apply=set(SumStats::UNIQUE));
    local b3 = SumStats::Reducer($stream="nsm.http_bf.basic.sample", $apply=set(SumStats::SAMPLE), $num_samples=svc_bf_num_samples);
    SumStats::create([
        $name="nsm-detect-http-bruteforce-basic", $epoch=svc_bf_epoch, $reducers=set(b1, b2, b3),
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            web_bf_report("basic", web_bf_basic_threshold, key, result,
                          "nsm.http_bf.basic", "", "nsm.http_bf.basic.user", "nsm.http_bf.basic.sample");
            }
    ]);
    }

# 폼 로그인(GET): URI 쿼리
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=-5
    {
    if ( ! detect_http_bruteforce )
        return;
    local q = split_string1(original_URI, /\?/);
    if ( |q| < 2 )
        return;
    local r = web_bf_parse_form(q[1]);
    web_bf_observe(c, r[0], r[1], "uri");
    }

# 폼 로그인(POST·PUT): 본문 앞부분(폼 인코딩 또는 JSON). 첫 조각만 본다.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-5
    {
    if ( ! detect_http_bruteforce || ! is_orig )
        return;
    if ( ! c?$http || ! c$http?$method || ( c$http$method != "POST" && c$http$method != "PUT" ) )
        return;
    if ( ! web_body_budget(c, length) )
        return;
    local body = sub_bytes(data, 1, web_attack_body_max);
    local pw = "";
    local user = "";
    if ( /^[[:space:]]*[\{\[]/ in body )
        {
        pw = web_bf_json_value(body, web_bf_json_pw);
        user = to_lower(web_bf_json_value(body, web_bf_json_user));
        }
    else
        {
        local r = web_bf_parse_form(body);
        pw = r[0];
        user = r[1];
        }
    web_bf_observe(c, pw, user, "body");
    }

# HTTP Basic 인증 실패: Authorization: Basic 을 보낸 요청의 401
event http_reply(c: connection, version: string, code: count, reason: string) &priority=-5
    {
    if ( ! detect_http_bruteforce || code != 401 )
        return;
    if ( ! c?$http || ! c$http?$username )
        return;
    if ( web_attack_local_servers_only && ! Site::is_local_addr(c$id$resp_h) )
        return;
    if ( NSM::exception_drop_agg(HTTP_Bruteforce, c) )
        return;
    local user = to_lower(c$http$username);
    local key: SumStats::Key = [$host=c$id$orig_h, $str=cat(c$id$resp_h, "|", web_bf_path(c))];
    SumStats::observe("nsm.http_bf.basic", key, [$num=1]);
    SumStats::observe("nsm.http_bf.basic.user", key, [$str=user]);
    SumStats::observe("nsm.http_bf.basic.sample", key, [$str=cat(user, "|", c$uid, "|reply=401")]);
    }
