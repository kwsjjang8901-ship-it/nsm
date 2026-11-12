##! ============================================================================
##! [04] 웹쉘 접근 — T1505.003 (2026-11 재작성 후 활성화)
##!
##! 탐지 원리 (내부 웹서버로 들어오는 요청, 입력은 web_common 으로 정규화)
##!   - URI: 알려진 웹쉘 파일명 + 스크립트 확장자 (shell.php, b374k.php, reGeorg tunnel.jsp ...)
##!   - URI: 명령 실행 파라미터에 "실제 명령"이 들어 있음 (?cmd=whoami, ?exec=cat /etc/passwd ...)
##!   - URI: 코드 실행 함수 + 사용자 입력/디코딩 (eval(base64_decode(, assert($_POST ...)
##!   - 본문(POST): China Chopper·AntSword 류 페이로드 서명
##!       (@ini_set("display_errors","0"), @set_time_limit(0), eval(base64_decode(, $_POST[ ...)
##!
##! 이전 구현과의 차이
##!   - ?c= / ?cmd= / ?run= 같은 파라미터 이름만으로 탐지하던 패턴을 제거하고,
##!     파라미터 값이 명령일 때만 탐지한다(정상 파라미터 cmd=refresh, c=blue 오탐 제거).
##!   - 경로 조작(../) 패턴은 웹쉘이 아니라 별도 공격이므로 제외.
##!   - 본문 페이로드 검사 추가(웹쉘 접속의 대부분은 POST 본문으로 명령을 보낸다).
##!   - 내부 웹서버 대상 요청으로 한정.
##!
##! 상관 계약: notice $src = 공격 출발지, $dst = 웹쉘이 있는 서버 (초기 침투 단계).
##! ============================================================================

@load base/protocols/http
@load base/frameworks/notice
@load ./main
@load ./evidence_log
@load ./web_common

module NSM;

export {
    ## URI 시그니처(정규화된 소문자 입력 기준).
    const webshell_uri_patterns =
        # 알려진 웹쉘 파일명 + 스크립트 확장자 (뒤에 ? 쿼리 / 또는 URI 끝)
        /\/(c99|r57|b374k|wso|webshell|regeorg|tunnel|antsword|chopper|cmd|shell|backdoor)[0-9]*\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|ashx|cer)\?/
      | /\/(c99|r57|b374k|wso|webshell|regeorg|tunnel|antsword|chopper|cmd|shell|backdoor)[0-9]*\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|ashx|cer)$/
        # 명령 실행 파라미터 + 실제 명령 값
      | /[?&](cmd|exec|command|execute|run|c|e|q)=[[:space:]]*(whoami|uname|hostname|ipconfig|ifconfig|systeminfo|net[[:space:]]+(user|localgroup|group)|cat[[:space:]]+\/etc\/(passwd|shadow)|type[[:space:]]+c:|dir[[:space:]]+c:|ls[[:space:]]+-|powershell|cmd(\.exe)?[[:space:]]*\/c|bash[[:space:]]+-|sh[[:space:]]+-c|wget[[:space:]]|curl[[:space:]]|certutil)/
      | /[?&](cmd|exec|command|execute|run|c|e|q)=[[:space:]]*id&/
      | /[?&](cmd|exec|command|execute|run|c|e|q)=[[:space:]]*id$/
        # 코드 실행 함수 + 디코딩/사용자 입력
      | /(eval|assert|system|passthru|shell_exec|popen|proc_open)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(post|get|request|cookie))/
      &redef;

    ## 본문 시그니처(정규화된 소문자 입력 기준). 웹쉘 클라이언트가 보내는 페이로드 특징.
    const webshell_body_patterns =
        # 주의: Zeek 정규식에서 " 는 인용 구간 기호라 따옴표는 문자 클래스 ["'] 로 쓴다.
        /@ini_set\([[:space:]]*["']display_errors["'][[:space:]]*,[[:space:]]*["']?0["']?[[:space:]]*\)/   # China Chopper / AntSword
      | /@set_time_limit\([[:space:]]*0[[:space:]]*\)/
      | /(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13)[[:space:]]*\(/
      | /(eval|assert)[[:space:]]*\([[:space:]]*\$_(post|get|request)\[/
      | /request\.item\[.*\];?[[:space:]]*eval/                                            # ASP(X) chopper
      &redef;
}

function webshell_evidence_id(c: connection): string
    {
    return cat(c$id$orig_h, "|webshell|", c$id$resp_h, "|", c$uid);
    }

function webshell_report(c: connection, where: string, method: string, raw: string)
    {
    local eid = webshell_evidence_id(c);

    # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
    local nid = cat(c$id$orig_h, c$id$resp_h, "webshell");
    if ( NSM::notice_suppressed(Webshell_Access, nid) )
        return;

    if ( NSM::evidence_is_new(eid, where) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Webshell_Access,
            $technique="T1505.003",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="http_request",
            $uid=c$uid,
            $detail=fmt("location=%s method=%s value=%s", where, method, sub_bytes(raw, 1, 256))]);

    NOTICE([$note=Webshell_Access,
            $conn=c,
            $msg=fmt("Possible webshell access (%s): %s %s", where, method,
                     c?$http && c$http?$uri ? c$http$uri : "<uri?>"),
            $sub=sub_bytes(raw, 1, 256),
            $identifier=nid,
            $suppress_for=10min,
            $evidence_id=eid]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! web_attack_target(c, Webshell_Access) )
        return;
    if ( webshell_uri_patterns in web_normalize(original_URI) )
        webshell_report(c, "uri", method, original_URI);
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;
    if ( ! c?$http || ! c$http?$method || c$http$method != "POST" )
        return;
    if ( ! web_attack_target(c, Webshell_Access) )
        return;
    if ( ! web_body_budget(c, length) )
        return;
    if ( webshell_body_patterns in web_normalize(sub_bytes(data, 1, web_attack_body_max)) )
        webshell_report(c, "body", "POST", data);
    }
