##! ============================================================================
##! [3] Exploit Attempt (Webshell) - 웹쉘 접근 탐지
##!
##! 탐지 원리
##!   - 알려진 웹쉘 파일명(c99, r57, wso, b374k...) 및 스크립트 파일에 대한
##!     명령 실행 파라미터(cmd=, exec=, eval...)를 URI 에서 패턴 검사.
##! NOTE: cmd=/run= 등 빈출 파라미터는 오탐 위험 -> 운영 환경에 맞게 redef.
##! ============================================================================

@load base/protocols/http
@load base/frameworks/notice
@load ./main
@load ./evidence_log

module NSM;

export {
    ## 알려진 웹쉘 파일명 / 웹쉘성 접근 패턴 (대소문자 무시)
    const webshell_patterns =
        /(?i:(c99|r57|b374k|wso|cmd|shell|backdoor|webshell|reGeorg|antsword|china[[:space:]]?chopper))\.(php|jsp|jspx|asp|aspx|war)/
      | /(?i:(eval|assert|system|passthru|shell_exec|popen|proc_open)[[:space:]]*\()/
      | /(?i:[?&](cmd|exec|command|run|c)=)/        # ?cmd=whoami 류
      | /(?i:[?&](file|path|dir)=.*(\.\.\/|\.\.\\))/ # 경로 조작 동반
      &redef;
}

## 단일 연결형 증적 key: 연결(uid) 자체가 근거의 단위다.
function webshell_evidence_id(c: connection): string
    {
    return cat(c$id$orig_h, "|webshell|", c$id$resp_h, "|", c$uid);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( webshell_patterns in unescaped_URI )
        {
        local eid = webshell_evidence_id(c);

        # 근거를 NOTICE 보다 먼저 적재한다(detection 의 evidence_count 산출 시점).
        if ( NSM::evidence_is_new(eid, "uri") )
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=Webshell_Access,
                $technique="T1505.003",
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $operation="http_request",
                $uid=c$uid,
                $detail=fmt("method=%s uri=%s", method,
                            sub_bytes(unescaped_URI, 1, 256))]);

        NOTICE([$note=Webshell_Access,
                $conn=c,
                $msg=fmt("Possible webshell access: %s %s", method, original_URI),
                $sub=unescaped_URI,
                $identifier=cat(c$id$orig_h, c$id$resp_h, "webshell"),
                $suppress_for=10min,
                $evidence_id=eid]);
        }
    }
