##! ============================================================================
##! [28] 크로스 사이트 스크립팅(XSS) 시도 — T1190 (2026-11 신규)
##!
##! Cross_Site_Scripting
##!   - 내부 웹서버로 들어오는 HTTP 요청의 URI 와 POST/PUT 본문(앞부분)을 03 SQLi 와 같은 방식으로
##!     정규화(URL 디코딩 2회, '+' -> 공백, 소문자)한 뒤, 스크립트가 실행되는 HTML 구조가 있어야
##!     맞는 시그니처로 검사한다: <script> 태그, 태그 안의 이벤트 핸들러(onerror= 등),
##!     javascript:/vbscript: URL 에서의 함수 호출, document.cookie·document.domain 접근,
##!     data:text/html 을 src·href 로 넣는 태그.
##!   - "alert(" "<b>" 같은 단어나 태그 단독은 보지 않는다(검색어·게시글·서식 있는 글 오탐).
##!   - CIC-IDS2017 Thursday "Web Attack – XSS"(DVWA xss_r·xss_s)를 놓쳤던 것을 보완.
##!
##! 단건: (출발지, 서버) 단위 10분 억제. 예외는 03·04 와 같은 web_attack_target(exception_drop).
##! 상관 계약: notice $src = 공격 출발지, $dst = 대상 웹서버 (초기 침투 단계).
##! ============================================================================

@load base/protocols/http
@load base/frameworks/notice
@load ./main
@load ./evidence_log
@load ./web_common

module NSM;

export {
    const detect_xss = T &redef;

    ## XSS 시그니처(정규화된 소문자 입력 기준). 모두 스크립트가 실행되는 구조를 요구한다.
    const xss_patterns =
        /<script[[:space:]\/>]/                                                          # <script> 태그
      | /<\/script[[:space:]]*>/
      | /<[a-z][a-z0-9]*[^>]*[[:space:]\/"']on[a-z]{3,}[[:space:]]*=/                   # 태그 안 이벤트 핸들러
      | /(javascript|vbscript|livescript)[[:space:]]*:[^ ]*[a-z_$][a-z0-9_$.]*[[:space:]]*\(/   # javascript:fn(
      | /document[[:space:]]*\.[[:space:]]*(cookie|domain)/
      | /<[a-z][a-z0-9]*[^>]*(src|href|data|action)[[:space:]]*=[[:space:]]*["']?[[:space:]]*data:text\/html/
      | /<(iframe|frame|object|embed|applet|meta|base)[[:space:]\/>][^>]*(src|data|href|content|url)[[:space:]]*=/
      &redef;
}

function xss_report(c: connection, where: string, method: string, raw: string)
    {
    local nid = cat(c$id$orig_h, c$id$resp_h, "xss");
    # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
    if ( NSM::notice_suppressed(Cross_Site_Scripting, nid) )
        return;
    local eid = cat(c$id$orig_h, "|xss|", c$id$resp_h, "|", c$uid);
    if ( NSM::evidence_is_new(eid, where) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=Cross_Site_Scripting,
            $technique="T1190",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="http_request",
            $uid=c$uid,
            $detail=fmt("location=%s method=%s value=%s", where, method, sub_bytes(raw, 1, 256))]);

    NOTICE([$note=Cross_Site_Scripting,
            $conn=c,
            $msg=fmt("Possible cross-site scripting in %s: %s %s", where, method,
                     c?$http && c$http?$uri ? c$http$uri : "<uri?>"),
            $sub=sub_bytes(raw, 1, 256),
            $identifier=nid,
            $suppress_for=10min,
            $lm_targets=set(c$id$resp_h),   # 침투 대상: 상관에서 다음 단계의 출발지
            $evidence_id=eid]);
    }

# URI 검사
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! detect_xss || ! web_attack_target(c, Cross_Site_Scripting) )
        return;
    if ( xss_patterns in web_normalize(original_URI) )
        xss_report(c, "uri", method, original_URI);
    }

# POST/PUT 본문 검사(요청 본문 앞 web_attack_body_max 바이트, 03 과 같은 예산)
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! detect_xss || ! is_orig )
        return;
    if ( ! c?$http || ! c$http?$method )
        return;
    if ( c$http$method != "POST" && c$http$method != "PUT" )
        return;
    if ( ! web_attack_target(c, Cross_Site_Scripting) )
        return;
    if ( ! web_body_budget(c, length) )
        return;
    if ( xss_patterns in web_normalize(sub_bytes(data, 1, web_attack_body_max)) )
        xss_report(c, "body", c$http$method, data);
    }
