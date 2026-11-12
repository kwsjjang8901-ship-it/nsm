##! ============================================================================
##! [03] SQL Injection 시도 — T1190 (2026-11 재작성 후 활성화)
##!
##! 탐지 원리
##!   - 내부 웹서버로 들어오는 HTTP 요청의 URI 와 POST/PUT 본문(앞부분)을 정규화한 뒤
##!     "SQL 구문 구조"가 있어야 매칭되는 시그니처로 검사한다.
##!     정규화: URL 디코딩 2회(이중 인코딩 우회), 폼 '+' -> 공백, 소문자 (web_common.zeek)
##!
##! 이전 구현과의 차이
##!   - 주석·구문 종료 문자 단독(#, --, /*) 과 'select ... from' 단독 패턴을 제거했다.
##!     검색어("select from the list #top")·앵커(#) 만으로 탐지되던 오탐 원인이었다.
##!   - 방향 제한이 없어 내부 사용자의 외부 사이트 요청까지 검사하던 것을 내부 웹서버로 한정.
##!   - Zeek 미지원 정규식 문법 (?: 로 로드 실패하던 문제는 0단계에서 수정.
##!
##! 상관 계약: notice $src = 공격 출발지, $dst = 대상 웹서버 (초기 침투 단계).
##! ============================================================================

@load base/protocols/http
@load base/frameworks/notice
@load ./main
@load ./evidence_log
@load ./web_common

module NSM;

export {
    ## SQL Injection 시그니처 (정규화된 소문자 입력 기준). 모두 SQL 구문 구조를 요구한다.
    const sqli_patterns =
        /union([[:space:]]|\/\*.*\*\/)+(all([[:space:]]|\/\*.*\*\/)+)?select[[:space:]]/  # UNION SELECT (주석 우회 포함)
      | /'[[:space:]]*(or|and)[[:space:]]+'?[0-9]+'?[[:space:]]*=[[:space:]]*'?[0-9]+/    # ' or 1=1
      | /'[[:space:]]*(or|and)[[:space:]]+'[a-z]*'[[:space:]]*=[[:space:]]*'[a-z]*/       # ' or 'a'='a
      | /information_schema\.(tables|columns|schemata)/
      | /(sleep|benchmark|pg_sleep)[[:space:]]*\([[:space:]]*[0-9]/                     # 시간 지연
      | /waitfor[[:space:]]+delay[[:space:]]+'/
      | /;[[:space:]]*(drop|truncate|alter)[[:space:]]+table[[:space:]]/                 # 스택 쿼리
      | /;[[:space:]]*(insert[[:space:]]+into|update[[:space:]]+[a-z_]+[[:space:]]+set|delete[[:space:]]+from)[[:space:]]/
      | /xp_cmdshell/
      | /into[[:space:]]+(outfile|dumpfile)[[:space:]]+'/
      | /load_file[[:space:]]*\(/
      | /(extractvalue|updatexml)[[:space:]]*\(.*concat/
      &redef;
}

function sqli_evidence_id(c: connection): string
    {
    return cat(c$id$orig_h, "|sqli|", c$id$resp_h, "|", c$uid);
    }

function sqli_report(c: connection, where: string, method: string, raw: string)
    {
    local eid = sqli_evidence_id(c);

    # 근거를 NOTICE 보다 먼저 적재한다(detection 의 evidence_count 산출 시점).
    # 억제 중이면 NOTICE 가 버려지므로 근거도 쓰지 않는다
    local nid = cat(c$id$orig_h, c$id$resp_h, "sqli");
    if ( NSM::notice_suppressed(SQL_Injection, nid) )
        return;

    if ( NSM::evidence_is_new(eid, where) )
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=SQL_Injection,
            $technique="T1190",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $operation="http_request",
            $uid=c$uid,
            $detail=fmt("location=%s method=%s value=%s", where, method, sub_bytes(raw, 1, 256))]);

    NOTICE([$note=SQL_Injection,
            $conn=c,
            $msg=fmt("Possible SQL Injection in %s: %s %s", where, method,
                     c?$http && c$http?$uri ? c$http$uri : "<uri?>"),
            $sub=sub_bytes(raw, 1, 256),
            $identifier=nid,
            $suppress_for=10min,
            $evidence_id=eid]);
    }

# URI 검사
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! web_attack_target(c, SQL_Injection) )
        return;
    if ( sqli_patterns in web_normalize(original_URI) )
        sqli_report(c, "uri", method, original_URI);
    }

# POST/PUT 본문 검사(요청 본문 앞 web_attack_body_max 바이트)
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;
    if ( ! c?$http || ! c$http?$method )
        return;
    if ( c$http$method != "POST" && c$http$method != "PUT" )
        return;
    if ( ! web_attack_target(c, SQL_Injection) )
        return;
    if ( ! web_body_budget(c, length) )
        return;
    if ( sqli_patterns in web_normalize(sub_bytes(data, 1, web_attack_body_max)) )
        sqli_report(c, "body", c$http$method, data);
    }
