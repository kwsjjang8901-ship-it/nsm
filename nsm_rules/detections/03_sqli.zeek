##! ============================================================================
##! [3] Exploit Attempt (SQLi) - SQL Injection 탐지
##!
##! 탐지 원리
##!   - HTTP 요청 URI(unescaped) 와 POST/PUT 본문을 SQLi 시그니처로 검사.
##!   - UNION SELECT, ' OR 1=1, information_schema, sleep()/benchmark(),
##!     주석 우회(-- , /*) 등 대표 패턴.
##! NOTE: 시그니처 기반 -> 오탐/미탐 존재. 패턴은 redef 로 확장.
##! ============================================================================

@load base/protocols/http
@load base/frameworks/notice
@load ./main
@load ./evidence_log

module NSM;

export {
    ## SQL Injection 시그니처 (대소문자 무시)
    const sqli_patterns =
        /(?i:union[[:space:]]+(all[[:space:]]+)?select)/
      | /(?i:'[[:space:]]*(or|and)[[:space:]]+'?[0-9]'?[[:space:]]*=[[:space:]]*'?[0-9])/  # ' or 1=1
      | /(?i:information_schema)/
      | /(?i:(sleep|benchmark|pg_sleep|waitfor[[:space:]]+delay)[[:space:]]*\()/
      | /(?i:select[[:space:]].+[[:space:]]from[[:space:]])/
      | /(?i:(load_file|into[[:space:]]+outfile|into[[:space:]]+dumpfile))/
      | /(?i:(xp_cmdshell|exec[[:space:]]*\(|extractvalue|updatexml))/
      | /(?:--[[:space:]]|;--|\/\*|\*\/|#)/  # 인라인 주석/구문 종료 우회
      &redef;
}

## 단일 연결형 증적 key: 연결(uid) 자체가 근거의 단위다.
function sqli_evidence_id(c: connection): string
    {
    return cat(c$id$orig_h, "|sqli|", c$id$resp_h, "|", c$uid);
    }

## URI 검사
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( sqli_patterns in unescaped_URI )
        {
        local eid = sqli_evidence_id(c);

        # 근거를 NOTICE 보다 먼저 적재한다(detection 의 evidence_count 산출 시점).
        if ( NSM::evidence_is_new(eid, "uri") )
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=SQL_Injection,
                $technique="T1190",
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $operation="http_request",
                $uid=c$uid,
                $detail=fmt("location=uri method=%s uri=%s", method,
                            sub_bytes(unescaped_URI, 1, 256))]);

        NOTICE([$note=SQL_Injection,
                $conn=c,
                $msg=fmt("Possible SQL Injection in URI: %s %s", method, original_URI),
                $sub=unescaped_URI,
                $identifier=cat(c$id$orig_h, c$id$resp_h, "sqli-uri"),
                $suppress_for=10min,
                $evidence_id=eid]);
        }
    }

## POST/PUT 본문 검사
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;
    if ( ! c?$http || ! c$http?$method )
        return;
    if ( c$http$method != "POST" && c$http$method != "PUT" )
        return;

    if ( sqli_patterns in data )
        {
        local eid = sqli_evidence_id(c);

        if ( NSM::evidence_is_new(eid, "body") )
            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=SQL_Injection,
                $technique="T1190",
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $operation="http_request",
                $uid=c$uid,
                $detail=fmt("location=body method=%s payload=%s", c$http$method,
                            sub_bytes(data, 1, 256))]);

        NOTICE([$note=SQL_Injection,
                $conn=c,
                $msg=fmt("Possible SQL Injection in request body: %s %s",
                         c$http$method, c$http?$uri ? c$http$uri : "<uri?>"),
                $sub=sub_bytes(data, 1, 256),
                $identifier=cat(c$id$orig_h, c$id$resp_h, "sqli-body"),
                $suppress_for=10min,
                $evidence_id=eid]);
        }
    }
