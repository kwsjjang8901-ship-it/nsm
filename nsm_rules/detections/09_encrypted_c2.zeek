##! ============================================================================
##! [9] Encrypted C2 (자체서명 인증서 + TLS 지문 이탈) - T1573 / T1071.001
##!
##!   - 암호화라 페이로드를 못 보므로 핸드셰이크 메타데이터로 가중 스코어링한다.
##!     단일 신호(자체서명 등)는 FP 가 커서, 여러 신호의 합산이 임계를 넘을 때만 발화.
##!   - 신호: 자체서명(issuer==subject) · SNI 부재 · SNI-인증서 불일치(sni_matches_cert)
##!           · JA4 차단목록 정확 일치(주력) · JA4 "a" 섹션 워치리스트(보조)
##!           · JA3 차단목록 매칭(레거시, 전환기 병행).
##!   - JA4/JA3 는 main.zeek 의 get_ja4/get_ja3 훅으로 조회 -> 패키지 없으면
##!     ""(미사용), 컴파일 안전. JA4 는 BSD 라이선스(TLS 클라이언트)만 사용하며
##!     JA4S 등 JA4+ 계열은 FoxIO License(비상용) 문제로 채택하지 않음.
##!   - abuse.ch JA3 피드는 사실상 방치 상태 -> 주력 인텔은 JA4DB/ThreatFox 로
##!     이관하고, JA3 는 기존 자산 소진 시까지만 병행(레거시 가중치 유지).
##!
##!   - 한계: TLS 1.3 은 인증서가 암호화되어 자체서명/불일치 신호를 볼 수 없다.
##!     이 경우 SNI 부재와 JA3(JA4) 지문만 점수에 기여한다.
##!
##! 상관 계약: notice $src = 감염 host (C2 단계, SRC_TO_SRC 로 Lateral 에 연결).
##! 클러스터: 연결 단위 무상태 판정 -> 워커 로컬이라도 안전.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/ssl
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_encrypted_c2 = T &redef;

    ## 정상 자체서명 외부 서비스(사내 SaaS 등) 제외 대역.
    const enc_c2_allowlist: set[subnet] = {} &redef;

    ## SNI(server_name) 기반 예외 목록. 부분매칭(하위 도메인 포함).
    ##  예: "telemetry.elastic.co" 또는 상위 "elastic.co" 를 넣으면
    ##      해당 SNI 의 TLS 세션은 C2 판정에서 제외된다.
    ##  ja3 우연 매칭 등으로 정상 서비스(텔레메트리/업데이트)가 오탐될 때 사용.
    ##  IP 변동과 무관하게 안정적으로 예외 처리된다.
    const enc_c2_allowlist_sni: set[string] = {} &redef;

    ## 발화 임계(신호 가중치 합).
    const enc_c2_score_threshold = 3 &redef;

    ## 신호별 가중치.
    const enc_c2_w_selfsigned = 2 &redef;   # 자체서명
    const enc_c2_w_nosni      = 1 &redef;   # SNI 부재
    const enc_c2_w_mismatch   = 1 &redef;   # SNI-인증서 불일치
    const enc_c2_w_ja3        = 3 &redef;   # JA3 차단목록 매칭(레거시)
    const enc_c2_w_ja4        = 3 &redef;   # JA4 차단목록 정확 일치(주력)
    const enc_c2_w_ja4_a      = 1 &redef;   # JA4 "a" 워치리스트(부분 매칭, 보조)
}

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |enc_c2_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:enc_c2_allowlist",
            [$scope=set("Encrypted_C2"), $dst=enc_c2_allowlist]);
    if ( |enc_c2_allowlist_sni| > 0 )
        NSM::exception_add_legacy("legacy:enc_c2_allowlist_sni",
            [$scope=set("Encrypted_C2"), $domain=enc_c2_allowlist_sni]);
    }

event ssl_established(c: connection)
    {
    if ( ! detect_encrypted_c2 )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    if ( ! Site::is_local_addr(orig) || ! is_external(resp) )
        return;                            # 내부 -> 외부 방향만
    # 예외(예외 파일 + 기존 enc_c2_allowlist·enc_c2_allowlist_sni). 축: dst, SNI(domain), ja4 등
    if ( NSM::exception_drop(Encrypted_C2, c) )
        return;

    local score = 0;
    local reasons = "";

    # 1) 자체서명: issuer == subject
    local selfsigned = F;
    if ( c$ssl?$subject && c$ssl?$issuer && c$ssl$subject == c$ssl$issuer )
        selfsigned = T;
    if ( selfsigned )
        { score += enc_c2_w_selfsigned; reasons += "selfsigned "; }

    # 2) SNI 부재 / 불일치
    #   불일치는 Zeek 의 sni_matches_cert(Zeek 6+, x509_check_cert_hostname 기반)를 쓴다.
    #   와일드카드(*.example.com)·SAN(subjectAltName) 을 인증서 규칙대로 비교한다.
    #   (이전: SNI 가 subject 문자열에 부분문자열로 들어 있는지 검사 -> 와일드카드/SAN
    #    인증서가 전부 "불일치"로 잡히는 오탐이 있었다)
    #   인증서를 볼 수 없으면(TLS 1.3 등) 필드가 비어 있으므로 불일치 신호를 주지 않는다.
    local has_sni = c$ssl?$server_name && c$ssl$server_name != "";
    if ( ! has_sni )
        { score += enc_c2_w_nosni; reasons += "no_sni "; }
    else if ( c$ssl?$sni_matches_cert && ! c$ssl$sni_matches_cert )
        { score += enc_c2_w_mismatch; reasons += "sni_mismatch "; }

    # 3) JA4 차단목록 정확 일치(주력: 패키지 없으면 get_ja4 가 "" 반환)
    local ja4 = get_ja4(c);
    if ( ja4 != "" && ja4 in ja4_blocklist )
        { score += enc_c2_w_ja4; reasons += fmt("ja4=%s ", ja4); }

    # 4) JA4 "a" 섹션 워치리스트(부분 매칭). 단독(가중치 1)으로는 임계(3) 미달
    #    -> 자체서명/SNI 이상 등과 결합될 때만 발화에 기여 (FP 억제).
    if ( ja4 != "" )
        {
        local ja4_parts = split_string(ja4, /_/);
        if ( |ja4_parts| > 0 && ja4_parts[0] in ja4_a_watchlist )
            { score += enc_c2_w_ja4_a; reasons += fmt("ja4_a=%s ", ja4_parts[0]); }
        }

    # 5) JA3 차단목록(레거시, 전환기 병행: 패키지 없으면 get_ja3 가 "" 반환)
    local ja3 = get_ja3(c);
    if ( ja3 != "" && ja3 in ja3_blocklist )
        { score += enc_c2_w_ja3; reasons += fmt("ja3=%s ", ja3); }

    if ( score < enc_c2_score_threshold )
        return;

    local sni = has_sni ? c$ssl$server_name : "-";
    local iss = c$ssl?$issuer ? c$ssl$issuer : "-";
    local eid = cat(orig, "|enc-c2|", resp, "|", time_bucket(suppress_enc_c2));

    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=Encrypted_C2,
        $technique="T1573.002",
        $src=orig,
        $dst=resp,
        $operation="tls_c2",
        $uid=c$uid,
        $detail=fmt("score=%d [%s] sni=%s issuer=%s", score, strip(reasons), sni, iss)]);

    NOTICE([$note=Encrypted_C2,
            $conn=c,
            $src=orig,
            $msg=fmt("Encrypted C2 suspected: %s -> %s (score=%d: %s)",
                     orig, resp, score, strip(reasons)),
            $sub=fmt("score=%d sni=%s", score, sni),
            $identifier=cat(orig, resp, "enc-c2"),
            $suppress_for=suppress_enc_c2,
            $evidence_id=eid]);
    }
