##! ============================================================================
##! [9] Encrypted C2 (자체서명 인증서 + TLS 지문 이탈) - T1573 / T1071.001
##!
##!   - 암호화라 페이로드를 못 보므로 핸드셰이크 메타데이터로 가중 스코어링한다.
##!     단일 신호(자체서명 등)는 FP 가 커서, 여러 신호의 합산이 임계를 넘을 때만 발화.
##!   - 신호: 자체서명(issuer==subject/validation_status) · SNI 부재 · SNI-인증서 불일치
##!           · JA4 차단목록 정확 일치(주력) · JA4 "a" 섹션 워치리스트(보조)
##!           · JA3 차단목록 매칭(레거시, 전환기 병행).
##!   - JA4/JA3 는 main.zeek 의 get_ja4/get_ja3 훅으로 조회 -> 패키지 없으면
##!     ""(미사용), 컴파일 안전. JA4 는 BSD 라이선스(TLS 클라이언트)만 사용하며
##!     JA4S 등 JA4+ 계열은 FoxIO License(비상용) 문제로 채택하지 않음.
##!   - abuse.ch JA3 피드는 사실상 방치 상태 -> 주력 인텔은 JA4DB/ThreatFox 로
##!     이관하고, JA3 는 기존 자산 소진 시까지만 병행(레거시 가중치 유지).
##!
##! 상관 계약: notice $src = 감염 host (C2 단계, SRC_TO_SRC 로 Lateral 에 연결).
##! 클러스터: 연결 단위 무상태 판정 -> 워커 로컬이라도 안전.
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/ssl
@load base/utils/site
@load ./main
@load ./evidence_log

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

event ssl_established(c: connection)
    {
    if ( ! detect_encrypted_c2 )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    if ( ! Site::is_local_addr(orig) || ! is_external(resp) )
        return;                            # 내부 -> 외부 방향만
    if ( resp in enc_c2_allowlist )
        return;

    # SNI 도메인 예외(부분매칭): 신뢰 SNI 의 TLS 는 C2 판정 스킵.
    #   ja3 우연 매칭 등으로 정상 서비스가 오탐되는 것을 IP 변동과 무관하게 억제.
    if ( c$ssl?$server_name &&
         NSM::domain_matches(c$ssl$server_name, enc_c2_allowlist_sni) )
        return;

    local score = 0;
    local reasons = "";

    # 1) 자체서명: issuer == subject 또는 검증 상태로 판정
    local selfsigned = F;
	if ( c$ssl?$subject && c$ssl?$issuer && c$ssl$subject == c$ssl$issuer )
		selfsigned = T;
		if ( selfsigned )
		{ score += enc_c2_w_selfsigned; 
		reasons += "selfsigned "; }

    # 2) SNI 부재 / 불일치
    local has_sni = c$ssl?$server_name && c$ssl$server_name != "";
    if ( ! has_sni )
        { score += enc_c2_w_nosni; reasons += "no_sni "; }
    else if ( c$ssl?$subject && c$ssl$server_name !in c$ssl$subject )
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
    local eid = cat(orig, "|enc-c2|", resp, "|", time_bucket(1hr));

    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=Encrypted_C2,
        $technique="T1573",
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
