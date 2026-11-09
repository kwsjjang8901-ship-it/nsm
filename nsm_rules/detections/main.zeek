##! ============================================================================
##! NSM 통합 탐지 룰 - 공통 정의 (Notice 타입 + 튜닝 파라미터 + 헬퍼)
##!
##! 첨부 시나리오(킬체인)를 Zeek 스크립트로 구현한 패키지의 진입부.
##! 모든 임계값은 const ... &redef 로 선언했으므로, 운영(폐쇄망/POC) 환경에
##! 맞게 별도 site 정책 파일에서 redef 만으로 조정할 수 있습니다.
##!   예) redef NSM::port_scan_threshold = 50;
##! ============================================================================

module NSM;

@load base/frameworks/notice
@load base/utils/site

export {
    ## 집계형(SumStats) 탐지에서 근거로 남길 표본 개수.
    ##   탐지 시점에 이 개수만큼 evidence 행을 적재하므로, evidence_count 의
    ##   상한이자 detection 이 가리킬 수 있는 근거 수의 상한이다.
    ##   늘리면 근거는 풍부해지지만 워커 메모리와 evidence.log 볼륨이 는다.
    const lm_num_samples = 20 &redef;

    ## ----------------------------------------------------------------------
    ## Notice 타입 정의
    ## 화면(notice.log)·XDR 연동 시 이 enum 이름이 그대로 식별자가 됩니다.
    ## ----------------------------------------------------------------------
    redef enum Notice::Type += {
        ## 1. 포트 스캔 (수직 스캔: 1 src -> 1 dst, 다수 포트)
        Port_Scan,
        ## 2. 호스트 스캔 (수평 스캔: 1 src -> 다수 dst, 동일 포트)
        Host_Scan,
        ## 3. SQL Injection 시도 (URI/POST 바디 패턴 매칭)
        SQL_Injection,
        ## 3. 웹쉘 접근 (알려진 웹쉘 파일명/명령 파라미터)
        Webshell_Access,
        ## 4. NTLM 패스워드 스프레이 (1 src -> 다수 계정)
        NTLM_Spray,
        ## 5. SMB 관리 공유 접근 (ADMIN$/C$/IPC$ = Lateral Movement)
        SMB_Admin_Share,
        ## 15. RDP 내부 확산 (1 src -> 다수 host 3389 = Lateral Movement)
        RDP_Lateral,
        ## 16. SSH 내부 확산 (1 src -> 다수 host 인증성공 = Lateral Movement)
        SSH_Lateral,
        ## 8. HTTP 비커닝 (주기적 C2 콜백)
        HTTP_Beaconing,
        ## 9. DNS 터널링 (구조 기반: 고유 서브도메인/긴 라벨/고엔트로피)
        DNS_Tunneling,
        ## 10. 암호화 C2 (자체서명 인증서 + JA3)
        Encrypted_C2,
        ## 13. 대용량 전송 Exfiltration (단일 연결 100MB+ 업로드) - 10번 룰
        Exfil_Large_Transfer,
        ## 13-agg. 대용량 전송 Exfiltration (호스트 단위 바이트 집계형) - 14번 룰
        ##         10번과 분리. 추후 삭제 가능성 있어 독립 타입으로 유지.
        Exfil_Volume_Aggregate,
        ## 14. DNS 기반 Exfiltration (누적 인코딩 바이트 기준)
        Exfil_DNS,
        ## 15. 웹 서비스(클라우드) 업로드 Exfiltration
        Exfil_Web_Upload,
        ## 16. DGA 도메인 탐지 (높은 NXDOMAIN 비율 + 고엔트로피)
        DGA_Domain,
        ## [상관] kill-chain 상관 탐지 (측면확산 -> 유출 등 단계 연결)
        ##        correlation-killchain.zeek 가 소비. 모듈 제거해도 enum 만 남아 무해.
        Correlated_KillChain
    };

    ## ----------------------------------------------------------------------
    ## 공유 Notice 필드 (상관분석용)
    ##  - lm_targets: 측면확산 notice 가 "피해 host 집합"을 구조 필드로 실어,
    ##    상관 모듈이 문자열 파싱 없이 피벗 host 를 prime 할 수 있게 한다.
    ##    (SAMPLE 기반이라 최대 num_samples 개까지만 채워질 수 있음)
    ## ----------------------------------------------------------------------
    redef record Notice::Info += {
        lm_targets: set[addr] &optional &log;
    };

    ## ----------------------------------------------------------------------
    ## [1,2] 스캔 탐지 파라미터
    ## ----------------------------------------------------------------------
    const scan_interval         = 5min &redef;  # 집계 윈도우(epoch)
    const port_scan_threshold   = 25   &redef;  # 단일 src->dst 고유 포트 수
    const host_scan_threshold   = 25   &redef;  # 단일 src 고유 dst 수(동일 포트)

    ## ----------------------------------------------------------------------
    ## [4] NTLM 스프레이 파라미터
    ## ----------------------------------------------------------------------
    const ntlm_interval         = 10min &redef; # 집계 윈도우
    const ntlm_user_threshold   = 10    &redef; # 단일 src 가 시도한 고유 계정 수

    ## ----------------------------------------------------------------------
    ## [8] HTTP 비커닝 파라미터 (기본: 10초 주기 x 12회)
    ## ----------------------------------------------------------------------
    const beacon_min_interval   = 3sec   &redef; # 비커닝으로 볼 최소 주기
    const beacon_max_interval   = 3600sec &redef;# 비커닝으로 볼 최대 주기
    const beacon_jitter         = 0.25   &redef; # 주기 허용 오차(비율, 25%)
    const beacon_min_hits       = 12     &redef; # 동일 주기 연속 콜백 횟수
    const beacon_expire         = 30min  &redef; # 상태 만료 시간

    # ---- 알람 억제(suppress) 창 -------------------------------------------------
    # 동일 identifier 재발화를 이 시간 동안 억제한다. 룰별로 하드코딩하지 않고
    # 여기서 관리하여 운영 튜닝을 용이하게 한다.
    const suppress_enc_c2       = 1hr &redef;   # 09 암호화 C2
    const suppress_large_exfil  = 1hr &redef;   # 10 단일 연결 대용량 유출
    const suppress_web_upload   = 1hr &redef;   # 12 클라우드 업로드 유출
    const suppress_vol_agg      = 5min &redef;  # 14 볼륨 집계 유출

    ## ----------------------------------------------------------------------
    ## [9] DNS 터널링 파라미터
    ## ----------------------------------------------------------------------
    const dnstun_interval       = 5min &redef;
    const dnstun_unique_sub     = 50   &redef;  # 동일 부모도메인 고유 서브도메인 수
    const dnstun_label_len      = 40   &redef;  # 긴 라벨 길이 기준(byte)
    const dnstun_entropy        = 3.5  &redef;  # 서브도메인 Shannon 엔트로피(bit/byte)

    ## ----------------------------------------------------------------------
    ## [10] 암호화 C2 파라미터
    ## ----------------------------------------------------------------------
    # JA3 차단 목록(알려진 악성 클라이언트 핑거프린트). JA3 패키지 필요(README 참고).
    const ja3_blocklist: set[string] = {} &redef;

    ## JA3 조회 훅.
    ##  - 기본 구현은 빈 문자열을 반환(=JA3 미사용)하여 JA3 패키지 없이도 컴파일됨.
    ##  - zeek/ja3 패키지나 Zeek 7 fingerprint 프레임워크 사용 시 site 정책에서 redef:
    ##      redef NSM::get_ja3 = function(c: connection): string {
    ##          return c$ssl?$ja3 ? c$ssl$ja3 : "";
    ##      };
    global get_ja3: function(c: connection): string =
        function(c: connection): string { return ""; } &redef;

    ## JA4 차단 목록(정확 일치). BSD 라이선스인 JA4(TLS 클라이언트)만 사용.
    ## 갱신 소스: FoxIO JA4DB(ja4db.com), ThreatFox. (JA4S 등 JA4+ 는 FoxIO
    ## License(비상용) 문제로 채택 제외 — 훅/목록 자체를 두지 않음)
    const ja4_blocklist: set[string] = {} &redef;

    ## JA4 "a" 섹션 워치리스트(부분 매칭). JA4 는 a_b_c 구조라 전체 해시가
    ## 랜덤화돼도 프로토콜 특성 구획(a)으로 계열 추적 가능. 단독 신호로는 FP 가
    ## 크므로 낮은 가중치(enc_c2_w_ja4_a)로 스코어링에만 기여시킨다.
    const ja4_a_watchlist: set[string] = {} &redef;

    ## JA4 조회 훅.
    ##  - 기본 구현은 빈 문자열 반환(=JA4 미사용) -> ja4 패키지 없이도 컴파일됨.
    ##  - zkg install zeek/foxio/ja4 후 ssl.log 의 실측 필드에 맞춰 site 정책에서 redef:
    ##      redef NSM::get_ja4 = function(c: connection): string {
    ##          return c$ssl?$ja4 ? c$ssl$ja4 : "";
    ##      };
    ##  ※ 패키지 config.zeek 에서 JA4(TLS) 외 JA4+ 메서드는 비활성화할 것(라이선스).
    global get_ja4: function(c: connection): string =
        function(c: connection): string { return ""; } &redef;

    ## ----------------------------------------------------------------------
    ## [13] 대용량 전송 Exfiltration 파라미터
    ## ----------------------------------------------------------------------
    const exfil_bytes_threshold = 100*1024*1024 &redef; # 100MB (orig_bytes 기준)

    ## ----------------------------------------------------------------------
    ## [14] DNS Exfiltration 파라미터 (누적 인코딩 바이트)
    ## ----------------------------------------------------------------------
    const dnsexfil_interval     = 5min &redef;
    const dnsexfil_bytes        = 1*1024*1024 &redef;   # qname 누적 1MB+

    ## ----------------------------------------------------------------------
    ## [15] 웹 업로드 Exfiltration 파라미터
    ## ----------------------------------------------------------------------
    const webupload_bytes       = 50*1024*1024 &redef;  # 단일 요청 본문 50MB+
    # 클라우드 스토리지/협업 서비스 Host 패턴
    const cloud_hosts =
        /(?i:.*\.(googleapis|googleusercontent)\.com)/
      | /(?i:.*drive\.google\.com)/
      | /(?i:.*\.dropboxapi\.com|.*dropbox\.com)/
      | /(?i:.*\.amazonaws\.com)/        # S3 등
      | /(?i:.*\.blob\.core\.windows\.net)/  # Azure Blob
      | /(?i:.*\.storage\.googleapis\.com)/
      | /(?i:.*onedrive\.live\.com|.*\.sharepoint\.com)/
      | /(?i:.*mega\.nz|.*\.mega\.co\.nz)/
      | /(?i:.*\.wetransfer\.com|.*\.box\.com)/ &redef;

    ## ----------------------------------------------------------------------
    ## [16] DGA 탐지 파라미터
    ## ----------------------------------------------------------------------
    const dga_interval          = 10min &redef;
    const dga_nxdomain_threshold = 50   &redef; # 윈도우 내 NXDOMAIN 응답 수
    const dga_ratio_threshold   = 0.8   &redef; # NXDOMAIN / 전체 응답 비율
    const dga_entropy           = 4.0   &redef; # 도메인 평균 엔트로피

    ## ----------------------------------------------------------------------
    ## 공통 헬퍼 함수
    ## ----------------------------------------------------------------------

    ## 도메인에서 "부모 도메인"(마지막 2개 라벨)을 추출.
    ## NOTE: 정확한 eTLD+1 추출은 Public Suffix List 가 필요합니다(zeek-tld 패키지).
    ##       폐쇄망/POC 에서는 단순 2-라벨 근사로 충분한 경우가 많아 기본 제공합니다.
    global parent_domain: function(name: string): string;

    ## 외부(인터넷) 주소 여부. Site::local_nets 설정이 선행되어야 합니다.
    global is_external: function(a: addr): bool;

    ## evidence_id 유일성을 위한 시간 버킷.
    ##  네트워크 시각을 win(억제창) 단위로 잘라 정수 버킷을 만든다.
    ##  같은 버킷(=같은 억제창) 안의 재관측은 동일 evidence_id 를 갖고,
    ##  버킷이 바뀌면(다른 시간대) 다른 evidence_id 가 되어 evidence.log 조인 시 시간대가 섞이지 않는다.
    global time_bucket: function(win: interval): string;

    ## 도메인 부분매칭 예외 판정.
    ##  name(관측된 host/SNI)이 allow 집합의 어느 항목과 매칭되면 T.
    ##  매칭 규칙(부분매칭): allow 항목 d 에 대해
    ##    - name == d                (완전 일치)                예: telemetry.elastic.co
    ##    - name 이 "."+d 로 끝남     (하위 도메인 포함)          예: a.telemetry.elastic.co
    ##  즉 allow 에 "elastic.co" 를 넣으면 *.elastic.co 전부 예외 처리된다.
    ##  대소문자 무시. name 이 비었으면 F.
    global domain_matches: function(name: string, allow: set[string]): bool;

    ## note(탐지 유형) -> 킬체인 단계명 매핑. evidence_log/detection_log 공용.
    ##   evidence_log 가 detection_log 보다 먼저 로드되므로 공용 위치(main)에 둔다.
    const stage_name_map: table[Notice::Type] of string = {
        [Port_Scan]              = "Recon",
        [Host_Scan]              = "Recon",
        [SQL_Injection]          = "Initial Access",
        [Webshell_Access]        = "Initial Access",
        [NTLM_Spray]             = "Credential Access",
        [SMB_Admin_Share]        = "Lateral Movement",
        [RDP_Lateral]            = "Lateral Movement",
        [SSH_Lateral]            = "Lateral Movement",
        [HTTP_Beaconing]         = "Command and Control",
        [DNS_Tunneling]          = "Command and Control",
        [Encrypted_C2]           = "Command and Control",
        [DGA_Domain]             = "Command and Control",
        [Exfil_Large_Transfer]   = "Exfiltration",
        [Exfil_Volume_Aggregate] = "Exfiltration",
        [Exfil_DNS]              = "Exfiltration",
        [Exfil_Web_Upload]       = "Exfiltration",
    } &redef;

    ## note -> 킬체인 단계명(매핑 없으면 "").
    global killchain_stage_of: function(n: Notice::Type): string;

    ## detection 의 victims 에 표시할 최대 host 수(쉼표 구분, 초과분 생략).
    ##   detection_log(Single) 와 correlation_killchain(Correlated) 공용.
    const chain_max_victims = 8 &redef;
}

function killchain_stage_of(n: Notice::Type): string
    {
    return ( n in stage_name_map ) ? stage_name_map[n] : "";
    }

function parent_domain(name: string): string
    {
    local parts = split_string(name, /\./);
    local n = |parts|;
    if ( n <= 2 )
        return name;
    return cat(parts[n-2], ".", parts[n-1]);
    }

function is_external(a: addr): bool
    {
    # local_nets 에 포함되지 않으면 외부로 간주
    return ! Site::is_local_addr(a);
    }

function domain_matches(name: string, allow: set[string]): bool
    {
    if ( name == "" )
        return F;
    local host = to_lower(name);
    # FQDN 끝점(trailing dot) 제거: "a.b.com." -> "a.b.com"
    #   DNS/HTTP Host 에 루트 표기 점이 붙는 경우가 있어 매칭이 어긋나는 것을 방지.
    if ( |host| > 0 && host[|host| - 1 :] == "." )
        host = host[: |host| - 1];
    for ( d in allow )
        {
        local dd = to_lower(d);
        if ( dd == "" )
            next;
        # allow 항목에 끝점이 붙어도 무시
        if ( |dd| > 0 && dd[|dd| - 1 :] == "." )
            dd = dd[: |dd| - 1];
        # 완전 일치
        if ( host == dd )
            return T;
        # 하위 도메인 포함: host 가 "."+dd 로 끝나면 매칭
        #   (예: allow="elastic.co" -> "telemetry.elastic.co" 매칭,
        #        단 "notelastic.co" 는 미매칭 -> 경계 오탐 방지)
        local suffix = cat(".", dd);
        local hlen = |host|;
        local slen = |suffix|;
        if ( hlen > slen && host[hlen - slen :] == suffix )
            return T;
        }
    return F;
    }

function time_bucket(win: interval): string
    {
    # network_time() 을 win 초 단위로 내림 → 버킷 인덱스(문자열).
    # win<=0 이면 항상 "0"(버킷 비활성)로 안전 처리.
    # |time| 은 동일 숫자값의 double, |interval| 은 초 단위 double (Zeek 표준).
    local w = |win|;
    if ( w <= 0.0 )
        return "0";
    local now = |network_time()|;
    return cat(double_to_count(floor(now / w)));
    }
