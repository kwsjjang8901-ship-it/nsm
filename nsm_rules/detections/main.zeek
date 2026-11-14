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
@load base/frameworks/sumstats

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
        ## 17. Kerberos 패스워드 스프레이 (1 src -> 다수 계정 사전인증 실패)
        Kerberos_Spray,
        ## 17. Kerberos 무차별 대입 (1 src -> 1 계정 반복 사전인증 실패)
        Kerberos_Bruteforce,
        ## 18. Kerberoasting (1 src -> 다수 SPN 의 RC4 서비스 티켓)
        Kerberoasting,
        ## 18. AS-REP Roasting (사전인증 없는 AS 요청에 RC4 AS-REP)
        ASREP_Roasting,
        ## 19. 외부 NTLM 인증 (내부 -> 외부 서버로 NetNTLM 자격증명 전송)
        NTLM_Credential_Leak,
        ## 19. 외부향 SMB (내부 -> 외부 445/139 연결 성립)
        Outbound_SMB,
        ## 20. WinRM 내부 확산 (1 src -> 다수 host 5985/5986)
        WinRM_Lateral,
        ## 20. DCOM 내부 확산 (1 src -> 다수 host 원격 COM 객체 생성)
        DCOM_Lateral,
        ## 21. 랜섬웨어성 SMB 파일 변경 (확장자 변경 rename 대량 / 여러 폴더에 랜섬 노트)
        SMB_Ransomware,
        ## 22. LLMNR/NBT-NS/mDNS 포이즈닝 (1 응답자 -> 다수 이름에 긍정 응답)
        Name_Poisoning,
        ## 23. DCSync (DC 가 아닌 host 의 DRSUAPI DRSGetNCChanges)
        DCSync,
        ## 24. 비표준 포트 프로토콜 (외부향 HTTP/TLS/SSH 가 표준 포트가 아님)
        Nonstandard_Port,
        ## 24. 장기 외부 연결 (내부 -> 외부 TCP 가 long_conn_duration 이상 지속)
        Long_Connection,
        ## 25. 식별 안 된 프로토콜의 외부 통신 (역방향 셸·자체 프로토콜 C2)
        Unknown_Protocol,
        ## 26. SSH·FTP 무차별 대입 (같은 서버로 인증 실패 반복)
        SSH_Bruteforce,
        FTP_Bruteforce,
        ## 27. Heartbleed (TLS 하트비트 과다 읽기)
        TLS_Heartbleed,
        ## 28. 크로스 사이트 스크립팅 시도 (내부 웹서버 요청의 스크립트 구조)
        Cross_Site_Scripting,
        ## 29. 웹 로그인 무차별 대입 (같은 경로로 비밀번호 값 반복 변경, Basic 인증 401 반복)
        HTTP_Bruteforce,
        ## 30. TLS(HTTPS) 비커닝 (같은 목적지로 일정 주기·비슷한 크기의 TLS 연결 반복)
        TLS_Beaconing,
        ## 31. 단일 대상 원격 실행 (원격 서비스 생성·예약 작업·WMI 메서드 호출)
        Remote_Service_Creation,
        Remote_Task_Creation,
        Remote_WMI_Execution,
        ## 32. 남의 머신 계정 사용 (한 IP 가 머신 계정 여러 개로 인증: NTLM 릴레이·해시 전달)
        Machine_Account_Misuse,
        ## 33. AI 관련 위협 (AI 서비스 대량 업로드, 서버의 AI API 호출, 사내 AI 인프라 관리 API 공격)
        AI_Service_Upload,
        AI_API_From_Server,
        AI_Service_Exploit,
        ## 34. AD 공격(DCE-RPC: 강제 인증, 원격 레지스트리 하이브 저장, Zerologon, AD 정보 수집)
        Coerced_Authentication,
        Remote_Registry_Dump,
        Zerologon_Attempt,
        AD_Enumeration,
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
        ##        correlation_killchain.zeek 가 소비. 모듈 제거해도 enum 만 남아 무해.
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
    const ntlm_user_threshold   = 10    &redef; # 단일 src 가 인증에 실패한 고유 계정 수

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
    ## [08] DNS 터널링·유출 파라미터 (08_dns_tunneling.zeek, 터널링/유출 통합 판정)
    ## ----------------------------------------------------------------------
    const dnstun_interval       = 5min &redef;  # 집계 윈도우(터널링·유출 공용)
    const dnstun_unique_sub     = 50   &redef;  # [터널링] (src,등록도메인) 고유 서브도메인 수
    const dnstun_label_len      = 40   &redef;  # 이 길이 이상 라벨이 있으면 수상한 질의
    const dnstun_min_label_len  = 20   &redef;  # 이 길이 이상 라벨은 무작위성 점수로 판정
    const dnstun_suspicious_ratio = 0.5 &redef; # 수상한 질의 비율(이상일 때만 판정)
    ## (폐기) 서브도메인 원시 엔트로피 임계. 무작위성 점수(13 DGA 와 공용)로 대체.
    const dnstun_entropy        = 3.5  &redef &deprecated="NSM::dnstun_entropy 는 더 이상 쓰이지 않습니다";

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
    ## [08] DNS 유출 임계 (누적 인코딩 바이트, 집계 윈도우는 dnstun_interval)
    ## ----------------------------------------------------------------------
    const dnsexfil_bytes        = 256*1024 &redef;   # [유출] 서브도메인 누적 256KB+ / 5분
    ## (폐기) 별도 유출 윈도우. 터널링과 같은 dnstun_interval 로 통합.
    const dnsexfil_interval     = 5min &redef &deprecated="NSM::dnsexfil_interval 는 더 이상 쓰이지 않습니다. NSM::dnstun_interval 을 사용하세요";

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
    const dga_like_ratio        = 0.5   &redef; # NXDOMAIN 중 무작위형(DGA형) 등록 라벨 비율
    ## (폐기) qname 전체 평균 엔트로피 임계. 일반 DGA 길이(8~16자)에서 도달하지 못해
    ## 미탐이 컸으므로 등록 라벨 무작위성 점수(dga_like_ratio)로 대체했다. 값은 쓰이지 않는다.
    const dga_entropy           = 4.0   &redef &deprecated="NSM::dga_entropy 는 더 이상 쓰이지 않습니다. NSM::dga_like_ratio 를 사용하세요";

    ## ----------------------------------------------------------------------
    ## 도메인 접미사: 2단계 공용 접미사(eTLD). 등록 도메인/라벨 추출에 사용.
    ##   예) www.example.co.kr -> 등록 도메인 example.co.kr, 등록 라벨 example
    ##   Public Suffix List 전체 대신 실무에서 자주 보이는 것만 둔다. 필요 시 redef 로 추가.
    ## ----------------------------------------------------------------------
    const multi_label_suffixes: set[string] = {
        "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "mil.kr",
        "hs.kr", "ms.kr", "es.kr", "kg.kr", "sc.kr",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "com.tw", "com.hk", "com.sg",
        "co.in", "com.br", "co.nz", "co.za",
    } &redef;

    ## ----------------------------------------------------------------------
    ## 공통 헬퍼 함수
    ## ----------------------------------------------------------------------

    ## 도메인에서 "부모(등록) 도메인"을 추출.
    ##   기본은 마지막 2개 라벨, 끝이 multi_label_suffixes(예: co.kr)면 마지막 3개 라벨.
    ##   예) a.b.example.com -> example.com,  x.y.naver.co.kr -> naver.co.kr
    ## NOTE: 정확한 eTLD+1 추출은 Public Suffix List 가 필요합니다(zeek-tld 패키지).
    global parent_domain: function(name: string): string;

    ## 등록 라벨(등록 도메인에서 접미사를 뺀 이름)을 소문자로 추출. 끝점(.) 무시.
    ##   예) www.example.com -> example,  a.b.Example.CO.KR. -> example,  example -> example
    global registered_label: function(name: string): string;

    ## 외부(인터넷) 주소 여부. Site::local_nets 설정이 선행되어야 합니다.
    global is_external: function(a: addr): bool;

    ## evidence_id 유일성을 위한 시간 버킷.
    ##  네트워크 시각을 win(억제창) 단위로 잘라 정수 버킷을 만든다.
    ##  같은 버킷(=같은 억제창) 안의 재관측은 동일 evidence_id 를 갖고,
    ##  버킷이 바뀌면(다른 시간대) 다른 evidence_id 가 되어 evidence.log 조인 시 시간대가 섞이지 않는다.
    global time_bucket: function(win: interval): string;

    ## 임계(threshold)만 쓰는 SumStats 에 붙이는 빈 epoch_result.
    ##  standalone(비클러스터)에서는 epoch_result 가 없으면 Zeek 가 epoch 를 끝내지 않는다
    ##  (base/frameworks/sumstats/non-cluster.zeek 의 do_finish_epoch 가 바로 반환). 그러면 임계 판정이
    ##  키마다 실행 내내 한 번만 되고(같은 스캐너의 다음 회차를 놓침) 집계 상태가 비워지지 않는다.
    ##  클러스터 매니저는 epoch_result 없이도 epoch 를 끝낸다.
    global sumstats_epoch_noop: function(ts: time, key: SumStats::Key, result: SumStats::Result);

    ## 도메인 부분매칭 예외 판정.
    ##  name(관측된 host/SNI)이 allow 집합의 어느 항목과 매칭되면 T.
    ##  매칭 규칙(부분매칭): allow 항목 d 에 대해
    ##    - name == d                (완전 일치)                예: telemetry.elastic.co
    ##    - name 이 "."+d 로 끝남     (하위 도메인 포함)          예: a.telemetry.elastic.co
    ##  즉 allow 에 "elastic.co" 를 넣으면 *.elastic.co 전부 예외 처리된다.
    ##  대소문자 무시. name 이 비었으면 F.
    global domain_matches: function(name: string, allow: set[string]): bool;

    ## 같은 identifier 의 notice 가 억제 창 안에 있는지. 건별 룰은 근거(evidence)를 쓰기 전에 확인한다.
    ##   억제 중이면 NOTICE 는 어차피 버려지므로 근거도 쓰지 않는다(쓰면 어떤 탐지에도 연결되지 않는 행이 쌓인다).
    global notice_suppressed: function(note: Notice::Type, identifier: string): bool;

    ## note(탐지 유형) -> 킬체인 단계명 매핑. evidence_log/detection_log 공용.
    ##   evidence_log 가 detection_log 보다 먼저 로드되므로 공용 위치(main)에 둔다.
    const stage_name_map: table[Notice::Type] of string = {
        [Port_Scan]              = "Recon",
        [Host_Scan]              = "Recon",
        [SQL_Injection]          = "Initial Access",
        [Webshell_Access]        = "Initial Access",
        [NTLM_Spray]             = "Credential Access",
        [Kerberos_Spray]         = "Credential Access",
        [Kerberos_Bruteforce]    = "Credential Access",
        [Kerberoasting]          = "Credential Access",
        [ASREP_Roasting]         = "Credential Access",
        [NTLM_Credential_Leak]   = "Credential Access",
        [Outbound_SMB]           = "Exfiltration",
        [WinRM_Lateral]          = "Lateral Movement",
        [DCOM_Lateral]           = "Lateral Movement",
        [SMB_Ransomware]         = "Impact",
        [Name_Poisoning]         = "Credential Access",
        [DCSync]                 = "Credential Access",
        [Nonstandard_Port]       = "Command and Control",
        [Long_Connection]        = "Command and Control",
        [Unknown_Protocol]       = "Command and Control",
        [SSH_Bruteforce]         = "Credential Access",
        [FTP_Bruteforce]         = "Credential Access",
        [TLS_Heartbleed]         = "Initial Access",
        [Cross_Site_Scripting]   = "Initial Access",
        [HTTP_Bruteforce]        = "Credential Access",
        [TLS_Beaconing]          = "Command and Control",
        [Remote_Service_Creation] = "Lateral Movement",
        [Remote_Task_Creation]   = "Lateral Movement",
        [Remote_WMI_Execution]   = "Lateral Movement",
        [Machine_Account_Misuse] = "Credential Access",
        [AI_Service_Upload]      = "Exfiltration",
        [AI_API_From_Server]     = "Command and Control",
        [AI_Service_Exploit]     = "Initial Access",
        [Coerced_Authentication] = "Credential Access",
        [Remote_Registry_Dump]   = "Credential Access",
        [Zerologon_Attempt]      = "Credential Access",
        [AD_Enumeration]         = "Recon",
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
    if ( to_lower(cat(parts[n-2], ".", parts[n-1])) in multi_label_suffixes )
        return cat(parts[n-3], ".", parts[n-2], ".", parts[n-1]);
    return cat(parts[n-2], ".", parts[n-1]);
    }

function registered_label(name: string): string
    {
    local host = to_lower(name);
    if ( |host| > 0 && host[|host| - 1 :] == "." )
        host = host[: |host| - 1];
    local parts = split_string(host, /\./);
    local n = |parts|;
    if ( n < 2 )
        return host;
    if ( n >= 3 && cat(parts[n-2], ".", parts[n-1]) in multi_label_suffixes )
        return parts[n-3];
    return parts[n-2];
    }

function is_external(a: addr): bool
    {
    # local_nets 에 포함되지 않으면 외부로 간주
    return ! Site::is_local_addr(a);
    }

function notice_suppressed(note: Notice::Type, identifier: string): bool
    {
    return Notice::is_being_suppressed(Notice::Info($note=note, $identifier=identifier));
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

function sumstats_epoch_noop(ts: time, key: SumStats::Key, result: SumStats::Result)
    {
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
