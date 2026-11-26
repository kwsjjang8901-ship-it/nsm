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
        ## 35. IOC 일치(위협 정보의 IP·도메인·URL 과 일치하는 통신)
        IOC_Match,
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

    ## 룰 정책(docs/SENSOR_CONTROL_SPEC.md): 끌 룰 이름(notice 이름에서 NSM:: 를 뺀 값, 예: "Port_Scan").
    ##   Manager 가 만드는 nsm_config_policy.zeek 에서 redef 하고, 바꾸면 센서를 다시 시작한다.
    ##   끈 룰은 계산(예외 입구)·근거·notice·탐지 요약·상관에서 모두 빠진다. 룰별 detect_* 스위치와 함께 쓰며 둘 중 하나라도 끄면 꺼진다.
    const disabled_rules: set[string] = {} &redef;

    ## 룰 정책 버전(Manager 가 정책 파일에 씀). 센서 상태 로그(nsm_sensor.log)의 rule_policy_version 으로 보고해
    ##   Manager 가 "배포한 정책이 재시작 뒤 적용됐는지" 확인한다. 비우면 보고하지 않는다.
    const rule_policy_version = "" &redef;

    ## disabled_rules 를 notice 종류로 바꾼 것(시작할 때 한 번). 판정은 rule_disabled() 로.
    global disabled_notes: set[Notice::Type] = set();

    ## 이 탐지 종류가 룰 정책으로 꺼졌는지.
    global rule_disabled: function(note: Notice::Type): bool;

    ## 룰 레지스트리: 탐지 종류(notice)마다 진단명·ATT&CK 기법·킬체인 단계를 한 곳에 둔다.
    ##   탐지 요약(diagnosis·techniques·killchain_stages), notice 의 attack, 근거의 technique 기본값,
    ##   상관 체인의 단계 태그·기법 흐름, 로그 스키마의 열거값과 룰 목록(schema/rules.json)이 모두 이 표에서 나온다.
    ##   룰을 추가하면 여기에 한 줄을 넣는다(btest rules/rule-registry 가 빠진 notice 를 잡는다).
    type RuleInfo: record {
        diagnosis: string;              ##< nsm_detection.diagnosis(표시용 진단명)
        technique: string;              ##< ATT&CK 기법 ID(여러 개면 쉼표)
        stage:     string &default="";  ##< 킬체인 단계명(Recon … Impact). 상관 탐지는 ""
    };

    const rule_registry: table[Notice::Type] of RuleInfo = {
        [Port_Scan]                = [$diagnosis="NSM.Recon.PortScan", $technique="T1046", $stage="Recon"],
        [Host_Scan]                = [$diagnosis="NSM.Recon.HostScan", $technique="T1018", $stage="Recon"],
        [SQL_Injection]            = [$diagnosis="NSM.WebAttack.SqlInjection", $technique="T1190", $stage="Initial Access"],
        [Webshell_Access]          = [$diagnosis="NSM.WebAttack.Webshell", $technique="T1505.003", $stage="Initial Access"],
        [NTLM_Spray]               = [$diagnosis="NSM.CredentialAccess.NtlmSpray", $technique="T1110.003", $stage="Credential Access"],
        [Kerberos_Spray]           = [$diagnosis="NSM.CredentialAccess.KerberosSpray", $technique="T1110.003", $stage="Credential Access"],
        [Kerberos_Bruteforce]      = [$diagnosis="NSM.CredentialAccess.KerberosBruteforce", $technique="T1110.001", $stage="Credential Access"],
        [Kerberoasting]            = [$diagnosis="NSM.CredentialAccess.Kerberoasting", $technique="T1558.003", $stage="Credential Access"],
        [ASREP_Roasting]           = [$diagnosis="NSM.CredentialAccess.AsrepRoasting", $technique="T1558.004", $stage="Credential Access"],
        [NTLM_Credential_Leak]     = [$diagnosis="NSM.CredentialAccess.NtlmCredentialLeak", $technique="T1187", $stage="Credential Access"],
        [Outbound_SMB]             = [$diagnosis="NSM.Exfiltration.OutboundSmb", $technique="T1048", $stage="Exfiltration"],
        [WinRM_Lateral]            = [$diagnosis="NSM.LateralMovement.WinrmAccess", $technique="T1021.006", $stage="Lateral Movement"],
        [DCOM_Lateral]             = [$diagnosis="NSM.LateralMovement.DcomExec", $technique="T1021.003", $stage="Lateral Movement"],
        [SMB_Ransomware]           = [$diagnosis="NSM.Impact.SmbRansomware", $technique="T1486", $stage="Impact"],
        [Name_Poisoning]           = [$diagnosis="NSM.CredentialAccess.NamePoisoning", $technique="T1557.001", $stage="Credential Access"],
        [DCSync]                   = [$diagnosis="NSM.CredentialAccess.DcSync", $technique="T1003.006", $stage="Credential Access"],
        [Nonstandard_Port]         = [$diagnosis="NSM.C2.NonstandardPort", $technique="T1571", $stage="Command and Control"],
        [Long_Connection]          = [$diagnosis="NSM.C2.LongConnection", $technique="T1572", $stage="Command and Control"],
        [Unknown_Protocol]         = [$diagnosis="NSM.C2.UnknownProtocol", $technique="T1095", $stage="Command and Control"],
        [SSH_Bruteforce]           = [$diagnosis="NSM.CredentialAccess.SshBruteforce", $technique="T1110.001", $stage="Credential Access"],
        [FTP_Bruteforce]           = [$diagnosis="NSM.CredentialAccess.FtpBruteforce", $technique="T1110.001", $stage="Credential Access"],
        [TLS_Heartbleed]           = [$diagnosis="NSM.WebAttack.Heartbleed", $technique="T1190", $stage="Initial Access"],
        [Cross_Site_Scripting]     = [$diagnosis="NSM.WebAttack.Xss", $technique="T1190", $stage="Initial Access"],
        [HTTP_Bruteforce]          = [$diagnosis="NSM.CredentialAccess.HttpBruteforce", $technique="T1110.001", $stage="Credential Access"],
        [TLS_Beaconing]            = [$diagnosis="NSM.C2.TlsBeaconing", $technique="T1071.001", $stage="Command and Control"],
        [Remote_Service_Creation]  = [$diagnosis="NSM.LateralMovement.RemoteService", $technique="T1569.002", $stage="Lateral Movement"],
        [Remote_Task_Creation]     = [$diagnosis="NSM.LateralMovement.RemoteTask", $technique="T1053.005", $stage="Lateral Movement"],
        [Remote_WMI_Execution]     = [$diagnosis="NSM.LateralMovement.RemoteWmi", $technique="T1047", $stage="Lateral Movement"],
        [Machine_Account_Misuse]   = [$diagnosis="NSM.CredentialAccess.MachineAccountMisuse", $technique="T1557.001", $stage="Credential Access"],
        [AI_Service_Upload]        = [$diagnosis="NSM.Exfiltration.AiServiceUpload", $technique="T1567", $stage="Exfiltration"],
        [AI_API_From_Server]       = [$diagnosis="NSM.C2.AiApiFromServer", $technique="T1102", $stage="Command and Control"],
        [IOC_Match]                = [$diagnosis="NSM.C2.IocMatch", $technique="T1071", $stage="Command and Control"],
        [AI_Service_Exploit]       = [$diagnosis="NSM.WebAttack.AiServiceExploit", $technique="T1190", $stage="Initial Access"],
        [Coerced_Authentication]   = [$diagnosis="NSM.CredentialAccess.CoercedAuth", $technique="T1187", $stage="Credential Access"],
        [Remote_Registry_Dump]     = [$diagnosis="NSM.CredentialAccess.RemoteRegistryDump", $technique="T1003.002", $stage="Credential Access"],
        [Zerologon_Attempt]        = [$diagnosis="NSM.CredentialAccess.Zerologon", $technique="T1210", $stage="Credential Access"],
        [AD_Enumeration]           = [$diagnosis="NSM.Recon.AdEnumeration", $technique="T1087.002", $stage="Recon"],
        [SMB_Admin_Share]          = [$diagnosis="NSM.LateralMovement.SmbAccess", $technique="T1021.002", $stage="Lateral Movement"],
        [RDP_Lateral]              = [$diagnosis="NSM.LateralMovement.RdpAccess", $technique="T1021.001", $stage="Lateral Movement"],
        [SSH_Lateral]              = [$diagnosis="NSM.LateralMovement.SshAccess", $technique="T1021.004", $stage="Lateral Movement"],
        [HTTP_Beaconing]           = [$diagnosis="NSM.C2.HttpBeaconing", $technique="T1071.001", $stage="Command and Control"],
        [DNS_Tunneling]            = [$diagnosis="NSM.C2.DnsTunneling", $technique="T1071.004,T1572", $stage="Command and Control"],
        [Encrypted_C2]             = [$diagnosis="NSM.C2.EncryptedChannel", $technique="T1573.002", $stage="Command and Control"],
        [Exfil_Large_Transfer]     = [$diagnosis="NSM.Exfiltration.LargeTransfer", $technique="T1041", $stage="Exfiltration"],
        [Exfil_Volume_Aggregate]   = [$diagnosis="NSM.Exfiltration.VolumeAggregate", $technique="T1041", $stage="Exfiltration"],
        [Exfil_DNS]                = [$diagnosis="NSM.Exfiltration.DnsTunnel", $technique="T1048.003", $stage="Exfiltration"],
        [Exfil_Web_Upload]         = [$diagnosis="NSM.Exfiltration.WebUpload", $technique="T1567.002", $stage="Exfiltration"],
        [DGA_Domain]               = [$diagnosis="NSM.C2.DgaDomain", $technique="T1568.002", $stage="Command and Control"],
        [Correlated_KillChain]     = [$diagnosis="NSM.Correlation", $technique="T1021.002,T1041"],
    } &redef;

    ## 킬체인 단계명 -> 상관 체인의 짧은 태그(진단명 NSM.Correlation.<첫 단계>.<마지막 단계>에 씀)
    const stage_tags: table[string] of string = {
        ["Recon"] = "Recon", ["Initial Access"] = "InitialAccess", ["Command and Control"] = "C2",
        ["Credential Access"] = "CredentialAccess", ["Lateral Movement"] = "Lateral",
        ["Exfiltration"] = "Exfil", ["Impact"] = "Impact",
    } &redef;

    ## 진단명·기법·단계명(레지스트리에 없으면 "")
    global rule_diagnosis: function(n: Notice::Type): string;
    global rule_technique: function(n: Notice::Type): string;

    ## note -> 킬체인 단계명(매핑 없으면 "").
    global killchain_stage_of: function(n: Notice::Type): string;

    ## detection 의 victims 에 표시할 최대 host 수(쉼표 구분, 초과분 생략).
    ##   detection_log(Single) 와 correlation_killchain(Correlated) 공용.
    const chain_max_victims = 8 &redef;
}

function killchain_stage_of(n: Notice::Type): string
    {
    return ( n in rule_registry ) ? rule_registry[n]$stage : "";
    }

function rule_diagnosis(n: Notice::Type): string
    {
    return ( n in rule_registry ) ? rule_registry[n]$diagnosis : "";
    }

function rule_technique(n: Notice::Type): string
    {
    return ( n in rule_registry ) ? rule_registry[n]$technique : "";
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
    if ( note in disabled_notes )
        return T;
    return Notice::is_being_suppressed(Notice::Info($note=note, $identifier=identifier));
    }

function rule_disabled(note: Notice::Type): bool
    {
    return note in disabled_notes;
    }

# 룰 레지스트리 값 검사: 단계명이 stage_tags 에 없으면 상관 진단명이 깨지므로 시작할 때 알린다
#   (고객이 레지스트리에 룰을 더하거나 단계명을 바꿨을 때)
event zeek_init() &priority=90
    {
    for ( n, ri in rule_registry )
        if ( ri$stage != "" && ri$stage !in stage_tags )
            Reporter::warning(fmt("NSM::rule_registry: %s 의 단계 '%s' 가 stage_tags 에 없음(상관 진단명에 notice 이름을 씀)", n, ri$stage));
    }

# 끌 룰 이름 -> notice 종류. 모르는 이름(다른 패키지 버전의 룰 등)은 경고하고 건너뛴다.
event zeek_init() &priority=100
    {
    local known = enum_names(Notice::Type);
    for ( r in disabled_rules )
        {
        local id = "NSM::" + r;
        if ( id !in known )
            {
            Reporter::warning(fmt("NSM::disabled_rules: 모르는 룰 이름 %s (건너뜀)", r));
            next;
            }
        local v = lookup_ID(id);
        if ( v is Notice::Type )
            add disabled_notes[v as Notice::Type];
        }
    }

# 끈 룰의 notice 는 다른 처리(ATT&CK·예외·묶기·탐지 요약)보다 먼저 버린다: 기록하지 않으면 상관에도 들어가지 않는다.
hook Notice::policy(n: Notice::Info) &priority=100
    {
    if ( n$note !in disabled_notes )
        return;
    n$actions = set();
    break;
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

# ------------------------------------------------------------------ 클러스터: 학습한 값 공유
#
# 워커는 연결 단위로 트래픽을 나눠 받으므로, 한 워커가 배운 서버(DC·AI 판별용 서버·프록시)를
# 다른 워커가 모르면 같은 판단이 워커마다 달라진다(DC 복제를 DCSync 로 오탐 등).
# 처음 배웠을 때(이후 share_learned_refresh 마다 한 번) 매니저로 보내고, 매니저가 모든 워커·프록시에
# 다시 알린다(Broker 백엔드는 워커끼리 직접 메시지를 주고받지 않으므로 매니저를 거친다).
# 받은 노드는 자기 표에 넣기만 하고 다시 보내지 않는다. 단독 실행에서는 아무 일도 하지 않는다.

export {
    ## 같은 학습 값을 다시 알리는 간격(만료된 표를 채운다)
    const share_learned_refresh = 1hr &redef;
    ## 매니저가 학습 값을 기억하는 시간(마지막으로 받은 뒤). 새로 붙거나 다시 시작한 노드에 이 값을 다시 보낸다
    const share_learned_keep = 24hr &redef;

    ## 학습 값 알리기. kind 는 받는 룰이 고른다("dc"·"ai_server"·"proxy"). a·p 는 서버 주소·포트,
    ##   b 는 덧붙일 주소(프록시를 쓴 PC 등, 없으면 0.0.0.0)
    global share_learned: function(kind: string, a: addr, p: port, b: addr);

    ## 다른 노드가 배운 값(룰이 kind 를 골라 자기 표에 넣는다). 매니저는 받은 값을 워커·프록시에 다시 알린다
    global learned_shared: event(kind: string, a: addr, p: port, b: addr);
}

global share_sent: set[string, addr, port, addr] &create_expire=share_learned_refresh;

function share_learned(kind: string, a: addr, p: port, b: addr)
    {
@if ( Cluster::is_enabled() )
    if ( [kind, a, p, b] in share_sent )
        return;
    add share_sent[kind, a, p, b];
@if ( Cluster::local_node_type() == Cluster::MANAGER )
    event NSM::learned_shared(kind, a, p, b);
@else
    Cluster::publish(Cluster::manager_topic, NSM::learned_shared, kind, a, p, b);
@endif
@endif
    }

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
# 매니저가 아는 학습 값과 마지막으로 다시 알린 시각
global share_known: table[string, addr, port, addr] of time &write_expire=share_learned_keep;

# 매니저: 워커·프록시가 배운 값을 모든 워커·프록시에 다시 알린다(보낸 워커도 받지만 표에 이미 있다).
#   워커의 재전송(share_learned_refresh 마다)을 매니저가 같은 간격으로 걸러 버리면 시점이 조금만 어긋나도
#   계속 버려지므로, 매니저는 그 절반 간격으로만 거른다.
event NSM::learned_shared(kind: string, a: addr, p: port, b: addr) &priority=10
    {
    local now = network_time();
    if ( [kind, a, p, b] in share_known && now - share_known[kind, a, p, b] < share_learned_refresh / 2 )
        {
        share_known[kind, a, p, b] = share_known[kind, a, p, b];   # 기억 시간만 늘린다
        return;
        }
    share_known[kind, a, p, b] = now;
    Cluster::publish(Cluster::worker_topic, NSM::learned_shared, kind, a, p, b);
    Cluster::publish(Cluster::proxy_topic, NSM::learned_shared, kind, a, p, b);
    }

# 새로 붙거나 다시 시작한 워커·프록시는 표가 비어 있으므로 매니저가 아는 값을 모두 보낸다
event Cluster::node_up(name: string, id: string)
    {
    if ( name !in Cluster::nodes )
        return;
    local nt = Cluster::nodes[name]$node_type;
    if ( nt != Cluster::WORKER && nt != Cluster::PROXY )
        return;
    for ( [kind, a, p, b] in share_known )
        Cluster::publish(Cluster::node_topic(name), NSM::learned_shared, kind, a, p, b);
    }
@endif
