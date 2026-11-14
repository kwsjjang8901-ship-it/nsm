##! ============================================================================
##! nsm_config_fixed.zeek  —  NSM 탐지 패키지 통합 설정 파일 (운영/POC 환경별 튜닝)
##!
##!   임계값·토글을 이 파일 한 곳에서 redef 로 제어한다.
##!   예외는 예외 파일(NSM::exception_file, docs/SRS.md 7.8절)로 관리한다(재시작 불필요, 사유·만료 기록).
##!   아래 *_allowlist 예시는 호환용이다. 계속 동작하지만(drop 예외로 자동 등록) 폐기 예정이다.
##!   룰 스크립트 본체는 건드리지 않고, 이 파일만 환경에 맞게 수정/배포한다.
##!
##!   [로드 순서]  이 파일은 __load__.zeek 에서 모든 룰·상관 모듈 **뒤에** 로드된다.
##!     (뒤이어 nsm_config_custom → intel_ja3 → policy 스크립트 → rules/filter_log 순)
##!     - 이유: 여기서 redef 하는 식별자 중 상당수(allowlist·토글·룰별 임계)가
##!       각 탐지 룰 파일 안에서 선언되므로, 그 선언들이 먼저 파싱돼야 한다.
##!     - redef 값은 파싱 시점에 확정되어 어떤 zeek_init 보다 먼저 반영되므로,
##!       마지막에 로드해도 SumStats 생성 등에 정상적으로 적용된다.
##!
##!   [사용법]  주석(#) 을 풀고 값을 바꾼 뒤 배포. 값이 기본값과 같으면 그대로 둬도 무방.
##!   [원칙]    allowlist 는 전부 기본 비어 있음 -> 환경에 맞게 여기서 채운다.
##!   [주의]    이 파일은 **순수 redef 전용**이다. @load 를 두지 않는다.
##!             로드는 항상 `@load nsm_rules`(=nsm_rules/__load__.zeek) 경유로만 하며,
##!             __load__.zeek 가 main/룰/상관 을 먼저 로드한 뒤에 이 파일을
##!             로드하므로, 여기서 redef 하는 식별자는 모두 이미 선언돼 있다.
##!             (이 파일을 단독 실행하지 말 것 — 선언부가 없어 에러난다.)
##! ============================================================================

# =============================================================================
# [0] 방향 / 내부망 기준  (전 룰 공통 · 최우선)
#     내부망 = Site::local_nets. 방향(내부↔외부)은 이 값에서 파생된다.
#     ※ 반드시 환경 대역으로 지정할 것. 잘못 잡으면 모든 룰의 방향 판정이 틀어진다.
# =============================================================================
# (예시 - 환경에 맞게 위 값을 조정) nsm_config_custom.zeek에 포함됨
#redef Site::local_nets += {
#    10.0.0.0/8,
#    172.16.0.0/12,
#    192.168.0.0/16,
#};

# =============================================================================
# [01] Port_Scan  (T1046 · Recon)
# =============================================================================
# redef NSM::port_scan_local_only         = T;          # 내부 출발지만 관측
# redef NSM::port_scan_count_established   = T;          # F면 미응답/거부만 카운트(FP↓)
redef NSM::port_scan_threshold           = 25;          # (src,dst) 고유 포트 수 임계
redef NSM::scan_interval                 = 5min;        # 집계 윈도우(01·02 공유)
# redef NSM::port_scan_count_nosyn       = T;          # SYN 없는 TCP 탐침(FIN·NULL·Xmas·ACK·Window)도 셈
# redef NSM::port_scan_count_udp         = T;          # 응답 없는 UDP 탐침도 셈(traceroute 33434~33534 제외)
# redef NSM::port_scan_exclude_ports      += { 3389/tcp };            # 제외 포트, nsm_config_custom.zeek에 포함됨.
# redef NSM::port_scan_allowlist          += { 10.20.99.10/32 };      # 취약점 스캐너 등

# =============================================================================
# [02] Host_Scan  (T1018 · Recon)
# =============================================================================
# redef NSM::host_scan_local_only         = T;
# redef NSM::host_scan_count_established   = T;
redef NSM::host_scan_threshold           = 25;          # (src,포트) 고유 host 수 임계
# redef NSM::host_scan_exclude_ports      += { 123/udp };             # 제외 포트, nsm_config_custom.zeek에 포함됨.
# redef NSM::host_scan_allowlist          += { 10.20.99.20/32 };      # 모니터링/프록시

# =============================================================================
# [03] SQL_Injection (T1190) / [04] Webshell_Access (T1505.003) — 내부 웹서버 대상 요청만 검사
# =============================================================================
# redef NSM::web_attack_local_servers_only = T;                    # 내부(local_nets) 웹서버 대상만
# redef NSM::web_attack_allowlist         += { 10.20.99.10/32 };   # 취약점 스캐너·모의해킹 장비, nsm_config_custom.zeek 에 기록
# redef NSM::web_attack_body_max          = 4096;                  # 요청당 본문 검사 바이트

# =============================================================================
# [05] NTLM_Spray (T1110.003) — 내부 서버 대상 NTLM 인증 "실패" 계정 수
# =============================================================================
# redef NSM::ntlm_interval                 = 10min;                 # 집계 윈도우
# redef NSM::ntlm_user_threshold           = 10;                    # 단일 출발지의 인증 실패 고유 계정 수
# redef NSM::ntlm_spray_allowlist         += { 10.20.40.0/28 };     # 인증 프록시·VDI 게이트웨이, nsm_config_custom.zeek 에 기록

# =============================================================================
# [17] Kerberos_Spray (T1110.003) / Kerberos_Bruteforce (T1110.001) — 내부 KDC 대상 AS 사전인증 실패
# =============================================================================
# redef NSM::krb_spray_interval            = 10min;                 # 집계 윈도우
# redef NSM::krb_spray_user_threshold      = 10;                    # 출발지별 실패 고유 계정 수
# redef NSM::krb_bruteforce_threshold      = 20;                    # (출발지, 계정)별 비밀번호 실패 횟수
# redef NSM::krb_spray_allowlist          += { 10.20.40.0/28 };     # 계정 점검 도구 등, nsm_config_custom.zeek 에 기록

# =============================================================================
# [18] Kerberoasting (T1558.003) / ASREP_Roasting (T1558.004) — 약한 암호(RC4/DES) 티켓
# =============================================================================
# redef NSM::krb_roast_interval            = 10min;                 # 집계 윈도우
# redef NSM::krb_roast_service_threshold   = 5;                     # 출발지별 RC4 서비스 티켓 고유 SPN 수
# redef NSM::krb_roast_allowlist          += { 10.20.50.10/32 };    # 레거시 RC4 서비스를 대량 사용하는 서버
# redef NSM::asrep_require_weak_cipher     = T;                     # F 면 사전인증 없는 AS-REP 전부 탐지(PKINIT 오탐 가능)

# =============================================================================
# [19] Outbound_SMB (T1048) / NTLM_Credential_Leak (T1187) — 내부 -> 외부 SMB·NTLM 인증
# =============================================================================
# redef NSM::outbound_smb_allowlist       += { 10.20.60.5/32 };     # 외부 파일 공유가 허용된 장비
# redef NSM::outbound_smb_allowed_dsts    += { 203.0.113.0/28 };    # 허용한 외부 SMB 서버, nsm_config_custom.zeek 에 기록

# =============================================================================
# [20] WinRM_Lateral (T1021.006) / DCOM_Lateral (T1021.003) — 내부 원격 관리 채널 fan-out
# =============================================================================
# redef NSM::lm_mgmt_epoch                 = 5min;                  # 집계 윈도우
# redef NSM::winrm_lm_threshold            = 3;                     # WinRM 고유 목적지 수
# redef NSM::dcom_lm_threshold             = 3;                     # DCOM 원격 객체 생성 고유 목적지 수
# redef NSM::lm_mgmt_allowlist            += { 10.20.30.0/24 };     # SCCM·모니터링·Ansible·점프 서버, nsm_config_custom.zeek 에 기록

# =============================================================================
# [21] SMB_Ransomware (T1486 · Impact) — 확장자 변경 rename 대량 / 여러 폴더 랜섬 노트
# =============================================================================
# redef NSM::ransomware_interval           = 1min;                  # 집계 윈도우
# redef NSM::ransomware_rename_threshold   = 30;                    # 확장자가 바뀐 rename 고유 파일 수
# redef NSM::ransomware_note_threshold     = 5;                     # 랜섬 노트를 만든 고유 폴더 수
# redef NSM::ransomware_allowlist         += { 10.20.70.0/28 };     # 백업·동기화·DLP 서버, nsm_config_custom.zeek 에 기록

# =============================================================================
# [22] Name_Poisoning (T1557.001) — 한 응답자가 LLMNR/NBT-NS/mDNS 로 다수 이름에 긍정 응답
# =============================================================================
# redef NSM::poisoning_interval            = 10min;                 # 집계 윈도우
# redef NSM::poisoning_name_threshold      = 5;                     # 응답자별 고유 이름 수
# redef NSM::poisoning_allowlist          += { 10.0.0.53/32 };      # WINS 서버 등, nsm_config_custom.zeek 에 기록

# =============================================================================
# [23] DCSync (T1003.006) — DC 가 아닌 host 의 DRSUAPI DRSGetNCChanges
# =============================================================================
# redef NSM::dcsync_domain_controllers    += { 10.0.0.10, 10.0.0.11 }; # DC 목록(권장), nsm_config_custom.zeek 에 기록
# redef NSM::dcsync_learn_dcs              = T;                     # Kerberos 응답을 보낸 내부 host 를 DC 로 학습
# redef NSM::dcsync_allowlist             += { 10.20.80.5/32 };     # Azure AD Connect 등 복제 권한 사용 서버

# =============================================================================
# [24] Nonstandard_Port (T1571) / Long_Connection (T1572) — 외부향 비표준 포트·장기 연결
# =============================================================================
# redef NSM::nonstd_port_allowed_ports   += { 8081/tcp };         # 사내 표준으로 허용한 외부 포트
# redef NSM::nonstd_port_allowed_dsts    += { 203.0.113.0/24 };   # 허용한 외부 서비스
# redef NSM::long_conn_duration           = 6hr;                  # 장기 연결 기준
# redef NSM::long_conn_allowed_dsts      += { 203.0.113.10/32 };  # VPN·메신저·동기화 목적지, nsm_config_custom.zeek 에 기록

# =============================================================================
# [25] Unknown_Protocol (T1095) — 외부향 TCP 중 프로토콜 미식별 + 비표준 포트 + 대량 또는 장시간
# =============================================================================
# redef NSM::unknown_proto_min_bytes      = 1000000;              # 한 방향 바이트 임계
# redef NSM::unknown_proto_min_duration   = 30min;                # 대화형 연결 기준 시간
# redef NSM::unknown_proto_skip_ports    += { 1194/tcp };         # 검사하지 않을 포트(사내 VPN 등)
# 사내 전용 프로그램·게임 서버 등은 예외 파일(목적지·포트 축)로 뺀다.

# =============================================================================
# [26] SSH_Bruteforce / FTP_Bruteforce (T1110.001) — 같은 (출발지, 목적지)로 5분 안 인증 실패 반복
# =============================================================================
# redef NSM::svc_bf_epoch                 = 5min;                 # 집계 창
# redef NSM::ssh_bf_threshold             = 20;                   # 인증이 성공하지 않은 SSH 세션 수
# redef NSM::ftp_bf_threshold             = 10;                   # FTP 530 응답 수
# 인터넷에 노출된 SSH·FTP 서버(외부 스캐너가 늘 들어옴)는 예외 파일(목적지 축)로 뺀다.

# =============================================================================
# [27] TLS_Heartbleed (T1190) — 하트비트 과다 읽기 요청·응답 없는 요청(시도) / 요청보다 큰 응답(성공), 평문·암호화
# =============================================================================
# redef NSM::detect_heartbleed            = F;                    # 끄기
# redef NSM::heartbleed_enc_slack          = 32;                   # 암호화: 응답 - 요청 길이 여유
# 취약점 스캐너는 예외 파일(출발지 축)로 뺀다.

# =============================================================================
# [28] Cross_Site_Scripting (T1190) — 내부 웹서버 요청의 스크립트 실행 구조(<script>, onerror= 등)
# =============================================================================
# redef NSM::xss_patterns                 = NSM::xss_patterns | /<math[^>]*href/;   # 패턴 추가
# 분석 스크립트 등을 정상으로 올리는 CMS 관리 PC 는 예외 파일(출발지·목적지 축)로 뺀다.

# =============================================================================
# [29] HTTP_Bruteforce (T1110.001) — 같은 로그인 경로로 5분 안 비밀번호 값 20가지 이상 / Basic 인증 401 20회 이상
# =============================================================================
# redef NSM::web_bf_threshold             = 20;                   # 서로 다른 비밀번호 값 수
# redef NSM::web_bf_password_params      += { "userpw" };         # 고객 앱의 비밀번호 필드 이름
# redef NSM::web_bf_user_params          += { "empno" };          # 고객 앱의 계정 필드 이름

# =============================================================================
# [30] TLS_Beaconing (T1071.001) — 같은 외부 목적지로 일정 주기·비슷한 크기의 TLS 연결 12회 연속(주기 파라미터는 [07] 공통)
# =============================================================================
# redef NSM::tls_beacon_size_tolerance    = 0.25;                 # 크기 허용 비율
# redef NSM::tls_beacon_min_span          = 30min;                # 연속 구간 최소 길이(웹 페이지 스크립트 오탐 방지)
# 업데이트·텔레메트리 등 정상 주기 서비스는 예외 파일(SNI·목적지 축)로 뺀다.

# =============================================================================
# [31] Remote_Service_Creation / Remote_Task_Creation / Remote_WMI_Execution — 단일 대상 원격 실행(1건)
# =============================================================================
# SCCM·백업·배포 도구 등 원격 관리 서버는 예외 파일(출발지 축)로 뺀다.

# =============================================================================
# [32] Machine_Account_Misuse (T1557.001) — 한 출발지가 10분 안 머신 계정 2개 이상으로 인증
# =============================================================================
# redef NSM::machine_acct_threshold       = 2;
# NAT·장애 조치 클러스터 노드는 예외 파일(출발지 축)로 뺀다.

# =============================================================================
# [33] AI_Service_Upload (T1567) / AI_API_From_Server (T1102) / AI_Service_Exploit (T1190) — AI 관련 위협
# =============================================================================
# redef NSM::ai_service_domains          += { "ai.corp.example" };   # 고객이 쓰는 국내·사내 AI 서비스
# redef NSM::ai_upload_bytes              = 10000000;            # AI 서비스 1시간 업로드 임계
# redef NSM::ai_server_nets              += { 10.20.0.0/24 };     # 서버 대역(클러스터 권장)
# 승인한 AI 서비스·부서, 사내 챗봇 백엔드, ML 팀 대역은 예외 파일(도메인·출발지 축)로 뺀다.

# =============================================================================
# [34] Coerced_Authentication (T1187) / Remote_Registry_Dump (T1003.002) / Zerologon_Attempt (T1210)
#      / AD_Enumeration (T1087.002) — AD 공격(DCE-RPC)
# =============================================================================
# redef NSM::coerce_spoolss_dc_only       = T;     # spoolss 알림 등록은 대상이 DC 일 때만(DC 는 [23] 목록·학습)
# redef NSM::zerologon_threshold          = 20;    # 1분 안 netlogon 인증 호출 수
# redef NSM::ad_enum_threshold            = 10;    # 5분 안 세션·로컬 그룹 조회를 받은 고유 host 수
# 백업 에이전트(winreg 하이브 저장), 자산·인벤토리 도구(세션 조회)는 예외 파일(출발지 축)로 뺀다.

# =============================================================================
# [06] SMB_Admin_Share  (T1021.002 · Lateral)
# =============================================================================
redef NSM::smb_lm_epoch                  = 1min;        # 집계 윈도우
redef NSM::smb_lm_thresholds             = vector(2.0, 3.0);  # 단계 임계(고유 피해host)
# 단일 대상 확산도 경보로 잡으려면(psexec 1대) 임계를 1로:
# redef NSM::exclude_ipc_share            = T;          # IPC$ 제외
# redef NSM::smb_lm_allowlist             += { 10.20.30.0/24 };       # SCCM/백업/AV관리, nsm_config_custom.zeek에 포함됨.

# =============================================================================
# [15] RDP_Lateral  (T1021.001 · Lateral)
# =============================================================================
redef NSM::rdp_lm_epoch                  = 1min;        # 집계 윈도우
redef NSM::rdp_lm_thresholds             = vector(3.0, 5.0, 10.0);  # 단계 임계(고유 피해host)
# redef NSM::rdp_lm_allowlist             += { 10.20.30.0/24 };       # 점프박스/원격지원/IT관리자 PC, nsm_config_custom.zeek에 포함됨.

# =============================================================================
# [16] SSH_Lateral  (T1021.004 · Lateral)
# =============================================================================
redef NSM::ssh_lm_epoch                  = 1min;        # 집계 윈도우
redef NSM::ssh_lm_thresholds             = vector(3.0, 5.0, 10.0);  # 단계 임계(고유 피해host)
# redef NSM::ssh_lm_allowlist             += { 10.20.30.0/24 };       # CI/CD·Ansible·모니터링·백업·점프박스, nsm_config_custom.zeek에 포함됨.

# =============================================================================
# [07] HTTP_Beaconing  (T1071.001 · C2)
# =============================================================================
redef NSM::beacon_min_interval           = 3sec;        # 비커닝 최소 주기
redef NSM::beacon_max_interval           = 3600sec;     # 비커닝 최대 주기
redef NSM::beacon_jitter                 = 0.25;        # 주기 허용오차(25%)
redef NSM::beacon_min_hits               = 12;          # 연속 콜백 횟수(손실환경 하향 검토)
redef NSM::beacon_expire                 = 30min;       # 상태 만료
# redef NSM::beacon_allowlist             += { 210.112.192.0/24 };    # 정상 주기 트래픽 예외 대역, nsm_config_custom.zeek에 포함됨.
# redef NSM::beacon_allowlist_domains     += { "microsoft.com" };    # 도메인(HTTP Host) 예외, nsm_config_custom.zeek에 포함됨.

# =============================================================================
# [09] Encrypted_C2  (T1573 · C2)
# =============================================================================
redef NSM::enc_c2_score_threshold        = 3;           # 발화 점수 임계
redef NSM::enc_c2_w_selfsigned           = 2;           # 자체서명 가중치
redef NSM::enc_c2_w_nosni                = 1;           # SNI 부재
redef NSM::enc_c2_w_mismatch             = 1;           # SNI-인증서 불일치
# redef NSM::enc_c2_w_mismatch_selfsigned = 0;          # 자체서명이면서 SNI 불일치일 때(기본 0: 호스팅 기본 인증서 사이트 오탐 방지, 1 이면 이전 동작)
redef NSM::enc_c2_w_ja3                  = 2;           # JA3 차단목록 매칭(레거시, 단독으로는 임계 미달: 정상 브라우저와 지문 충돌)
redef NSM::enc_c2_w_ja4                  = 3;           # JA4 차단목록 정확 일치(주력)
redef NSM::enc_c2_w_ja4_a                = 1;           # JA4 "a" 워치리스트(보조)
# redef NSM::enc_c2_allowlist             += { 210.112.192.0/24 };    # 정상 자체서명 외부 서비스 예외 대역, nsm_config_custom.zeek에 포함됨.
# redef NSM::enc_c2_allowlist_sni         += { "elastic.co" };       # SNI(server_name) 기반 예외 목록, nsm_config_custom.zeek에 포함됨.
# --- JA4: FoxIO License 1.1 상 상업적 사용 제한으로 제품 형상에서는 미사용. ---
# ---       (지문 탐지는 JA3 레거시로 대체. JA4 는 평가/테스트 형상에서만 사용) ---
# redef NSM::get_ja4 = function(c: connection): string {
#     return c$ssl?$ja4 ? c$ssl$ja4 : "";
# };
# --- JA3 (Salesforce, BSD): rules/ja3 패키지 로드 후 훅 연결. 인텔은 intel_ja3.zeek(97개) ---
redef NSM::get_ja3 = function(c: connection): string {
    return c$ssl?$ja3 ? c$ssl$ja3 : "";
};

# =============================================================================
# [13] DGA_Domain  (T1568.002 · C2)
#   판정: src별 dga_interval 창에서 아래 3조건 AND
#     (1) NXDOMAIN 수 >= dga_nxdomain_threshold
#     (2) NXDOMAIN/전체 비율 >= dga_ratio_threshold
#     (3) NXDOMAIN 중 무작위형(DGA형) 등록 라벨 비율 >= dga_like_ratio
#         (2026-11 개정: 이전의 qname 평균 엔트로피 >= dga_entropy 는 폐기. 13_dga.zeek 머리말 참고)
#   ※ 13은 유일하게 방향(local_nets) 판정을 쓰지 않는다 -> local_nets 미설정 시에도 발화.
#   ※ evidence 는 무작위형 라벨인 NXDOMAIN 만 남긴다(정상 NXDOMAIN 의 evidence 폭증 억제).
# =============================================================================
redef NSM::dga_interval                  = 10min;       # 집계 윈도우
redef NSM::dga_nxdomain_threshold        = 50;          # 창 내 NXDOMAIN 응답 수
redef NSM::dga_ratio_threshold           = 0.8;         # NXDOMAIN / 전체 응답 비율
redef NSM::dga_like_ratio                = 0.5;         # NXDOMAIN 중 무작위형 라벨 비율
# ── 무작위형 라벨 판정(고급) — 기본값 그대로 두는 것을 권장 ──
# redef NSM::dga_min_label_len           = 6;           # 이보다 짧은 라벨은 판정 제외
# redef NSM::dga_label_min_score         = 2;           # 무작위형 판정 최소 점수
# redef NSM::multi_label_suffixes        += { "go.th" }; # 2단계 공용 접미사 추가
# ── 오탐/노이즈 억제 토글 ──
#   역방향 조회(in-addr.arpa·ip6.arpa)는 DGA와 무관. T면 집계·evidence 양쪽에서 완전 제외(기본 T).
redef NSM::dga_exclude_reverse_dns       = T;
# ── 내부/신뢰 도메인 예외(부분매칭): 집계·evidence 모두 제외 ──
#   내부 DNS·k8s·검색도메인 때문에 정상 조회가 NXDOMAIN 으로 잡히는 것을 막는다.
#   상위 도메인 하나로 하위 전체 매칭(예: "ahnlab.com" -> *.ahnlab.com).
#   집계에서도 빠지므로 NXDOMAIN 비율(nx/total) 정확도가 올라간다.
#redef NSM::dga_allowlist_domains         += { "localdomain" };           # 내부 도메인(k8s 등)
#redef NSM::dga_allowlist_domains         += { "svc.cluster.local" };     # 쿠버네티스 서비스
#redef NSM::dga_allowlist_domains         += { "cluster.local" };         # 쿠버네티스
#redef NSM::dga_allowlist_domains         += { "ahnlab.com" };            # 자사(검색도메인 포함)
#redef NSM::dga_allowlist_domains         += { "mshome.net" };            # Windows 홈네트워크
# redef NSM::dga_allowlist_domains       += { "internal" };             # 필요 시 추가

# =============================================================================
# [08] DNS_Tunneling / Exfil_DNS  (T1071.004 · C2 / T1048.003 · Exfil) — 통합 판정
#   (src, 등록도메인) 단위 dnstun_interval 창에서 수상한 질의 비율 >= dnstun_suspicious_ratio 일 때
#     고유 서브도메인 >= dnstun_unique_sub -> DNS_Tunneling,  누적 서브도메인 바이트 >= dnsexfil_bytes -> Exfil_DNS
# =============================================================================
redef NSM::dnstun_interval               = 5min;        # 집계 윈도우
redef NSM::dnstun_unique_sub             = 50;          # [터널링] 고유 서브도메인 수
redef NSM::dnsexfil_bytes                = 256*1024;    # [유출] 누적 인코딩 바이트
redef NSM::dnstun_suspicious_ratio       = 0.5;         # 수상한 질의 비율
# redef NSM::dns_tunnel_resolvers         += { 10.0.0.53 };          # 내부 재귀 리졸버(출발지 제외), nsm_config_custom.zeek 에 기록
# redef NSM::dns_tunnel_allowlist_domains += { "example-av.com" };   # 서브도메인 조회형 정상 서비스

# =============================================================================
# [10] Exfil_Large_Transfer  (T1041 · Exfil)
# =============================================================================
redef NSM::exfil_bytes_threshold         = 50*1024*1024;   # 단일 연결 orig_bytes 임계(50MB)

# =============================================================================
# [12] Exfil_Web_Upload  (T1567.002 · Exfil)
# =============================================================================
redef NSM::webupload_bytes               = 50*1024*1024;    # 업로드 바이트 임계(50MB)
# redef NSM::web_upload_allowlist         += { 10.20.60.0/24 };       # 승인된 클라우드 대역, nsm_config_custom.zeek에 포함됨.
# 클라우드 서비스 목적지 패턴 추가(예: mega, wetransfer 변형 등):
# redef NSM::cloud_hosts                  += /(?i:.*mega\.nz)/;

# =============================================================================
# [14] Exfil_Volume_Aggregate  (T1041 · Exfil)
# =============================================================================
redef NSM::exfil_epoch                   = 1min;            # 집계 윈도우
redef NSM::exfil_thresholds              = vector(50.0 * 1024 * 1024);  # host당 합계 임계(50MB/1min)
# redef NSM::exfil_volume_step            = 1024 * 1024;  # 연결당 집계 갱신 간격(기본 1MB). 작을수록 빠르고 이벤트 증가
#   ※ 룰 기본값(5MB/1min)은 정상 업무(파일 전송·백업·동기화·화상회의)에서도
#     흔히 넘어 오탐이 잦으므로 50MB/1min 으로 상향 운영 중.
#     운영 데이터로 재산정 권장. (epoch_result 가 아닌 threshold_series 라 단계값 사용 가능)


# =============================================================================
# [공통] 알람 억제(suppress) 창 — 동일 identifier 재발화 억제 시간
# =============================================================================
redef NSM::suppress_enc_c2               = 1hr;          # 09 암호화 C2
redef NSM::suppress_large_exfil          = 1hr;          # 10 단일 연결 대용량 유출
redef NSM::suppress_web_upload           = 1hr;          # 12 클라우드 업로드 유출
redef NSM::suppress_vol_agg              = 5min;         # 14 볼륨 집계 유출
# 참고: 01·02 는 scan_interval(5min), 06 은 smb_lm_epoch(1min),
#       07 은 beacon_expire(30min) 를 억제 창으로 사용(각 집계/상태 창과 동기).


# =============================================================================
# [상관] Correlated_KillChain
# =============================================================================
redef NSM::chain_max_expire              = 2hr;         # prime 최대 보관 시간
# 전이 규칙은 두 가지다(correlation_killchain.zeek, 고급):
#   chain_rules       : 탐지 -> 탐지 개별 전이(기존 23개)
#   chain_group_rules : 단계 묶음 -> 단계 묶음 전이(정찰·C2·자격증명·도메인 장악·확산·유출·영향)
#   묶음 구성은 corr_*_notes 집합. 예) 새 C2 탐지를 묶음에 넣기
#     redef NSM::corr_c2_notes += { NSM::Encrypted_C2 };   (chain_group_rules 도 함께 다시 정의해야 반영됨)


# =============================================================================
# [인증 맥락] 확산 근거의 계정 (auth_context.zeek, SRS 5.6절)
# =============================================================================
# NTLM 인증(출발지->목적지)과 Kerberos 서비스 티켓(출발지, 서비스 종류)을 모아 06·15·20·21·23 근거에 계정을 붙인다.
# redef NSM::auth_ctx_expire       = 30min;   # 보관 시간(확산 집계 창보다 길게)
# redef NSM::auth_ctx_resend       = 5min;    # 같은 조합을 매니저로 다시 보내지 않는 시간
# redef NSM::auth_ctx_max_accounts = 3;       # 키마다 남기는 계정 수
# redef NSM::auth_krb_classes     += { "mssqlsvc" };   # 기록할 서비스 종류 추가

# =============================================================================
# [메타데이터] 선별 전송 (T1) — docs/METADATA_EXPORT_PLAN.md
# =============================================================================
# 탐지 결과 외에 조사용 프로토콜 메타데이터를 골라 /log/zeek/meta/<이름>.log(JSON)에 쓴다.
# 수집 에이전트가 /log/zeek/meta 를 Manager 로 보낸다. 운영 값은 룰 파일 기본값을 그대로 쓴다.
# redef NSM::meta_export_enable   = T;                    # 전체 토글
# redef NSM::meta_path_prefix     = "/log/zeek/meta/";    # 출력 경로 앞부분
# redef NSM::meta_keep_raw_local  = F;                    # T: 선별 대상 원본을 /hdd_tmp/log/zeek 에도 남김(T2)
# redef NSM::meta_admin_ports    += { 8530/tcp };         # 내부 관리 포트 추가
# redef NSM::meta_dce_rpc_endpoints += { "epmapper" };    # 남길 RPC 인터페이스 추가
# redef NSM::meta_domain_allowlist += { "windowsupdate.com" };  # ssl·http·dns 에서 뺄 도메인(접미사 일치)
# redef NSM::meta_flow_interval    = 30min;               # conn 요약(flow_summary) 주기
# redef NSM::meta_dns_interval     = 1hr;                 # dns 요약(dns_summary) 주기
# redef NSM::meta_dns_max_domains_per_src = 100;          # 출발지별 dns_summary 도메인 행 상한
# 스트림별 필드·범위·중복 억제·분당 상한은 NSM::meta_export_streams(metadata/main.zeek)에서 정한다.
#   예) Kerberos 를 노드당 분당 5000행으로 제한: 그 항목에 $rate_limit=5000 을 넣어 표를 다시 정의한다.
