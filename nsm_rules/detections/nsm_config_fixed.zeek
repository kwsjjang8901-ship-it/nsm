##! ============================================================================
##! nsm-config.zeek  —  NSM 탐지 패키지 통합 설정 파일 (운영/POC 환경별 튜닝)
##!
##!   모든 임계값·토글·예외(allowlist)를 이 파일 한 곳에서 redef 로 제어한다.
##!   룰 스크립트 본체는 건드리지 않고, 이 파일만 환경에 맞게 수정/배포한다.
##!
##!   [로드 순서]  이 파일은 __load__.zeek 에서 **가장 마지막**에 로드된다.
##!     - 이유: 여기서 redef 하는 식별자 중 상당수(allowlist·토글·룰별 임계)가
##!       각 탐지 룰 파일 안에서 선언되므로, 그 선언들이 먼저 파싱돼야 한다.
##!     - redef 값은 파싱 시점에 확정되어 어떤 zeek_init 보다 먼저 반영되므로,
##!       마지막에 로드해도 SumStats 생성 등에 정상적으로 적용된다.
##!
##!   [사용법]  주석(#) 을 풀고 값을 바꾼 뒤 배포. 값이 기본값과 같으면 그대로 둬도 무방.
##!   [원칙]    allowlist 는 전부 기본 비어 있음 -> 환경에 맞게 여기서 채운다.
##!   [주의]    이 파일은 **순수 redef 전용**이다. @load 를 두지 않는다.
##!             로드는 항상 `@load nsm-detection`(=__load__.zeek) 경유로만 하며,
##!             __load__.zeek 가 main/룰/상관 을 먼저 로드한 뒤 맨 마지막에 이 파일을
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
#    172.0.0.0/8,
#    192.168.0.0/16,
#};

# =============================================================================
# [01] Port_Scan  (T1046 · Recon)
# =============================================================================
# redef NSM::port_scan_local_only         = T;          # 내부 출발지만 관측
# redef NSM::port_scan_count_established   = T;          # F면 미응답/거부만 카운트(FP↓)
redef NSM::port_scan_threshold           = 25;          # (src,dst) 고유 포트 수 임계
redef NSM::scan_interval                 = 5min;        # 집계 윈도우(01·02 공유)
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
redef NSM::enc_c2_w_ja3                  = 3;           # JA3 차단목록 매칭(레거시)
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
#     (3) NXDOMAIN qname 평균 엔트로피 >= dga_entropy
#   ※ 13은 유일하게 방향(local_nets) 판정을 쓰지 않는다 -> local_nets 미설정 시에도 발화.
# =============================================================================
redef NSM::dga_interval                  = 10min;       # 집계 윈도우
redef NSM::dga_nxdomain_threshold        = 50;          # 창 내 NXDOMAIN 응답 수
redef NSM::dga_ratio_threshold           = 0.8;         # NXDOMAIN / 전체 응답 비율
redef NSM::dga_entropy                   = 4.0;         # NXDOMAIN 도메인 평균 엔트로피
# ── 오탐/노이즈 억제 토글 ──
#   역방향 조회(in-addr.arpa·ip6.arpa)는 숫자·점이 많아 엔트로피가 높지만 DGA와 무관.
#   T면 집계·evidence 양쪽에서 완전 제외한다(기본 T).
redef NSM::dga_exclude_reverse_dns       = T;
#   evidence 를 남길 최소 엔트로피. 미달 NXDOMAIN 은 집계(nx/ratio/평균)에는 반영하되
#   evidence 행만 생략한다 -> 판정 정확도 불변, evidence 폭증만 억제(기본 = dga_entropy).
redef NSM::dga_evidence_min_entropy      = 4.0;
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
redef NSM::exfil_thresholds              = vector(50.0 * 1024 * 1024);  # host당 합계 임계(5MB/1min)
#   ※ [검토] 5MB/1min 은 상당히 민감하다. 정상 업무(파일 전송·백업·동기화·화상회의)에서
#     1분 5MB 는 흔하므로 오탐이 잦을 수 있다. 10번(단일연결 100MB)과 20배 차이.
#     운영 데이터로 재산정 권장 (예: vector(50.0*1024*1024, 200.0*1024*1024)).


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
# 전이 규칙(chain_rules)·단계별 윈도우는 correlation-killchain.zeek 에서 직접 편집(고급).
