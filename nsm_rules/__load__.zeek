# JA3 지문 패키지: SSL::Info 확장이 detections(nsm_config의 c$ssl$ja3 참조)보다 먼저 되도록 최상단 로드
@load ./rules/ja3

@load ./detections/main
@load ./detections/evidence_log
# 예외 엔진: 룰이 입구에서 NSM::exception_drop* 을 부르므로 룰보다 먼저 로드
@load ./detections/exceptions
@load ./detections/auth_context      # 확산 근거의 계정(NTLM·Kerberos TGS 최근 인증)

# 탐지 룰 (킬체인 순서, 1탐지 = 1파일)
@load ./detections/01_port_scan
@load ./detections/02_host_scan
@load ./detections/03_sqli                # 내부 웹서버 대상 SQL Injection
@load ./detections/04_webshell            # 내부 웹서버 대상 웹쉘 접근
@load ./detections/05_ntlm_spray       # NTLM 인증 실패 기반 패스워드 스프레이
@load ./detections/17_kerberos_spray    # Kerberos 사전인증 실패 기반 스프레이·무차별 대입
@load ./detections/18_kerberoasting     # Kerberoasting(RC4 서비스 티켓)·AS-REP Roasting
@load ./detections/19_outbound_smb      # 외부향 SMB 연결·외부 NTLM 인증(자격증명 유출)
@load ./detections/22_name_poisoning    # LLMNR/NBT-NS/mDNS 포이즈닝(Responder 류)
@load ./detections/23_dcsync            # DC 가 아닌 host 의 디렉터리 복제 요청(DRSGetNCChanges)
@load ./detections/06_smb_admin_share
@load ./detections/15_rdp_lateral
@load ./detections/16_ssh_lateral
@load ./detections/20_winrm_dcom_lateral  # WinRM(5985/5986)·DCOM(RemoteCreateInstance) 확산
@load ./detections/07_http_beaconing
@load ./detections/08_dns_tunneling       # 터널링(DNS_Tunneling) + 유출(Exfil_DNS) 통합
@load ./detections/09_encrypted_c2
@load ./detections/10_large_transfer_exfil
@load ./detections/12_web_upload_exfil
@load ./detections/13_dga
@load ./detections/24_nonstd_port         # 외부향 비표준 포트 프로토콜·장기 외부 연결
@load ./detections/25_unknown_protocol     # 식별 안 된 프로토콜의 외부 통신(역방향 셸 등)
@load ./detections/26_service_bruteforce   # SSH·FTP 무차별 대입
@load ./detections/27_heartbleed           # TLS Heartbleed
@load ./detections/14_large_transfer_exfil
@load ./detections/21_smb_ransomware      # 랜섬웨어성 SMB 파일 변경(확장자 변경 rename·랜섬 노트)

# 공통 인프라(탐지 아님): ATT&CK 매핑 _> 동일 notice 집계
@load ./detections/detection_log
@load ./detections/attack_mapping
@load ./detections/notice_aggregation

# 상관분석(탐지 아님): 확정 notice 를 manager 에서 소비 _> kill_chain 연결.
# 반드시 맨 마지막(notice_aggregation 이후)에 로드.
@load ./detections/correlation_killchain

# 자산 식별(탐지 아님): 자산 신호를 asset_signal.log 로 남긴다(docs/asset-id/, Manager 리졸버 입력).
@load ./asset-id

# 메타데이터 선별 전송(T1): 설정(nsm_config_*)에서 meta_* 를 redef 할 수 있도록 설정보다 먼저 로드.
@load ./metadata

@load ./detections/nsm_config_fixed
@load ./detections/nsm_config_custom
@load ./detections/intel_ja3

@load policy/protocols/conn/mac-logging
@load policy/tuning/json-logs

@load ./rules/filter_log