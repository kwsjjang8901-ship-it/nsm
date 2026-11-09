@load nsm_rules/detections/main

# 증적(Evidence) 전용 로그 스트림 _ 탐지 룰보다 먼저 로드되어야 함
# (탐지 룰이 NSM::write_evidence / Notice::Info$evidence_id 를 사용)
@load ./evidence_log

# 탐지 룰 (킬체인 순서, 1탐지 = 1파일)
@load ./01_port_scan
@load ./02_host_scan
#@load ./03_sqli
#@load ./04_webshell
#@load ./05_ntlm_spray
@load ./06_smb_admin_share
@load ./15_rdp_lateral
@load ./16_ssh_lateral
@load ./07_http_beaconing
#@load ./08_dns_tunneling
@load ./09_encrypted_c2
@load ./10_large_transfer_exfil
#@load ./11_dns_exfil
@load ./12_web_upload_exfil
@load ./13_dga
@load ./14_large_transfer_exfil

# 공통 인프라(탐지 아님): ATT&CK 매핑 -> 동일 notice 집계
@load ./attack_mapping
@load ./notice_aggregation

# 상관분석(탐지 아님): 확정 notice 를 manager 에서 소비 -> kill_chain 연결.
# 반드시 맨 마지막(notice_aggregation 이후)에 로드.
@load ./correlation_killchain
@load ./nsm_config_fixed
@load ./nsm_config_custom
@load ./intel_ja3
