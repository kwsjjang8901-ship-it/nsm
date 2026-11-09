# JA3 지문 패키지: SSL::Info 확장이 detections(nsm_config의 c$ssl$ja3 참조)보다 먼저 되도록 최상단 로드
@load ./rules/ja3

@load ./detections/main
@load ./detections/evidence_log

# 탐지 룰 (킬체인 순서, 1탐지 = 1파일)
@load ./detections/01_port_scan
@load ./detections/02_host_scan
#@load ./03_sqli
#@load ./04_webshell
#@load ./05_ntlm_spray
@load ./detections/06_smb_admin_share
@load ./detections/15_rdp_lateral
@load ./detections/16_ssh_lateral
@load ./detections/07_http_beaconing
#@load ./08_dns_tunneling
@load ./detections/09_encrypted_c2
@load ./detections/10_large_transfer_exfil
#@load ./11_dns_exfil
@load ./detections/12_web_upload_exfil
@load ./detections/13_dga
@load ./detections/14_large_transfer_exfil

# 공통 인프라(탐지 아님): ATT&CK 매핑 _> 동일 notice 집계
@load ./detections/detection_log
@load ./detections/attack_mapping
@load ./detections/notice_aggregation

# 상관분석(탐지 아님): 확정 notice 를 manager 에서 소비 _> kill_chain 연결.
# 반드시 맨 마지막(notice_aggregation 이후)에 로드.
@load ./detections/correlation_killchain
@load ./detections/nsm_config_fixed
@load ./detections/nsm_config_custom
@load ./detections/intel_ja3

@load policy/protocols/conn/mac-logging
@load policy/tuning/json-logs

@load ./rules/filter_log