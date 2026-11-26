##! 룰 정책: MDS Manager 가 만들어 배포하는 파일(docs/SENSOR_CONTROL_SPEC.md). 저장소에서는 비워 둔다.
##!
##! 고객 설정(nsm_config_custom.zeek) 다음에 읽으므로 같은 값이면 이 파일이 우선한다.
##! 바꾸면 센서를 다시 시작한다(진행 중인 집계·비커닝 추적·킬체인 상관은 처음부터 다시 쌓인다).
##! Manager 가 쓰는 내용(예):
##!   redef NSM::rule_policy_version = "RP-2026.11.26-3";
##!   redef NSM::disabled_rules += { "Port_Scan", "Host_Scan" };
##!   redef NSM::beacon_min_hits = 16;
