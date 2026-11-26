# @TEST-DOC: 룰 정책(docs/SENSOR_CONTROL_SPEC.md) — NSM::disabled_rules 로 끈 룰은 notice·탐지 요약·근거에서 모두 빠지고 킬체인 상관에도 들어가지 않는다(룰 파일은 그대로, 공통 지점에서 막음). 나머지 탐지는 그대로. 정책 버전(NSM::rule_policy_version)은 센서 상태 로그로 보고한다. 모르는 룰 이름은 경고하고 건너뛴다. 정책 파일(nsm_config_policy.zeek)은 고객 설정 다음에 읽힌다
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP policy.zeek > /dev/null 2> err.txt
# @TEST-EXEC: test ! -s err.txt
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SQL_Injection
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Ransomware
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 rule=Port_Scan
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 rule=SQL_Injection
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 rule=SMB_Ransomware
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::Port_Scan
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::SQL_Injection
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::SMB_Ransomware
# 나머지 탐지는 그대로
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Webshell_Access
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberoasting
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer
# @TEST-EXEC: python3 check.py
# 모르는 룰 이름: 경고하고 나머지는 적용
# @TEST-EXEC: mkdir bad && cd bad && zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP ../bad.zeek > /dev/null 2> err.txt; grep -q "모르는 룰 이름 No_Such_Rule" err.txt && assert-rows notice.log eq 0 note=NSM::Port_Scan
# 로드 순서: fixed -> custom -> policy(정책이 고객 설정보다 우선)
# @TEST-EXEC: python3 order.py $PKG/__load__.zeek

# @TEST-START-FILE policy.zeek
redef NSM::rule_policy_version = "RP-TEST-1";
redef NSM::disabled_rules += { "Port_Scan", "SQL_Injection", "SMB_Ransomware" };
# @TEST-END-FILE

# @TEST-START-FILE bad.zeek
redef NSM::disabled_rules += { "Port_Scan", "No_Such_Rule" };
# @TEST-END-FILE

# @TEST-START-FILE check.py
import json
rows = [json.loads(l) for l in open("nsm_detection.log")]
corr = [r for r in rows if r.get("rule") == "Correlated_KillChain"]
assert corr, "상관 탐지가 없음"
last = max(corr, key=lambda r: r.get("revision") or 0)
st = last["killchain_stages"]
# 끈 룰의 단계(정찰=포트 스캔, 피해=랜섬웨어)는 체인에 없다. 나머지 단계로는 이어진다
assert "Recon" not in st and "Impact" not in st, st
assert {"Initial Access", "Command and Control", "Credential Access", "Lateral Movement", "Exfiltration"} <= set(st), st
sen = [json.loads(l) for l in open("nsm_sensor.log")]
assert sen and all(r.get("rule_policy_version") == "RP-TEST-1" for r in sen), sen[:1]
# @TEST-END-FILE

# @TEST-START-FILE order.py
import re, sys
loads = re.findall(r"^@load \./detections/(nsm_config_\w+)", open(sys.argv[1]).read(), re.M)
assert loads == ["nsm_config_fixed", "nsm_config_custom", "nsm_config_policy"], loads
# @TEST-END-FILE
