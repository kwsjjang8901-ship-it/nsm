# @TEST-DOC: nsm_detection 추가 필드 — rule(notice 이름, 상관은 Correlated_KillChain), severity_id(단독 1·상관 3), victim_count(잘리기 전 피해 host 수), 근거 요약 accounts·dst_names. 공격 스토리 7단계 pcap 에서 피해 host 표시를 1개로 줄여도 victim_count 는 실제 수(확산 2대)다. 상관 id 는 kc-<epoch>-<프로세스 값>-<번호>
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP %INPUT
# 모든 행에 rule·severity_id 가 있고, 등급과 숫자가 짝이 맞는다
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 rule=-
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Single severity_id=3
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated severity_id=1
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=Port_Scan severity=Information severity_id=1
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 rule=Correlated_KillChain category=Correlated severity=Suspicious severity_id=3
# 피해 host 표시는 잘려도 전체 수는 남는다(SMB 확산 .31·.32)
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=SMB_Admin_Share victims=10.0.20.31 victim_count=2
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=Port_Scan victims=10.0.10.81 victim_count=1
# 근거 요약: Kerberoasting 계정, 비콘 목적지 이름. 상관 행은 체인 근거 전체에서 모은다
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=Kerberoasting accounts=svc_web@corp.example
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=HTTP_Beaconing dst_names=cdn.update-check.net
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 rule=Correlated_KillChain accounts=svc_web@corp.example dst_names=cdn.update-check.net
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 rule=Port_Scan accounts=svc_web@corp.example
# 상관 id 형식
# @TEST-EXEC: python3 -c "import json,re;ids={json.loads(l)['detection_id'] for l in open('nsm_detection.log') if json.loads(l)['category']=='Correlated'};assert ids and all(re.fullmatch(r'kc-[0-9]+-[0-9a-f]{6}-[0-9]+',i) for i in ids),ids"

redef NSM::chain_max_victims = 1;
