# @TEST-DOC: evidence.log 공통 필드 — 근거 연결의 src_port·dst_port·proto·community_id 가 conn.log 의 5-tuple 과 맞고(Community ID v1 스펙으로 따로 계산해 대조), detail 에서 올린 dst_name·bytes·window_s, 모든 행의 rule, 상관 근거의 parent_id 배열. 공격 스토리 7단계 pcap
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-community-id 30
# 연결이 하나로 정해지지 않는 집계형 근거(스캔·볼륨 집계)와 상관 근거는 연결 필드가 없다
# @TEST-EXEC: python3 -c "import json;r=[json.loads(l) for l in open('evidence.log')];assert not [x for x in r if 'uid' not in x and 'community_id' in x] and not [x for x in r if '~' in x.get('uid','')]"
# @TEST-EXEC: assert-rows evidence.log ge 1 rule=Port_Scan community_id=- window_s=300.000000
# @TEST-EXEC: assert-rows evidence.log eq 0 rule=-
# detail 에서 올린 값
# @TEST-EXEC: assert-rows evidence.log ge 1 rule=HTTP_Beaconing dst_name=cdn.update-check.net proto=tcp
# @TEST-EXEC: assert-rows evidence.log ge 1 rule=Kerberoasting window_s=600.000000 dst_port=88
# @TEST-EXEC: assert-rows evidence.log eq 1 rule=Exfil_Large_Transfer bytes=62915560
# @TEST-EXEC: assert-rows evidence.log ge 1 rule=Exfil_Volume_Aggregate bytes=62915560 window_s=60.000000
# 상관 근거의 하위 근거는 배열
# @TEST-EXEC: python3 -c "import json;r=[json.loads(l) for l in open('evidence.log')];k=[x for x in r if x.get('rule')=='Correlated_KillChain'];assert k and all(isinstance(x['parent_id'],list) and len(x['parent_id'])>=2 for x in k),k[:1]"
