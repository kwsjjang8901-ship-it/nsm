# @TEST-DOC: 고객 정의 에이전트 정책 — 사내 서버형(ep-mgr: 서버+포트, 서버에 device), 포트만(nac: 2개 이상), 클라우드 도메인(edr-cloud: SNI 하위 도메인, 프록시 CONNECT), User-Agent(patch). 다른 서버·거부된 연결·포트 하나·제조사 웹사이트·브라우저는 맞지 않는다. 틀린 정책 4개는 빼고 kind=invalid 로 남긴다
# @TEST-EXEC: zeek -C -r $TRACES/agent_policy.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep '	agent_policy	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out
# @TEST-EXEC: zeek-cut kind policy_id msg < asset_agent_policy.log | sort > policy.out
# @TEST-EXEC: btest-diff policy.out
# 끄면 정책 파일을 읽지 않고 신호도 없다
# @TEST-EXEC: rm -f asset_signal.log asset_agent_policy.log && zeek -C -r $TRACES/agent_policy.pcap $ASSETID %INPUT AssetID::enable_agent_policy=F
# @TEST-EXEC: ! grep -q '	agent_policy	' asset_signal.log
# @TEST-EXEC: test ! -e asset_agent_policy.log

redef AssetID::asset_nets = { 10.0.0.0/8 };
redef AssetID::agent_policy_file = "policy.tsv";

# @TEST-START-FILE policy.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	product	server	ports	domain	user_agent	min_ports	device
ep-mgr	사내 백신 관리 서버	10.0.55.5	8443/tcp	-	-	-	epp-server
nac	NAC 에이전트	-	7001/tcp,7002/tcp	-	-	2	-
edr-cloud	클라우드 EDR	-	-	*.sensor.edr-vendor.example	-	-	-
patch	패치 관리	-	-	-	PatchAgent/	-	-
bad-port	포트 오류	10.0.55.9	99999	-	-	-	-
only-port	포트 하나만	-	8291/tcp	-	-	1	-
empty	조건 없음	-	-	-	-	-	-
bad id	id 오류	10.0.55.9	-	-	-	-	-
# @TEST-END-FILE
