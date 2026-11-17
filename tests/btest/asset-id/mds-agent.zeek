# @TEST-DOC: AhnLab MDS Agent(기본 규칙) — MDS 장비의 에이전트 포트 두 개(8291·8293/tcp)에 연결이 성립한 단말만 security_agent ahnlab:mds-agent(70), 장비는 device ahnlab-mds(60). 포트 하나(50007, 다른 장비의 8291)나 거부된 연결은 기록하지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/mds_agent.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -E '	(security_agent|device)	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
