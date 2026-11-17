# @TEST-DOC: AhnLab MDS Agent(MDS 장비 주소 지정) — mds_servers 의 에이전트 포트에 연결이 성립하면 포트 하나여도 단말을 에이전트(90)로, 장비를 ahnlab-mds(80)로 기록한다. 다른 장비(.99)의 8291 은 기록하지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/mds_agent.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -E '	(security_agent|device)	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
redef AssetID::mds_servers = { 10.0.30.5/32 };
