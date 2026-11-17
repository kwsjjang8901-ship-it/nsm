##! AhnLab MDS Agent 신호: 단말이 MDS 장비의 에이전트 포트(mds_agent_ports)로 접속하면
##! 단말에 security_agent "ahnlab:mds-agent", 장비에 device "ahnlab-mds" 를 남긴다.
##!
##!   mds_servers 지정   : 그 주소로의 연결 성립 1건이면 기록(단말 90, 장비 80)
##!   mds_servers 비어 있음: 같은 서버의 서로 다른 에이전트 포트 mds_agent_min_ports(2)개 이상에
##!                         mds_agent_window(1시간) 안에 연결이 성립하면 기록(단말 70, 장비 60)
##!
##! 연결 성립(SYN-ACK)만 본다. 응답 없는 시도는 장비가 없거나 막힌 것이라 설치 근거가 아니다.
##! 신호가 없는 단말이 미설치라는 뜻은 아니다(센서가 그 경로를 못 보거나, 관측 시간이 보고 주기보다 짧을 수 있음).

@load base/protocols/conn
@load ../main

module AssetID;

## (클라이언트, 서버) -> 연결이 성립한 에이전트 포트
global mds_pair_ports: table[addr, addr] of set[port] &create_expire=mds_agent_window;
## 이미 기록한 (클라이언트, 서버)
global mds_pair_done: set[addr, addr] &create_expire=mds_agent_window;

event connection_established(c: connection)
	{
	if ( ! enable_mds_agent )
		return;

	local p = c$id$resp_p;
	if ( p !in mds_agent_ports )
		return;

	local cl = c$id$orig_h;
	local sv = c$id$resp_h;
	if ( [cl, sv] in mds_pair_done )
		return;

	if ( |mds_servers| > 0 )
		{
		if ( sv !in mds_servers )
			return;
		add mds_pair_done[cl, sv];
		emit(cl, SECURITY_AGENT, "ahnlab:mds-agent", "mds", 90, c$uid);
		emit(sv, DEVICE, "ahnlab-mds", "mds", 80, c$uid);
		return;
		}

	if ( [cl, sv] !in mds_pair_ports )
		mds_pair_ports[cl, sv] = set();
	add mds_pair_ports[cl, sv][p];
	if ( |mds_pair_ports[cl, sv]| < mds_agent_min_ports )
		return;

	add mds_pair_done[cl, sv];
	delete mds_pair_ports[cl, sv];
	emit(cl, SECURITY_AGENT, "ahnlab:mds-agent", "mds", 70, c$uid);
	emit(sv, DEVICE, "ahnlab-mds", "mds", 60, c$uid);
	}
