# @TEST-DOC: [07 클러스터] 같은 src->dst 비콘이 워커 2대로 흩어져도 HRW 로 같은 프록시에 모여 탐지된다
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=manager  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run proxy-1  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=proxy-1  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-1 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-2 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-wait 90
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.60 peer_descr=proxy-1
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 1 diagnosis=NSM.C2.HttpBeaconing attacker=10.0.0.60
# @TEST-EXEC: assert-rows manager/evidence.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.60

@load policy/frameworks/cluster/experimental

# 30초 주기 HTTP 비콘 14회(10.0.0.60 -> 93.184.215.14). 5-튜플 해시로 연결이 흩어진 상황을
# 재현하려고 짝수 번째는 worker-1, 홀수 번째는 worker-2 가 관측한다. 이전 구조(워커 로컬 상태)
# 에서는 각 워커가 60초 간격 7회씩만 보게 되어 최소 연속 12회 조건을 넘지 못한다.
# 도착 순서를 보장하려고 매니저가 300ms 간격으로 i 번째 관측을 지시하고 해당 워커만 보낸다.

global T0 = double_to_time(1794182400.0);
global N_BEACONS = 14;

global send_obs: event(i: count);
global next_step: event(i: count);
global finish: event();

event send_obs(i: count)
	{
	local owner = ( i % 2 == 0 ) ? "worker-1" : "worker-2";
	if ( Cluster::node != owner )
		return;
	NSM::beacon_submit(NSM::BeaconObs($orig=10.0.0.60, $resp=93.184.215.14,
	                                  $ts=T0 + i * 30secs, $host="update.beacon-c2.net",
	                                  $uid=fmt("Ctest%d", i)));
	}

event finish()
	{
	terminate();
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event next_step(i: count)
	{
	if ( i >= N_BEACONS )
		{
		schedule 15secs { finish() };   # 탐지가 안 되면 여기서 끝난다(실패로 검출)
		return;
		}
	Cluster::publish(Cluster::worker_topic, send_obs, i);
	schedule 300msec { next_step(i + 1) };
	}

event Cluster::Experimental::cluster_started()
	{
	schedule 1sec { next_step(0) };
	}

# 비커닝 notice 가 (프록시든 매니저든) 기록되면 상관 요약이 매니저로 온다 -> 종료
event NSM::corr_notice(cn: NSM::CorrNotice) &priority=-10
	{
	if ( cn$note == NSM::HTTP_Beaconing )
		schedule 2secs { finish() };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
