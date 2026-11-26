# @TEST-DOC: [22 NBNS 클러스터] 질의(브로드캐스트)와 응답(유니캐스트)을 다른 워커가 봐도 질의 host 기준 한 워커에서 짝지어 포이즈닝을 탐지한다. 응답이 질의보다 먼저 도착해도 짝짓는다
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=manager  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-1 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-2 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-wait 90
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Name_Poisoning src=10.0.0.66
# @TEST-EXEC: log-cut sub < manager/notice.log | grep -q 'unique_names=6 protocols=nbns'

@load policy/frameworks/cluster/experimental

# 학습 표·짝짓기 함수는 모듈 안 이름이라 NSM 모듈에서 부른다
module NSM;

# 원격으로만 부르는 이벤트라 export 한다(로컬 호출이 없으면 Zeek 가 경고)
export {
    global step: event(i: count);
    global next_step: event(i: count);
    global finish: event();
}

# 클러스터 SumStats 는 집계 구간이 끝날 때 워커 값을 모아 임계를 다시 본다. 테스트 시간을 줄이려고 구간을 짧게 둔다.
redef poisoning_interval = 5secs;

# 응답자 10.0.0.66 이 질의 host 10.0.0.5 의 서로 다른 이름 6개에 답한다(기준 5개).
# 질의는 worker-1, 응답은 worker-2 가 본다. 5·6 번은 응답을 먼저 보낸다.

event step(i: count)
	{
	if ( i == 0 && Cluster::node == "worker-2" )
		{
		NSM::nbns_answer(10.0.0.66, 10.0.0.5, 5);
		NSM::nbns_answer(10.0.0.66, 10.0.0.5, 6);
		}
	if ( i == 1 && Cluster::node == "worker-1" )
		for ( n in set(1, 2, 3, 4, 5, 6) )
			NSM::nbns_query(10.0.0.5, n, fmt("FILESRV%d", n));
	if ( i == 2 && Cluster::node == "worker-2" )
		for ( n in set(1, 2, 3, 4) )
			NSM::nbns_answer(10.0.0.66, 10.0.0.5, n);
	}

event finish()
	{
	terminate();
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event next_step(i: count)
	{
	if ( i > 2 )
		{
		schedule 15secs { finish() };   # 탐지가 안 되면 여기서 끝난다(실패로 검출)
		return;
		}
	Cluster::publish(Cluster::worker_topic, step, i);
	schedule 500msec { next_step(i + 1) };
	}

event Cluster::Experimental::cluster_started()
	{
	schedule 1sec { next_step(0) };
	}

event NSM::corr_notice(cn: NSM::CorrNotice) &priority=-10
	{
	if ( cn$note == NSM::Name_Poisoning )
		schedule 2secs { finish() };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
