# @TEST-DOC: [클러스터 학습 공유] 한 워커가 배운 DC(23·34)·AI 판별용 서버(33)·프록시(10·12·14 등)를 다른 워커와 매니저도 안다. 프록시 출발지 제외의 PC 수는 워커를 합쳐 센다
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=manager  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-1 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-2 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-wait 60
# 배운 노드(worker-1)뿐 아니라 보지 못한 worker-2 와 매니저도 같은 판단을 한다
# @TEST-EXEC: grep -qx 'worker-1 dc=T ai=T proxy=T proxy_host=T' worker-1/.stdout
# @TEST-EXEC: grep -qx 'worker-2 dc=T ai=T proxy=T proxy_host=T' worker-2/.stdout
# @TEST-EXEC: grep -qx 'manager dc=T ai=T proxy=T proxy_host=T' manager/.stdout
# 학습 대상이 아닌 주소는 공유돼도 바뀌지 않는다
# @TEST-EXEC: grep -qx 'worker-2 other dc=F ai=F proxy=F' worker-2/.stdout

@load policy/frameworks/cluster/experimental

# 학습 표·짝짓기 함수는 모듈 안 이름이라 NSM 모듈에서 부른다
module NSM;

# 원격으로만 부르는 이벤트라 export 한다(로컬 호출이 없으면 Zeek 가 경고)
export {
    global learn: event();
    global check: event();
    global finish: event();
    global check_all: event();
    global finish_all: event();
}


event learn()
	{
	if ( Cluster::node == "worker-1" )
		{
		NSM::dcsync_learn_addr(10.0.0.10);              # Kerberos 에 답한 DC
		NSM::ai_learn(10.0.0.20, 1433/tcp);             # DB 서버
		NSM::proxy_learn_tunnel(10.0.0.30, 3128/tcp, 10.0.1.1);
		NSM::proxy_learn_tunnel(10.0.0.30, 3128/tcp, 10.0.1.3);
		}
	if ( Cluster::node == "worker-2" )
		# 같은 프록시를 쓰는 세 번째 PC 는 worker-2 만 봤다(워커마다 따로 세면 둘 다 3대 미만)
		NSM::proxy_learn_tunnel(10.0.0.30, 3128/tcp, 10.0.1.2);
	}

function state(): string
	{
	return fmt("%s dc=%s ai=%s proxy=%s proxy_host=%s", Cluster::node,
	           NSM::dcsync_is_dc(10.0.0.10) ? "T" : "F", NSM::ai_is_server(10.0.0.20) ? "T" : "F",
	           [10.0.0.30, 3128/tcp] in NSM::proxy_learned ? "T" : "F", NSM::is_proxy_host(10.0.0.30) ? "T" : "F");
	}

event check()
	{
	print state();
	if ( Cluster::node == "worker-2" )
		print fmt("%s other dc=%s ai=%s proxy=%s", Cluster::node, NSM::dcsync_is_dc(10.0.0.11) ? "T" : "F",
		          NSM::ai_is_server(10.0.0.21) ? "T" : "F", [10.0.0.30, 8080/tcp] in NSM::proxy_learned ? "T" : "F");
	}

event finish()
	{
	terminate();
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Cluster::Experimental::cluster_started()
	{
	Cluster::publish(Cluster::worker_topic, learn);
	schedule 3secs { check_all() };
	}

event check_all()
	{
	Cluster::publish(Cluster::worker_topic, check);
	event check();
	schedule 2secs { finish_all() };
	}

event finish_all()
	{
	Cluster::publish(Cluster::worker_topic, finish);
	schedule 1sec { finish() };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
