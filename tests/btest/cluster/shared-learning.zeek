# @TEST-DOC: [클러스터 학습 공유] 한 워커가 배운 DC(23·34)·AI 판별용 서버(33)·프록시(10·12·14 등)를 다른 워커와 매니저도 안다. DC 의 클라이언트 3대·프록시 출발지 제외의 PC 3대는 워커를 합쳐 세고, PC 는 3대까지만 알린다. 이미 배운 서버의 포트는 다른 워커 값으로 덮어쓰지 않는다. 다시 시작한 노드(표가 빈 노드)에는 매니저가 아는 값을 다시 보낸다
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
# 노드마다 시작·실행 중 경고·오류가 없다(워커·매니저에서만 쓰는 함수는 그 노드에만 둔다)
# @TEST-EXEC: ! grep -hiE "warning|error" manager/.stderr worker-1/.stderr worker-2/.stderr
# 배운 노드뿐 아니라 보지 못한 노드와 매니저도 같은 판단을 한다(DC 클라이언트는 worker-1 2대 + worker-2 1대)
# @TEST-EXEC: grep -qx 'worker-1 dc=T ai=T proxy=T proxy_host=T' worker-1/.stdout
# @TEST-EXEC: grep -qx 'worker-2 dc=T ai=T proxy=T proxy_host=T' worker-2/.stdout
# @TEST-EXEC: grep -qx 'manager dc=T ai=T proxy=T proxy_host=T' manager/.stdout
# 학습 대상이 아닌 주소는 공유돼도 바뀌지 않는다. worker-2 는 자기가 배운 서버 포트를 지킨다
# @TEST-EXEC: grep -qx 'worker-2 other dc=F ai=F proxy=F ai_port=3306/tcp' worker-2/.stdout
# 프록시를 쓴 PC 11대(worker-1 10대, worker-2 1대) 중 워커마다 3대까지만 알린다: worker-2 가 받는 프록시 메시지는
#   worker-1 의 PC 3건 + 프록시만 알리는 1건 + 자기 PC 가 되돌아온 1건 = 5건 이하(전에는 PC 마다 1건씩 11건)
# @TEST-EXEC: awk '/^worker-2 proxy_msgs=/ {split($2,a,"="); exit !(a[2] >= 1 && a[2] <= 5)}' worker-2/.stdout
# 표를 비운 worker-2(다시 시작한 것과 같음)에 매니저가 node_up 때 다시 보낸다
# @TEST-EXEC: grep -qx 'worker-2 after-restart dc=T ai=T proxy=T' worker-2/.stdout

@load policy/frameworks/cluster/experimental

# 학습 표·짝짓기 함수는 모듈 안 이름이라 NSM 모듈에서 부른다
module NSM;

# 원격으로만 부르는 이벤트라 export 한다(로컬 호출이 없으면 Zeek 가 경고)
export {
    global learn: event();
    global check: event();
    global forget: event();
    global recheck: event();
    global finish: event();
    global check_all: event();
    global restart_all: event();
    global recheck_all: event();
    global finish_all: event();
}

global proxy_msgs = 0;

event NSM::learned_shared(kind: string, a: addr, p: port, b: addr)
	{
	if ( kind == "proxy" )
		++proxy_msgs;
	}

event learn()
	{
	if ( Cluster::node == "worker-1" )
		{
		dcsync_learn_addr(10.0.0.10, 10.0.1.1);         # DC 가 Kerberos 로 응답한 클라이언트
		dcsync_learn_addr(10.0.0.10, 10.0.1.2);
		ai_learn(10.0.0.20, 1433/tcp);                  # DB 서버
		for ( c in set(10.0.2.1, 10.0.2.2, 10.0.2.3, 10.0.2.4, 10.0.2.5, 10.0.2.7, 10.0.2.8, 10.0.2.9, 10.0.2.10, 10.0.2.11) )
			proxy_learn_tunnel(10.0.0.30, 3128/tcp, c);
		}
	if ( Cluster::node == "worker-2" )
		{
		dcsync_learn_addr(10.0.0.10, 10.0.1.3);         # 세 번째 클라이언트는 worker-2 만 봤다
		ai_learn(10.0.0.20, 3306/tcp);                  # 같은 서버를 다른 포트로 배움
		proxy_learn_tunnel(10.0.0.30, 3128/tcp, 10.0.2.6);
		}
	}

function state(): string
	{
	return fmt("%s dc=%s ai=%s proxy=%s proxy_host=%s", Cluster::node,
	           dcsync_is_dc(10.0.0.10) ? "T" : "F", ai_is_server(10.0.0.20) ? "T" : "F",
	           [10.0.0.30, 3128/tcp] in proxy_learned ? "T" : "F", is_proxy_host(10.0.0.30) ? "T" : "F");
	}

event check()
	{
	print state();
	if ( Cluster::node == "worker-2" )
		{
		print fmt("%s other dc=%s ai=%s proxy=%s ai_port=%s", Cluster::node, dcsync_is_dc(10.0.0.11) ? "T" : "F",
		          ai_is_server(10.0.0.21) ? "T" : "F", [10.0.0.30, 8080/tcp] in proxy_learned ? "T" : "F",
		          ai_learned_servers[10.0.0.20]);
		print fmt("%s proxy_msgs=%d", Cluster::node, proxy_msgs);
		}
	}

# worker-2 가 다시 시작한 것처럼 학습 표를 비운다
event forget()
	{
	if ( Cluster::node != "worker-2" )
		return;
	dcsync_learned_dcs = set();
	dcsync_dc_clients = table();
	ai_learned_servers = table();
	proxy_learned = set();
	proxy_clients = table();
	}

event recheck()
	{
	if ( Cluster::node == "worker-2" )
		print fmt("%s after-restart dc=%s ai=%s proxy=%s", Cluster::node, dcsync_is_dc(10.0.0.10) ? "T" : "F",
		          ai_is_server(10.0.0.20) ? "T" : "F", [10.0.0.30, 3128/tcp] in proxy_learned ? "T" : "F");
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
	schedule 1sec { restart_all() };
	}

event restart_all()
	{
	Cluster::publish(Cluster::worker_topic, forget);
	# worker-2 가 다시 붙은 것과 같게 매니저의 node_up 처리를 부른다
	schedule 500msec { Cluster::node_up("worker-2", "") };
	schedule 2secs { recheck_all() };
	}

event recheck_all()
	{
	Cluster::publish(Cluster::worker_topic, recheck);
	schedule 1sec { finish_all() };
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
