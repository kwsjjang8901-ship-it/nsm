##! 테스트용 클러스터 레이아웃 (매니저 1 + 워커 2 [+ 프록시 1], 매니저가 로거 겸임).
##! Zeek 프로젝트 testing/btest/Files/broker/cluster-layout.zeek 를 축약했다(BSD).
##!
##! 사용: 테스트에서 이 파일을 작업 디렉터리로 복사하고 @TEST-PORT 로 포트를 받는다.
##!   BROKER_MANAGER_PORT, BROKER_WORKER1_PORT, BROKER_WORKER2_PORT [, BROKER_PROXY1_PORT]
##!
##! 통신 백엔드: Zeek 8.x 는 Broker 가 기본, Zeek 9.x 는 기본 백엔드가 없으므로(zeekctl 은
##! ZeroMQ 사용) 테스트에서는 Broker 백엔드를 로드한다. nsm_rules 는 백엔드와 무관한
##! Cluster::publish 를 쓰므로 운영(ZeroMQ)에서도 같은 코드 경로다.
@if ( Cluster::backend != Cluster::CLUSTER_BACKEND_BROKER )
@load policy/frameworks/cluster/backend/broker
@endif

redef Cluster::manager_is_logger = T;

redef Cluster::nodes = {
	["manager"]  = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=to_port(getenv("BROKER_MANAGER_PORT"))],
	["worker-1"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER1_PORT")), $manager="manager"],
	["worker-2"] = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=to_port(getenv("BROKER_WORKER2_PORT")), $manager="manager"],
};

# 프록시는 테스트가 BROKER_PROXY1_PORT 를 요청할 때만 추가한다.
@if ( getenv("BROKER_PROXY1_PORT") != "" )
redef Cluster::nodes += {
	["proxy-1"]  = [$node_type=Cluster::PROXY,   $ip=127.0.0.1, $p=to_port(getenv("BROKER_PROXY1_PORT")), $manager="manager"],
};
@endif
