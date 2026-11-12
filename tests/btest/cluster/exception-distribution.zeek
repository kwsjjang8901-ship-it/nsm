# @TEST-DOC: [예외 엔진 클러스터] 매니저만 예외 파일을 읽고 워커로 배포한다. 워커가 판정하고 적중 수는 워커 이름으로 로거에 남는다
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
#
# 적재 결과는 파일을 읽은 매니저만 1번 기록한다
# @TEST-EXEC: assert-rows manager/nsm_exception.log eq 1 kind=loaded exception_id=E-cl node=manager
# @TEST-EXEC: assert-rows manager/nsm_exception.log eq 0 kind=loaded node=worker-1
# 워커-1 이 배포받은 예외로 판정: 맞는 관측 1건(적중), 다른 목적지 1건(통과)
# @TEST-EXEC: assert-rows manager/nsm_exception.log eq 1 kind=hits exception_id=E-cl node=worker-1 hits=1
# @TEST-EXEC: grep -q "worker-1 match=T other=F" worker-1/.stdout

@load policy/frameworks/cluster/experimental

redef NSM::exception_file = "../ex.tsv";
# 적중 수를 빨리 내보낸다(종료 시점 기록은 로거에 닿지 않을 수 있다)
redef NSM::exception_stats_interval = 1sec;

global finish: event();

event finish()
	{
	terminate();
	}

global checked = F;

event NSM::exception_update(recs: table[string] of NSM::ExceptionRec) &priority=-10
	{
	if ( Cluster::node != "worker-1" || checked )
		return;
	checked = T;
	local hit = NSM::exception_drop_ctx(NSM::SSH_Lateral,
		[$src=10.0.0.50, $dst=10.0.0.51, $dst_port=22/tcp], T);
	local other = NSM::exception_drop_ctx(NSM::SSH_Lateral,
		[$src=10.0.0.50, $dst=10.0.0.52, $dst_port=22/tcp], T);
	print fmt("%s match=%s other=%s", Cluster::node, hit, other);
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "manager" )
		schedule 6sec { finish() };
	}

event finish() &priority=-10
	{
	if ( Cluster::node == "manager" )
		Cluster::publish(Cluster::worker_topic, finish);
	}

# @TEST-START-FILE ex.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-cl	group:lateral	10.0.0.50/32	10.0.0.51/32	22/tcp	-	-	-	-	점프 서버 경로	lee	-	-
# @TEST-END-FILE
