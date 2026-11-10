# @TEST-DOC: [메타데이터 선별 전송 클러스터] 선별 판정은 로그를 쓰는 워커에서 일어나고, 통과한 행만 로거(매니저)에 기록된다
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
# 워커-1 이 Kerberos 1행, conn 경계 1행·내부 1행을 쓴다 -> 매니저(로거)에 Kerberos 1행, conn 경계 1행만
# @TEST-EXEC: assert-rows manager/meta_kerberos.log eq 1 client=user01/CORP.EXAMPLE
# @TEST-EXEC: assert-rows manager/meta_conn.log eq 1 id.resp_h=93.184.215.200
# @TEST-EXEC: assert-rows manager/meta_conn.log eq 0 id.resp_h=10.0.0.201
# 탈락 집계가 워커-1 의 통계로 남는다(판정 위치 = 워커)
# @TEST-EXEC: assert-rows manager/meta_export_stats.log ge 1 node=worker-1 stream=conn dropped_scope=1
# @TEST-EXEC: assert-rows manager/meta_export_stats.log eq 0 node=manager stream=conn

@load policy/frameworks/cluster/experimental

redef NSM::meta_export_streams += {
    [Conn::LOG] = [$name="conn", $scope=NSM::META_BOUNDARY],
};
# 통계를 빨리 내보낸다
redef NSM::meta_stats_interval = 1sec;

global finish: event();

event finish()
	{
	terminate();
	}

event write_rows()
	{
	local id_ext: conn_id = [$orig_h=10.0.0.200, $orig_p=50000/tcp, $resp_h=93.184.215.200, $resp_p=443/tcp];
	local id_int: conn_id = [$orig_h=10.0.0.200, $orig_p=50001/tcp, $resp_h=10.0.0.201, $resp_p=8080/tcp];
	Log::write(Conn::LOG, Conn::Info($ts=network_time(), $uid="Cmeta1", $id=id_ext, $proto=tcp));
	Log::write(Conn::LOG, Conn::Info($ts=network_time(), $uid="Cmeta2", $id=id_int, $proto=tcp));
	Log::write(KRB::LOG, KRB::Info($ts=network_time(), $uid="Cmeta3",
	                               $id=[$orig_h=10.0.0.200, $orig_p=50002/udp, $resp_h=10.0.0.10, $resp_p=88/udp],
	                               $request_type="AS", $client="user01/CORP.EXAMPLE", $success=T));
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		schedule 1sec { write_rows() };
	if ( Cluster::node == "manager" )
		schedule 6sec { finish() };
	}

event finish() &priority=-10
	{
	if ( Cluster::node == "manager" )
		Cluster::publish(Cluster::worker_topic, finish);
	}
