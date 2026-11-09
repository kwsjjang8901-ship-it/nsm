# @TEST-DOC: 클러스터 상관 5단계 — 워커-1 스캔 -> 매니저 DGA -> 워커-2 비커닝 -> 매니저 SMB 확산(피해 2대) -> 워커-1·워커-2 의 피해 host 유출이 노드를 넘어 하나의 체인으로 2·3·4·5단계까지 자라고, 5단계는 피해 host 별 2갈래
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
# 단일 탐지가 의도한 노드에서 났는지(로그는 매니저가 기록)
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Port_Scan src=10.0.0.240 peer_descr=worker-1
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.240 peer_descr=manager
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.240 peer_descr=worker-2
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::SMB_Admin_Share src=10.0.0.240 peer_descr=manager
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.241 peer_descr=worker-1
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.242 peer_descr=worker-2
#
# 체인: 2·3단계 Recon.C2, 4단계 Recon.Lateral, 5단계 Recon.Exfil x 2갈래 = 상관 5건
# @TEST-EXEC: assert-rows manager/notice.log eq 5 note=NSM::Correlated_KillChain src=10.0.0.240
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 2 category=Correlated diagnosis=NSM.Correlation.Recon.C2 attacker=10.0.0.240
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 1 category=Correlated diagnosis=NSM.Correlation.Recon.Lateral attacker=10.0.0.240
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 2 category=Correlated diagnosis=NSM.Correlation.Recon.Exfil attacker=10.0.0.240
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 2 category=Correlated 'techniques=T1046->T1568.002->T1071.001->T1021.002->T1041'
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 5 category=Correlated

@load policy/frameworks/cluster/experimental

# 실제 룰이 동작하는 노드에서 같은 형태의 notice 를 직접 발생시킨다.
#   01 스캔·07 비커닝·10 유출 = 워커(연결 단위), 13 DGA·06 확산 = 매니저(SumStats)
# 순서를 보장하려고 매니저가 앞 단계 notice 를 상관 이벤트로 받은 뒤 다음 단계를 지시한다.

global step_scan: event();
global step_beacon: event();
global step_exfil: event();
global finish: event();

global exfil_seen = 0;

event step_scan()
	{
	NOTICE([$note=NSM::Port_Scan, $src=10.0.0.240, $dst=10.0.0.9,
	        $msg="test: port scan", $identifier="t-scan", $evidence_id="t-scan"]);
	}

event step_beacon()
	{
	if ( Cluster::node != "worker-2" )
		return;
	NOTICE([$note=NSM::HTTP_Beaconing, $src=10.0.0.240, $dst=93.184.215.90,
	        $msg="test: beacon", $identifier="t-beacon", $evidence_id="t-beacon"]);
	}

event step_exfil()
	{
	# 피해 host 별 유출을 서로 다른 워커에서
	if ( Cluster::node == "worker-1" )
		NOTICE([$note=NSM::Exfil_Large_Transfer, $src=10.0.0.241, $dst=93.184.215.92,
		        $msg="test: exfil v1", $identifier="t-exfil-1", $evidence_id="t-exfil-1"]);
	else if ( Cluster::node == "worker-2" )
		NOTICE([$note=NSM::Exfil_Large_Transfer, $src=10.0.0.242, $dst=93.184.215.93,
		        $msg="test: exfil v2", $identifier="t-exfil-2", $evidence_id="t-exfil-2"]);
	}

event finish()
	{
	terminate();
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		schedule 1sec { step_scan() };
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NSM::corr_notice(cn: NSM::CorrNotice) &priority=-10
	{
	if ( cn$note == NSM::Port_Scan && cn$src == 10.0.0.240 )
		NOTICE([$note=NSM::DGA_Domain, $src=10.0.0.240, $msg="test: dga",
		        $identifier="t-dga", $evidence_id="t-dga"]);
	else if ( cn$note == NSM::DGA_Domain )
		Cluster::publish(Cluster::worker_topic, step_beacon);
	else if ( cn$note == NSM::HTTP_Beaconing )
		NOTICE([$note=NSM::SMB_Admin_Share, $src=10.0.0.240, $msg="test: smb lateral",
		        $identifier="t-smb", $evidence_id="t-smb", $lm_targets=set(10.0.0.241, 10.0.0.242)]);
	else if ( cn$note == NSM::SMB_Admin_Share )
		Cluster::publish(Cluster::worker_topic, step_exfil);
	else if ( cn$note == NSM::Exfil_Large_Transfer )
		{
		exfil_seen += 1;
		if ( exfil_seen == 2 )
			schedule 2sec { finish() };
		}
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
