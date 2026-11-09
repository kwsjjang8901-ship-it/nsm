# @TEST-DOC: [검토 H2] 클러스터 상관 — 워커-1 의 암호화 C2 -> 매니저의 SMB 확산 -> 워커-2 의 대용량 유출이 노드를 넘어 하나의 kill-chain 으로 연결된다
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-2 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-wait 60
#
# 단일 탐지 3건이 각 노드에서 났는지(로그는 매니저가 기록)
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.5 peer_descr=worker-1
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::SMB_Admin_Share src=10.0.0.5 peer_descr=manager
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.21 peer_descr=worker-2
# 노드를 넘는 전이: C2(워커-1) -> 확산(매니저) [2단계], 확산(매니저) -> 유출(워커-2, 피해 host 피벗) [3단계]
# @TEST-EXEC: assert-rows manager/notice.log ge 2 note=NSM::Correlated_KillChain src=10.0.0.5
# @TEST-EXEC: assert-rows manager/nsm_detection.log ge 1 category=Correlated diagnosis=NSM.Correlation.C2.Lateral attacker=10.0.0.5
# @TEST-EXEC: assert-rows manager/nsm_detection.log ge 1 category=Correlated diagnosis=NSM.Correlation.C2.Exfil attacker=10.0.0.5

@load policy/frameworks/cluster/experimental

# 시나리오: 실제 룰이 내는 notice 와 같은 형태를, 실제로 그 룰이 동작하는 노드에서 직접 발생시킨다.
#   09 암호화 C2      : 워커(연결 단위 룰)
#   06 SMB 확산       : 매니저(SumStats 룰)
#   10 대용량 유출    : 워커(연결 단위 룰), 확산의 피해 host 가 유출 -> DST_TO_SRC 피벗
# 순서를 보장하려고 매니저가 앞 단계 notice 를 상관 이벤트로 받은 뒤 다음 단계를 지시한다.

global step_c2: event();
global step_exfil: event();
global finish: event();

event step_c2()
	{
	NOTICE([$note=NSM::Encrypted_C2, $src=10.0.0.5, $dst=93.184.215.20,
	        $msg="test: encrypted c2", $identifier="t-c2", $evidence_id="t-c2"]);
	}

event step_exfil()
	{
	# 워커 토픽으로 모든 워커가 받으므로 worker-2 만 실행
	if ( Cluster::node != "worker-2" )
		return;
	NOTICE([$note=NSM::Exfil_Large_Transfer, $src=10.0.0.21, $dst=93.184.215.30,
	        $msg="test: large transfer", $identifier="t-exfil", $evidence_id="t-exfil"]);
	}

event finish()
	{
	terminate();
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		schedule 1sec { step_c2() };
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NSM::corr_notice(cn: NSM::CorrNotice) &priority=-10
	{
	if ( cn$note == NSM::Encrypted_C2 && cn$src == 10.0.0.5 )
		{
		# 06 SMB 확산을 매니저에서 발생(SumStats epoch_result 와 같은 위치)
		NOTICE([$note=NSM::SMB_Admin_Share, $src=10.0.0.5, $msg="test: smb lateral",
		        $identifier="t-smb", $evidence_id="t-smb", $lm_targets=set(10.0.0.21)]);
		}
	else if ( cn$note == NSM::SMB_Admin_Share )
		Cluster::publish(Cluster::worker_topic, step_exfil);   # 워커에게 다음 단계 지시
	else if ( cn$note == NSM::Exfil_Large_Transfer )
		schedule 2sec { finish() };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
