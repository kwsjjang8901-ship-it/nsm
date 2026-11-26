# @TEST-DOC: [사건 묶기 클러스터] 같은 (탐지 종류, 공격자, 피해 host)의 단독 탐지가 다른 워커에서 나와도 한 사건이다. 워커는 탐지 행을 매니저로 보내고 매니저가 incident_id·occurrence 를 정해 기록한다(전에는 워커마다 사건을 따로 정해 사건이 쪼개졌다). 다른 피해 host 는 다른 사건
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
# @TEST-EXEC: python3 check.py manager/nsm_detection.log

@load policy/frameworks/cluster/experimental

module NSM;

# 원격으로만 부르는 이벤트라 export 한다(로컬 호출이 없으면 Zeek 가 경고)
export {
    global step: event(i: count);
    global finish: event();
}
# 원격으로 받는 이벤트는 export 한다(로컬 호출이 없는 노드에서 Zeek 가 경고)
export {
    global next_step: event(i: count);
    global finish_all: event();
}

# 0: worker-1 이 .80 웹 공격, 1: worker-2 가 같은 .80 웹 공격(같은 사건), 2: worker-2 가 .81 웹 공격(다른 사건)
event step(i: count)
	{
	local owner = ( i == 0 ) ? "worker-1" : "worker-2";
	if ( Cluster::node != owner )
		return;
	local dst = ( i == 2 ) ? 10.0.0.81 : 10.0.0.80;
	NOTICE([$note=SQL_Injection, $src=198.51.100.7, $dst=dst, $msg=fmt("sqli %d", i), $sub=fmt("payload=%d", i), $identifier=fmt("t-sqli-%d", i)]);
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
		schedule 2secs { finish_all() };
		return;
		}
	Cluster::publish(Cluster::worker_topic, step, i);
	schedule 700msec { next_step(i + 1) };
	}

event finish_all()
	{
	Cluster::publish(Cluster::worker_topic, finish);
	schedule 1sec { finish() };
	}

event Cluster::Experimental::cluster_started()
	{
	schedule 1sec { next_step(0) };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}

@TEST-START-FILE check.py
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
s = sorted((r for r in rows if r.get("rule") == "SQL_Injection"), key=lambda r: r["first_seen"])
assert len(s) == 3, rows
a, b, c = s
assert a["victims"] == ["10.0.0.80"] and b["victims"] == ["10.0.0.80"] and c["victims"] == ["10.0.0.81"], s
assert a["incident_id"] == b["incident_id"] and (a["occurrence"], b["occurrence"]) == (1, 2), s
assert c["incident_id"] != a["incident_id"] and c["occurrence"] == 1, s
@TEST-END-FILE
