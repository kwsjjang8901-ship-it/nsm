# @TEST-DOC: [35 IOC 일치 클러스터] 프록시가 있는 구성: 지표가 프록시를 거쳐 워커에 배포되고, 워커가 본 값을 매니저가 판정한다(지운 IOC·예외 포함)
#
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY1_PORT
# @TEST-PORT: BROKER_WORKER1_PORT
# @TEST-PORT: BROKER_WORKER2_PORT
#
# @TEST-EXEC: cp $FILES/cluster-layout.zeek .
# @TEST-EXEC: btest-bg-run manager  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=manager  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run proxy-1  ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=proxy-1  zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-1 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-1 zeek -C -r $TRACES/ioc.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-run worker-2 ZEEKPATH=$(zeek-config --zeekpath):.. CLUSTER_NODE=worker-2 zeek $PKG $SETUP %INPUT
# @TEST-EXEC: btest-bg-wait 90
#
# 매니저가 IOC 파일을 두 번 읽음: 처음 6개, 다시 읽을 때 phish-ioc.example 1개를 뺌(Intel::remove -> 워커에도 전파)
# @TEST-EXEC: assert-rows manager/nsm_ioc.log eq 1 kind=summary msg=active=6\ added=6\ removed=0\ invalid=0
# @TEST-EXEC: assert-rows manager/nsm_ioc.log eq 1 kind=summary msg=active=5\ added=0\ removed=1\ invalid=0
# 워커-1 이 본 값을 매니저가 IOC 상세로 판정: IP·대역·하위 도메인(DNS)·URL·프록시 CONNECT 대상
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::IOC_Match src=10.0.42.10 dst=93.184.216.66 peer_descr=manager
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::IOC_Match src=10.0.42.12
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::IOC_Match src=10.0.42.13
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::IOC_Match src=10.0.42.16
# @TEST-EXEC: assert-rows manager/notice.log eq 1 note=NSM::IOC_Match src=10.0.42.23
# 지운 IOC(phish-ioc.example, .15)는 워커 목록에 남았더라도 매니저 판정에서 맞지 않는다. 예외(drop) 걸린 .20 도 매니저에서 걸러진다
# @TEST-EXEC: assert-rows manager/notice.log eq 0 note=NSM::IOC_Match src=10.0.42.15
# @TEST-EXEC: assert-rows manager/notice.log eq 0 note=NSM::IOC_Match src=10.0.42.20
# 워커가 보낸 연결 정보(DNS 조회 이름)가 매니저까지 와서 근거에 원래 이름이 남는다
# @TEST-EXEC: log-cut src detail < manager/evidence.log | awk -F'\t' '$1=="10.0.42.13" && $2 ~ /seen=x1\.cdn\.evil-ioc\.example where=dns_query status=lookup/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < manager/evidence.log | awk -F'\t' '$1=="10.0.42.10" && $2 ~ /status=established/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: assert-rows manager/nsm_detection.log eq 1 diagnosis=NSM.C2.IocMatch attacker=10.0.42.13

@load policy/frameworks/cluster/experimental

# 매니저만 IOC 파일·예외 파일을 읽는다. 노드는 하위 폴더에서 돌므로 한 단계 위를 본다.
redef NSM::ioc_file = "../ioc.tsv";
redef NSM::exception_file = "../exc.tsv";
redef NSM::dns_tunnel_resolvers += { 10.0.0.53 };
# 워커는 pcap 을 다 읽어도 매니저가 끝낼 때까지 기다린다(일치 결과가 매니저로 가야 함).
redef exit_only_after_terminate = T;

global go: event();
global rewrite_ioc_ev: event();
global finish: event();
global ioc_loads = 0;
global workers_up = F;
global ready = F;

# ---- 워커: 지표를 다 받을 때까지 pcap 처리를 멈춘다
event zeek_init()
	{
	if ( Cluster::local_node_type() == Cluster::WORKER && reading_traces() )
		suspend_processing();
	}

event go()
	{
	if ( Cluster::local_node_type() == Cluster::WORKER && reading_traces() )
		continue_processing();
	}

event finish()
	{
	terminate();
	}

# 매니저가 끝나면 워커·프록시도 따라 끝난다(프록시는 finish 를 받지 않는다)
event Cluster::node_down(name: string, id: string)
	{
	if ( name == "manager" )
		terminate();
	}

# ---- 매니저: IOC 를 읽고(1회차) -> phish-ioc.example 줄을 지운 파일로 바꿔 다시 읽고(2회차)
#      -> 워커가 지운 지표까지 반영한 뒤 pcap 을 보게 한다
function rewrite_ioc()
	{
	local f = open("../ioc.tsv.tmp");
	write_file(f, "#separator \\x09\x0a#set_separator\x09,\x0a#empty_field\x09(empty)\x0a#unset_field\x09-\x0a#fields\x09indicator\x09ioc_type\x09source\x09category\x09expires\x09desc\x0a");
	write_file(f, "93.184.216.66\x09ip\x09test-feed\x09c2\x09-\x09C2 서버\x0a");
	write_file(f, "93.184.217.0/24\x09ip\x09test-feed\x09scanner\x09-\x09악성 대역\x0a");
	write_file(f, "evil-ioc.example\x09domain\x09test-feed\x09c2\x09-\x09C2 도메인\x0a");
	write_file(f, "http://dl.malware-ioc.example/payload/a.exe\x09url\x09test-feed\x09malware\x09-\x09악성코드 배포\x0a");
	write_file(f, "93.184.216.67\x09ip\x09test-feed\x09c2\x09-\x09예외 시험\x0a");
	close(f);
	rename("../ioc.tsv.tmp", "../ioc.tsv");
	Input::force_update("nsm-ioc");
	}

event start_traffic()
	{
	Cluster::publish(Cluster::worker_topic, go);
	schedule 8sec { finish() };
	}

event finish() &priority=-10
	{
	if ( Cluster::node == "manager" )
		Cluster::publish(Cluster::worker_topic, finish);
	}

function maybe_start()
	{
	if ( workers_up && ready )
		schedule 3sec { start_traffic() };   # remove_indicator·insert_indicator 가 워커에 닿을 시간
	}

event Input::end_of_data(name: string, source: string) &priority=-20
	{
	if ( Cluster::node != "manager" || name != "nsm-ioc" )
		return;
	++ioc_loads;
	if ( ioc_loads == 1 )
		schedule 1sec { rewrite_ioc_ev() };
	else if ( ioc_loads == 2 )
		{
		ready = T;
		maybe_start();
		}
	}

event rewrite_ioc_ev()
	{
	rewrite_ioc();
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node != "manager" )
		return;
	workers_up = T;
	maybe_start();
	}

# @TEST-START-FILE ioc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	indicator	ioc_type	source	category	expires	desc
93.184.216.66	ip	test-feed	c2	-	C2 서버
93.184.217.0/24	ip	test-feed	scanner	-	악성 대역
evil-ioc.example	domain	test-feed	c2	-	C2 도메인
phish-ioc.example	domain	test-feed	phishing	-	피싱(2회차에 지움)
http://dl.malware-ioc.example/payload/a.exe	url	test-feed	malware	-	악성코드 배포
93.184.216.67	ip	test-feed	c2	-	예외 시험
# @TEST-END-FILE

# @TEST-START-FILE exc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-ioc-20	IOC_Match	10.0.42.20/32	-	-	-	-	-	drop	시험용 예외	admin	-	-
# @TEST-END-FILE
