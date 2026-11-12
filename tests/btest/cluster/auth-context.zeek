# @TEST-DOC: [인증 맥락 클러스터] 워커가 본 Kerberos TGS·NTLM 인증을 매니저로 보내고, 확산 판정 노드(매니저)에서 계정을 찾는다. 워커 표는 비어 있다
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
# 매니저: WinRM 대상은 http 티켓 계정, SMB 대상은 같은 대상 NTLM 계정(티켓보다 우선)
# @TEST-EXEC: grep -q "manager winrm=opsadmin@corp.example smb=corp\\\\admin01 none=" manager/.stdout
# 같은 조합을 두 번 보내도 매니저는 한 번만 받는다(재전송 억제)
# @TEST-EXEC: grep -q "manager krb_events=1 ntlm_events=1" manager/.stdout
# 워커-1: 보낸 맥락을 자기 표에 두지 않는다(조회는 매니저에서)
# @TEST-EXEC: grep -q "worker-1 local=$" worker-1/.stdout

@load policy/frameworks/cluster/experimental

module NSM;

global finish: event();
global check: event();
global krb_n = 0;
global ntlm_n = 0;

event finish()
	{
	terminate();
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		{
		auth_send_krb(10.0.0.61, "http", "opsadmin@corp.example");
		auth_send_krb(10.0.0.61, "http", "opsadmin@corp.example");   # 재전송 억제
		auth_send_krb(10.0.0.62, "cifs", "backupop@corp.example");
		print fmt("worker-1 local=%s", auth_accounts(10.0.0.61, 10.0.30.11, set("http")));
		}
	if ( Cluster::node == "worker-2" )
		{
		auth_send_ntlm(10.0.0.62, 10.0.30.12, "corp\\admin01");
		auth_send_ntlm(10.0.0.62, 10.0.30.12, "corp\\admin01");
		}
	if ( Cluster::node == "manager" )
		schedule 3sec { check() };
	}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event NSM::auth_ctx_krb(src: addr, klass: string, who: string) &priority=-10
	{
	if ( src == 10.0.0.61 )
		++krb_n;
	}

event NSM::auth_ctx_ntlm(src: addr, dst: addr, who: string) &priority=-10
	{
	++ntlm_n;
	}

event check()
	{
	print fmt("manager winrm=%s smb=%s none=%s", auth_accounts(10.0.0.61, 10.0.30.11, set("http", "wsman")),
	          auth_accounts(10.0.0.62, 10.0.30.12, set("cifs")), auth_accounts(10.0.0.63, 10.0.30.11, set("cifs")));
	print fmt("manager krb_events=%d ntlm_events=%d", krb_n, ntlm_n);
	Cluster::publish(Cluster::worker_topic, finish);
	schedule 1sec { finish() };
	}
@endif

event Cluster::node_down(name: string, id: string)
	{
	terminate();
	}
