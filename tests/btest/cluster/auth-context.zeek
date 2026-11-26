# @TEST-DOC: [인증 맥락 클러스터] 워커가 본 Kerberos TGS·NTLM 인증을 자기 표에 넣고 매니저로 보낸다. 매니저(확산 판정)와 다른 워커(연결 단위 판정 23·31·34)도 같은 계정을 찾는다(매니저가 새 조합만 워커에 다시 알림)
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
# 다른 워커가 본 맥락도 매니저를 거쳐 받는다: worker-1 은 worker-2 의 NTLM, worker-2 는 worker-1 의 Kerberos
# @TEST-EXEC: grep -q "worker-1 later winrm=opsadmin@corp.example smb=corp\\\\admin01$" worker-1/.stdout
# @TEST-EXEC: grep -q "worker-2 later winrm=opsadmin@corp.example smb=corp\\\\admin01$" worker-2/.stdout

@load policy/frameworks/cluster/experimental

module NSM;

# 원격으로만 부르는 이벤트라 export 한다(로컬 호출이 없으면 Zeek 가 경고)
export {
    global finish: event();
    global wcheck: event();
}
global check: event();
global krb_n = 0;
global finish_all: event();
global ntlm_n = 0;

event finish()
	{
	terminate();
	}

event wcheck()
	{
	print fmt("%s later winrm=%s smb=%s", Cluster::node, auth_accounts(10.0.0.61, 10.0.30.11, set("http", "wsman")),
	          auth_accounts(10.0.0.62, 10.0.30.12, set("cifs")));
	}

event Cluster::Experimental::cluster_started()
	{
	if ( Cluster::node == "worker-1" )
		{
		auth_send_krb(10.0.0.61, "http", "opsadmin@corp.example");
		auth_send_krb(10.0.0.61, "http", "opsadmin@corp.example");   # 재전송 억제
		auth_send_krb(10.0.0.62, "cifs", "backupop@corp.example");
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
	Cluster::publish(Cluster::worker_topic, wcheck);
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
