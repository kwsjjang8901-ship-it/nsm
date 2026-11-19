# @TEST-DOC: Kerberos 서비스 티켓(SMB2 SESSION_SETUP 안 AP-REQ)의 서비스 이름 -> 서버 dns_name(krb 50), realm -> domain(krb 70). 도메인 이름 자체로 받은 티켓(DFS 루트 .11)과 외부 서버는 기록하지 않고, 짧은 이름(.12)과 포트 붙은 이름(.13)은 이름 부분만
# @TEST-EXEC: zeek -C -r $TRACES/asset_krb_spn.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -E '	(dns_name|domain)	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
