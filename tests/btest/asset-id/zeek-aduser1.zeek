# @TEST-DOC: Kerberos 사용자 + NTLM 서버 응답(Server 2022) (Zeek 테스트 trace). 이 trace 의 서비스 티켓(krb)은 LDAP SASL 안에 있어 Zeek 9.x 에서만 보이므로 krb-spn-ldap 에서 따로 본다
# @TEST-EXEC: zeek -C -r $TRACES/asset-id/zeek/aduser1.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | grep -v '	krb	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
