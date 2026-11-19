# @TEST-DOC: LDAP SASL(GSSAPI) 안 서비스 티켓 ldap/WIN-VGO56I95EAK -> DC 이름·도메인. 같은 trace 의 TGS-REQ 안 krbtgt/ADHACKING.LOCAL 티켓은 서버 이름이 아니라 기록하지 않는다 (Zeek 테스트 trace, Zeek 9.x 필요)
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/asset-id/zeek/aduser1.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep '	krb	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
