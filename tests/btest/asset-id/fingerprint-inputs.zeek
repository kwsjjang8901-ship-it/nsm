# @TEST-DOC: 지문 대조용 입력 신호 — SNMP 응답(스위치: sysDescr·sysObjectID·sysName, 프린터: sysDescr), TCP SYN·SYN-ACK 특징(tcp_fp: Windows ittl 128, Linux·macOS ittl 64, 네트워크 장비 ittl 255), 장비 인증서 주체·발급자(x509_subject·x509_issuer). 끄면 SNMP·tcp_fp 신호가 없다
# @TEST-EXEC: zeek -C -r $TRACES/asset_fingerprint.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -E '	(snmp|tcp_fp|x509)	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out
# @TEST-EXEC: rm -f asset_signal.log && zeek -C -r $TRACES/asset_fingerprint.pcap $ASSETID %INPUT AssetID::enable_snmp=F AssetID::enable_tcp_fp=F
# @TEST-EXEC: ! grep -qE '	(snmp|tcp_fp)	' asset_signal.log

redef AssetID::asset_nets = { 10.0.0.0/8 };
