# @TEST-DOC: 서비스 배너 — HTTP 401 Basic realm(.10)·Digest realm만(.12, nonce 뺌), SIP User-Agent(전화기 .20)·Server(PBX .21), FTP 220(.30), SMTP 첫 220(.31, STARTTLS 의 220 은 아님), POP3 +OK(.32), MySQL 버전(.33). Negotiate·NTLM 토큰(.11)과 프록시(.5) 경유 응답은 남기지 않는다. 끄면 없다
# @TEST-EXEC: zeek -C -r $TRACES/asset_banners.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep '	software	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out
# @TEST-EXEC: rm -f asset_signal.log && zeek -C -r $TRACES/asset_banners.pcap $ASSETID %INPUT AssetID::enable_http_wwwauth=F AssetID::enable_sip=F AssetID::enable_service_banners=F
# @TEST-EXEC: ! grep -qE '	(http_wwwauth|sip|ftp|smtp|pop3|mysql)	' asset_signal.log

redef AssetID::asset_nets = { 10.0.0.0/8 };
