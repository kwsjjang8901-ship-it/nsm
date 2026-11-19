# @TEST-DOC: HTTP 응답 Server 헤더 -> 서버 software(http_server 50), os_hint(45): IIS 10.0 -> windows server 2016+, Apache (Ubuntu) -> linux(ubuntu), HTTPAPI -> windows, nginx 는 OS 없음. 프록시(.5)에 절대 URL 로 보낸 요청의 응답과 외부 서버는 기록하지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/asset_http_server.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep '	http_server	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out
# @TEST-EXEC: zeek -C -r $TRACES/asset_http_server.pcap $ASSETID %INPUT AssetID::enable_http_server=F
# @TEST-EXEC: ! grep -q '	http_server	' asset_signal.log

redef AssetID::asset_nets = { 10.0.0.0/8 };
