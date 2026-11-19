# @TEST-DOC: DHCP 릴레이 구간(릴레이 10.0.52.1 <-> DHCP 서버 10.0.51.67, 67/udp 양쪽)만 보여도 ACK 의 할당 IP(10.0.52.20)에 client-id, MAC, 호스트명, vendor class, 지문, 도메인을 기록하고 DHCP 서버는 udp/67 서비스로
# @TEST-EXEC: zeek -C -r $TRACES/dhcp_relay.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep '	dhcp	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
