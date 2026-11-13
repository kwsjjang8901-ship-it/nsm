# @TEST-DOC: 08 DNS 터널링 — AWS 로드밸런서 이름(<이름>-<숫자>.<리전>.elb.amazonaws.com) 고유 80개 조회(.116)는 기본 예외로 미탐. 기본 예외를 빼면 탐지되는 형태임을 함께 확인(CIC-IDS2017 오탐 재현)
# @TEST-EXEC: zeek -C -r $TRACES/dns_elb.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.116
# @TEST-EXEC: mkdir off && cd off && zeek -C -r $TRACES/dns_elb.pcap $PKG $SETUP ../off.zeek
# @TEST-EXEC: cd off && assert-rows notice.log eq 1 note=NSM::DNS_Tunneling src=10.0.0.116

@TEST-START-FILE off.zeek
redef NSM::dns_tunnel_allowlist_domains -= { "elb.amazonaws.com" };
@TEST-END-FILE
