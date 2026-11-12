# @TEST-DOC: 예외 엔진 E3-3 — 도메인 기반 룰(07·08·13)이 예외 파일을 따른다. 08 은 두 탐지 공통 예외는 질의 단위, 한 탐지 예외는 창 판정 때 거른다
#
# 07: HTTP Host(domain) 예외 update.beacon-c2.net -> .60 미탐, 형제 서브도메인(sync.)인 .62 는 그대로. 적중 = 연결 14개
# @TEST-EXEC: mkdir bc && cd bc && zeek -C -r $TRACES/http_beacon.pcap $PKG $SETUP NSM::exception_file=../beacon.tsv
# @TEST-EXEC: assert-rows bc/notice.log eq 0 note=NSM::HTTP_Beaconing src=10.0.0.60
# @TEST-EXEC: assert-rows bc/notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.62
# @TEST-EXEC: assert-rows bc/nsm_exception.log eq 1 kind=hits exception_id=E-bc hits=14
#
# 08: 두 탐지 공통 예외(evil-tunnel.com)는 질의 80개를 집계 전에 뺀다. 터널링에만 건 예외(exfil-dns.net)는
#     창 판정 때 터널링만 빼고, 같은 집계의 DNS 유출 탐지는 그대로 낸다
# @TEST-EXEC: mkdir dns && cd dns && zeek -C -r $TRACES/dns_tunnel.pcap $PKG $SETUP ../dns.zeek NSM::exception_file=../dns.tsv
# @TEST-EXEC: assert-rows dns/notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.110
# @TEST-EXEC: assert-rows dns/nsm_exception.log eq 1 kind=hits exception_id=E-both hits=80
# @TEST-EXEC: assert-rows dns/notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.111
# @TEST-EXEC: assert-rows dns/notice.log eq 1 note=NSM::Exfil_DNS src=10.0.0.111
# @TEST-EXEC: assert-rows dns/evidence.log eq 0 note=NSM::DNS_Tunneling
# @TEST-EXEC: assert-rows dns/nsm_exception.log eq 1 kind=hits exception_id=E-tun hits=1
# 기본 도메인 예외(AV·스팸 평판 조회) 목록은 legacy drop 예외로 등록된다
# @TEST-EXEC: assert-rows dns/nsm_exception.log eq 1 kind=loaded exception_id=legacy:dns_tunnel_allowlist_domains msg=legacy
#
# 13: 출발지 예외 .100 미탐, .101 그대로
# @TEST-EXEC: mkdir dga && cd dga && zeek -C -r $TRACES/dga.pcap $PKG $SETUP NSM::exception_file=../dga.tsv
# @TEST-EXEC: assert-rows dga/notice.log eq 0 note=NSM::DGA_Domain src=10.0.0.100
# @TEST-EXEC: assert-rows dga/notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.101

# @TEST-START-FILE dns.zeek
redef NSM::dnsexfil_bytes = 32 * 1024;
# @TEST-END-FILE
# @TEST-START-FILE beacon.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-bc	HTTP_Beaconing	-	-	-	-	update.beacon-c2.net	-	-	업데이트 서버	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE dns.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-both	DNS_Tunneling,Exfil_DNS	-	-	-	-	evil-tunnel.com	-	-	보안 평판 조회 서비스	kim	-	-
E-tun	DNS_Tunneling	-	-	-	-	exfil-dns.net	-	-	CDN 동적 서브도메인	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE dga.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-dga	DGA_Domain	10.0.0.100/32	-	-	-	-	-	-	보안 장비 조회	lee	-	-
# @TEST-END-FILE
