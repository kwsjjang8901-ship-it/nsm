# @TEST-DOC: 35 IOC 일치 — IP(.10 연결 성립·.11 시도), 대역(.12), 하위 도메인 DNS(.13), SNI(.15), 쿼리 뗀 URL(.16), 프록시 CONNECT 대상(.23) 탐지 / 접미사 아닌 이름(.14)·다른 경로(.17)·들어온 연결(.18, 기본)·만료(.19)·리졸버 대신 조회·일반 통신(.22) 미탐 / 두 번째 실행: 들어온 연결 탐지(ioc_match_inbound=T), 예외(drop) 걸린 .20 미탐
# @TEST-EXEC: zeek -C -r $TRACES/ioc.pcap $PKG $SETUP %INPUT NSM::ioc_file=ioc.tsv
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.10 dst=93.184.216.66
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.11
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.12
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.13
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.42.14
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.15
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.16
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.42.17
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=93.184.216.66
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.42.19
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.20
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.0.53
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.42.22
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.23
# 근거: 상태(연결 성립·시도·조회), 어디서 맞았나, 하위 도메인·쿼리 뗀 URL 이 IOC 로 맞음
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.10" && $2 ~ /ioc=93\.184\.216\.66 type=ip/ && $2 ~ /status=established/ && $2 ~ /category=c2/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.11" && $2 ~ /status=attempt/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.12" && $2 ~ /ioc=93\.184\.217\.0\/24/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.13" && $2 ~ /ioc=evil-ioc\.example type=domain seen=x1\.cdn\.evil-ioc\.example where=dns_query status=lookup/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.16" && $2 ~ /ioc=dl\.malware-ioc\.example\/payload\/a\.exe type=url/ && $2 ~ /where=http_url/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.42.23" && $2 ~ /where=(http_host|tls_sni)/ {n++} END {exit !(n==1)}'
# DNS 조회는 연결 상대가 리졸버라 피해 대상(dst)을 비운다
# @TEST-EXEC: log-cut src dst < notice.log | awk -F'\t' '$1=="10.0.42.13" && ($2=="-" || $2=="") {n++} END {exit !(n==1)}'
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.IocMatch attacker=10.0.42.10
# @TEST-EXEC: assert-rows nsm_ioc.log eq 1 kind=invalid indicator=not-an-ip
# @TEST-EXEC: assert-rows nsm_ioc.log eq 1 kind=summary msg=active=7\ added=7\ removed=0\ invalid=1
# @TEST-EXEC: assert-evidence-join NSM::IOC_Match
#
# 두 번째 실행: 들어온 연결도 보고(.18 <- IOC), .20 은 예외(drop)
# @TEST-EXEC: zeek -C -r $TRACES/ioc.pcap $PKG $SETUP %INPUT NSM::ioc_file=ioc.tsv NSM::ioc_match_inbound=T NSM::exception_file=exc.tsv
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=93.184.216.66 dst=10.0.42.18
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::IOC_Match src=10.0.42.20
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::IOC_Match src=10.0.42.10

redef NSM::dns_tunnel_resolvers += { 10.0.0.53 };

# @TEST-START-FILE ioc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	indicator	ioc_type	source	category	expires	desc
93.184.216.66	ip	test-feed	c2	-	C2 서버
93.184.217.0/24	ip	test-feed	scanner	-	악성 대역
evil-ioc.example	domain	test-feed	c2	-	C2 도메인
phish-ioc.example	domain	test-feed	phishing	-	피싱
http://dl.malware-ioc.example/payload/a.exe	url	test-feed	malware	-	악성코드 배포
old-ioc.example	domain	test-feed	c2	1000000000	만료
93.184.216.67	ip	test-feed	c2	-	예외 시험
not-an-ip	ip	test-feed	-	-	잘못된 줄
# @TEST-END-FILE

# @TEST-START-FILE exc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-ioc-20	IOC_Match	10.0.42.20/32	-	-	-	-	-	drop	시험용 예외	admin	-	-
# @TEST-END-FILE
