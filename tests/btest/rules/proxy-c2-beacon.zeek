# @TEST-DOC: 07·30 프록시 인식(proxy_aware_beacon=T). CONNECT cdn.sync-relay.net 60초 주기(.10)·update.code.visualstudio.com(.11) 30 탐지, 평문 HTTP 30초 주기(.12, 연결마다 같은 Host 2회+프록시 자신 1회 -> Host 별 첫 요청만 세어 30초)·www.msftconnecttest.com(.15) 07 탐지, 프록시 자신(PAC)만(.13)·첫 요청을 못 본 터널(.14) 미탐. 기본 예외 목록(docs/examples/exceptions.proxy-beacon.tsv)을 쓰면 .11·.15 는 실제 목적지 이름(domain 축)으로 빠지고 .10·.12 는 남는다. 고객 예외를 CONNECT 대상 이름으로 걸면 24 도 빠진다
# @TEST-EXEC: zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP NSM::proxy_aware_beacon=T
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Beaconing src=10.0.60.10
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Beaconing src=10.0.60.11
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.60.12
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.60.15
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.60.13
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.60.14
# @TEST-EXEC: grep -q 'HTTP beaconing: 10.0.60.12 -> beacon.relay-check.net ~30.0s interval x12 hits (via proxy)' notice.log
# @TEST-EXEC: grep -q 'TLS beaconing: 10.0.60.10 -> cdn.sync-relay.net ~60.0s' notice.log
# @TEST-EXEC: log-cut note src detail < evidence.log | awk -F'\t' '$1=="NSM::HTTP_Beaconing" && $2=="10.0.60.12" && $3 ~ /interval=30\.0s consecutive=12 / && $3 ~ /host=beacon\.relay-check\.net via_proxy=10\.0\.60\.5:3128/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut note src detail < evidence.log | awk -F'\t' '$1=="NSM::TLS_Beaconing" && $2=="10.0.60.10" && $3 ~ /host=cdn\.sync-relay\.net via_proxy=/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: assert-evidence-join NSM::HTTP_Beaconing
# @TEST-EXEC: assert-evidence-join NSM::TLS_Beaconing
# 기본 예외 목록 + 고객 예외(24, CONNECT 대상 이름)
# @TEST-EXEC: cat $PKG/../docs/examples/exceptions.proxy-beacon.tsv > exc.tsv && tail -n 1 cust.tsv >> exc.tsv
# @TEST-EXEC: mkdir exc && cd exc && zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP NSM::proxy_aware_beacon=T NSM::exception_file=../exc.tsv
# @TEST-EXEC: assert-rows exc/notice.log eq 1 note=NSM::TLS_Beaconing src=10.0.60.10
# @TEST-EXEC: assert-rows exc/notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.60.12
# @TEST-EXEC: assert-rows exc/notice.log eq 0 src=10.0.60.11
# @TEST-EXEC: assert-rows exc/notice.log eq 0 src=10.0.60.15
# @TEST-EXEC: assert-rows exc/notice.log eq 0 src=10.0.60.17
# @TEST-EXEC: assert-rows exc/nsm_exception.log eq 0 kind=rejected
# @TEST-EXEC: assert-rows exc/nsm_exception.log eq 9 kind=loaded msg=file
# @TEST-EXEC: assert-rows exc/nsm_exception.log eq 1 kind=hits exception_id=EX-pb-vscode hits=40
# @TEST-EXEC: assert-rows exc/nsm_exception.log eq 1 kind=hits exception_id=EX-pb-ms-ncsi hits=14
# @TEST-EXEC: assert-rows exc/nsm_exception.log eq 1 kind=hits exception_id=EX-relay hits=1

# @TEST-START-FILE cust.tsv
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
EX-relay	Nonstandard_Port	-	-	4444/tcp	-	relay-drop.net	-	-	업무용 파일 중계(테스트)	tester	-	-
# @TEST-END-FILE
