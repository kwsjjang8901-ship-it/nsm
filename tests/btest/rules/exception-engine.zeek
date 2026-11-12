# @TEST-DOC: 예외 엔진(E1) — 예외 파일 drop·suppress·검증·만료·적중 수, 집계형 쌍 예외, 묶음 범위, 기존 redef 호환, 다시 읽기, 파일 없음
#
# (1) 09 건별 룰: dst drop(.70 은 notice·근거·탐지 요약 모두 없음), SNI suppress(.74 는 표시만), 검증 거부·만료
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT NSM::exception_file=c2.tsv
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows evidence.log eq 0 src=10.0.0.70
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 attacker=10.0.0.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.74 disposition=suppressed exception_id=E-c2-sni
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 attacker=10.0.0.74 disposition=suppressed exception_id=E-c2-sni
# @TEST-EXEC: assert-evidence-join NSM::Encrypted_C2
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=loaded exception_id=E-c2-dst disposition=drop msg=file
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=loaded exception_id=E-c2-sni disposition=suppress
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=expired exception_id=E-expired
# @TEST-EXEC: assert-rows nsm_exception.log eq 5 kind=rejected
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=rejected exception_id=E-bad-broad
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=rejected exception_id=E-bad-port
# 적중 수: drop 은 관측 수(.70 의 TLS 세션 2개), suppress 는 표시한 notice 수
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=hits exception_id=E-c2-dst hits=2
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=hits exception_id=E-c2-sni hits=1
#
# (2) 16 집계형 룰 + 묶음(group:lateral): 쌍 예외는 suppress 로 지정해도 관측 전에 빠진다(4대 -> 2대, 임계 3 미달)
# @TEST-EXEC: mkdir pair && cd pair && zeek -C -r $TRACES/ssh_lateral.pcap $PKG $SETUP NSM::exception_file=../lm.tsv
# @TEST-EXEC: assert-rows pair/notice.log eq 0 note=NSM::SSH_Lateral
# @TEST-EXEC: assert-rows pair/nsm_exception.log eq 1 kind=hits exception_id=E-lm-pair hits=2
# 출발지만 있는 suppress 예외는 집계 notice 에 표시만 한다
# @TEST-EXEC: mkdir srcsup && cd srcsup && zeek -C -r $TRACES/ssh_lateral.pcap $PKG $SETUP NSM::exception_file=../lmsup.tsv
# @TEST-EXEC: assert-rows srcsup/notice.log eq 1 note=NSM::SSH_Lateral src=10.0.0.50 disposition=suppressed exception_id=E-lm-src
# @TEST-EXEC: assert-rows srcsup/nsm_detection.log eq 1 attacker=10.0.0.50 disposition=suppressed
#
# (3) 기존 redef 예외 목록은 drop 예외로 옮겨져 그대로 동작한다
# @TEST-EXEC: mkdir legacy && cd legacy && zeek -C -r $TRACES/ssh_lateral.pcap $PKG $SETUP ../legacy.zeek
# @TEST-EXEC: assert-rows legacy/notice.log eq 0 note=NSM::SSH_Lateral
# @TEST-EXEC: assert-rows legacy/nsm_exception.log eq 1 kind=loaded exception_id=legacy:ssh_lm_allowlist disposition=drop msg=legacy
# @TEST-EXEC: mkdir legacy2 && cd legacy2 && zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP ../legacy.zeek
# @TEST-EXEC: assert-rows legacy2/notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.74
# @TEST-EXEC: assert-rows legacy2/notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
#
# (4) 파일이 바뀌면 다시 읽는다: v1(.70 drop)으로 시작해 .71 세션에서 v2(.74 drop)로 교체
# @TEST-EXEC: mkdir reload && cd reload && cp ../v1.tsv ex.tsv && zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP ../reload.zeek
# @TEST-EXEC: assert-rows reload/notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows reload/notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.74
# @TEST-EXEC: assert-rows reload/nsm_exception.log eq 1 kind=loaded exception_id=E-v1
# @TEST-EXEC: assert-rows reload/nsm_exception.log eq 1 kind=loaded exception_id=E-v2
#
# (5) 파일이 없어도 pcap 처리가 멈추지 않고 탐지는 그대로 나온다
# @TEST-EXEC: mkdir missing && cd missing && zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP NSM::exception_file=no-such.tsv
# @TEST-EXEC: assert-rows missing/notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows missing/notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.74
# @TEST-EXEC: assert-rows missing/nsm_exception.log eq 1 kind=error

# @TEST-START-FILE c2.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-c2-dst	Encrypted_C2	-	93.184.215.20/32	-	-	-	-	drop	백업 SaaS 정기 동기화	kim	-	-
E-c2-sni	Encrypted_C2	-	-	-	-	bank.example	-	suppress	관찰 중인 은행 서비스	lee	-	DET-1
E-expired	Encrypted_C2	-	93.184.215.24/32	-	-	-	-	-	지난 장애 대응	kim	1000000000.0	-
E-bad-noaxis	Encrypted_C2	-	-	-	-	-	-	-	축 없음	kim	-	-
E-bad-scope	No_Such_Notice	-	93.184.215.21/32	-	-	-	-	-	오타	kim	-	-
E-bad-noreason	Encrypted_C2	-	93.184.215.21/32	-	-	-	-	-	-	kim	-	-
E-bad-broad	Encrypted_C2	-	93.0.0.0/8	-	-	-	-	-	넓음	kim	-	-
E-bad-port	Encrypted_C2	-	-	443	-	-	-	-	프로토콜 없음	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE lm.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-lm-pair	group:lateral	10.0.0.50/32	10.0.0.51/32,10.0.0.52/32	-	-	-	-	suppress	운영팀 정상 접근 경로	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE lmsup.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-lm-src	SSH_Lateral	10.0.0.50/32	-	-	-	-	-	suppress	점프 서버 관찰	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE v1.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-v1	Encrypted_C2	-	93.184.215.20/32	-	-	-	-	-	v1	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE v2.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-v2	Encrypted_C2	-	93.184.215.24/32	-	-	-	-	-	v2	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE legacy.zeek
redef NSM::ssh_lm_allowlist += { 10.0.0.50/32 };
redef NSM::enc_c2_allowlist_sni += { "bank.example" };
# @TEST-END-FILE
# @TEST-START-FILE reload.zeek
redef NSM::exception_file = "ex.tsv";
global swapped = F;
global waiting = F;
event ssl_established(c: connection) &priority=10
	{
	if ( swapped || c$id$orig_h != 10.0.0.71 )
		return;
	swapped = T;
	# Manager 배포 방식대로 임시 파일에 쓰고 이름을 바꾼다(같은 초 안의 제자리 덮어쓰기는 감지되지 않는다).
	# system() 은 백그라운드로 돌므로 Zeek 에서 직접 쓴다.
	local f = open("ex.tsv.tmp");
	write_file(f, "#separator \\x09\x0a#set_separator\x09,\x0a#empty_field\x09(empty)\x0a#unset_field\x09-\x0a#fields\x09id\x09scope\x09src\x09dst\x09dst_port\x09service\x09domain\x09ja4\x09disposition\x09reason\x09owner\x09expires\x09ref\x0aE-v2\x09Encrypted_C2\x09-\x0993.184.215.24/32\x09-\x09-\x09-\x09-\x09-\x09v2\x09kim\x09-\x09-\x0a");
	close(f);
	rename("ex.tsv.tmp", "ex.tsv");
	waiting = T;
	suspend_processing();
	Input::force_update("nsm-exceptions");
	}
event Input::end_of_data(name: string, source: string) &priority=-10
	{
	if ( waiting )
		{
		waiting = F;
		continue_processing();
		}
	}
# @TEST-END-FILE
