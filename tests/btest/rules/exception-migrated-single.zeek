# @TEST-DOC: 예외 엔진 E3-1 — 건별 룰(03·04·10·12·19·23·24)이 예외 파일을 따른다. 범위가 다른 탐지는 영향받지 않는다
#
# 03·04: SQLi .120 drop(.122 는 그대로), 웹쉘 .125 suppress(표시만)
# @TEST-EXEC: mkdir web && cd web && zeek -C -r $TRACES/web_attack.pcap $PKG $SETUP NSM::exception_file=../web.tsv
# @TEST-EXEC: assert-rows web/notice.log eq 0 note=NSM::SQL_Injection src=10.0.0.120
# @TEST-EXEC: assert-rows web/evidence.log eq 0 note=NSM::SQL_Injection src=10.0.0.120
# @TEST-EXEC: assert-rows web/notice.log eq 1 note=NSM::SQL_Injection src=10.0.0.122
# @TEST-EXEC: assert-rows web/notice.log eq 1 note=NSM::Webshell_Access src=10.0.0.125 disposition=suppressed exception_id=E-ws
# @TEST-EXEC: assert-rows web/nsm_exception.log ge 1 kind=hits exception_id=E-sqli
#
# 10·12: .80 대용량 전송 drop, .84 웹 업로드만 drop(같은 host 의 대용량 전송 탐지는 범위가 달라 그대로)
# @TEST-EXEC: mkdir exfil && cd exfil && zeek -C -r $TRACES/exfil.pcap $PKG $SETUP NSM::exception_file=../exfil.tsv
# @TEST-EXEC: assert-rows exfil/notice.log eq 0 note=NSM::Exfil_Large_Transfer src=10.0.0.80
# @TEST-EXEC: assert-rows exfil/notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.85
# @TEST-EXEC: assert-rows exfil/notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.0.84
# @TEST-EXEC: assert-rows exfil/notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.84
#
# 19: 허용 목적지 .70 은 외부 SMB·NTLM 유출 둘 다 drop, .72 는 그대로
# @TEST-EXEC: mkdir smb && cd smb && zeek -C -r $TRACES/outbound_smb.pcap $PKG $SETUP NSM::exception_file=../smb.tsv
# @TEST-EXEC: assert-rows smb/notice.log eq 0 note=NSM::Outbound_SMB dst=93.184.215.70
# @TEST-EXEC: assert-rows smb/notice.log eq 0 note=NSM::NTLM_Credential_Leak dst=93.184.215.70
# @TEST-EXEC: assert-rows smb/notice.log eq 1 note=NSM::Outbound_SMB src=10.0.0.163 dst=93.184.215.72
#
# 23: 묶음 범위(group:domain)로 동기화 서버 .210 drop
# @TEST-EXEC: mkdir dc && cd dc && zeek -C -r $TRACES/dcsync.pcap $PKG $SETUP NSM::exception_file=../dc.tsv
# @TEST-EXEC: assert-rows dc/notice.log eq 0 note=NSM::DCSync src=10.0.0.210
# @TEST-EXEC: assert-rows dc/nsm_exception.log eq 1 kind=hits exception_id=E-dc hits=1
#
# 24: 비표준 포트 .80 목적지만 drop(.81 그대로), 장기 연결 .85 drop(임계 시점 판정)
# @TEST-EXEC: mkdir np && cd np && zeek -C -r $TRACES/nonstd_port.pcap $PKG $SETUP ../np.zeek NSM::exception_file=../np.tsv
# @TEST-EXEC: assert-rows np/notice.log eq 0 note=NSM::Nonstandard_Port dst=93.184.215.80
# @TEST-EXEC: assert-rows np/notice.log eq 1 note=NSM::Nonstandard_Port dst=93.184.215.81
# @TEST-EXEC: assert-rows np/notice.log eq 0 note=NSM::Long_Connection dst=93.184.215.85
# @TEST-EXEC: assert-rows np/nsm_exception.log eq 1 kind=hits exception_id=E-lc hits=1

# @TEST-START-FILE np.zeek
redef NSM::long_conn_duration = 10min;
# @TEST-END-FILE
# @TEST-START-FILE web.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-sqli	SQL_Injection	10.0.0.120/32	-	-	-	-	-	-	취약점 스캐너	kim	-	-
E-ws	Webshell_Access	10.0.0.125/32	-	-	-	-	-	suppress	모의해킹 관찰	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE exfil.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-big	Exfil_Large_Transfer	10.0.0.80/32	-	-	-	-	-	-	백업 서버	lee	-	-
E-up	Exfil_Web_Upload	10.0.0.84/32	-	-	-	-	-	-	클라우드 동기화	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE smb.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-smb	Outbound_SMB,NTLM_Credential_Leak	-	93.184.215.70/32	-	-	-	-	-	협력사 파일 서버	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE dc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-dc	group:domain	10.0.0.210/32	-	-	-	-	-	-	Azure AD Connect	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE np.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-np	Nonstandard_Port	-	93.184.215.80/32	-	-	-	-	-	허용 외부 서비스	lee	-	-
E-lc	Long_Connection	-	93.184.215.85/32	-	-	-	-	-	VPN	lee	-	-
# @TEST-END-FILE
