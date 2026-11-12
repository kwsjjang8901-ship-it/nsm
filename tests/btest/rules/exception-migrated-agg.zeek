# @TEST-DOC: 예외 엔진 E3-2 — 집계형 룰(01·02·05·06·14·15·17·18·20·21·22)이 예외 파일을 따른다(관측 전에 거름). 범위가 다른 탐지는 그대로
#
# 01·02: 묶음 범위(group:recon) 하나로 포트·호스트 스캔 모두
# @TEST-EXEC: mkdir ps && cd ps && zeek -C -r $TRACES/port_scan.pcap $PKG $SETUP NSM::exception_file=../scan.tsv
# @TEST-EXEC: mkdir hs && cd hs && zeek -C -r $TRACES/host_scan.pcap $PKG $SETUP NSM::exception_file=../scan.tsv
# @TEST-EXEC: assert-rows ps/notice.log eq 0 note=NSM::Port_Scan
# @TEST-EXEC: assert-rows hs/notice.log eq 0 note=NSM::Host_Scan
# @TEST-EXEC: assert-rows ps/nsm_exception.log ge 1 kind=hits exception_id=E-scan
#
# 05·06·15·21·22: 출발지 예외
# @TEST-EXEC: mkdir ntlm && cd ntlm && zeek -C -r $TRACES/ntlm_spray.pcap $PKG $SETUP NSM::exception_file=../ntlm.tsv
# @TEST-EXEC: assert-rows ntlm/notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.140
# @TEST-EXEC: mkdir smb && cd smb && zeek -C -r $TRACES/smb_admin_share.pcap $PKG $SETUP NSM::exception_file=../smb.tsv
# @TEST-EXEC: assert-rows smb/notice.log eq 0 note=NSM::SMB_Admin_Share src=10.0.0.20
# @TEST-EXEC: mkdir rdp && cd rdp && zeek -C -r $TRACES/rdp_lateral.pcap $PKG $SETUP NSM::exception_file=../rdp.tsv
# @TEST-EXEC: assert-rows rdp/notice.log eq 0 note=NSM::RDP_Lateral src=10.0.0.40
# @TEST-EXEC: mkdir rw && cd rw && zeek -C -r $TRACES/smb_ransomware.pcap $PKG $SETUP NSM::exception_file=../rw.tsv
# @TEST-EXEC: assert-rows rw/notice.log eq 0 note=NSM::SMB_Ransomware src=10.0.0.180
# @TEST-EXEC: assert-rows rw/notice.log eq 1 note=NSM::SMB_Ransomware src=10.0.0.184
# @TEST-EXEC: mkdir poison && cd poison && zeek -C -r $TRACES/name_poisoning.pcap $PKG $SETUP NSM::exception_file=../poison.tsv
# @TEST-EXEC: assert-rows poison/notice.log eq 0 note=NSM::Name_Poisoning src=10.0.0.190
# @TEST-EXEC: assert-rows poison/nsm_exception.log ge 1 kind=hits exception_id=E-wins
#
# 14: 예외 연결은 더 세지 않는다(.90 미탐, .93 그대로)
# @TEST-EXEC: mkdir vol && cd vol && zeek -C -r $TRACES/volume_aggregate.pcap $PKG $SETUP ../vol.zeek NSM::exception_file=../vol.tsv
# @TEST-EXEC: assert-rows vol/notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.0.90
# @TEST-EXEC: assert-rows vol/notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.93
#
# 17·18: 같은 pcap 에서 스프레이·무차별 대입·Kerberoasting 을 범위별로 따로 뺀다(AS-REP Roasting 은 그대로)
# @TEST-EXEC: mkdir krb && cd krb && zeek -C -r $TRACES/kerberos.pcap $PKG $SETUP NSM::exception_file=../krb.tsv
# @TEST-EXEC: assert-rows krb/notice.log eq 0 note=NSM::Kerberos_Spray src=10.0.0.150
# @TEST-EXEC: assert-rows krb/notice.log eq 1 note=NSM::Kerberos_Spray src=10.0.0.159
# @TEST-EXEC: assert-rows krb/notice.log eq 0 note=NSM::Kerberos_Bruteforce src=10.0.0.152
# @TEST-EXEC: assert-rows krb/notice.log eq 0 note=NSM::Kerberoasting src=10.0.0.156
# @TEST-EXEC: assert-rows krb/notice.log eq 3 note=NSM::ASREP_Roasting src=10.0.0.154
#
# 20: WinRM 범위만 뺀다(DCOM 은 그대로)
# @TEST-EXEC: mkdir lm && cd lm && zeek -C -r $TRACES/winrm_dcom.pcap $PKG $SETUP NSM::exception_file=../lm.tsv
# @TEST-EXEC: assert-rows lm/notice.log eq 0 note=NSM::WinRM_Lateral src=10.0.0.170
# @TEST-EXEC: assert-rows lm/notice.log eq 1 note=NSM::DCOM_Lateral src=10.0.0.173

# @TEST-START-FILE vol.zeek
redef NSM::exfil_thresholds = vector(50.0 * 1024);
redef NSM::exfil_volume_step = 10 * 1024;
# @TEST-END-FILE
# @TEST-START-FILE scan.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-scan	group:recon	10.0.0.5/32	-	-	-	-	-	-	취약점 스캐너	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE ntlm.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-ntlm	NTLM_Spray	10.0.0.140/32	-	-	-	-	-	-	인증 프록시	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE smb.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-smb	SMB_Admin_Share	10.0.0.20/32	-	-	-	-	-	-	SCCM	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE vol.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-vol	Exfil_Volume_Aggregate	10.0.0.90/32	-	-	-	-	-	-	백업 서버	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE rdp.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-rdp	RDP_Lateral	10.0.0.40/32	-	-	-	-	-	-	점프 서버	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE krb.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-kspray	Kerberos_Spray	10.0.0.150/32	-	-	-	-	-	-	계정 점검 도구	kim	-	-
E-kbrute	Kerberos_Bruteforce	10.0.0.152/32	-	-	-	-	-	-	레거시 앱 재시도	kim	-	-
E-roast	Kerberoasting	10.0.0.156/32	-	-	-	-	-	-	레거시 RC4 서버	kim	-	-
# @TEST-END-FILE
# @TEST-START-FILE lm.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-winrm	WinRM_Lateral	10.0.0.170/32	-	-	-	-	-	-	Ansible	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE rw.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-rw	SMB_Ransomware	10.0.0.180/32	-	-	-	-	-	-	DLP 서버	lee	-	-
# @TEST-END-FILE
# @TEST-START-FILE poison.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-wins	Name_Poisoning	10.0.0.190/32	-	-	-	-	-	-	WINS 서버	kim	-	-
# @TEST-END-FILE
