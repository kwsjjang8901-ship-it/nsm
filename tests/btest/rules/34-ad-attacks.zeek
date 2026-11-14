# @TEST-DOC: 34 AD 공격 — 강제 인증(efsrpc2·netdfs·DC 대상 spoolss·FileServerVssAgent), 원격 하이브 저장(winreg BaseRegSaveKey), Zerologon(netlogon 인증 1분 20회 이상), AD 정보 수집(세션·로컬 그룹 조회 5분 10대 이상) 탐지 / 프린트 서버 대상 spoolss·조회 호출·백업 에이전트(예외)·인증 2회·5대·공유 목록 조회 미탐. Zerologon -> DCSync, AD 정보 수집 -> 원격 서비스 생성 상관
# @TEST-EXEC: zeek -C -r $TRACES/ad_attacks.pcap $PKG $SETUP %INPUT NSM::exception_file=ad.tsv
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Coerced_Authentication src=10.0.5.10 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Coerced_Authentication src=10.0.5.11 dst=10.0.5.50
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Coerced_Authentication src=10.0.5.12 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Coerced_Authentication src=10.0.5.14 dst=10.0.5.50
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.5.13
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.5.15
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Coerced_Authentication operation=efsrpc2::EfsRpcOpenFileRaw
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Coerced_Authentication operation=spoolss::RpcRemoteFindFirstPrinterChangeNotificationEx
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Remote_Registry_Dump src=10.0.5.20 dst=10.0.5.52
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.5.21
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.5.22
# @TEST-EXEC: assert-rows nsm_exception.log ge 1 kind=hits exception_id=E-backup
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Zerologon_Attempt src=10.0.5.30 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Zerologon_Attempt src=10.0.5.31
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AD_Enumeration src=10.0.5.40
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::AD_Enumeration src=10.0.5.41
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::AD_Enumeration src=10.0.5.42
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::AD_Enumeration src=10.0.5.40
#
# @TEST-EXEC: assert-rows nsm_detection.log eq 4 diagnosis=NSM.CredentialAccess.CoercedAuth
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.RemoteRegistryDump attacker=10.0.5.20
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.Zerologon attacker=10.0.5.30
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Recon.AdEnumeration attacker=10.0.5.40
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Correlated_KillChain src=10.0.5.30
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Correlated_KillChain src=10.0.5.40
# @TEST-EXEC: assert-evidence-join NSM::Coerced_Authentication
# @TEST-EXEC: assert-evidence-join NSM::Remote_Registry_Dump
# @TEST-EXEC: assert-evidence-join NSM::Zerologon_Attempt
# @TEST-EXEC: assert-evidence-join NSM::AD_Enumeration

# @TEST-START-FILE ad.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-backup	Remote_Registry_Dump	10.0.5.22/32	-	-	-	-	-	-	백업 에이전트	kim	-	-
# @TEST-END-FILE
