# @TEST-DOC: 17 Kerberos 스프레이·무차별 대입 — 12개 계정 사전인증 실패(.150)·없는 계정 섞인 12개(.159) 스프레이 탐지, 1개 계정 25회 실패(.152) 무차별 대입 탐지, 정상 로그온 12개(.151)·예외 출발지(.153) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/kerberos.pcap $PKG $SETUP %INPUT
#
# Zeek 가 합성 Kerberos 메시지를 파싱했는지(kerberos.log)
# @TEST-EXEC: assert-rows kerberos.log eq 12 id.orig_h=10.0.0.150 request_type=AS success=F
# @TEST-EXEC: assert-rows kerberos.log eq 12 id.orig_h=10.0.0.151 request_type=AS success=T
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberos_Spray src=10.0.0.150
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberos_Spray src=10.0.0.159
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Spray src=10.0.0.151
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Spray src=10.0.0.152
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Spray src=10.0.0.153
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberos_Bruteforce src=10.0.0.152
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Bruteforce src=10.0.0.150
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Bruteforce src=10.0.0.151
# 근거: 임계(10) 도달 시점까지 실패한 계정 10개 / 무차별 대입 대상 계정 1개
# @TEST-EXEC: assert-rows evidence.log eq 10 note=NSM::Kerberos_Spray src=10.0.0.150 dst=10.0.0.10 operation=kerberos_as_failure
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Kerberos_Bruteforce src=10.0.0.152 account=administrator@corp.example
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.KerberosSpray attacker=10.0.0.150
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.KerberosBruteforce attacker=10.0.0.152
# @TEST-EXEC: assert-evidence-join NSM::Kerberos_Spray
# @TEST-EXEC: assert-evidence-join NSM::Kerberos_Bruteforce

redef NSM::krb_spray_allowlist += { 10.0.0.153/32 };
redef NSM::keep_log_streams += { KRB::LOG };
