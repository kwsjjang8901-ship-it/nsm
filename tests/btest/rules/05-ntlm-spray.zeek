# @TEST-DOC: 05 NTLM 스프레이 — 12개 계정 SMB 로그온 실패(.140) 탐지, 12개 계정 성공(.141)·단일 계정 반복 실패(.142)·대소문자만 바꾼 6개 계정(.143)·외부 서버 대상(.144)·예외 출발지(.145) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/ntlm_spray.pcap $PKG $SETUP %INPUT
#
# Zeek 의 ntlm.log 는 SMB 로그온 실패를 success 없이(-) 남긴다 → 룰이 SMB 상태 코드로 실패를 판정해야 하는 이유
# @TEST-EXEC: assert-rows ntlm.log eq 12 id.orig_h=10.0.0.140 success=-
# @TEST-EXEC: assert-rows ntlm.log eq 12 id.orig_h=10.0.0.141 success=T
# @TEST-EXEC: assert-rows ntlm.log eq 1 id.orig_h=10.0.0.140 username=user01 domainname=CORP
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::NTLM_Spray src=10.0.0.140
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.141
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.142
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.143
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.144
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Spray src=10.0.0.145
# 근거: 임계(10) 도달 시점까지 실패한 계정 10개, 대상 서버와 실패 상태 포함
# @TEST-EXEC: assert-rows evidence.log eq 10 note=NSM::NTLM_Spray src=10.0.0.140 dst=10.0.0.5 operation=ntlm_auth_failure
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.NtlmSpray attacker=10.0.0.140
# @TEST-EXEC: assert-evidence-join NSM::NTLM_Spray

redef NSM::ntlm_spray_allowlist += { 10.0.0.145/32 };
redef NSM::keep_log_streams += { NTLM::LOG };
