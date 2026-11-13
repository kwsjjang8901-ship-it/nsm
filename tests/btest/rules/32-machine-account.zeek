# @TEST-DOC: 32 남의 머신 계정 사용 — 한 IP 가 10분 안에 NTLM PC01$·PC02$ 와 Kerberos pc03$ 로 인증(.190) 탐지 / 자기 머신 계정만 반복(.191)·사용자 계정 여러 개(.192) 미탐. NTLM 도메인(CORP)과 Kerberos 렐름(CORP.EXAMPLE)을 같은 도메인으로 맞춘다
# @TEST-EXEC: zeek -C -r $TRACES/detect_gap.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Machine_Account_Misuse src=10.0.0.190
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Machine_Account_Misuse src=10.0.0.191
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Machine_Account_Misuse src=10.0.0.192
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::Machine_Account_Misuse src=10.0.0.190
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Machine_Account_Misuse 'account=corp\pc03$' operation=kerberos_machine_account_auth
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.MachineAccountMisuse
# @TEST-EXEC: assert-evidence-join NSM::Machine_Account_Misuse
