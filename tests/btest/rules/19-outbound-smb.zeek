# @TEST-DOC: 19 외부향 SMB·NTLM — 외부 445 연결+NTLM 인증(.160) 둘 다 탐지, 외부 139 연결만(.163) Outbound_SMB, 경계에서 막힌 SYN(.161)·내부 파일 서버(.162)·허용 외부 서버(.164) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/outbound_smb.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Outbound_SMB src=10.0.0.160 dst=93.184.215.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::NTLM_Credential_Leak src=10.0.0.160 dst=93.184.215.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Outbound_SMB src=10.0.0.163 dst=93.184.215.72
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::NTLM_Credential_Leak src=10.0.0.163
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.0.161
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.0.162
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.0.164
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::NTLM_Credential_Leak src=10.0.0.160 operation=ntlm_authenticate_external
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.OutboundSmb attacker=10.0.0.160
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.NtlmCredentialLeak attacker=10.0.0.160
# @TEST-EXEC: assert-evidence-join NSM::Outbound_SMB
# @TEST-EXEC: assert-evidence-join NSM::NTLM_Credential_Leak

redef NSM::outbound_smb_allowed_dsts += { 93.184.215.73/32 };
