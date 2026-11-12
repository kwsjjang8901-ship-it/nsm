# @TEST-DOC: 18 Kerberoasting·AS-REP Roasting — 6개 SPN RC4 티켓(.156) Kerberoasting 탐지, 사전인증 없는 RC4 AS-REP 3개 계정(.154) AS-REP Roasting 탐지, AES 티켓(.157)·RC4 2개 SPN(.158)·사전인증 없는 AES AS-REP(.155)·정상 로그온(.151) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/kerberos.pcap $PKG $SETUP %INPUT
#
# @TEST-EXEC: assert-rows kerberos.log eq 6 id.orig_h=10.0.0.156 request_type=TGS cipher=rc4-hmac
# @TEST-EXEC: assert-rows kerberos.log eq 1 id.orig_h=10.0.0.154 request_type=AS cipher=aes256-cts-hmac-sha1-96 client=svc_backup/CORP.EXAMPLE
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberoasting src=10.0.0.156 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberoasting src=10.0.0.157
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberoasting src=10.0.0.158
# @TEST-EXEC: assert-rows notice.log eq 3 note=NSM::ASREP_Roasting src=10.0.0.154 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::ASREP_Roasting src=10.0.0.154 sub=svc_legacy@corp.example
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::ASREP_Roasting src=10.0.0.155
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::ASREP_Roasting src=10.0.0.151
# 근거: 임계(5) 도달 시점까지 SPN 5개 / AS-REP 계정마다 1건
# @TEST-EXEC: assert-rows evidence.log eq 5 note=NSM::Kerberoasting src=10.0.0.156 operation=kerberos_tgs_weak_cipher account=user01@corp.example
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::ASREP_Roasting src=10.0.0.154 operation=kerberos_as_rep_without_preauth
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.Kerberoasting attacker=10.0.0.156
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 diagnosis=NSM.CredentialAccess.AsrepRoasting attacker=10.0.0.154
# @TEST-EXEC: assert-evidence-join NSM::Kerberoasting
# @TEST-EXEC: assert-evidence-join NSM::ASREP_Roasting
# 근거 행마다 대표 연결 uid(집계형 근거와 원본 연결 조인)
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::Kerberoasting uid=-

redef NSM::keep_log_streams += { KRB::LOG };
