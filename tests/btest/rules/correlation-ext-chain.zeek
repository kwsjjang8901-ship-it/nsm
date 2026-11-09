# @TEST-DOC: 상관 8단계(단계 묶음 전이) — A(.250) 포트 스캔 -> DGA -> HTTP 비커닝 -> Kerberoasting -> DCSync -> WinRM 확산(.251~.253) -> 피해 .251 유출(10·14 두 갈래) -> 피해 .251 랜섬웨어. Kerberoasting 만(.254)·랜섬웨어만(.255)은 상관 없음
# @TEST-EXEC: zeek -C -r $TRACES/chain_ext.pcap $PKG $SETUP %INPUT
#
# 단계마다 실제 룰이 탐지했는지
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberoasting src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DCSync src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::WinRM_Lateral src=10.0.0.250
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.251
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.251
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Ransomware src=10.0.0.251
#
# 체인 성장: 2·3단계 Recon.C2, 4·5단계 Recon.CredentialAccess, 6단계 Recon.Lateral,
#   7단계 Recon.Exfil x 2갈래(10·14), 8단계 Recon.Impact => 상관 8건
# @TEST-EXEC: assert-rows notice.log eq 8 note=NSM::Correlated_KillChain src=10.0.0.250
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.250 diagnosis=NSM.Correlation.Recon.C2
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.250 diagnosis=NSM.Correlation.Recon.CredentialAccess
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated attacker=10.0.0.250 diagnosis=NSM.Correlation.Recon.Lateral
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.250 diagnosis=NSM.Correlation.Recon.Exfil
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated attacker=10.0.0.250 diagnosis=NSM.Correlation.Recon.Impact
# 8단계 전체 기법 흐름(신규 탐지의 기법은 attack_map 에서 가져온다)
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated 'techniques=T1046->T1568.002->T1071.001->T1558.003->T1003.006->T1021.006->T1041->T1486'
# 7·8단계의 마지막 host = 피해 .251
# @TEST-EXEC: assert-rows evidence.log eq 8 note=NSM::Correlated_KillChain src=10.0.0.250 operation=killchain
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::Correlated_KillChain src=10.0.0.250 dst=10.0.0.251
#
# 계약: 상관 notice 수 = 상관 detection 수
# @TEST-EXEC: assert-rows nsm_detection.log eq 8 category=Correlated
# @TEST-EXEC: assert-rows notice.log eq 8 note=NSM::Correlated_KillChain
# @TEST-EXEC: assert-evidence-join NSM::Correlated_KillChain
#
# 비교군: 단일 탐지만, 상관 없음
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Kerberoasting src=10.0.0.254
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Ransomware src=10.0.0.255
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.254
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.255
