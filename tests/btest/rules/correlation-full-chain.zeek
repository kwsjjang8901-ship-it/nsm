# @TEST-DOC: 상관 5단계 — A(.240) 포트 스캔 -> DGA -> HTTP 비커닝 -> SMB 관리 공유(.241·.242) -> 피해 host 별 대용량 유출로 체인이 2·3·4·5단계로 자라고 5단계는 피해 host 별 2갈래. 비커닝 후 스캔(B .245, 순서 반대)·창 초과(C .246)·확산 없는 유출(D .247)은 상관 없음
# @TEST-EXEC: zeek -C -r $TRACES/chain_full.pcap $PKG $SETUP %INPUT
#
# 단계마다 실제 룰이 탐지했는지
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Admin_Share src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.241
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.242
#
# 체인 성장: 2단계(스캔->DGA)·3단계(+비커닝) = Recon.C2, 4단계(+확산) = Recon.Lateral, 5단계(+유출) = Recon.Exfil x 피해 host 2
# @TEST-EXEC: assert-rows notice.log eq 5 note=NSM::Correlated_KillChain src=10.0.0.240
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.C2
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.Lateral
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.Exfil
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated techniques=T1046->T1568.002->T1071.001->T1021.002->T1041
# 5단계 갈래별 마지막 host 가 victims 맨 앞
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Correlation.Recon.Exfil victims=10.0.0.241,10.0.0.242
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Correlation.Recon.Exfil victims=10.0.0.242,10.0.0.241
# @TEST-EXEC: assert-rows evidence.log eq 5 note=NSM::Correlated_KillChain src=10.0.0.240 operation=killchain
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Correlated_KillChain src=10.0.0.240 dst=10.0.0.241
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Correlated_KillChain src=10.0.0.240 dst=10.0.0.242
#
# 계약: 상관 notice 수 = 상관 detection 수(갈래가 생겨도 notice 가 억제되지 않아야 함)
# @TEST-EXEC: assert-rows nsm_detection.log eq 5 category=Correlated
# @TEST-EXEC: assert-rows notice.log eq 5 note=NSM::Correlated_KillChain
# @TEST-EXEC: assert-evidence-join NSM::Correlated_KillChain
#
# 비교군: 단일 탐지는 나지만 상관은 없음
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.245
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.245
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.246
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.246
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.247
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.245
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.246
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.247
