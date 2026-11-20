# @TEST-DOC: 상관 5단계 — A(.240) 포트 스캔 -> DGA -> HTTP 비커닝 -> SMB 관리 공유(.241·.242) -> 피해 host 별 대용량 유출로 체인이 2·3·4·5단계로 자라고 5단계는 피해 host 2대 x 유출 룰 2개(10 단일 연결·14 볼륨 집계) = 4갈래. 비커닝 후 스캔(B .245, 순서 반대)·창 초과(C .246)·확산 없는 유출(D .247)은 상관 없음
# @TEST-EXEC: zeek -C -r $TRACES/chain_full.pcap $PKG $SETUP %INPUT
#
# 단계마다 실제 룰이 탐지했는지
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Admin_Share src=10.0.0.240
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.241
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.242
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.241
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.242
#
# 체인 성장: 2단계(스캔->DGA)·3단계(+비커닝) = Recon.C2, 4단계(+확산) = Recon.Lateral,
# 5단계(+유출) = Recon.Exfil x 4갈래(피해 host 2 x 유출 룰 2) => 상관 7건
# @TEST-EXEC: assert-rows notice.log eq 7 note=NSM::Correlated_KillChain src=10.0.0.240
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.C2
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.Lateral
# @TEST-EXEC: assert-rows nsm_detection.log eq 4 category=Correlated attacker=10.0.0.240 diagnosis=NSM.Correlation.Recon.Exfil
# 상관 행은 갈래를 합친 체인 전체(revision 이 오를수록 커짐): 유출 룰 2개(10·14)는 기법이 같아 T1041 이 두 번
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated revision=4 'techniques=T1046,T1568.002,T1071.001,T1021.002,T1041'
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 category=Correlated 'techniques=T1046,T1568.002,T1071.001,T1021.002,T1041,T1041'
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated revision=7 'killchain_stages=Recon,Command and Control,Lateral Movement,Exfiltration' victim_count=2
# 한 체인 = 한 detection_id, revision 1..7, 사건 묶기(incident_id·occurrence)와 같은 값
# @TEST-EXEC: python3 -c "import json;r=[json.loads(l) for l in open('nsm_detection.log')];c=[d for d in r if d['category']=='Correlated'];assert len({d['detection_id'] for d in c})==1 and [d['revision'] for d in c]==list(range(1,len(c)+1)) and all(d['incident_id']==d['detection_id'] and d['occurrence']==d['revision'] for d in c),c"
# 마지막 행의 구성 탐지: 스캔·DGA·비커닝·확산·피해 host 2대 x 유출 2개 = 8
# @TEST-EXEC: python3 -c "import json;r=[json.loads(l) for l in open('nsm_detection.log')];last=max((x for x in r if x['category']=='Correlated'),key=lambda x:x['revision']);m=last['member_detection_ids'];s={x['detection_id'] for x in r if x['category']=='Single'};assert len(m)==8 and set(m)<=s and last['evidence_ids']==[last['detection_id']]+m,last"
# 갈래별 마지막 host 가 victims 맨 앞(host 마다 유출 룰 2개)
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.Correlation.Recon.Exfil victims=10.0.0.241,10.0.0.242
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.Correlation.Recon.Exfil victims=10.0.0.242,10.0.0.241
# @TEST-EXEC: assert-rows evidence.log eq 7 note=NSM::Correlated_KillChain src=10.0.0.240 operation=killchain
# @TEST-EXEC: assert-rows evidence.log eq 2 note=NSM::Correlated_KillChain src=10.0.0.240 dst=10.0.0.241
# @TEST-EXEC: assert-rows evidence.log eq 2 note=NSM::Correlated_KillChain src=10.0.0.240 dst=10.0.0.242
#
# 계약: 상관 notice 수 = 상관 detection 수(갈래가 생겨도 notice 가 억제되지 않아야 함)
# @TEST-EXEC: assert-rows nsm_detection.log eq 7 category=Correlated
# @TEST-EXEC: assert-rows notice.log eq 7 note=NSM::Correlated_KillChain
# @TEST-EXEC: assert-evidence-join NSM::Correlated_KillChain
#
# 비교군: 단일 탐지는 나지만 상관은 없음
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.245
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.245
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.0.246
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.246
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.247
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.247
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.245
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.246
# @TEST-EXEC: assert-rows nsm_detection.log eq 0 category=Correlated attacker=10.0.0.247
