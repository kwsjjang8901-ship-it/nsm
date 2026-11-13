# @TEST-DOC: 공격 스토리 7단계 — 공격자(172.16.0.66)가 웹서버를 스캔·SQL 인젝션·웹쉘로 침투하고, 침해된 웹서버(.81)가 C2 비콘·Kerberoasting·SMB 확산(.31·.32)을 하고, 확산 대상이 유출(.31)·랜섬웨어(.32)까지 가는 하나의 시나리오. 통합 리포트 공격 스토리 확인용 pcap(killchain_story.pcap)의 단계별 탐지와 웹서버 기준 상관 체인을 고정한다
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP %INPUT
# 정찰·초기 침투(공격자 -> 웹서버)
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Recon.PortScan attacker=172.16.0.66
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.WebAttack.SqlInjection attacker=172.16.0.66
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.WebAttack.Webshell attacker=172.16.0.66
# C2·자격증명·확산(침해된 웹서버)
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.HttpBeaconing attacker=10.0.10.81
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.Kerberoasting attacker=10.0.10.81
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.SmbAccess attacker=10.0.10.81
# 유출·영향(확산 대상)
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.LargeTransfer attacker=10.0.20.31
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Impact.SmbRansomware attacker=10.0.20.32
# 상관: 웹서버의 C2 에서 자격증명·확산·유출·영향으로 이어지는 체인
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated diagnosis=NSM.Correlation.C2.CredentialAccess attacker=10.0.10.81
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated diagnosis=NSM.Correlation.C2.Lateral attacker=10.0.10.81
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 category=Correlated diagnosis=NSM.Correlation.C2.Exfil attacker=10.0.10.81
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 category=Correlated diagnosis=NSM.Correlation.C2.Impact attacker=10.0.10.81
