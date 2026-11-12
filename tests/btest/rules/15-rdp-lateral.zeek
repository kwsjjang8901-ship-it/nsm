# @TEST-DOC: 15 RDP 확산 — 4대(10.0.0.40) 탐지, 2대(10.0.0.45) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/rdp_lateral.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::RDP_Lateral src=10.0.0.40
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::RDP_Lateral src=10.0.0.45
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.RdpAccess attacker=10.0.0.40
# @TEST-EXEC: assert-rows evidence.log eq 4 note=NSM::RDP_Lateral src=10.0.0.40
# 근거에 RDP cookie(mstshash) 계정이 남는다
# @TEST-EXEC: assert-rows evidence.log eq 4 note=NSM::RDP_Lateral src=10.0.0.40 account=administrator
# @TEST-EXEC: assert-evidence-join NSM::RDP_Lateral
# 근거 행마다 대표 연결 uid(집계형 근거와 원본 연결 조인)
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::RDP_Lateral uid=-
