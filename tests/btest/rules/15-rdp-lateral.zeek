# @TEST-DOC: 15 RDP 확산 — 4대(10.0.0.40) 탐지, 2대(10.0.0.45) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/rdp_lateral.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::RDP_Lateral src=10.0.0.40
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::RDP_Lateral src=10.0.0.45
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.RdpAccess attacker=10.0.0.40
# @TEST-EXEC: assert-rows evidence.log eq 4 note=NSM::RDP_Lateral src=10.0.0.40
# @TEST-EXEC: assert-evidence-join NSM::RDP_Lateral
