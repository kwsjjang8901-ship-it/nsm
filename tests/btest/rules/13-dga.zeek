# @TEST-DOC: 13 DGA — 30자 무작위 라벨 NXDOMAIN 60건(10.0.0.100) 탐지, 정상 조회(10.0.0.102) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/dga.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.100
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DGA_Domain src=10.0.0.102
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.DgaDomain attacker=10.0.0.100
# @TEST-EXEC: assert-evidence-join NSM::DGA_Domain
