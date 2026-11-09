# @TEST-DOC: 13 DGA — 무작위형 등록 라벨 NXDOMAIN(30자 .100, 10자 .101, co.kr 9자 .104, 16진수 12자 .105) 탐지, 정상 조회(.102)와 단어 조합형 미등록 도메인(.103) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/dga.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.100
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.101
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.104
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DGA_Domain src=10.0.0.105
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DGA_Domain src=10.0.0.102
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DGA_Domain src=10.0.0.103
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.DgaDomain attacker=10.0.0.101
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::DGA_Domain src=10.0.0.101
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::DGA_Domain src=10.0.0.103
# @TEST-EXEC: assert-evidence-join NSM::DGA_Domain
