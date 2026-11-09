# @TEST-DOC: 13 DGA [알려진 한계, 검토 H4] — 10자 라벨 DGA(10.0.0.101)는 평균 엔트로피 4.0 미달로 현재 미탐. 2단계 개선 시 eq 0 -> ge 1 로 바꾼다
# @TEST-EXEC: zeek -C -r $TRACES/dga.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DGA_Domain src=10.0.0.101
