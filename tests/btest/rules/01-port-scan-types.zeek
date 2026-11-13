# @TEST-DOC: 01 포트 스캔 방식별 — SYN 없는 TCP 탐침 FIN(.240)·NULL(.242)·Xmas(.244)·ACK(.246)과 UDP 스캔(.248)을 포트 30개에서 탐지 / UDP traceroute(.250)·UDP 10포트(.252)·캡처 전부터 이어진 데이터 연결(.254) 미탐. 표본에 탐침 종류(nosyn·udp)를 남긴다
# @TEST-EXEC: zeek -C -r $TRACES/scan_types.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.1.240 dst=10.0.1.241
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.1.242
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.1.244
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.1.246
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Port_Scan src=10.0.1.248
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan src=10.0.1.250
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan src=10.0.1.252
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan src=10.0.1.254
# @TEST-EXEC: grep -q '/tcp(nosyn)' evidence.log && grep -q '/udp(udp)' evidence.log
# @TEST-EXEC: assert-evidence-join NSM::Port_Scan
