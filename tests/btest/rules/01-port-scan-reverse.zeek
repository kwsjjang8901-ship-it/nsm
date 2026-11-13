# @TEST-DOC: 01 포트 스캔 — 캡처 손실로 스캐너(.230)의 SYN 이 빠지고 피해 host(.231)의 RST/ACK 응답 30개만 남아도 피해 host 를 스캐너로 탐지하지 않는다(출발지 RST 'R'·방향 뒤집힘 '^' 은 SYN 없는 탐침으로 세지 않음, CIC-IDS2017 Friday 오탐 재현)
# @TEST-EXEC: zeek -C -r $TRACES/scan_reverse.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan
