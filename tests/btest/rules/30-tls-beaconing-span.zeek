# @TEST-DOC: 30 TLS 비커닝 지속 시간 — 60초마다 같은 크기 TLS 가 39분 이어진 .204 는 연속 구간이 30분에 닿을 때 탐지 / 10초마다 같은 크기지만 10분 만에 멈춘 .205(웹 페이지 분석 스크립트형) 미탐. 기본 설정에서 6분 30초짜리 .200(detect_gap.pcap)도 미탐
# @TEST-EXEC: zeek -C -r $TRACES/tls_beacon_long.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Beaconing src=10.0.0.204 dst=93.184.215.163
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Beaconing src=10.0.0.205
# @TEST-EXEC: grep -q 'interval=60.0s consecutive=31 span=30.0 mins' evidence.log
# @TEST-EXEC: mkdir short && cd short && zeek -C -r $TRACES/detect_gap.pcap $PKG $SETUP
# @TEST-EXEC: assert-rows short/notice.log eq 0 note=NSM::TLS_Beaconing
