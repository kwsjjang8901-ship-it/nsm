# @TEST-DOC: 24 비표준 포트 — 443 이 아닌 UDP 포트(4433)의 QUIC(.96)은 ssl 비표준 포트로 탐지. Zeek 8.x 는 QUIC 을 443/udp 에서만 분석해 Zeek 9 이상만 본다
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/nonstd_quic.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows conn.log eq 1 id.orig_h=10.0.0.96 service=quic,ssl
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.96 dst=93.184.215.171
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.96 operation=ssl_on_nonstandard_port
# @TEST-EXEC: assert-evidence-join NSM::Nonstandard_Port
