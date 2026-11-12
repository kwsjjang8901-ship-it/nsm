# @TEST-DOC: 24 비표준 포트 — QUIC(HTTP/3) 443/udp(.95)는 Zeek 가 ssl 로 확인해도 표준 포트라 미탐
# @TEST-EXEC: zeek -C -r $TRACES/nonstd_quic.pcap $PKG $SETUP %INPUT
# Zeek 가 QUIC 안의 TLS 를 ssl 로 확인했는지(전제)
# @TEST-EXEC: assert-rows conn.log eq 1 id.orig_h=10.0.0.95 service=quic,ssl
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.95
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.95
