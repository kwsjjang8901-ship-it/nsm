# @TEST-DOC: 02·24 정상 서비스 오탐 회귀 — TLS 전용 서비스 포트(APNs 5223 .97, FCM 5228 .98, NTS 4460 .99)와 HTTP 프록시 CONNECT 터널 안의 TLS(80 .100)는 비표준 포트 미탐, TLS 4444(.101)는 탐지. Windows 배달 최적화 7680 으로 30대(.102)는 호스트 스캔 미탐
# @TEST-EXEC: zeek -C -r $TRACES/service_ports.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.97
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.98
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.99
# 터널 연결은 HTTP 와 SSL 이 모두 확인된다(전제)
# @TEST-EXEC: assert-rows conn.log eq 1 id.orig_h=10.0.0.100 service=http,ssl
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.100
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.101 dst=93.184.215.184
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Host_Scan src=10.0.0.102
