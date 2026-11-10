# @TEST-DOC: 메타데이터 선별 전송 — 중복 억제 기간: 기본(ssl 24시간)은 1시간 뒤 같은 SNI 도 억제, 기간을 10분으로 줄이면 기간이 끝난 뒤 다시 보낸다
# @TEST-EXEC: zeek -C -r $TRACES/meta_dedup.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows meta/ssl.log eq 1 id.orig_h=10.0.0.80 server_name=app.example-saas.com
# @TEST-EXEC: assert-rows meta/meta_export_stats.log ge 1 stream=ssl dropped_dedup=1
#
# @TEST-EXEC: mkdir short && cd short && zeek -C -r $TRACES/meta_dedup.pcap $PKG $SETUP $FILES/meta-dedup-short.zeek
# @TEST-EXEC: assert-rows short/meta/ssl.log eq 2 id.orig_h=10.0.0.80 server_name=app.example-saas.com
