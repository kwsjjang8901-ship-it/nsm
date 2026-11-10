# @TEST-DOC: 메타데이터 선별 전송 끔 — meta_* 로그가 없고, 대상 스트림도 운영 필터대로 꺼진다. T2(원본 로컬 보관) 켬 — 원본이 별도 경로에 전체 필드로 남는다
# @TEST-EXEC: zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: test ! -e meta && test ! -f meta_export_stats.log
# @TEST-EXEC: test ! -f kerberos.log && test ! -f ntlm.log
# @TEST-EXEC: test -f notice.log
#
# @TEST-EXEC: mkdir raw && cd raw && zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP $FILES/meta-raw-local.zeek
# @TEST-EXEC: assert-rows raw/meta/kerberos.log eq 3
# @TEST-EXEC: assert-rows raw/raw_kerberos.log eq 3
# @TEST-EXEC: assert-rows raw/raw_kerberos.log eq 3 forwardable=T
# @TEST-EXEC: assert-rows raw/raw_dce_rpc.log eq 4

redef NSM::meta_export_enable = F;
