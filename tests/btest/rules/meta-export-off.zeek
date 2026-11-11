# @TEST-DOC: 메타데이터 선별 전송 끔 — meta_* 로그가 없고, 대상 스트림도 운영 필터대로 꺼진다. T2(원본 로컬 보관) 켬 — 원본이 별도 경로에 전체 필드로 남는다
# @TEST-EXEC: zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: test ! -e meta && test ! -f meta_export_stats.log
# @TEST-EXEC: test ! -f kerberos.log && test ! -f ntlm.log
# @TEST-EXEC: test -f notice.log
#
# @TEST-EXEC: mkdir raw && cd raw && zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP $FILES/meta-no-raw.zeek $FILES/meta-raw-local.zeek
# @TEST-EXEC: assert-rows raw/meta/kerberos.log eq 3
# @TEST-EXEC: assert-rows raw/raw_kerberos.log eq 3
# @TEST-EXEC: assert-rows raw/raw_kerberos.log eq 3 forwardable=T
# @TEST-EXEC: assert-rows raw/raw_dce_rpc.log eq 4
# 원본은 Zeek 기본 이름으로 남는다(선별 로그 이름 flow_summary·dns_summary 를 쓰지 않는다)
# @TEST-EXEC: test -f raw/raw_conn.log && test ! -f raw/raw_flow_summary.log && test ! -f raw/raw_dns_summary.log
# 원본을 남기면 흐름 요약에 대표 연결 uid(sample_uid)를 붙이고, 그 uid 로 원본 conn 행을 찾을 수 있다
# @TEST-EXEC: grep -q sample_uid raw/meta/flow_summary.log
# @TEST-EXEC: uid=$(grep -o '"sample_uid":"[A-Za-z0-9]*"' raw/meta/flow_summary.log | head -1 | cut -d'"' -f4) && test -n "$uid" && grep -q "\"uid\":\"$uid\"" raw/raw_conn.log

redef NSM::meta_export_enable = F;
