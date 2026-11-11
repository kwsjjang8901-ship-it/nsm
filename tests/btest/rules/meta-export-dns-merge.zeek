# @TEST-DOC: 메타데이터 선별 전송 — dns_summary 는 (출발지, 등록 도메인) 하나로 묶고 질의 유형·결과를 필드로 모은다(A·AAAA 성공 2 + 다른 이름 NXDOMAIN 1 -> 1행)
# @TEST-EXEC: zeek -C -r $TRACES/meta_dns_qtypes.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows meta/dns_summary.log eq 1
# @TEST-EXEC: assert-rows meta/dns_summary.log eq 1 orig_h=10.0.0.90 domain=example-mixed.com qtypes=A,AAAA rcodes=NOERROR:2,NXDOMAIN:1 queries=3 unique_names=2
# 거짓인 unique_names_capped 와 원본 보관을 끈 상태의 sample_uid 는 쓰지 않는다
# @TEST-EXEC: assert-fields meta/dns_summary.log ts ts_end node orig_h domain qtypes rcodes queries unique_names sample_names answers
