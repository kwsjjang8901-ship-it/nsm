# @TEST-DOC: 메타데이터 선별 전송 2차 — ssl·http 행 선별(경계·도메인 예외·중복 억제·쿼리 문자열 제거), conn·dns 요약 로그
# @TEST-EXEC: zeek -C -r $TRACES/meta_summary.pcap $PKG $SETUP %INPUT
#
# DNS 요약((출발지, 등록 도메인) 단위, 유형·결과는 필드): 같은 질의 5번 -> 1행 queries=5, 역방향 조회·예외 도메인·리졸버(.54)의 질의는 제외
# @TEST-EXEC: assert-rows meta/dns_summary.log eq 1 orig_h=10.0.0.70 domain=example-news.com qtypes=A rcodes=NOERROR:5 queries=5 unique_names=1 sample_names=www.example-news.com answers=93.184.215.130
# @TEST-EXEC: assert-rows meta/dns_summary.log eq 1 orig_h=10.0.0.70 domain=partner.example rcodes=NXDOMAIN:1 queries=1
# @TEST-EXEC: assert-rows meta/dns_summary.log eq 2
# 출발지별 도메인 행 상한(테스트 1): 두 번째 도메인은 "(other)" 로 묶인다
# @TEST-EXEC: mkdir cap && cd cap && zeek -C -r $TRACES/meta_summary.pcap $PKG $SETUP $FILES/meta-dns-cap.zeek
# @TEST-EXEC: assert-rows cap/meta/dns_summary.log eq 1 orig_h=10.0.0.70 domain=example-news.com queries=5
# @TEST-EXEC: assert-rows cap/meta/dns_summary.log eq 1 orig_h=10.0.0.70 'domain=(other)' queries=1 sample_names=mail.partner.example
#
# 흐름 요약(duration·ts_end 없음): 외부 443 3번 -> 1행 conns=3, 내부 445(관리 포트) 2번 -> 1행, 내부 8080 은 제외
# @TEST-EXEC: assert-rows meta/flow_summary.log eq 1 orig_h=10.0.0.73 resp_h=93.184.215.133 resp_p=443 conns=3 states=SF:3
# @TEST-EXEC: assert-rows meta/flow_summary.log eq 1 orig_h=10.0.0.73 resp_h=10.0.30.5 resp_p=445 conns=2
# @TEST-EXEC: assert-rows meta/flow_summary.log eq 0 resp_p=8080
# @TEST-EXEC: assert-rows meta/flow_summary.log eq 1 orig_h=10.0.0.72 resp_h=93.184.215.132 service=ssl conns=2
# @TEST-EXEC: assert-rows meta/flow_summary.log eq 0 resp_p=53
# @TEST-EXEC: assert-fields meta/flow_summary.log ts node orig_h resp_h resp_p proto service conns orig_bytes resp_bytes states
# 원본 보관(T2)을 끈 기본 설정에서는 조인할 원본이 없으므로 sample_uid 를 쓰지 않는다
# @TEST-EXEC: ! grep -q sample_uid meta/flow_summary.log meta/dns_summary.log
#
# HTTP: 외부만, 같은 요청 2번 -> 1행, 예외 호스트 제외, 경로만(쿼리 문자열 없음)
# @TEST-EXEC: assert-rows meta/http.log eq 1 host=files.example-cdn.net uri_path=/download/file.zip method=GET status_code=200
# @TEST-EXEC: assert-rows meta/http.log eq 1
# @TEST-EXEC: assert-fields meta/http.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri_path status_code request_body_len response_body_len
# User-Agent 는 (출발지, UA)별 요약으로: 범위·예외를 통과한 요청 2건(중복 억제 전)
# @TEST-EXEC: assert-rows meta/http_ua_summary.log eq 1 orig_h=10.0.0.71 user_agent=Mozilla/5.0 requests=2 hosts=1 sample_host=files.example-cdn.net
# @TEST-EXEC: ! grep -q SECRET123 meta_*.log
#
# SSL: 외부만, 같은 SNI 2번 -> 1행, 예외 SNI 제외
# @TEST-EXEC: assert-rows meta/ssl.log eq 1 server_name=api.example-saas.com established=T
# @TEST-EXEC: assert-rows meta/ssl.log eq 1
#
# 원본 conn·dns 는 이 테스트에서도 SETUP 이 남기고, 요약 필터는 행을 쓰지 않는다
# @TEST-EXEC: test ! -f meta/flow_summary_rows.log && test ! -f meta/dns_summary_rows.log
# @TEST-EXEC: assert-rows meta/meta_export_stats.log ge 1 stream=dns_summary summarized=6 dropped_filter=3
# @TEST-EXEC: assert-rows meta/meta_export_stats.log ge 1 stream=http sent=1 dropped_scope=1 dropped_filter=1 dropped_dedup=1

redef NSM::meta_domain_allowlist += { "vendor.example" };
redef NSM::dns_tunnel_resolvers += { 10.0.0.54 };
