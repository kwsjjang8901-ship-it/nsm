# @TEST-DOC: 27 Heartbleed 즉시 탐지 — 10분 넘게 이어지는 연결에서 성공은 첫 유출 때(.147, 요청 1·응답 1), 암호화 시도는 응답 없는 요청 4번째에(.148) 나온다. 연결 종료 때의 누적값(요청 20·10)이 아니다
# @TEST-EXEC: zeek -C -r $TRACES/heartbleed_long.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.147 'sub=result=success requests=1 responses=1'
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.148 'sub=result=attempt requests=4 responses=0'
# 같은 연결에서 같은 결과를 다시 내지 않는다(성공 1건, 시도 1건)
# @TEST-EXEC: assert-rows notice.log eq 2 note=NSM::TLS_Heartbleed
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.147 operation=tls_heartbleed_success
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.148 operation=tls_heartbleed_attempt
# @TEST-EXEC: assert-evidence-join NSM::TLS_Heartbleed
