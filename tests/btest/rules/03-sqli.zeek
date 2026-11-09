# @TEST-DOC: 03 SQLi — 내부 웹서버 대상 UNION SELECT(.120)·POST 본문 ' or 1=1(.122)·이중 인코딩(.123) 탐지, 검색어 "select ... from ... #"(.121)·외부 서버 대상(.124)·웹쉘 요청은 SQLi 미탐
# @TEST-EXEC: zeek -C -r $TRACES/web_attack.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SQL_Injection src=10.0.0.120 dst=10.0.10.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SQL_Injection src=10.0.0.122
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SQL_Injection src=10.0.0.123
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SQL_Injection src=10.0.0.121
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SQL_Injection src=10.0.0.124
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SQL_Injection src=10.0.0.125
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SQL_Injection src=10.0.0.127
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::SQL_Injection src=10.0.0.122 operation=http_request
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.WebAttack.SqlInjection attacker=10.0.0.120
# @TEST-EXEC: assert-evidence-join NSM::SQL_Injection
