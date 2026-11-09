# @TEST-DOC: 24 비표준 포트·장기 연결 — 외부 HTTP 8081·TLS 4444·SSH 2222(.230) 각각 탐지, 표준 포트(.231)·내부 서버(.235)·허용 외부 서비스(.236) 미탐 / 외부 12분 연결(.232) 탐지, 외부 5분(.233)·내부 12분(.234) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/nonstd_port.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 3 note=NSM::Nonstandard_Port src=10.0.0.230
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.230 dst=93.184.215.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.230 dst=93.184.215.81
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.230 dst=93.184.215.82
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.231
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.235
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Nonstandard_Port src=10.0.0.236
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Long_Connection src=10.0.0.232 dst=93.184.215.85
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Long_Connection src=10.0.0.233
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Long_Connection src=10.0.0.234
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Long_Connection src=10.0.0.230
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Nonstandard_Port src=10.0.0.230 operation=ssh_on_nonstandard_port
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Long_Connection src=10.0.0.232 operation=long_external_connection
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.LongConnection attacker=10.0.0.232
# @TEST-EXEC: assert-evidence-join NSM::Nonstandard_Port
# @TEST-EXEC: assert-evidence-join NSM::Long_Connection

redef NSM::long_conn_duration = 10min;
redef NSM::nonstd_port_allowed_dsts += { 93.184.215.84/32 };
