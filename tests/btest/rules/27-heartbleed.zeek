# @TEST-DOC: 27 Heartbleed — 평문: 선언 길이 16384·실제 0 인 하트비트 요청에 16KB 응답(.140, 성공), 같은 요청에 응답 없음(.141, 시도) / 암호화(핸드셰이크 뒤, 서버가 하트비트 확장 수락): 작은 요청에 16KB 응답(.144, 성공), 응답 없는 요청 5회(.146, 시도) 탐지 / 정상 평문 하트비트(.142)·하트비트 없는 TLS(.143)·같은 크기로 오가는 암호화 하트비트(.145) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/heartbleed.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.140 dst=10.0.60.30
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.141 dst=10.0.60.31
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.144 dst=10.0.60.34
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Heartbleed src=10.0.0.146 dst=10.0.60.36
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Heartbleed src=10.0.0.142
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Heartbleed src=10.0.0.143
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Heartbleed src=10.0.0.145
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed operation=tls_heartbleed_success src=10.0.0.140
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed operation=tls_heartbleed_attempt src=10.0.0.141
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed operation=tls_heartbleed_success src=10.0.0.144
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Heartbleed operation=tls_heartbleed_attempt src=10.0.0.146
# @TEST-EXEC: grep -q 'max_response_len=16387' evidence.log && grep -q 'max_response_len=16448 overread_request=F encrypted=T' evidence.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 4 diagnosis=NSM.WebAttack.Heartbleed
# @TEST-EXEC: assert-evidence-join NSM::TLS_Heartbleed
