# @TEST-DOC: 25 식별 안 된 프로토콜 — 444 포트 미식별 TCP 대량 송신(.110, 연결 중 임계), 캡처 손실로 데이터 대부분이 빠진 대량 송신(.116, 종료 때 판정), 2분 넘는 대화형 연결(.114) 탐지 / 소량(.111)·443 포트(.112)·HTTP 로 식별(.113)·내부 대상(.115) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/unknown_proto.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Unknown_Protocol src=10.0.0.110 dst=93.184.215.190
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Unknown_Protocol src=10.0.0.116
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Unknown_Protocol src=10.0.0.114
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Unknown_Protocol src=10.0.0.111
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Unknown_Protocol src=10.0.0.112
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Unknown_Protocol src=10.0.0.113
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Unknown_Protocol src=10.0.0.115
# 근거: 판정 경로(연결 중 바이트 / 종료 때 / 지속 시간)와 uid
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::Unknown_Protocol operation=unidentified_protocol_outbound
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::Unknown_Protocol uid=-
# @TEST-EXEC: grep -q 'bytes_sent>=100000' evidence.log && grep -q 'at_close' evidence.log && grep -q 'duration>=2.0 mins' evidence.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 diagnosis=NSM.C2.UnknownProtocol
# @TEST-EXEC: assert-evidence-join NSM::Unknown_Protocol

redef NSM::unknown_proto_min_bytes = 100000;
redef NSM::unknown_proto_min_duration = 2min;
