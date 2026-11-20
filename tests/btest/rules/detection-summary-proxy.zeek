# @TEST-DOC: nsm_detection 근거 요약 relays·dst_names — 명시적 프록시(10.0.60.5:3128) 경유 탐지 3건 모두 relays 에 프록시가 남고, 실제 목적지 이름(CONNECT 대상)이 dst_names 에 남는다. 목적지가 주소뿐인 09(.16)는 dst_names 가 비어 있다
# @TEST-EXEC: zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 relays=10.0.60.5:3128
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=Nonstandard_Port dst_names=files.relay-drop.net
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=AI_Service_Upload dst_names=api.openai.com
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 rule=Encrypted_C2 dst_names=-
