# @TEST-DOC: 09·24·33 명시적 프록시(10.0.60.5:3128) 인식(기본 켬)과 07·30 프록시 인식(기본 끔). 기본값: 터널 안 SNI 없음+자체서명(.16) 09 탐지, CONNECT 대상 포트 4444(.17) 24 탐지·443(.18) 미탐, api.openai.com 12MB(.19) 33 탐지, 주기 접속(.10~.15) 07·30 미탐. 근거에 실제 목적지(host=·name=)와 via_proxy= 가 남는다. 09·24·33 스위치를 끄면 이전처럼 미탐
# @TEST-EXEC: zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.60.16
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Nonstandard_Port src=10.0.60.17
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.60.18
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::AI_Service_Upload src=10.0.60.19
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::HTTP_Beaconing
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Beaconing
# @TEST-EXEC: assert-rows notice.log eq 3
# @TEST-EXEC: log-cut note detail < evidence.log | awk -F'\t' '$1=="NSM::Encrypted_C2" && $2 ~ /host=93\.184\.215\.170 via_proxy=10\.0\.60\.5:3128/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut note detail < evidence.log | awk -F'\t' '$1=="NSM::Nonstandard_Port" && $2 ~ /port=4444\/tcp host=files\.relay-drop\.net via_proxy=/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut note detail < evidence.log | awk -F'\t' '$1=="NSM::AI_Service_Upload" && $2 ~ /name=api\.openai\.com/ && $2 ~ /host=api\.openai\.com via_proxy=10\.0\.60\.5:3128/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: grep -q 'files.relay-drop.net:4444/tcp' notice.log
# @TEST-EXEC: assert-evidence-join NSM::Encrypted_C2
# @TEST-EXEC: assert-evidence-join NSM::Nonstandard_Port
# 스위치를 끄면 프록시 경유는 이전처럼 보지 않는다
# @TEST-EXEC: mkdir off && cd off && zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP NSM::proxy_aware_ai=F NSM::proxy_aware_nonstd=F NSM::proxy_aware_enc_c2=F
# @TEST-EXEC: assert-rows off/notice.log eq 0
