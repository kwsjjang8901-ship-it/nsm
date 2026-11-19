# @TEST-DOC: 프록시 학습 — CONNECT 2xx 뒤 같은 연결에서 TLS 가 시작돼야 프록시로 배운다. 어떤 요청에도 200 으로 답하는 내부 장비(.20)를 점검 장비가 CONNECT 로만 두드린 경우 배우지 않아, PC(.30)가 그 장비로 올린 60MB 는 유출 미탐. 진짜 프록시(.5:3128)는 배워서 첫 요청 없는 연결(.31)도 10·14 탐지, 처음 보는 프록시(.22)의 터널 연결(.32)은 확인 뒤부터 세어 10·14 탐지
# @TEST-EXEC: zeek -C -r $TRACES/proxy_learn.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.43.30
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.43.31 dst=10.0.43.5
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.43.31
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.43.32 dst=10.0.43.22
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.43.32
# @TEST-EXEC: log-cut src detail < evidence.log | awk -F'\t' '$1=="10.0.43.31" && $2 ~ /via_proxy=10\.0\.43\.5:3128/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Large_Transfer
