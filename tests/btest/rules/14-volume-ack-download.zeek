# @TEST-DOC: 14 볼륨 유출 — 다운로드 중 내부 PC 가 보내는 ACK(IP 헤더 약 14KB)는 외부 전송량이 아니다. 임계 10KB 에서도 500KB 다운로드(.92)는 미탐, 80KB 업로드(.90)는 탐지
# @TEST-EXEC: zeek -C -r $TRACES/volume_aggregate.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.0.92
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.90
# 다운로드 연결의 IP 바이트가 실제로 임계를 넘었는지(=이 테스트가 의미 있는지) conn.log 로 확인
# @TEST-EXEC: log-cut id.orig_h orig_ip_bytes < conn.log | awk -F'\t' '$1=="10.0.0.92" && $2 > 10240 {n++} END {exit !(n==1)}'

redef NSM::exfil_thresholds = vector(10.0 * 1024);
redef NSM::exfil_volume_step = 2 * 1024;
