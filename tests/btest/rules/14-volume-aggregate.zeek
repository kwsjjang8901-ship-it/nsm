# @TEST-DOC: 14 호스트 단위 볼륨 유출 — 테스트 임계 50KB/1분: 80KB 업로드(.90) 탐지, 20KB(.91) 미탐, 500KB 다운로드(.92) 미탐, 장기 연결(.93)은 연결 종료 전(첫 1분 안)에 탐지
# @TEST-EXEC: zeek -C -r $TRACES/volume_aggregate.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.90
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.0.91
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.0.92
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.93
# 장기 연결: 업로드는 T0+10초, 연결 종료는 T0+160초. 탐지 시각이 T0+60초(1794182460) 이전이어야 한다.
# @TEST-EXEC: log-cut ts src note < notice.log | awk -F'\t' '$2=="10.0.0.93" && $3=="NSM::Exfil_Volume_Aggregate" && $1 < 1794182460 {n++} END {exit !(n==1)}'
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.VolumeAggregate attacker=10.0.0.90
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Volume_Aggregate

# pcap 크기를 줄이기 위해 임계·갱신 간격만 낮춘다(로직 검증 목적).
redef NSM::exfil_thresholds = vector(50.0 * 1024);
redef NSM::exfil_volume_step = 10 * 1024;
