# @TEST-DOC: 14 호스트 단위 볼륨 유출 — 테스트 임계 50KB/1분: 80KB(10.0.0.90) 탐지, 20KB(10.0.0.91) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/volume_aggregate.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.0.90
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.0.91
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.VolumeAggregate attacker=10.0.0.90
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Volume_Aggregate

# pcap 크기를 줄이기 위해 임계만 낮춘다(로직 검증 목적).
redef NSM::exfil_thresholds = vector(50.0 * 1024);
