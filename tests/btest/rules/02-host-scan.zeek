# @TEST-DOC: 02 호스트 스캔 — 445 포트 30대(10.0.0.5)는 탐지, 기본 제외 포트 443 30대(10.0.0.6)는 미탐
# @TEST-EXEC: zeek -C -r $TRACES/host_scan.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::Host_Scan src=10.0.0.5
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Host_Scan src=10.0.0.6
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 diagnosis=NSM.Recon.HostScan attacker=10.0.0.5
# @TEST-EXEC: assert-evidence-join NSM::Host_Scan
