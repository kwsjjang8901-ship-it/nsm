# @TEST-DOC: 01 포트 스캔 — 거부된 고유 포트 30개(10.0.0.5)는 탐지, 10개(10.0.0.6)는 미탐
# @TEST-EXEC: zeek -C -r $TRACES/port_scan.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::Port_Scan src=10.0.0.5
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Port_Scan src=10.0.0.6
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::Port_Scan src=10.0.0.5 dst=10.0.0.9
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 diagnosis=NSM.Recon.PortScan attacker=10.0.0.5 victims=10.0.0.9
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::Port_Scan src=10.0.0.5 dst=10.0.0.9
# @TEST-EXEC: assert-evidence-join NSM::Port_Scan
