# @TEST-DOC: 10 단일 연결 대용량 유출 — 외부로 60MB(10.0.0.80/84/85) 탐지, 10MB(10.0.0.81)와 내부 간 60MB(10.0.0.82) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/exfil.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.80
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Large_Transfer src=10.0.0.81
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Large_Transfer src=10.0.0.82
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.84
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.0.85
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.LargeTransfer attacker=10.0.0.80
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Large_Transfer
