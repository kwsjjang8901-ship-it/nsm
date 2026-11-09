# @TEST-DOC: 07 HTTP 비커닝 — 30초 주기 14회(10.0.0.60) 탐지, 불규칙 간격(10.0.0.61) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/http_beacon.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.60
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::HTTP_Beaconing src=10.0.0.61
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.HttpBeaconing attacker=10.0.0.60
# @TEST-EXEC: assert-evidence-join NSM::HTTP_Beaconing
