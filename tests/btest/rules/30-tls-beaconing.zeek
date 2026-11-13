# @TEST-DOC: 30 TLS 비커닝 — 30초마다 같은 크기의 TLS 연결 14회(.200) 탐지 / 30초마다지만 응답 크기가 매번 크게 다름(.201)·같은 크기지만 간격이 불규칙(.202) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/detect_gap.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::TLS_Beaconing src=10.0.0.200 dst=93.184.215.160
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Beaconing src=10.0.0.201
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::TLS_Beaconing src=10.0.0.202
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::TLS_Beaconing src=10.0.0.200 operation=tls_beacon
# @TEST-EXEC: grep -q 'interval=30.0s consecutive=12' evidence.log && grep -q 'sni=api.sync-check.net' evidence.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.TlsBeaconing
# @TEST-EXEC: assert-evidence-join NSM::TLS_Beaconing
