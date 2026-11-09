# @TEST-DOC: 09 암호화 C2 — SNI 없음 + 자체서명(10.0.0.70) 탐지(반복 세션은 억제창으로 1건), SNI 정상(10.0.0.71)과 SNI만 없음(10.0.0.72) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.71
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.72
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.EncryptedChannel attacker=10.0.0.70
# @TEST-EXEC: assert-evidence-join NSM::Encrypted_C2
