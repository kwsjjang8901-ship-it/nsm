# @TEST-DOC: [검토 C1/C2] 같은 C2 세션 반복 — 기본은 룰 억제창으로 notice 1건. dedup 전담(과거 동작)이어도 detection 은 1건
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.EncryptedChannel attacker=10.0.0.70
# 과거 동작: 억제를 끄고 dedup 이 전담 -> 첫 건 + 창 종료 요약(dup_count=2) 2행, detection 은 여전히 1건
# @TEST-EXEC: rm -f *.log && zeek -C -r $TRACES/tls_c2.pcap -e "redef NSM::dedup_override_suppression = T;" $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 2 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70 dup_count=2
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.EncryptedChannel attacker=10.0.0.70
