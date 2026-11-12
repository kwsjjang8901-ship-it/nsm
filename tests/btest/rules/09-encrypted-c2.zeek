# @TEST-DOC: 09 암호화 C2 — SNI 없음+자체서명(.70) 탐지(반복 세션은 억제창으로 1건), SNI 정상(.71)·SNI만 없음(.72) 미탐. 자체서명+SNI-인증서 불일치(.74) 탐지, 와일드카드 일치(.73)·SAN 일치(.75) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.71
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.72
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.73
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.74
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.75
# 전제 확인: Zeek 의 SNI-인증서 일치 판정(와일드카드·SAN 반영)
# @TEST-EXEC: assert-rows ssl.log eq 1 id.orig_h=10.0.0.73 sni_matches_cert=T
# @TEST-EXEC: assert-rows ssl.log eq 1 id.orig_h=10.0.0.74 sni_matches_cert=F
# @TEST-EXEC: assert-rows ssl.log eq 1 id.orig_h=10.0.0.75 sni_matches_cert=T
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.EncryptedChannel attacker=10.0.0.70
# @TEST-EXEC: assert-evidence-join NSM::Encrypted_C2
# 억제 창 안의 두 번째 세션(.70)은 notice 가 버려지므로 근거도 남지 않는다(탐지 1건 = 근거 1행)
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
