# @TEST-DOC: 09 암호화 C2 — 자체서명 + SNI 불일치(.74)는 같은 원인을 두 번 세지 않아 기본 미탐(2점). enc_c2_w_mismatch_selfsigned=1(이전 동작)이면 3점으로 탐지. SNI 없는 자체서명(.70)은 두 경우 모두 탐지
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.70
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.74

redef NSM::enc_c2_w_mismatch_selfsigned = 1;
