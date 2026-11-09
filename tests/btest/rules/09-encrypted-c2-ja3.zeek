# @TEST-DOC: 09 암호화 C2 — 10.0.0.72 의 JA3 를 차단목록에 넣으면 탐지된다(JA3 가중치 3)
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.72
# @TEST-EXEC: zeek-cut id.orig_h ja3 < ssl.log | awk -F'\t' '$1=="10.0.0.72" && $2!="-" {print $2}' | sort -u > ja3.txt && test "$(wc -l < ja3.txt)" -eq 1
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap -e "redef NSM::ja3_blocklist += { \"$(cat ja3.txt)\" };" $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.72
