# @TEST-DOC: 09 암호화 C2 — JA3 차단목록 일치만으로는 탐지하지 않는다(JA3 2 < 임계 3). SNI 가 있고 인증서 문제가 없는 10.0.0.71 은 미탐, 같은 ClientHello 에 자체서명(2)이 더해진 10.0.0.73 은 탐지
# @TEST-EXEC: zeek -C -r $TRACES/tls_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: log-cut id.orig_h ja3 < ssl.log | awk -F'\t' '$1=="10.0.0.71" && $2!="-" {print $2}' | sort -u > ja3.txt && test "$(wc -l < ja3.txt)" -eq 1
# 10.0.0.73 이 같은 JA3 인지(전제)
# @TEST-EXEC: log-cut id.orig_h ja3 < ssl.log | awk -F'\t' '$1=="10.0.0.73" {print $2}' | sort -u | cmp -s - ja3.txt
# @TEST-EXEC: rm -f *.log && zeek -C -r $TRACES/tls_c2.pcap -e "redef NSM::ja3_blocklist += { \"$(cat ja3.txt)\" };" $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Encrypted_C2 src=10.0.0.71
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Encrypted_C2 src=10.0.0.73
