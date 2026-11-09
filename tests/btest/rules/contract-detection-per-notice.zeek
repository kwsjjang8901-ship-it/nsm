# @TEST-DOC: [검토 C2] notice.log 에 기록된 단일 탐지 notice 수 = nsm_detection.log 의 Single detection 수
# @TEST-EXEC: zeek -C -r $TRACES/chain_recon_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: zeek-cut note < notice.log | grep -v -c '^NSM::Correlated_KillChain$' > n_notice
# @TEST-EXEC: zeek-cut category < nsm_detection.log | grep -c '^Single$' > n_detection
# @TEST-EXEC: test "$(cat n_notice)" -ge 1 && cmp n_notice n_detection
