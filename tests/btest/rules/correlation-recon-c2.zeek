# @TEST-DOC: 상관 — 같은 host(10.0.0.5)의 포트 스캔 후 HTTP 비커닝은 kill-chain 으로 연결, 비커닝만 한 host(10.0.0.7)는 연결 안 됨
# @TEST-EXEC: zeek -C -r $TRACES/chain_recon_c2.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::Correlated_KillChain src=10.0.0.5
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Correlated_KillChain src=10.0.0.7
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Beaconing src=10.0.0.7
# @TEST-EXEC: assert-rows nsm_detection.log ge 1 category=Correlated diagnosis=NSM.Correlation.Recon.C2 attacker=10.0.0.5
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::Correlated_KillChain src=10.0.0.5
