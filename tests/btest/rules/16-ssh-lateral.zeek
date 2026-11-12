# @TEST-DOC: 16 SSH 확산 — 세션 성립 4대(10.0.0.50) 탐지, SYN 거부만 4대(10.0.0.55) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/ssh_lateral.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SSH_Lateral src=10.0.0.50
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SSH_Lateral src=10.0.0.55
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.SshAccess attacker=10.0.0.50
# @TEST-EXEC: assert-evidence-join NSM::SSH_Lateral
# 근거 행마다 대표 연결 uid(집계형 근거와 원본 연결 조인)
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::SSH_Lateral uid=-
