# @TEST-DOC: 06 SMB 관리공유 — ADMIN$/C$ 3대(10.0.0.20) 탐지, IPC$·일반 공유(10.0.0.30), 1대(10.0.0.31), 프린터 공유 print$ 3대(10.0.0.32)는 미탐
# @TEST-EXEC: zeek -C -r $TRACES/smb_admin_share.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Admin_Share src=10.0.0.20
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Admin_Share src=10.0.0.30
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Admin_Share src=10.0.0.31
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Admin_Share src=10.0.0.32
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.SmbAccess attacker=10.0.0.20
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::SMB_Admin_Share src=10.0.0.20
# @TEST-EXEC: assert-evidence-join NSM::SMB_Admin_Share
