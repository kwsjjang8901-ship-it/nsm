# @TEST-DOC: 20 WinRM/DCOM 확산 — WinRM 4대(.170)·DCOM RemoteCreateInstance 4대(.173) 탐지, WinRM 2대(.171)·관리 서버 예외(.172)·다른 DCE-RPC 인터페이스(.174)·ISystemActivator 다른 opnum(.175) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/winrm_dcom.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::WinRM_Lateral src=10.0.0.170
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::WinRM_Lateral src=10.0.0.171
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::WinRM_Lateral src=10.0.0.172
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCOM_Lateral src=10.0.0.170
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DCOM_Lateral src=10.0.0.173
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCOM_Lateral src=10.0.0.174
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCOM_Lateral src=10.0.0.175
# 근거: 피해 host 4대 각 1행
# @TEST-EXEC: assert-rows evidence.log eq 4 note=NSM::WinRM_Lateral src=10.0.0.170 operation=winrm_connect
# @TEST-EXEC: assert-rows evidence.log eq 4 note=NSM::DCOM_Lateral src=10.0.0.173 operation=dcom_remote_create_instance
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.WinrmAccess attacker=10.0.0.170
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.DcomExec attacker=10.0.0.173
# @TEST-EXEC: assert-evidence-join NSM::WinRM_Lateral
# @TEST-EXEC: assert-evidence-join NSM::DCOM_Lateral
# 근거 행마다 대표 연결 uid(집계형 근거와 원본 연결 조인)
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::WinRM_Lateral uid=-
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::DCOM_Lateral uid=-

redef NSM::lm_mgmt_allowlist += { 10.0.0.172/32 };
