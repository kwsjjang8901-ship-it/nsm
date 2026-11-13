# @TEST-DOC: 31 단일 대상 원격 실행 — svcctl CreateServiceW(.210)·atsvc NetrJobAdd(.212)·ITaskSchedulerService SchRpcRegisterTask(.214)·IWbemServices ExecMethod(.216)를 대상 1대여도 탐지 / OpenSCManagerW·ExecQuery 같은 조회(.218) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/detect_gap.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Remote_Service_Creation src=10.0.0.210 dst=10.0.0.211
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Remote_Task_Creation src=10.0.0.212 dst=10.0.0.213
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Remote_Task_Creation src=10.0.0.214 dst=10.0.0.215
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Remote_WMI_Execution src=10.0.0.216 dst=10.0.0.217
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.0.218
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Remote_Service_Creation operation=svcctl::CreateServiceW
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Remote_Task_Creation operation=ITaskSchedulerService::SchRpcRegisterTask
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.RemoteService attacker=10.0.0.210
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.LateralMovement.RemoteTask
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.LateralMovement.RemoteWmi
# @TEST-EXEC: assert-evidence-join NSM::Remote_Service_Creation
# @TEST-EXEC: assert-evidence-join NSM::Remote_Task_Creation
# @TEST-EXEC: assert-evidence-join NSM::Remote_WMI_Execution
