# @TEST-DOC: 23 DCSync — 일반 host 의 DRSGetNCChanges(.210) 탐지, 학습된 DC(10.0.0.11)·설정 목록 DC(10.0.0.12)·DRSCrackNames(.211)·예외 서버(.212) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/dcsync.pcap $PKG $SETUP %INPUT
#
# 동적 포트(49667)의 DRSUAPI 를 Zeek 가 DPD 로 해석했는지
# @TEST-EXEC: assert-rows dce_rpc.log eq 1 id.orig_h=10.0.0.210 endpoint=drsuapi operation=DRSGetNCChanges
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DCSync src=10.0.0.210 dst=10.0.0.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCSync src=10.0.0.11
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCSync src=10.0.0.12
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCSync src=10.0.0.211
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DCSync src=10.0.0.212
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::DCSync src=10.0.0.210 operation=drsuapi_DRSGetNCChanges
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.DcSync attacker=10.0.0.210
# @TEST-EXEC: assert-evidence-join NSM::DCSync

redef NSM::dcsync_domain_controllers += { 10.0.0.12 };
redef NSM::dcsync_allowlist += { 10.0.0.212/32 };
redef NSM::keep_log_streams += { DCE_RPC::LOG };
