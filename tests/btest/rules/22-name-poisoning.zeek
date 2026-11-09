# @TEST-DOC: 22 LLMNR/NBT-NS/mDNS 포이즈닝 — LLMNR 3개·NBNS 3개 이름에 응답한 Responder(.190) 탐지, 자기 이름만 응답하는 mDNS 프린터(.191)·LLMNR host(.192)·WINS 예외(.193) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/name_poisoning.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Name_Poisoning src=10.0.0.190
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Name_Poisoning src=10.0.0.191
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Name_Poisoning src=10.0.0.192
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Name_Poisoning src=10.0.0.193
# 근거: 임계(5) 시점까지 LLMNR 3개(질의 host 각각) + NBNS 2개
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::Name_Poisoning src=10.0.0.190 operation=llmnr_poisoned_response
# @TEST-EXEC: assert-rows evidence.log eq 2 note=NSM::Name_Poisoning src=10.0.0.190 operation=nbns_poisoned_response dst=10.0.0.204
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Name_Poisoning src=10.0.0.190 dst=10.0.0.203 operation=llmnr_poisoned_response
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.NamePoisoning attacker=10.0.0.190
# @TEST-EXEC: assert-evidence-join NSM::Name_Poisoning

redef NSM::poisoning_allowlist += { 10.0.0.193/32 };
