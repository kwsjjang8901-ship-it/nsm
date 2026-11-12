# @TEST-DOC: 21 랜섬웨어성 SMB — 40개 파일 .lockd 확장자 변경+랜섬 노트(.180)·랜섬 노트 6개 폴더(.184) 탐지, 확장자 유지 rename(.181)·Office 저장 임시 파일(.182)·백업 서버 예외(.183)·일반 readme.txt(.185) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/smb_ransomware.pcap $PKG $SETUP %INPUT
#
# Zeek 가 합성 SMB2 이름 변경을 해석했는지(smb_files.log)
# @TEST-EXEC: assert-rows smb_files.log eq 40 id.orig_h=10.0.0.180 action=SMB::FILE_RENAME
#
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Ransomware src=10.0.0.180
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SMB_Ransomware src=10.0.0.184
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Ransomware src=10.0.0.181
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Ransomware src=10.0.0.182
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Ransomware src=10.0.0.183
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SMB_Ransomware src=10.0.0.185
# 근거: .180 은 임계(30) 시점 표본(최대 20, 무작위 표본), .184 는 노트 5개 폴더
# @TEST-EXEC: assert-rows evidence.log ge 10 note=NSM::SMB_Ransomware src=10.0.0.180 dst=10.0.0.6 operation=smb_rename_extension_change
# @TEST-EXEC: assert-rows evidence.log eq 5 note=NSM::SMB_Ransomware src=10.0.0.184 operation=smb_ransom_note_create
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Impact.SmbRansomware attacker=10.0.0.180
# @TEST-EXEC: assert-evidence-join NSM::SMB_Ransomware
# 근거 행마다 대표 연결 uid(집계형 근거와 원본 연결 조인)
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::SMB_Ransomware uid=-

redef NSM::ransomware_allowlist += { 10.0.0.183/32 };
redef NSM::keep_log_streams += { SMB::FILES_LOG };
