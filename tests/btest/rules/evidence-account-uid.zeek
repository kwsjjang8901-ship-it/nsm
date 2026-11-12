# @TEST-DOC: 확산 근거의 계정·대표 uid — NTLM 로그인 후 관리 공유(.60, 같은 대상 NTLM 계정), HTTP 티켓 후 WinRM(.61), cifs 티켓 후 관리 공유(.62), 인증 없이 관리 공유(.63, 계정 없음). 모든 근거 행에 연결 uid
# @TEST-EXEC: zeek -C -r $TRACES/lateral_auth.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::SMB_Admin_Share src=10.0.0.60 account=corp\\admin01
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::WinRM_Lateral src=10.0.0.61 account=opsadmin@corp.example
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::SMB_Admin_Share src=10.0.0.62 account=backupop@corp.example
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::SMB_Admin_Share src=10.0.0.63 account=-
# 근거 행마다 대표 연결 uid 가 있고, 그 uid 는 확산 연결(관리 공유·WinRM)이다
# @TEST-EXEC: assert-rows evidence.log eq 9 operation=smb_tree_connect
# @TEST-EXEC: assert-rows evidence.log eq 3 operation=winrm_connect
# @TEST-EXEC: assert-rows evidence.log eq 0 uid=-
# @TEST-EXEC: python3 -c "import json;u={json.loads(l)['uid'] for l in open('evidence.log')};c={json.loads(l)['uid']:json.loads(l)['id.resp_p'] for l in open('conn.log')};assert all(c.get(x) in (445,5985) for x in u),u"
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 diagnosis=NSM.LateralMovement.SmbAccess
