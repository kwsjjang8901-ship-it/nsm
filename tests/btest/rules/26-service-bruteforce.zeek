# @TEST-DOC: 26 SSH·FTP 무차별 대입 — 같은 서버로 SSH 인증 실패 25회(.132, 임계 20)·FTP 530 12회·계정 3개(.130, 임계 10) 탐지 / SSH 5회(.133)·FTP 3회 실패 뒤 성공(.131) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/bruteforce.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::SSH_Bruteforce src=10.0.0.132 dst=10.0.60.22
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SSH_Bruteforce src=10.0.0.133
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::FTP_Bruteforce src=10.0.0.130 dst=10.0.60.21
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::FTP_Bruteforce src=10.0.0.131
# 근거: SSH 는 실패 연결 표본(uid·클라이언트 배너), FTP 는 시도한 계정별 1건
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::SSH_Bruteforce operation=ssh_auth_not_successful
# @TEST-EXEC: assert-rows evidence.log eq 3 note=NSM::FTP_Bruteforce operation=ftp_login_failure
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::FTP_Bruteforce account=root
# @TEST-EXEC: assert-rows evidence.log eq 0 note=NSM::SSH_Bruteforce uid=-
# @TEST-EXEC: grep -q 'failures=25 window' evidence.log && grep -q 'failures=12 unique_users=3' evidence.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.SshBruteforce
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.FtpBruteforce
# @TEST-EXEC: assert-evidence-join NSM::SSH_Bruteforce
# @TEST-EXEC: assert-evidence-join NSM::FTP_Bruteforce
