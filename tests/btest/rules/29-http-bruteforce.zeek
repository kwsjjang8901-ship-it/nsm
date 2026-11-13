# @TEST-DOC: 29 웹 로그인 무차별 대입 — GET 로그인 비밀번호 30가지(.160)·JSON 로그인 25가지(.162)·Basic 인증 401 25회(.163) 탐지 / 같은 비밀번호 30회(.161)·NTLM 챌린지 401(.164)·10가지(.165, 임계 미만) 미탐. 비밀번호 값은 어디에도 남기지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/web_xss_bf.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Bruteforce src=10.0.0.160 dst=10.0.10.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Bruteforce src=10.0.0.162
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::HTTP_Bruteforce src=10.0.0.163
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::HTTP_Bruteforce src=10.0.0.161
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::HTTP_Bruteforce src=10.0.0.164
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::HTTP_Bruteforce src=10.0.0.165
# 근거: 폼은 계정(사용자명 파라미터)·경로·고유 비밀번호 수, Basic 은 사용자명
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::HTTP_Bruteforce src=10.0.0.160 account=admin operation=http_login_password_variation
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::HTTP_Bruteforce src=10.0.0.162 account=bob
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::HTTP_Bruteforce src=10.0.0.163 operation=http_basic_auth_failure
# @TEST-EXEC: grep -q 'unique_passwords=30 unique_users=1 path=/dvwa/vulnerabilities/brute/' evidence.log
# @TEST-EXEC: ! grep -q 'guess0\|p00[0-9]\|pw0[0-9]\|Secret1' evidence.log notice.log nsm_detection.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 3 diagnosis=NSM.CredentialAccess.HttpBruteforce
# @TEST-EXEC: assert-evidence-join NSM::HTTP_Bruteforce
