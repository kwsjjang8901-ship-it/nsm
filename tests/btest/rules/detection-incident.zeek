# @TEST-DOC: 탐지 요약 사건 묶기 — 약 16분 이어진 SSH 무차별 대입(.134)은 5분 창마다 탐지가 나오지만 같은 사건 id 로 묶이고(occurrence 1,2,3, first_seen 은 사건 시작), 40분 쉰 뒤의 공격은 새 사건(occurrence 1)
# @TEST-EXEC: zeek -C -r $TRACES/bruteforce_long.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows nsm_detection.log eq 4 diagnosis=NSM.CredentialAccess.SshBruteforce attacker=10.0.0.134
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.CredentialAccess.SshBruteforce occurrence=1
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.SshBruteforce occurrence=2
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.CredentialAccess.SshBruteforce occurrence=3
# 사건 id 는 2개(첫 공격 3건이 하나, 두 번째 공격이 하나)
# @TEST-EXEC: test "$(log-cut incident_id < nsm_detection.log | sort -u | wc -l)" -eq 2
# 갱신 탐지의 first_seen 은 사건의 첫 탐지 시각
# @TEST-EXEC: test "$(log-cut incident_id first_seen < nsm_detection.log | sort -u | wc -l)" -eq 2
