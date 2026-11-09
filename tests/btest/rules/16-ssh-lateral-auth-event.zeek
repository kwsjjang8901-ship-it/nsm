# @TEST-DOC: 16 SSH 확산 — 실제 SSH 트래픽(Zeek 공개 trace 발췌)에서 인증 성공 이벤트 경로만으로 관측된다(폴백 끔, 임계 1대)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/ssh_auth_internal.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::SSH_Lateral src=192.168.2.1
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::SSH_Lateral src=192.168.1.31
# 대조: 인증 이벤트 경로도 끄면 관측되지 않는다(위 탐지가 인증 이벤트에서 왔음을 확인)
# 첫 실행 로그가 남아 있으면 notice 가 없는 실행에서도 이전 notice.log 를 읽게 되므로 지우고 실행한다.
# @TEST-EXEC: rm -f *.log && zeek -C -r $TRACES/zeek/ssh_auth_internal.pcap -e "redef NSM::ssh_lm_use_auth_event = F;" $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::SSH_Lateral

# trace 의 내부 SSH 는 src 당 목적지 1대뿐이라 임계를 1대로 낮춘다(경로 검증 목적).
redef NSM::ssh_lm_thresholds = vector(1.0);
redef NSM::ssh_lm_conn_fallback = F;
