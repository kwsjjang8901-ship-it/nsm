# @TEST-DOC: 28 XSS — URI 의 <script>(.150)·POST 본문의 onerror 핸들러(.151) 탐지 / 굵은 글씨 태그 + alert( 단어(.152)·서식 있는 글(.153)·외부 사이트로 보낸 요청(.154) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/web_xss_bf.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Cross_Site_Scripting src=10.0.0.150 dst=10.0.10.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Cross_Site_Scripting src=10.0.0.151 dst=10.0.10.80
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Cross_Site_Scripting src=10.0.0.152
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Cross_Site_Scripting src=10.0.0.153
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Cross_Site_Scripting src=10.0.0.154
# 로그인 무차별 대입 요청들에는 XSS 가 없다
# @TEST-EXEC: assert-rows notice.log eq 2 note=NSM::Cross_Site_Scripting
# @TEST-EXEC: assert-rows evidence.log eq 1 note=NSM::Cross_Site_Scripting src=10.0.0.150 operation=http_request
# @TEST-EXEC: grep -q 'location=body method=POST' evidence.log
# @TEST-EXEC: assert-rows nsm_detection.log eq 2 diagnosis=NSM.WebAttack.Xss
# @TEST-EXEC: assert-evidence-join NSM::Cross_Site_Scripting
