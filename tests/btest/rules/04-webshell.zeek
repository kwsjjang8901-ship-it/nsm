# @TEST-DOC: 04 웹쉘 — shell.php?cmd=whoami(.125)·POST China Chopper 페이로드(.127) 탐지, 정상 파라미터 cmd=refresh(.126)·index.php(.128)·shell.js(.129)·SQLi 요청은 웹쉘 미탐
# @TEST-EXEC: zeek -C -r $TRACES/web_attack.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Webshell_Access src=10.0.0.125 dst=10.0.10.80
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Webshell_Access src=10.0.0.127
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Webshell_Access src=10.0.0.126
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Webshell_Access src=10.0.0.128
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Webshell_Access src=10.0.0.129
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Webshell_Access src=10.0.0.120
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.WebAttack.Webshell attacker=10.0.0.125
# @TEST-EXEC: assert-evidence-join NSM::Webshell_Access
