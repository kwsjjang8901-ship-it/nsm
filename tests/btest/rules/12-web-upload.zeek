# @TEST-DOC: 12 클라우드 업로드 유출 — SNI uploads.dropboxapi.com 60MB(10.0.0.84) 탐지, 일반 사이트 60MB(10.0.0.85) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/exfil.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.0.84
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.0.85
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.0.80
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.WebUpload attacker=10.0.0.84
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Web_Upload
