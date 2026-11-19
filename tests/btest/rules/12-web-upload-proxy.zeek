# @TEST-DOC: 10·12·14 명시적 프록시(10.0.40.5:3128) 경유 유출과 12 클라우드 서비스 1시간 누적. Dropbox 30MB×2(.10) 12만, S3 60MB(.11) 10·12·14, 일반 사이트 60MB(.12) 10·14, Dropbox 20MB×2(.13) 미탐, 프록시 없이 Dropbox 20MB×3(.14) 12, 첫 요청 못 본 프록시 연결 60MB(.15) 10·14, 내부 일반 서버 60MB(.16) 미탐, 프록시 자신의 외부 전송 미탐
# @TEST-EXEC: zeek -C -r $TRACES/exfil_proxy.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.40.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Large_Transfer src=10.0.40.10
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate src=10.0.40.10
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.40.11
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.40.11
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.40.11
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.40.12
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.40.12
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.40.12
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.40.13
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.40.14
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Large_Transfer src=10.0.40.15
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.40.15
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Volume_Aggregate src=10.0.40.15
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.40.16
# @TEST-EXEC: assert-rows notice.log eq 0 src=10.0.40.5
# 근거에 실제 목적지(host=)와 프록시(via_proxy=)가 남는다. 누적 탐지는 연결마다 근거 1행
# @TEST-EXEC: assert-rows evidence.log eq 2 note=NSM::Exfil_Web_Upload src=10.0.40.10
# @TEST-EXEC: log-cut note src detail < evidence.log | awk -F'\t' '$1=="NSM::Exfil_Large_Transfer" && $2=="10.0.40.11" && $3 ~ /host=nsm-test\.s3\.ap-northeast-2\.amazonaws\.com/ && $3 ~ /via_proxy=10\.0\.40\.5:3128/ {n++} END {exit !(n==1)}'
# @TEST-EXEC: log-cut note src detail < evidence.log | awk -F'\t' '$1=="NSM::Exfil_Web_Upload" && $2=="10.0.40.14" && $3 !~ /via_proxy/ {n++} END {exit !(n==3)}'
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.WebUpload attacker=10.0.40.10
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Web_Upload
# @TEST-EXEC: assert-evidence-join NSM::Exfil_Large_Transfer
