# @TEST-DOC: 12 클라우드 저장 서비스 목록과 등록 도메인 추출 — 일반 AWS API(.5)·일반 Google API(.6)로 1시간에 60MB 를 올려도 12 미탐(클라우드 전체가 아니라 저장 서비스만), S3(.7)·Azure Blob(.8)은 탐지. 공용 접미사 목록에 없는 국가 2단계(com.vn, .20)와 동적 DNS(duckdns.org, .21) 아래 무작위 라벨 NXDOMAIN 은 13 DGA 로 탐지(등록 라벨을 접미사가 아니라 그 아래 라벨로)
# @TEST-EXEC: zeek -C -r $TRACES/domain_fp.pcap $PKG $SETUP
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.81.5
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Web_Upload src=10.0.81.6
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.81.7
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_Web_Upload src=10.0.81.8
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_Volume_Aggregate
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::DGA_Domain src=10.0.81.20
# @TEST-EXEC: assert-rows notice.log ge 1 note=NSM::DGA_Domain src=10.0.81.21
