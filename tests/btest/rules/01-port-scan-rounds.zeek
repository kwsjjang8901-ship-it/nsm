# @TEST-DOC: 01·02 스캔 회차 — 같은 스캐너가 같은 대상을 20분 간격으로 다시 스캔하면 회차마다 탐지한다(.90 -> .91 포트 스캔 3회, .92 445 스윕 2회). 임계만 쓰는 SumStats 는 standalone 에서 epoch_result 가 없으면 epoch 가 끝나지 않아 첫 회차만 탐지했다(CIC-IDS2017 Friday nmap 후속 회차 미탐 재현)
# @TEST-EXEC: zeek -C -r $TRACES/scan_rounds.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 3 note=NSM::Port_Scan src=10.0.2.90
# @TEST-EXEC: assert-rows notice.log eq 2 note=NSM::Host_Scan src=10.0.2.92
