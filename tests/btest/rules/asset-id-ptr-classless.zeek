# @TEST-DOC: 자산 식별 PTR — 정규 역방향 이름(5.0.0.10.in-addr.arpa)은 dns_name 신호, RFC 2317 클래스 없는 위임 이름(71.64/27.37.40.113.in-addr.arpa)은 reporter 오류 없이 무시(CIC-IDS2017 Monday pcap 에서 발견)
# @TEST-EXEC: zeek -C -r $TRACES/ptr_classless.pcap $PKG $SETUP %INPUT 2> zeek-stderr.txt
# @TEST-EXEC: ! grep -qi "bad PTR" zeek-stderr.txt
# @TEST-EXEC: assert-rows asset_signal.log eq 1 signal=dns_name ip=10.0.0.5 value=pc05.corp.example
# @TEST-EXEC: assert-rows asset_signal.log eq 0 value=mail.example-isp.net
