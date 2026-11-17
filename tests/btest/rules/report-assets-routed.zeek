# @TEST-DOC: 통합 리포트 자산 표(자산 신호 모드)의 라우팅 뒤 구간 — host 12대가 라우터 MAC 하나로 보이면 표 위에 한 번 설명(mac_summary)하고 행은 "(라우터)"로 짧게, IPv4 2개가 나눠 쓰는 MAC(이중화 VIP)은 공유로만, 서버 자기 MAC 은 그대로 보인다
# @TEST-EXEC: zeek -C -r $TRACES/report_assets_routed.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
ms = d["mac_summary"]
assert ms and ms["router_ips"] == 12 and ms["router_macs"] == 1, ms
for i in range(1, 13):
    assert a["10.0.20.%d" % i]["macs"] == ["02:00:0a:00:0e:01 (라우터)"], a["10.0.20.%d" % i]
for ip in ("10.0.14.30", "10.0.14.31"):
    assert a[ip]["macs"] == ["02:00:0a:00:0e:fe (IPv4 2개 공유)"], a[ip]
assert a["10.0.14.20"]["macs"] == ["02:00:0a:00:0e:14"], a["10.0.14.20"]
print("ok")
# @TEST-END-FILE
