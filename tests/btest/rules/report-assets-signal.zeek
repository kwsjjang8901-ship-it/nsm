# @TEST-DOC: 통합 리포트 자산 표(리졸버 없는 자산 신호 모드) — MAC·OS 힌트·응답한 서비스를 신호 값 그대로 보이고, IPv4 2개가 같은 MAC 이면 공유로만 표시한다(라우터 추정은 3개 이상)
# @TEST-EXEC: zeek -C -r $TRACES/report_assets.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
assert d["asset_mode"] == "signals", d["asset_mode"]
a = {r["ips"][0]: r for r in d["assets"]}
pc = a["10.0.11.10"]
assert pc["macs"] == ["02:00:0a:00:0b:0a"], pc
assert pc["os"].startswith("windows"), pc
assert "tcp/445" in a["10.0.11.20"]["services"], a["10.0.11.20"]
# IPv4 2개만 같은 MAC 이면 공유로만(라우터로 단정하지 않음), 라우팅 뒤 구간 요약도 없음
for ip in ("10.0.11.1", "10.0.12.5"):
    assert a[ip]["macs"] == ["02:00:0a:00:0b:01 (IPv4 2개 공유)"], a[ip]
assert d["mac_summary"] is None, d["mac_summary"]
assert a["10.0.11.1"]["services"] == ["tcp/22"], a["10.0.11.1"]
print("ok")
# @TEST-END-FILE
