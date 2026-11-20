# @TEST-DOC: 통합 리포트 — 명시적 프록시를 거친 유출 탐지의 대상(프록시 IP)은 피해 장비가 아니라 중계 장비로 표시한다. CONNECT 를 본 연결(.32 -> 프록시 .22)은 실제 목적지(files.example.net)를, 연결 시작을 못 본 연결(.31 -> 프록시 .5)은 "목적지 확인 안 됨". 프록시는 자산 표의 관련 탐지·같은 인프라 키에서 빠진다
# @TEST-EXEC: zeek -C -r $TRACES/proxy_learn.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
big = {x["attacker"]["ip"]: x for x in d["detections"] if x["diagnosis"] == "NSM.Exfiltration.LargeTransfer"}
v31 = big["10.0.43.31"]["victims"][0]
assert v31["ip"] == "10.0.43.5" and v31["proxy"] is True and v31["ext"] is True and v31["targets"] == [], v31
v32 = big["10.0.43.32"]["victims"][0]
assert v32["ip"] == "10.0.43.22" and v32["proxy"] is True and v32["targets"] == ["files.example.net"], v32
a = {r["ips"][0]: r for r in d["assets"]}
assert a["10.0.43.5"]["detections"] == 0 and a["10.0.43.22"]["detections"] == 0, (a["10.0.43.5"], a["10.0.43.22"])
for s in d["stories"]:
    for ln in s["lanes"]:
        if ln["ip"] in ("10.0.43.5", "10.0.43.22"):
            assert ln.get("proxy") is True, ln
print("ok")
# @TEST-END-FILE
