# @TEST-DOC: 통합 리포트 장비 유형 — 기기 형태 힌트로 스마트폰·태블릿·모바일, Apple 연결 확인은 PC 또는 모바일(Apple), Windows 브라우저는 PC, 기본 컴퓨터 이름·기기 모델로 노트북(LAPTOP-·MacBook)·데스크톱(DESKTOP-), Windows Server OS 는 서버, OS 를 모르는 웹 응답 서버는 서버(추정)
# @TEST-EXEC: zeek -C -r $TRACES/asset_device_class.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
want = {"10.0.58.10": "모바일(스마트폰)", "10.0.58.11": "모바일(태블릿)", "10.0.58.12": "모바일(스마트폰)",
        "10.0.58.13": "모바일(태블릿)", "10.0.58.14": "모바일", "10.0.58.15": "PC 또는 모바일(Apple)",
        "10.0.58.16": "PC", "10.0.58.20": "PC(노트북)", "10.0.58.21": "PC(데스크톱)", "10.0.58.22": "PC(노트북)",
        "10.0.58.30": "서버", "10.0.58.2": "서버(추정)"}
got = {ip: a[ip].get("dev_class") for ip in want}
assert got == want, {ip: (got[ip], want[ip], a[ip].get("dev_basis")) for ip in want if got[ip] != want[ip]}
assert a["10.0.58.2"]["dev_conf"] == "낮음" and a["10.0.58.10"]["dev_conf"] == "높음", (a["10.0.58.2"], a["10.0.58.10"])
print("ok")
# @TEST-END-FILE
