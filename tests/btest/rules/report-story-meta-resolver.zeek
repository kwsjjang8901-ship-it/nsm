# @TEST-DOC: 통합 리포트 같은 인프라의 내부 DNS 서버 제외 — 자산 신호로 DNS 를 제공한 것이 보이는 서버(10.0.0.53)는 조회한 도메인이 적어도(도메인 기준 미달) 이름 조회 기록을 빼고, 그 서버가 C2 에 직접 한 HTTP 접속은 남긴다
# @TEST-EXEC: zeek -C -r $TRACES/story_meta_resolver.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
s = next(x for x in d["stories"] if x["seed"] == "10.0.9.10")
c2 = {x["key"]: x for x in s["infra"]}["cdn.relay-node.net"]
hosts = {h["who"]["ip"]: h for h in c2["hosts"]}
assert set(hosts) == {"10.0.9.10", "10.0.9.11", "10.0.0.53"}, list(hosts)
assert "dns_summary" not in hosts["10.0.0.53"]["logs"] and "http" in hosts["10.0.0.53"]["logs"], hosts["10.0.0.53"]
assert hosts["10.0.9.11"]["status"] == "obs" and not c2["popular"], c2
print("ok")
# @TEST-END-FILE
