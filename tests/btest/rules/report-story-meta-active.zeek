# @TEST-DOC: 통합 리포트 같은 인프라의 흔한 목적지 분모 — 외부 유니캐스트로 접속한 내부 host 6대 중 5대가 붙는 C2 는 흔한 목적지(관측만 host 는 수만). IPv6 링크 로컬 주소 6개가 보내는 SSDP·mDNS 멀티캐스트(ff02::, 흐름 요약에는 경계로 남음)는 분모에 넣지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/story_meta_active.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
s = next(x for x in d["stories"] if x["seed"] == "10.0.10.10")
c2 = {x["key"]: x for x in s["infra"]}["cdn.sync-mirror.net"]
assert c2["total"] == 5 and c2["popular"] and c2["omitted"] == 4, c2
assert [h["who"]["ip"] for h in c2["hosts"]] == ["10.0.10.10"], c2
print("ok")
# @TEST-END-FILE
