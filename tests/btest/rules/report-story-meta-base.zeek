# @TEST-DOC: 통합 리포트 공격 스토리 관측의 평소 통신 제외 — 비콘 host .10 의 내부 접속 중 비콘 전부터 하던 .31 SSH 와 스토리 밖 3대도 하는 .30 SSH 는 빼고(건수만), 처음 보는 .32 ADMIN$ 와 원격 실행류인 .33 svcctl 은 남긴다. C2 에 내부 host 다수가 붙으면 관측만 host 는 수만 세고, 내부 리졸버 .53 은 같은 인프라 목록에서 뺀다
# @TEST-EXEC: zeek -C -r $TRACES/story_meta_base.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
s = next(x for x in d["stories"] if x["seed"] == "10.0.8.10")
obs = {(o["a"], o["b"]): o for o in s["observed"]}
assert set(obs) == {("10.0.8.10", "10.0.8.32"), ("10.0.8.10", "10.0.8.33")}, list(obs)
assert any("ADMIN$" in w for w in obs[("10.0.8.10", "10.0.8.32")]["what"]), obs
assert obs[("10.0.8.10", "10.0.8.33")]["what"] == ["RPC svcctl::OpenSCManagerW"], obs
assert s["observed_skip"] == {"prior": 1, "common": 1}, s["observed_skip"]
inf = {x["key"]: x for x in s["infra"]}
c2 = inf["cdn.patch-sync.net"]
assert c2["popular"] and c2["total"] == 5 and c2["omitted"] == 4, c2
assert [h["who"]["ip"] for h in c2["hosts"]] == ["10.0.8.10"], c2
assert not any(h["who"]["ip"] == "10.0.8.53" for x in s["infra"] for h in x["hosts"]), s["infra"]
print("ok")
# @TEST-END-FILE
