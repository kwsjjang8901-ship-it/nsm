# @TEST-DOC: 통합 리포트 공격 스토리의 메타데이터 관측 — 비콘(.10)과 같은 C2(cdn.update-check.net)에 3회만 접속한 .11 을 "같은 인프라·관측만"으로, WinRM 확산 뒤 .10 -> .24 ADMIN$(확산 임계 미만)과 확산 대상 .21 -> .25 svcctl 조회를 "탐지 밖 내부 이동"으로 붙인다. 흔한 사이트(.12·.13)는 붙지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/story_meta.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
s = next(x for x in d["stories"] if x["seed"] == "10.0.7.10")
infra = {x["key"]: {h["who"]["ip"]: h["status"] for h in x["hosts"]} for x in s["infra"]}
assert infra.get("cdn.update-check.net") == {"10.0.7.10": "story", "10.0.7.11": "obs"}, infra
assert not any("10.0.7.12" in v or "10.0.7.13" in v for v in infra.values()), infra
obs = {(o["a"], o["b"]): o for o in s["observed"]}
assert set(obs) == {("10.0.7.10", "10.0.7.24"), ("10.0.7.21", "10.0.7.25")}, list(obs)
assert any("ADMIN$" in w for w in obs[("10.0.7.10", "10.0.7.24")]["what"]), obs
assert obs[("10.0.7.21", "10.0.7.25")]["what"] == ["RPC svcctl::OpenSCManagerW"], obs
# 탐지로 이미 이어진 확산(.10 -> .21~.23)은 관측으로 다시 내지 않는다
assert not any(a == "10.0.7.10" and b in ("10.0.7.21", "10.0.7.22", "10.0.7.23") for a, b in obs)
print("ok")
# @TEST-END-FILE
