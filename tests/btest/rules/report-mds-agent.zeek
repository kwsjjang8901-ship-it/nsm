# @TEST-DOC: 통합 리포트 자산 표(자산 신호 모드)의 보안 제품 — AhnLab MDS Agent 로 판단된 단말(MDS 장비 에이전트 포트 2개 연결)에 ahnlab:mds-agent 를, 장비에 device 신호를 보인다
# @TEST-EXEC: zeek -C -r $TRACES/mds_agent.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
assert a["10.0.30.10"]["agents"] == ["ahnlab:mds-agent"], a["10.0.30.10"]
for ip in ("10.0.30.11", "10.0.30.12", "10.0.30.13"):
    assert not a.get(ip, {}).get("agents"), a.get(ip)
assert dict(d["signal_counts"]).get("security_agent") == 1, d["signal_counts"]
assert a["10.0.30.5"]["devices"] == ["ahnlab-mds"], a["10.0.30.5"]
print("ok")
# @TEST-END-FILE
