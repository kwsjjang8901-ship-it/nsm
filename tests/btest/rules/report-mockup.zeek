# @TEST-DOC: 목업형 리포트 — report_pcap.py 가 기존 리포트와 함께 ui/mockup/mdsm_nsm_mockup.html 을 템플릿으로 같은 데이터를 목업 화면용으로 넣은 *_mockup.html 을 만든다. 7단계 공격(killchain_story): 탐지 행 id 는 시각순 NSM-00001…, 상관 탐지는 공격자별로 가장 긴(같으면 마지막) 체인 1건(6단계, 피해까지), 스토리 1개(단계·이벤트 id 연결), 대상이 없는 비콘은 근거의 목적지, 내부 주소 목록. 프록시 경유(proxy_c2): 대상은 프록시, 실제 목적지(host)와 via. --no-mockup 이면 만들지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o kc.html --pcap killchain_story.pcap > out.txt
# @TEST-EXEC: test -s kc.html && test -s kc_mockup.html && grep -q '목업형 리포트: kc_mockup.html' out.txt
# @TEST-EXEC: python3 check.py kc_mockup.html kc
# @TEST-EXEC: mkdir px && cd px && zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP && python3 $PKG/../tests/report_pcap.py . -o px.html > /dev/null && python3 ../check.py px_mockup.html px
# @TEST-EXEC: mkdir no && cd no && zeek -C -r $TRACES/proxy_c2.pcap $PKG $SETUP && python3 $PKG/../tests/report_pcap.py . -o no.html --no-mockup > /dev/null && test -s no.html && test ! -e no_mockup.html

# @TEST-START-FILE check.py
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
# 목업 템플릿 그대로 + 데이터 블록 하나
assert page.count('id="report-data">{') == 1 and "function applyReport(D)" in page and "MDS Manager" in page
d = json.loads(re.search(r'id="report-data">(\{.*?)</script>', page, re.S).group(1).replace("<\\/", "</"))
ev = d["ev"]
assert [e["id"] for e in ev] == [f"NSM-{i:05d}" for i in range(1, len(ev) + 1)], [e["id"] for e in ev]
assert all(e["prod"] == "NSM" and e["t"] and e["d"] for e in ev)
if sys.argv[2] == "kc":
    corr = [e for e in ev if e.get("corr")]
    assert len(corr) == 1 and len(corr[0]["stages"]) == 6 and corr[0]["stages"][-1] == "Impact" and corr[0]["src"] == "172.16.0.66", corr
    notes = {e["note"] for e in ev if not e.get("corr")}
    assert {"Port_Scan", "SQL_Injection", "Webshell_Access", "HTTP_Beaconing", "Kerberoasting", "SMB_Admin_Share", "SMB_Ransomware"} <= notes, notes
    beacon = next(e for e in ev if e["note"] == "HTTP_Beaconing")
    assert beacon["dst"] not in ("-", "(대상 여러 곳)"), beacon
    st = d["stories"]
    assert len(st) == 1 and st[0]["seed"] == "172.16.0.66" and len(st[0]["steps"]) >= 7, st
    ids = {e["id"] for e in ev}
    assert all(x[8] in ids and x[1][0] for x in st[0]["steps"]), st[0]["steps"]
    assert "10.0.10.81" in d["internal"] and "93.184.215.140" not in d["internal"]
    assert any(a["ip"] == "10.0.10.81" for a in d["assets"]) and "10.0.10.81" in d["devx"]
else:
    up = next(e for e in ev if e["note"] == "AI_Service_Upload")
    assert up["dst"] == "10.0.60.5" and up["host"] == "api.openai.com" and up["via"].startswith("10.0.60.5:"), up
    assert "10.0.60.5" not in d["internal"], "프록시는 중계 장비(외부처럼)"
assert d["sensors"] and d["sent"] and d["banner"].startswith("PoC 리포트")
# @TEST-END-FILE
