# @TEST-DOC: 목업형 리포트의 Suricata 경보(설계 S6) — killchain_story.pcap 을 Suricata 8.0.6 + 테스트 룰(tests/suricata/test.rules)로 돌린 경보 고정본을 --suricata-eve 로 넣는다. 단계(메타데이터·분류·단계 없음), 출발지·대상(응답 방향·target 키워드·C2·유출은 내부가 출발지), 반복 묶기, 같은 연결·같은 단계의 Zeek 탐지와 한 탐지(also·mergedInto), 단계가 다르면 따로, 스토리 host 의 시그니처 탐지는 스토리 단계로, 시그니처 정의·센서 표시. 등급은 리포트 체계(Information). 정규화 규칙 단위 테스트(tests/suricata/test_normalize.py)도 함께 돈다
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o kc.html --pcap killchain_story.pcap --suricata-eve $PKG/../tests/suricata/killchain_story.eve-alert.json > out.txt
# @TEST-EXEC: grep -q '그중 시그니처 7건' out.txt
# @TEST-EXEC: python3 check.py kc_mockup.html
# @TEST-EXEC: python3 $PKG/../tests/suricata/test_normalize.py 2> unit.txt || { cat unit.txt; exit 1; }
# S5 측정 요약(measure.py): 테스트 룰에 ET 형식 이름·메타데이터를 입혀 1차 선별 룰셋(설계 6.3절) 시뮬레이션을 확인
# @TEST-EXEC: mkdir -p m/suricata && cp *.log m/ && cp -r meta m/ && python3 mkeve.py $PKG/../tests/suricata/killchain_story.eve-alert.json m/suricata/eve-alert.json
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py m -o m/kc_report.html --pcap kc --suricata-eve m/suricata/eve-alert.json > /dev/null
# @TEST-EXEC: python3 $PKG/../tests/suricata/measure.py --tz 9 m > measure.md && python3 checkm.py measure.md

# @TEST-START-FILE mkeve.py
import json, sys
M = {9910001: ("ET WEB_SERVER Possible SQL Injection UNION SELECT", {"signature_severity": ["Major"], "confidence": ["High"]}),
     9910002: ("GPL EXPLOIT web server answered", {}),
     9910003: ("ET MALWARE Beacon to update-check", {"signature_severity": ["Major"], "confidence": ["Medium"]}),
     9910004: ("ET POLICY SMB between internal hosts", {"signature_severity": ["Informational"]}),
     9910005: ("SURICATA Kerberos request", {}),
     9910006: ("ET MALWARE Large outbound data", {"signature_severity": ["Critical"], "confidence": ["High"], "performance_impact": ["Significant"]})}
with open(sys.argv[2], "w") as out:
    for line in open(sys.argv[1]):
        e = json.loads(line)
        a = e["alert"]
        name, md = M[a["signature_id"]]
        a["signature"], a["metadata"] = name, dict(a.get("metadata") or {}, **md)
        out.write(json.dumps(e) + "\n")
# @TEST-END-FILE

# @TEST-START-FILE checkm.py
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
# 선별에 남는 것: Major·High 인 ET WEB_SERVER 1개(Zeek SQL_Injection 과 같은 연결)
assert "남는 경보 1건" in t and "SID 1개" in t and "Zeek 에 없는 새 탐지 0건" in t, t
assert re.search(r"\| 9910001 \| ET WEB_SERVER [^|]+\| 초기 침투 \| Major·High \| 1 \| SQL_Injection \|", t), t
# 6.1 기본으로는 켜지지만 빠지는 것과 이유
for sid, why in ((9910002, "메타데이터 없음"), (9910003, "신뢰도 Medium"), (9910006, "성능 Significant")):
    assert re.search(rf"\| {sid} \|.*\| {why} \|", t), (sid, why)
# 메타데이터별 표, 시간대 표시, 공개 이름(ET·GPL·SURICATA)
assert "| Major | Medium | 14 | 1 |" in t and "시각(UTC+9)" in t and "SURICATA Kerberos request" in t
# 주소는 출력하지 않는다
assert not re.search(r"\b(10|172|192)\.\d+\.\d+\.\d+\b", t), "주소가 출력됨"
# @TEST-END-FILE

# @TEST-START-FILE check.py
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
d = json.loads(re.search(r'id="report-data">(\{.*?)</script>', page, re.S).group(1).replace("<\\/", "</"))
ev = d["ev"]
assert [e["id"] for e in ev] == [f"NSM-{i:05d}" for i in range(1, len(ev) + 1)]
by = {e["id"]: e for e in ev}
sig = [e for e in ev if e.get("eng") == "Suricata"]
assert len(sig) == 7 and all(e["prod"] == "NSM" and e["sev"] == "Information" and e["diag"].startswith("NSM.Signature.") for e in sig), sig
one = lambda sid, **kw: [e for e in sig if e["sid"] == sid and all(e.get(k) == v for k, v in kw.items())]

# 초기 침투: SQLi(메타데이터) + 서버 응답(분류, to_client -> 출발지 = 외부 공격자)이 한 탐지, Zeek SQL_Injection 과 같은 연결
ia = one(9910001)
assert len(ia) == 1 and ia[0]["note"] == "Suricata_Initial_Access" and ia[0]["src"] == "172.16.0.66" and ia[0]["dst"] == "10.0.10.81", ia
assert ia[0]["occ"] == 3 and ia[0]["sig"]["by"] == "mitre" and ia[0]["sigSev"] == "High", ia
z = by[ia[0]["mergedInto"]]
assert z["note"] == "SQL_Injection" and ia[0]["id"] in z["also"], z
assert d["sigs"]["9910002"]["by"] == "classtype" and d["sigs"]["9910002"]["cls"] == "web-application-attack"
# C2: 연결마다 경보 14건 -> 한 탐지, 내부가 출발지, Zeek HTTP_Beaconing 과 같은 연결, 목적지 이름은 선별 전송 http 로그에서
c2 = one(9910003)
assert len(c2) == 1 and c2[0]["note"] == "Suricata_C2" and c2[0]["src"] == "10.0.10.81" and c2[0]["occ"] == 14, c2
assert c2[0]["tech"] == "T1071.001" and c2[0]["host"] == "cdn.update-check.net" and by[c2[0]["mergedInto"]]["note"] == "HTTP_Beaconing", c2
# 내부 확산: target 키워드, 대상마다 따로. .31·.32 는 Zeek SMB_Admin_Share 와 같은 연결, .32 -> 10.0.0.6 은 Zeek 랜섬웨어(피해 단계)와 단계가 달라 따로
lat = one(9910004)
assert sorted((e["src"], e["dst"]) for e in lat) == [("10.0.10.81", "10.0.20.31"), ("10.0.10.81", "10.0.20.32"), ("10.0.20.32", "10.0.0.6")], lat
assert all(e["note"] == "Suricata_Lateral" for e in lat)
assert {by[e["mergedInto"]]["note"] for e in lat if e.get("mergedInto")} == {"SMB_Admin_Share"}
alone = [e for e in lat if not e.get("mergedInto")]
assert len(alone) == 1 and alone[0]["dst"] == "10.0.0.6", alone
# 단계 없음·Low: Kerberos 6건 -> 한 탐지, Zeek Kerberoasting(계정 탈취)과 단계가 달라 따로
oth = one(9910005)
assert len(oth) == 1 and oth[0]["note"] == "Suricata_Other" and oth[0]["stage"] == "" and oth[0]["occ"] == 6 and not oth[0].get("mergedInto"), oth
assert oth[0]["sig"]["pri"] == 3 and oth[0]["tech"] == "", oth
# 정보 유출: 내부가 출발지, Zeek Exfil_Large_Transfer 와 같은 연결
ex = one(9910006)
assert len(ex) == 1 and ex[0]["src"] == "10.0.20.31" and by[ex[0]["mergedInto"]]["note"] == "Exfil_Large_Transfer", ex
# 공격 스토리: 따로 있는 시그니처 탐지(단계 없음 포함)는 스토리 단계로, Zeek 과 묶인 것은 넣지 않음
st = d["stories"]
assert len(st) == 1
ids = [x[8] for x in st[0]["steps"]]
assert oth[0]["id"] in ids and alone[0]["id"] in ids and ia[0]["id"] not in ids, ids
assert [x[0] for x in st[0]["steps"]] == list(range(1, len(ids) + 1))
# 시그니처 정의·센서
assert sorted(d["sigs"]) == [str(s) for s in range(9910001, 9910007)], sorted(d["sigs"])
assert d["sensors"][0]["suri"].startswith("경보 27건"), d["sensors"][0]["suri"]
# 근거 줄: 시그니처·단계 근거
assert any(r[0] == "시그니처" and "SID 9910003" in r[1] for r in c2[0]["ev"]) and any(r[0] == "단계 근거" for r in c2[0]["ev"])
# @TEST-END-FILE
