# @TEST-DOC: 탐지 정보 보강(docs/DETECTION_ENRICH_SPEC.md) — 룰별 코드 없이 조회 4개·로그별 요약기·판단 4개로 탐지 상세의 한눈에 보기·핵심 사실·기록 표를 만든다. 7단계 공격(killchain_story): Kerberoasting 은 근거 uid 와 같은 kerberos 행(정확), RC4 티켓·성공 6, 계정 맥락, 성공 흔적은 kerberos 로만. 랜섬웨어는 이름 변경 파일·공유. HTTP 비콘은 User-Agent 요약. 기존 리포트 HTML 에는 기록 표를 넣지 않는다. 규칙 단위 테스트(tests/test_detection_enrich.py): 설정 표 = 룰 48개, 중복 억제 묶음(ssl 24시간), 웹 공격 성공 판단(오류 뒤 2xx), 연결 상태·통신 중, DNS 응답으로 이름, DNS 계열은 도메인으로
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o kc.html --pcap killchain_story.pcap > /dev/null
# @TEST-EXEC: python3 check.py kc_mockup.html kc.html
# @TEST-EXEC: python3 $PKG/../tests/test_detection_enrich.py 2> unit.txt

# @TEST-START-FILE check.py
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
d = json.loads(re.search(r'id="report-data">(\{.*?)</script>', page, re.S).group(1).replace("<\\/", "</"))
ev = {e["note"]: e for e in d["ev"] if not e.get("corr") and not e.get("eng")}
fact = lambda e, k: next((f[1] for f in e["xf"]["facts"] if f[0] == k), None)

k = ev["Kerberoasting"]
assert k["xf"]["ok"][0] == "hi" and k["xf"]["ok"][1].startswith("kerberos 성공 6"), k["xf"]
assert fact(k, "티켓 암호") == "rc4-hmac 6번" and fact(k, "결과") == "성공 6 · 실패 0", k["xf"]["facts"]
assert k["rec"]["exact"] and all(r[1] == "kerberos" and r[3] for r in k["rec"]["exact"]), k["rec"]
assert k["xf"]["acct"][1] == 1, k["xf"]

r = ev["SMB_Ransomware"]
assert r["xf"]["ok"][0] == "hi" and "rename" in fact(r, "파일 동작") and fact(r, "공유"), r["xf"]
assert any(x[1] == "smb_files" for x in r["rec"]["exact"]), r["rec"]

b = ev["HTTP_Beaconing"]
assert fact(b, "프로그램(User-Agent)") and fact(b, "상태 코드") == "200 × 14", b["xf"]["facts"]
assert len(b["rec"]["exact"]) == 1 and any("User-Agent" in x for x in b["xf"]["limits"]), (b["rec"], b["xf"]["limits"])

# 항목 이름은 요약기의 고정 목록(룰마다 다른 항목이 없다)
LABELS = {"요청 경로", "Host", "상태 코드", "가장 큰 응답", "접속 도메인", "TLS", "JA3", "요청 서비스", "티켓 암호", "결과", "계정", "공유",
          "파일 동작", "파일 예", "원격 호출", "접속 계정 힌트", "인증", "클라이언트", "연결", "연결 상태", "범위", "포트",
          "질의 이름 예", "고유 이름", "응답", "프로그램(User-Agent)"}
used = {f[0] for e in ev.values() if e.get("xf") for f in e["xf"]["facts"]}
assert used <= LABELS, used - LABELS
# 기존 리포트 HTML 에는 기록 표를 넣지 않는다(화면에서 쓰는 것은 핵심 사실)
assert '"records"' not in open(sys.argv[2], encoding="utf-8").read()
# @TEST-END-FILE
