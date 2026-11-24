#!/usr/bin/env python3
"""S5 측정 요약: run_pcap.sh -S 결과 디렉터리에서 Suricata 경보를 카테고리·단계별로 세고 Zeek 탐지와의 겹침을 잰다.

  python3 tests/suricata/measure.py <run_pcap.sh 출력 디렉터리> [...]   (일괄 모드 출력이면 그 아래 pcap 별 디렉터리를 모두 읽음)

출력은 숫자와 공개 값(ET 카테고리, SID, Zeek 탐지 종류)만이다. 주소·호스트명·시그니처 문장·도메인은 출력하지 않으므로
결과를 그대로 공유해도 된다. 근거: docs/SURICATA_INTEGRATION_DESIGN.md 6.1절(카테고리 기본값)·7장 S5.

  카테고리   : 시그니처 이름 앞부분(ET <카테고리>, SURICATA = Suricata 기본 이벤트 룰, 그 밖은 사내·기타)
  겹침       : 목업형 리포트에서 같은 연결·같은 단계의 Zeek 탐지와 한 탐지로 묶인 시그니처 탐지(mergedInto)
  전송량     : suricata/eve-alert.json 크기(센서 경보 파일과 같은 필드) = suricata_alert 스트림 원문 크기의 근사
"""
import collections
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import suricata_alerts as sa  # noqa: E402

STAGE_KO = {"Recon": "정찰", "Initial Access": "초기 침투", "Command and Control": "외부 연락", "Credential Access": "계정 탈취",
            "Lateral Movement": "내부 확산", "Exfiltration": "정보 유출", "Impact": "피해", "": "단계 없음"}


def category(msg):
    w = (msg or "").split()
    if len(w) >= 2 and w[0] == "ET":
        return "ET " + w[1]
    if w and w[0] == "SURICATA":
        return "SURICATA(기본 이벤트)"
    return "사내·기타"


def runs(paths):
    out = []
    for p in paths:
        if os.path.isfile(os.path.join(p, "suricata", "eve-alert.json")):
            out.append(p)
        else:
            out.extend(sorted(os.path.dirname(os.path.dirname(f)) for f in glob.glob(os.path.join(p, "*", "suricata", "eve-alert.json"))))
    return out


def mockup_ev(d):
    f = next(iter(glob.glob(os.path.join(d, "*_report_mockup.html"))), None)
    if not f:
        return []
    m = re.search(r'id="report-data">(\{.*?)</script>', open(f, encoding="utf-8").read(), re.S)
    return json.loads(m.group(1).replace("<\\/", "</"))["ev"] if m else []


def main(argv):
    dirs = runs(argv)
    if not dirs:
        print("suricata/eve-alert.json 이 있는 run_pcap.sh -S 출력이 없습니다", file=sys.stderr)
        return 2
    tot = collections.Counter()
    cat_alerts, cat_events, cat_merged = collections.Counter(), collections.Counter(), collections.Counter()
    stage_alerts, sid_alerts, merged_with = collections.Counter(), collections.Counter(), collections.Counter()
    rows = []
    for d in dirs:
        eve = os.path.join(d, "suricata", "eve-alert.json")
        al = sa.load([eve])
        ev = mockup_ev(d)
        by_id = {e["id"]: e for e in ev}
        sig = [e for e in ev if e.get("eng") == "Suricata"]
        merged = [e for e in sig if e.get("mergedInto")]
        zeek = [e for e in ev if not e.get("eng") and not e.get("corr")]
        for a in al:
            c = category(a["alert"].get("signature"))
            cat_alerts[c] += 1
            stage_alerts[sa.stage_of(a)[0]] += 1
            sid_alerts[a["alert"].get("signature_id")] += 1
        for e in sig:
            c = category(e.get("name"))
            cat_events[c] += 1
            if e.get("mergedInto"):
                cat_merged[c] += 1
                merged_with[by_id[e["mergedInto"]]["note"]] += 1
        b = os.path.getsize(eve)
        r = {"pcap": os.path.basename(os.path.normpath(d)), "alerts": len(al), "events": len(sig), "merged": len(merged),
             "zeek": len(zeek), "zeek_with_sig": sum(1 for e in zeek if e.get("also")), "bytes": b}
        rows.append(r)
        for k in ("alerts", "events", "merged", "zeek", "zeek_with_sig", "bytes"):
            tot[k] += r[k]

    pct = lambda a, b: f"{100 * a / b:.1f}%" if b else "-"
    print(f"## Suricata 측정 요약 (pcap {len(rows)}개)\n")
    print("| pcap | 경보 | 시그니처 탐지 | Zeek 와 겹침 | Zeek 단독 탐지 | 그중 시그니처도 | 경보 파일 |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in rows + [dict(tot, pcap="합계")]:
        print(f"| {r['pcap']} | {r['alerts']:,} | {r['events']:,} | {r['merged']:,} ({pct(r['merged'], r['events'])}) | {r['zeek']:,} | "
              f"{r['zeek_with_sig']:,} ({pct(r['zeek_with_sig'], r['zeek'])}) | {r['bytes'] / 1e6:,.2f} MB |")
    print("\n### 카테고리별 (6.1절 기본값 확인)\n")
    print("| 카테고리 | 경보 | 시그니처 탐지 | Zeek 와 겹침 |")
    print("| --- | ---: | ---: | ---: |")
    for c, n in cat_alerts.most_common():
        print(f"| {c} | {n:,} | {cat_events[c]:,} | {cat_merged[c]:,} ({pct(cat_merged[c], cat_events[c])}) |")
    print("\n### 공격 단계별 경보\n")
    print(" · ".join(f"{STAGE_KO[k]} {v:,}" for k, v in stage_alerts.most_common()))
    print("\n### 겹친 Zeek 탐지 종류\n")
    print(" · ".join(f"{k} {v:,}" for k, v in merged_with.most_common()) or "(없음)")
    print("\n### 경보가 많은 SID 상위 20\n")
    print(" · ".join(f"{k} {v:,}" for k, v in sid_alerts.most_common(20)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
