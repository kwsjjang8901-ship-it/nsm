#!/usr/bin/env python3
"""S5 측정 요약: run_pcap.sh -S 결과 디렉터리에서 Suricata 경보를 카테고리·단계·룰 메타데이터별로 세고 Zeek 탐지와의 겹침을 잰다.
1차 선별 룰셋(설계 6.3절) 기준을 적용했을 때 남는 탐지와 빠지는 탐지도 보여 준다.

  python3 tests/suricata/measure.py [--tz 시간] <run_pcap.sh 출력 디렉터리> [...]   (일괄 모드 출력이면 그 아래 pcap 별 디렉터리를 모두 읽음)

경보 파일(suricata/eve-alert.json)에 룰 메타데이터가 들어 있어 Suricata 를 다시 돌리지 않고 이 스크립트만 다시 실행하면 된다.

출력은 숫자와 공개 값(ET 카테고리, SID, Zeek 탐지 종류, ET Open·GPL·Suricata 기본 룰의 시그니처 이름)뿐이다. 주소·호스트명·
사내 룰 이름은 출력하지 않으므로 결과를 그대로 공유해도 된다(ET Open 이름에는 공개된 악성 도메인이 들어 있을 수 있음).
근거: docs/SURICATA_INTEGRATION_DESIGN.md 6.1절(카테고리 기본값)·6.3절(1차 선별 룰셋)·7장 S5.

  카테고리   : 시그니처 이름 앞부분(ET <카테고리>, SURICATA = Suricata 기본 이벤트 룰, 그 밖은 사내·기타)
  겹침       : 같은 연결(community_id)·같은 단계·10분 안의 Zeek 단독 탐지와 한 탐지로 묶이는 시그니처 탐지
  전송량     : suricata/eve-alert.json 크기(센서 경보 파일과 같은 필드) = suricata_alert 스트림 원문 크기의 근사
  시각       : --tz 로 준 시간대(기본 UTC). CIC-IDS2017 공격 시간표(현지 ADT)와 맞추려면 --tz -3
"""
import argparse
import collections
import datetime
import glob
import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import suricata_alerts as sa  # noqa: E402

STAGE_KO = {"Recon": "정찰", "Initial Access": "초기 침투", "Command and Control": "외부 연락", "Credential Access": "계정 탈취",
            "Lateral Movement": "내부 확산", "Exfiltration": "정보 유출", "Impact": "피해", "": "단계 없음"}

# 1차 선별 룰셋(설계 6.3절): 카테고리 + 룰 메타데이터. 바꾸면 설계 문서 표도 함께 고친다
CURATED_CATS = {"malware", "exploit", "exploit_kit", "web_server", "web_specific_apps", "current_events", "phishing",
                "coinminer", "worm", "attack_response", "shellcode"}
CURATED_SEV = {"Major", "Critical"}
CURATED_CONF = {"High"}
CURATED_PERF_OUT = {"Significant"}
# 6.1절에서 "켬"인 카테고리(선별에서 빠지는 탐지를 볼 때 비교 기준)
DEFAULT_ON = CURATED_CATS | {"web_client", "mobile_malware", "sql", "smb", "netbios", "rpc"}
MAX_LIST = 40

category = sa.category


def cat_word(msg):
    """'ET WEB_SERVER ...' -> 'web_server', 'GPL EXPLOIT ...' -> 'exploit'. 그 밖은 ''."""
    w = (msg or "").split()
    return w[1].lower() if len(w) >= 2 and w[0] in ("ET", "GPL") else ""


def meta(alert):
    md = alert["alert"].get("metadata")
    one = lambda k: (sa._meta_list(md, k) or ["(없음)"])[0]
    return one("signature_severity"), one("confidence"), one("performance_impact")


def curated(alert):
    """(선별에 드는지, 빠지는 이유)."""
    msg = alert["alert"].get("signature")
    c = cat_word(msg)
    if c not in CURATED_CATS:
        return False, "카테고리"
    sev, conf, perf = meta(alert)
    if sev == "(없음)" and conf == "(없음)":
        return False, "메타데이터 없음"
    if sev not in CURATED_SEV:
        return False, f"심각도 {sev}"
    if conf not in CURATED_CONF:
        return False, f"신뢰도 {conf}"
    if perf in CURATED_PERF_OUT:
        return False, f"성능 {perf}"
    return True, ""


def public_name(msg):
    """ET Open·GPL·Suricata 기본 룰 이름은 공개 문구라 그대로, 사내·기타 룰 이름은 숨긴다."""
    return msg if (msg or "").split()[:1] in (["ET"], ["GPL"], ["SURICATA"]) else "(사내·기타 룰: 이름 숨김)"


def runs(paths):
    out = []
    for p in paths:
        if os.path.isfile(os.path.join(p, "suricata", "eve-alert.json")):
            out.append(p)
        else:
            out.extend(sorted(os.path.dirname(os.path.dirname(f)) for f in glob.glob(os.path.join(p, "*", "suricata", "eve-alert.json"))))
    return out


def mockup(d):
    f = next(iter(glob.glob(os.path.join(d, "*_report_mockup.html"))), None)
    if not f:
        return {}
    m = re.search(r'id="report-data">(\{.*?)</script>', open(f, encoding="utf-8").read(), re.S)
    return json.loads(m.group(1).replace("<\\/", "</")) if m else {}


def _jsonl(path):
    out = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("{"):
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    return out


def zeek_events(d):
    """같은 연결 묶기에 쓰는 Zeek 단독 탐지(nsm_detection + evidence 의 community_id)."""
    cids = collections.defaultdict(set)
    for e in _jsonl(os.path.join(d, "evidence.log")):
        if e.get("community_id"):
            cids[e.get("evidence_id")].add(e["community_id"])
    out = []
    for r in _jsonl(os.path.join(d, "nsm_detection.log")):
        if r.get("category") == "Correlated":
            continue
        eids = r.get("evidence_ids") or [r.get("detection_id")]
        eids = eids if isinstance(eids, list) else str(eids).split(",")
        st = r.get("killchain_stages") or []
        st = st if isinstance(st, list) else str(st).split(",")
        out.append({"note": r.get("rule") or str(r.get("diagnosis", "")).split(".")[-1], "ts": r.get("first_seen") or r.get("ts"),
                    "_stage": (st[0] if st else "").strip(), "_cids": set().union(*[cids.get(x, set()) for x in eids]) if eids else set()})
    return out


def private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--tz", type=float, default=0.0, help="시각 표시 시간대(시간, 기본 0=UTC). CIC-IDS2017 은 -3")
    args = ap.parse_args(argv)
    dirs = runs(args.dirs)
    if not dirs:
        print("suricata/eve-alert.json 이 있는 run_pcap.sh -S 출력이 없습니다", file=sys.stderr)
        return 2
    import report_mockup  # noqa: E402  (같은 연결 묶기 규칙을 리포트와 같게)
    hm = lambda t: (datetime.datetime.fromtimestamp(t, datetime.timezone.utc) + datetime.timedelta(hours=args.tz)).strftime("%m-%d %H:%M") if t else "-"
    tzs = "UTC" if not args.tz else f"UTC{args.tz:+g}"

    tot = collections.Counter()
    cat_alerts, cat_events, cat_merged = collections.Counter(), collections.Counter(), collections.Counter()
    stage_alerts, sid_alerts, merged_with = collections.Counter(), collections.Counter(), collections.Counter()
    sid_name, sid_meta = {}, {}
    md_alerts, md_sids = collections.Counter(), collections.defaultdict(set)
    cur_rows, drop_rows, cur_tot = [], [], collections.Counter()
    rows = []
    for d in dirs:
        eve = os.path.join(d, "suricata", "eve-alert.json")
        mk = mockup(d)
        ev = mk.get("ev") or []
        st = mk.get("sigstats")      # 리포트가 전체 시그니처 탐지로 센 값(화면에는 일부만 있을 수 있음)
        by_id = {e["id"]: e for e in ev}
        sig = [e for e in ev if e.get("eng") == "Suricata"]
        merged = [e for e in sig if e.get("mergedInto")]
        zeek = [e for e in ev if not e.get("eng") and not e.get("corr")]
        n_al = 0
        why = {}                     # SID -> 선별에서 빠진 이유(6.1 기본 켬인 것만)
        for a in sa.iter_alerts([eve]):      # 한 줄씩(경보가 많아도 메모리에 모으지 않음)
            n_al += 1
            msg = a["alert"].get("signature")
            sid = a["alert"].get("signature_id")
            c = category(msg)
            cat_alerts[c] += 1
            stage_alerts[sa.stage_of(a)[0]] += 1
            sid_alerts[sid] += 1
            if sid not in sid_name:
                sid_name[sid] = public_name(msg)
                sid_meta[sid] = meta(a)
            sev, conf, _ = sid_meta[sid]
            md_alerts[(sev, conf)] += 1
            md_sids[(sev, conf)].add(sid)
            if sid not in why:
                ok, reason = curated(a)
                why[sid] = "" if ok else (reason if reason != "카테고리" else "카테고리(6.1 켬, 6.3 밖)") if cat_word(msg) in DEFAULT_ON else None
        if st:
            for c, (ne, nm) in st["by_cat"].items():
                cat_events[c] += ne
                cat_merged[c] += nm
            merged_with.update(st["merged_with"])
            n_ev, n_mg = st["events"], st["merged"]
        else:
            for e in sig:
                c = category(e.get("name"))
                cat_events[c] += 1
                if e.get("mergedInto"):
                    cat_merged[c] += 1
                    merged_with[by_id[e["mergedInto"]]["note"]] += 1
            n_ev, n_mg = len(sig), len(merged)
        # 선별 적용 시뮬레이션: 남는 경보만으로 다시 묶고 Zeek 와의 같은 연결을 다시 잰다.
        #   경보를 모아 두지 않고 파일을 SID 조건으로 다시 흘려 읽는다(경보가 수백만 건이어도 메모리를 쓰지 않음)
        zev = zeek_events(d)
        pcap = os.path.basename(os.path.normpath(d))
        keep_sids = {k for k, v in why.items() if v == ""}
        drop_sids = {k for k, v in why.items() if v}
        for kind, sids, out in (("keep", keep_sids, cur_rows), ("drop", drop_sids, drop_rows)):
            n_items = [0]

            def pick(sids=sids, n_items=n_items):
                for a in sa.iter_alerts([eve]):
                    if a["alert"].get("signature_id") in sids:
                        n_items[0] += 1
                        yield a
            groups = sa.normalize(pick(), d, private) if sids else []
            mt, _ = report_mockup._same_conn_groups(groups, zev)
            for k, g in enumerate(groups):
                sev, conf, _ = sid_meta.get(g["sid"], ("-", "-", "-"))
                out.append({"pcap": pcap, "ts": g["ts"], "sid": g["sid"], "name": sid_name.get(g["sid"], ""), "stage": g["stage"],
                            "sev": sev, "conf": conf, "occ": g["occ"], "zeek": mt[k]["note"] if k in mt else "",
                            "why": why.get(g["sid"], "")})
            if kind == "keep":
                cur_tot["alerts"] += n_items[0]
                cur_tot["events"] += len(groups)
                cur_tot["merged"] += len(mt)
                cur_tot["sids"] += len(sids)
        b = os.path.getsize(eve)
        # run_pcap.sh 의 Suricata 점검 값(적재된 룰·읽은 패킷). 없으면(옛 실행) 모름
        chk = {}
        try:
            with open(os.path.join(d, "suricata", "check.json"), encoding="utf-8") as f:
                chk = json.load(f)
        except (OSError, ValueError):
            pass
        r = {"pcap": pcap, "alerts": n_al, "events": n_ev, "merged": n_mg,
             "zeek": len(zeek), "zeek_with_sig": sum(1 for e in zeek if e.get("also")), "bytes": b,
             "loaded": chk.get("rules_loaded"), "packets": chk.get("packets")}
        rows.append(r)
        for k in ("alerts", "events", "merged", "zeek", "zeek_with_sig", "bytes"):
            tot[k] += r[k]

    pct = lambda a, b: f"{100 * a / b:.1f}%" if b else "-"
    print(f"## Suricata 측정 요약 (pcap {len(rows)}개)\n")
    num = lambda v: "?" if v is None else f"{v:,}"
    print("| pcap | 적재된 룰 | 읽은 패킷 | 경보 | 시그니처 탐지 | Zeek 와 겹침 | Zeek 단독 탐지 | 그중 시그니처도 | 경보 파일 |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in rows + [dict(tot, pcap="합계", loaded=None, packets=None)]:
        print(f"| {r['pcap']} | {num(r.get('loaded')) if r['pcap'] != '합계' else ''} | {num(r.get('packets')) if r['pcap'] != '합계' else ''} | "
              f"{r['alerts']:,} | {r['events']:,} | {r['merged']:,} ({pct(r['merged'], r['events'])}) | {r['zeek']:,} | "
              f"{r['zeek_with_sig']:,} ({pct(r['zeek_with_sig'], r['zeek'])}) | {r['bytes'] / 1e6:,.2f} MB |")
    # 경보 0건은 측정 결과가 아니라 실행 문제일 가능성이 크다: 원인을 표 아래에 적는다
    for r in rows:
        if r["alerts"]:
            continue
        if r.get("loaded") == 0:
            why = "적재된 룰이 0개입니다(룰 받기·ET_URL·룰 문법 확인). 이 결과는 측정에 쓰지 마세요"
        elif r.get("packets") == 0:
            why = "Suricata 가 패킷을 읽지 못했습니다(pcap 경로·형식 확인). 이 결과는 측정에 쓰지 마세요"
        elif r.get("loaded") is None:
            why = "경보가 0건이고 적재된 룰·패킷 수를 모릅니다(옛 실행). suricata/run.log 의 rules successfully loaded·read … packets 를 확인하세요"
        else:
            why = f"룰 {r['loaded']:,}개로 패킷 {r['packets']:,}개를 처리했는데 경보가 0건입니다. HOME_NET·룰 종류가 맞는지 확인하세요"
        print(f"\n> 주의({r['pcap']}): {why}")
    print("\n### 카테고리별 (6.1절 기본값 확인)\n")
    print("| 카테고리 | 경보 | 시그니처 탐지 | Zeek 와 겹침 |")
    print("| --- | ---: | ---: | ---: |")
    for c, n in cat_alerts.most_common():
        print(f"| {c} | {n:,} | {cat_events[c]:,} | {cat_merged[c]:,} ({pct(cat_merged[c], cat_events[c])}) |")
    print("\n### 룰 메타데이터별 경보 (signature_severity × confidence)\n")
    print("| 심각도 | 신뢰도 | 경보 | SID 수 |")
    print("| --- | --- | ---: | ---: |")
    for (sev, conf), n in md_alerts.most_common():
        print(f"| {sev} | {conf} | {n:,} | {len(md_sids[(sev, conf)]):,} |")
    print("\n### 1차 선별 룰셋(6.3절) 적용 시뮬레이션\n")
    print(f"기준: 카테고리 {', '.join(sorted(CURATED_CATS))} · 심각도 {'/'.join(sorted(CURATED_SEV))} · 신뢰도 {'/'.join(CURATED_CONF)} · "
          f"성능 {'/'.join(CURATED_PERF_OUT)} 제외\n")
    print(f"남는 경보 {cur_tot['alerts']:,}건(전체의 {pct(cur_tot['alerts'], tot['alerts'])}) · SID {cur_tot['sids']:,}개 · "
          f"시그니처 탐지 {cur_tot['events']:,}건 · 그중 Zeek 와 겹침 {cur_tot['merged']:,}건 · Zeek 에 없는 새 탐지 {cur_tot['events'] - cur_tot['merged']:,}건\n")

    def table(L, extra):
        if not L:
            print("(없음)\n")
            return
        print(f"| 시각({tzs}) | pcap | SID | 시그니처 | 단계 | 심각도·신뢰도 | 경보 | Zeek 와 겹침 |{' 빠진 이유 |' if extra else ''}")
        print(f"| --- | --- | ---: | --- | --- | --- | ---: | --- |{' --- |' if extra else ''}")
        for x in sorted(L, key=lambda x: x["ts"] or 0)[:MAX_LIST]:
            print(f"| {hm(x['ts'])} | {x['pcap']} | {x['sid']} | {x['name']} | {STAGE_KO.get(x['stage'], x['stage'])} | {x['sev']}·{x['conf']} | "
                  f"{x['occ']:,} | {x['zeek'] or '-'} |{' ' + x['why'] + ' |' if extra else ''}")
        if len(L) > MAX_LIST:
            print(f"\n(그 밖 {len(L) - MAX_LIST}건)")
        print()
    print("#### 남는 탐지\n")
    table(cur_rows, False)
    print("#### 6.1절 기본값으로는 켜지지만 선별에서 빠지는 탐지\n")
    table(drop_rows, True)
    print("### 공격 단계별 경보\n")
    print(" · ".join(f"{STAGE_KO[k]} {v:,}" for k, v in stage_alerts.most_common()))
    print("\n### 겹친 Zeek 탐지 종류\n")
    print(" · ".join(f"{k} {v:,}" for k, v in merged_with.most_common()) or "(없음)")
    print("\n### 경보가 많은 SID 상위 20\n")
    print("| SID | 경보 | 시그니처 | 심각도·신뢰도 |")
    print("| ---: | ---: | --- | --- |")
    for k, v in sid_alerts.most_common(20):
        sev, conf, _ = sid_meta.get(k, ("-", "-", "-"))
        print(f"| {k} | {v:,} | {sid_name.get(k, '')} | {sev}·{conf} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
