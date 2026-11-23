#!/usr/bin/env python3
"""목업형 리포트: report_pcap.collect() 결과를 MDS Manager 목업(ui/mockup/mdsm_nsm_mockup.html)과 같은 화면으로 만든다.

목업 파일을 그대로 템플릿으로 쓰고, <script type="application/json" id="report-data"> 에 이 pcap 의 탐지·공격 스토리·
자산·예외·센서 상태를 목업의 예시 데이터와 같은 모양으로 넣는다. 목업의 applyReport() 가 예시 데이터를 이 값으로 바꾼다.
등급은 센서 값(단독 탐지 Information, 상관 탐지 Suspicious)을 그대로 쓰고, 탐지명·공격 단계·탐지 기준은
목업의 룰 표(RULES, 룰별 기본값)에서 채운다.

리포트에 없는 것(Manager 기능): 대응 현황·조치, 보고서·로그 메뉴, MDS·MTA 탐지, 정책·예외 편집과 배포, 과거 기록 검색.
화면에서 숨기거나 읽기 전용으로 둔다. 기존 리포트(report_pcap.py 의 PAGE)는 그대로 함께 만든다.
"""
import collections
import datetime
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "ui", "mockup", "mdsm_nsm_mockup.html")
DETECTION_LOG = os.path.join(HERE, "..", "nsm_rules", "detections", "detection_log.zeek")

MAX_EV = 3000        # 탐지 행 상한(브라우저가 무거워지지 않게, 최근 것부터)
MAX_ASSETS = 2000
MAX_META = 12        # 탐지마다 붙이는 같은 시간대 통신 기록
MAX_PEERS = 6

SIG_KO = {"machine_account": "도메인 컴퓨터 계정", "dhcp_client_id": "DHCP 클라이언트 ID", "mac": "MAC 주소", "hostname": "호스트 이름",
          "fqdn": "FQDN", "domain": "도메인", "os_hint": "OS 추정", "service": "열린 서비스", "device": "장비 종류",
          "dns_name": "서버 이름", "software": "소프트웨어", "form_factor": "기기 형태", "tcp_fp": "TCP SYN 모양",
          "security_agent": "보안 에이전트", "user_account": "로그온 사용자", "smb_client_guid": "SMB 클라이언트 GUID",
          "ssh_host_key": "SSH 호스트 키", "dhcp_vendor_class": "DHCP 벤더 클래스", "dhcp_fingerprint": "DHCP 지문"}
SIG_ORDER = list(SIG_KO)
KEY_KO = {"machine_account": "도메인 컴퓨터 계정", "dhcp_client_id": "DHCP 정보", "mac": "MAC 주소", "hostname": "호스트 이름"}
PORT_KO = {80: "웹", 443: "HTTPS", 445: "파일 공유", 139: "파일 공유", 88: "도메인 로그인", 389: "LDAP", 636: "LDAPS",
           53: "DNS", 3389: "원격 데스크톱", 22: "SSH", 1433: "DB", 3306: "DB", 5432: "DB", 135: "원격 호출", 5985: "WinRM"}


def diag_to_note():
    """detection_log.zeek 의 notice -> 진단명 표를 거꾸로(진단명 -> notice 이름)."""
    out = {}
    try:
        for m in re.finditer(r"\[(\w+)\]\s*=\s*\"(NSM\.[\w.]+)\"", open(DETECTION_LOG, encoding="utf-8").read()):
            out[m.group(2)] = m.group(1)
    except OSError:
        pass
    return out


def build(data, zeek_dir, tz=9.0):
    """report_pcap.collect() 결과 -> 목업 데이터(applyReport 입력)."""
    off = datetime.timedelta(hours=tz)
    dmap = diag_to_note()

    def dt(ts):
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) + off if ts else None

    def hm(ts):
        d = dt(ts)
        return d.strftime("%H:%M") if d else "--:--"

    def md(ts):
        d = dt(ts)
        return d.strftime("%m-%d") if d else ""

    internal = set()

    def ip_of(who):
        if not who:
            return ""
        if not who.get("ext"):
            internal.add(who["ip"])
        return who["ip"]

    # ---- 탐지
    dets = data["detections"]
    ev, ev_id = [], {}
    for i, d in enumerate(dets):
        corr = d.get("category") == "Correlated"
        evs = d.get("evidence") or []
        note = next((str(e["note"]).replace("NSM::", "") for e in evs if e.get("note")), "") or dmap.get(d.get("diagnosis") or "", "")
        src = ip_of(d.get("attacker"))
        vics = [ip_of(v) for v in d.get("victims") or []]
        if not vics:
            vics = list(dict.fromkeys(str(x["dst"]) for x in evs if x.get("dst")))[:5]
        ts = d.get("first") or d.get("ts")
        det = " ".join(str(e.get("detail") or "") for e in evs)
        port = re.search(r"\bport=(\d+)", det)
        # 근거 필드(센서가 올린 값): 룰이 detail 에 port= 를 남기지 않았으면 연결의 목적지 포트·프로토콜
        cev = next((x for x in evs if x.get("dst_port") is not None), None)
        via = next((v for v in d.get("victims") or [] if v.get("proxy")), None)
        e = {"id": "", "key": str(d.get("id") or i), "prod": "NSM", "ts": ts, "t": hm(ts), "d": md(ts),
             "y": dt(ts).strftime("%Y") if ts else "", "diag": d.get("diagnosis") or "", "src": src or "-",
             "dst": vics[0] if vics else "(대상 여러 곳)", "sensor": data.get("pcap") or "NSM", "occ": d.get("occurrences") or 1,
             "port": port.group(1) if port else (str(cev["dst_port"]) if cev else "-"),
             "proto": str(cev.get("proto") or "") if cev else "",
             # 등급은 센서 값(nsm_detection.log severity: 단독 Information, 상관 Suspicious)
             "sev": d.get("severity") or ("Suspicious" if corr else "Information"),
             "ev": [[str(x.get("operation") or "-"), str(x.get("detail") or "")[:300]] for x in evs[:20]]}
        if len(vics) > 1:
            e["victims"] = vics
        acc = (d.get("ev_accounts") or []) + (d.get("accounts") or [])
        if acc:
            e["account"] = str(acc[0])
        if d.get("disposition") == "suppressed":
            e["disp"] = "suppressed"
            e["exc"] = d.get("exception_id") or ""
        m = re.search(r"\bsni=([^ ,]+)", det)
        if m and m.group(1) != "-":
            e["sni"] = m.group(1)
        m = re.search(r"\bhost=([^ ,]+)", det)
        if m:
            e["host"] = m.group(1)
        else:
            dn = next((x["dst_name"] for x in evs if x.get("dst_name")), None)
            if dn and not e.get("sni"):
                e["host"] = dn
        if via:
            vm = next((x["proxy"] for x in evs if x.get("proxy")), None)
            if not vm:
                vm = re.search(r"via_proxy=(\S+)", det)
                vm = vm.group(1) if vm else None
            e["via"] = vm or via["ip"]
            e["host"] = (via.get("targets") or [e.get("host") or "목적지 확인 안 됨"])[0]
        if corr:
            stages = [s.strip() for s in re.split(r"->|→|,", str(d.get("stages") or "")) if s.strip()]
            e.update({"note": "Correlated_KillChain", "corr": True, "stages": stages or ["Impact"],
                      "stage": stages[-1] if stages else "Impact", "name": f"여러 단계로 이어진 공격({len(stages)}단계)",
                      "tech": str(d.get("techniques") or "")})
            e["victims"] = vics or [e["dst"]]
        else:
            e["note"] = note or (d.get("diagnosis") or "").split(".")[-1]
            e["meta"] = [[hm(ts), log, src, e["dst"], f"{label}: {text}"] for label, text, log in (d.get("how") or [])[:MAX_META]]
        ev.append((i, e))
    # 상관 탐지는 체인이 길어질 때마다 새로 나온다. 공격자별로 가장 긴(같으면 마지막) 체인만 남긴다(기존 리포트의 기본 보기와 같음)
    best = {}
    for i, e in ev:
        if e.get("corr"):
            k = e["src"]
            if k not in best or len(e["stages"]) >= len(best[k][1]["stages"]):
                best[k] = (i, e)
    keep = {id(e) for _, e in best.values()}
    ev = [(i, e) for i, e in ev if not e.get("corr") or id(e) in keep]
    ev = sorted(ev, key=lambda x: x[1]["ts"] or 0)[-MAX_EV:]
    for n, (i, e) in enumerate(ev, 1):
        e["id"] = f"NSM-{n:05d}"
        ev_id[i] = e["id"]
    ev = [e for _, e in ev]

    # ---- 공격 스토리
    note_of = {x["id"]: x.get("note", "") for x in ev}
    stories = []
    for n, s in enumerate(data["stories"], 1):
        idx = [i for i in s["steps"] if i in ev_id]
        if not idx:
            continue
        conf = set(s.get("confirmed") or [])
        steps = []
        for k, i in enumerate(idx, 1):
            d = dets[i]
            src = d["attacker"]["ip"] if d.get("attacker") else "-"
            dst = d["victims"][0]["ip"] if d.get("victims") else next((x["dst"] for x in ev if x["id"] == ev_id[i]), "-")
            how = "; ".join(f"{a} {b}" for a, b, _ in (d.get("how") or [])[:2])
            fact = (d.get("facts") or [""])[0]
            text = f"{_nm(d.get('attacker'))} → {_nm(d['victims'][0]) if d.get('victims') else '-'}: {d.get('ko') or ''}"
            text += f" ({fact or how})" if (fact or how) else ""
            note = note_of.get(ev_id[i], "")
            steps.append([k, [note, src], hm(d.get("first") or d["ts"]), d.get("stages") or "", src, dst, text[:400], 1 if i in conf else 0, ev_id[i]])
        t0 = dets[idx[0]].get("first") or dets[idx[0]]["ts"]
        t1 = max(dets[i].get("last") or dets[i]["ts"] for i in idx)
        stages_seen = list(dict.fromkeys(x[3] for x in steps if x[3]))
        STG = {"Recon": "정찰", "Initial Access": "초기 침투", "Credential Access": "계정 탈취", "Lateral Movement": "내부 확산",
               "Command and Control": "외부 연락(C2)", "Exfiltration": "정보 유출", "Impact": "피해"}
        seed_lane = next((ln for ln in s.get("lanes") or [] if ln["ip"] == s["seed"]), {"ip": s["seed"]})
        title = f"{_nm(seed_lane)}: " + " → ".join(STG.get(x, x) for x in stages_seen)
        obs, moves, obs_hosts = [], [], []
        for o in s.get("observed") or []:
            what = ", ".join(o.get("what") or [])
            obs.append([hm(o["first"]), f"{_nm({'ip': o['a']})}에서 {_nm(o.get('who') or {'ip': o['b']})}로 {what}(탐지 기준 아래)", "move"])
            moves.append([o["a"], o["b"], what, hm(o["first"]), "관리 접속" if o.get("strong") else "연결"])
            if o["b"] not in obs_hosts:
                obs_hosts.append(o["b"])
            internal.update([o["a"], o["b"]])
        infra = []
        for x in s.get("infra") or []:
            hosts = []
            for h in x.get("hosts") or []:
                ip = h["who"]["ip"]
                internal.add(ip)
                hosts.append([ip, "스토리 안" if h["status"] == "story" else "통신 기록으로만",
                              f"{md(h['first'])} {hm(h['first'])} ~ {md(h['last'])} {hm(h['last'])}", f"{h['n']}회"])
                if h["status"] != "story" and ip not in obs_hosts:
                    obs_hosts.append(ip)
            infra.append([x["key"] + (f" (흔한 목적지, 관측만 {x['omitted']}대 생략)" if x.get("omitted") else ""), hosts, 0])
        for ln in s.get("lanes") or []:
            if not ln.get("ext"):
                internal.add(ln["ip"])
        stories.append({"id": f"ST-{n:02d}", "title": title, "seed": s["seed"], "status": "신규", "owner": "",
                        "first": hm(t0), "firstDet": hm(t0), "last": hm(t1), "d": md(t0), "d2": md(t1),
                        "dwell": _dur(t1 - t0), "single": len(steps) == 1, "steps": steps, "obs": obs, "infra": infra,
                        "moves": moves, "skipped": {"prior": (s.get("observed_skip") or {}).get("prior", 0),
                                                    "common": (s.get("observed_skip") or {}).get("common", 0)},
                        "ext": s.get("ext_keys") or [], "obsHosts": obs_hosts})

    # ---- 자산
    sig = _rows(os.path.join(zeek_dir, "asset_signal.log"))
    by_ip = collections.defaultdict(list)
    last_seen, first_seen = {}, {}
    for x in sig:
        by_ip[x.get("ip")].append(x)
        if isinstance(x.get("ts"), (int, float)) and x["ts"] > 1e9:
            last_seen[x.get("ip")] = max(last_seen.get(x.get("ip"), 0), x["ts"])
            first_seen[x.get("ip")] = min(first_seen.get(x.get("ip"), x["ts"]), x["ts"])
    assets, devx = [], {}
    for a in data["assets"][:MAX_ASSETS]:
        ip = (a.get("ips") or [""])[0]
        if not ip:
            continue
        internal.add(ip)
        sigs = by_ip.get(ip, [])
        kinds = {x.get("signal") for x in sigs}
        if a.get("key"):
            key = [a["key"].split("(")[0], int(re.sub(r"\D", "", a["key"].split("(")[-1]) or 50)]
        else:
            k = next((k for k in KEY_KO if k in kinds), None)
            key = [KEY_KO[k], {"machine_account": 90, "dhcp_client_id": 85, "hostname": 70, "mac": 40}[k]] if k else ["IP 주소", 20]
        role = (a.get("roles") or [""])[0] or ""
        mac = re.sub(r" \(.*\)$", "", (a.get("macs") or [""])[0] or "")
        assets.append({"ip": ip, "host": a.get("name") or "", "role": role, "os": a.get("os") or "", "mac": mac,
                       "agent": list(a.get("agents") or []), "key": key, "last": f"{md(last_seen.get(ip))} {hm(last_seen.get(ip))}" if last_seen.get(ip) else "",
                       "svc": list(a.get("services") or []), "first": f"{md(first_seen[ip])} {hm(first_seen[ip])}" if ip in first_seen else "", "sw": _sw(sigs), "hist": [], "sigs": _sigs(sigs)})
        devx[ip] = {"dc": [a.get("dev_class") or "알 수 없음", a.get("dev_basis") or "", a.get("dev_conf") or "낮음"],
                    "vendor": "local" if a.get("mac_local") else (a.get("vendor") or ""),
                    "fp": [[f.get("src", ""), f.get("text", "")] for f in a.get("fp") or []],
                    "tcp": a.get("tcp_os") or "", "osSrc": a.get("os_src") or ""}

    # ---- 주로 통신한 상대(흐름 요약, 탐지·스토리에 나온 내부 host 만)
    want = {x["src"] for x in ev} | {ip for s in stories for x in s["steps"] for ip in (x[4], x[5])}
    peer = collections.defaultdict(collections.Counter)
    for r in _rows(os.path.join(zeek_dir, "meta", "flow_summary.log")):
        o, d_, p = r.get("orig_h"), r.get("resp_h"), r.get("resp_p")
        if o in want and d_:
            peer[o][(d_, f"{PORT_KO.get(p, '')}({p})" if PORT_KO.get(p) else str(p))] += r.get("conns") or 1
    peers = {ip: [[k[0], k[1], n] for k, n in c.most_common(MAX_PEERS)] for ip, c in peer.items()}

    # ---- 예외(예외 파일 내용은 로그에 없어 id·처리·적용 탐지·적중 수만)
    loaded, rej, hits = {}, {}, collections.Counter()
    for x in data.get("exceptions") or []:
        k, i = x.get("kind"), x.get("exception_id")
        if k == "loaded":
            loaded[i] = x
        elif k == "rejected":
            rej[i] = x
        elif k == "hits":
            hits[i] += x.get("hits") or 0
    exc, bihits = [], {}
    for i, x in list(loaded.items()) + [(i, x) for i, x in rej.items() if i not in loaded]:
        if str(i).startswith("EX-pb-"):
            bihits[i] = hits.get(i, 0)
            continue
        scope = x.get("scope") or []
        exc.append({"id": i, "disp": "suppress" if x.get("disposition") == "suppress" else "drop", "src": "", "dst": "", "dst_port": "",
                    "service": "", "domain": "", "ja4": "", "scope": scope if isinstance(scope, list) else str(scope).split(","),
                    "reason": "기존 설정(redef)에서 등록" if x.get("msg") == "legacy" else "예외 파일", "owner": "", "expires": "", "ref": "",
                    "hits": hits.get(i, 0), "h7": [0, 0, 0, 0, 0, 0, hits.get(i, 0)],
                    **({"rej": str(x.get("msg") or "검증 거부")} if i in rej and i not in loaded else {})})

    # ---- 센서·전송량
    sz = lambda b: f"{b / 1e6:.1f} MB" if b >= 1e5 else f"{b / 1e3:.0f} KB"
    meta_b = sum(r["bytes"] for r in data.get("meta") or [])
    mgr = data.get("mgr") or {}
    parts = [["통신 기록", meta_b], ["장비 식별 정보", mgr.get("asset_signal", 0)],
             ["탐지", mgr.get("nsm_detection", 0) + mgr.get("evidence", 0)], ["예외 기록", mgr.get("nsm_exception", 0)],
             ["센서 상태", mgr.get("nsm_sensor", 0) + mgr.get("nsm_ioc", 0) + mgr.get("asset_agent_policy", 0)]]
    tot = sum(p[1] for p in parts) or 1
    sent = [[p[0], sz(p[1]), round(100 * p[1] / tot, 1)] for p in parts]
    sen = data.get("sensor") or {}
    loss = round(sen.get("capture_loss_max") or 0, 2)
    span = data.get("span") or 0
    sensors = [{"name": data.get("pcap") or "NSM 센서", "ip": "-", "grp": "PoC", "st": "warn" if loss > 1 or sen.get("warnings") else "ok",
                "hb": f"{md(data.get('end'))} {hm(data.get('end'))}", "cpu": None, "mem": None, "disk": None, "ifc": "pcap",
                "pps": "-", "bps": "-", "sig": "-", "ioc": "-", "loss": loss, "zeek": "경고 있음" if sen.get("warnings") else "정상",
                "suri": "사용 안 함", "lag": "-", "send": "-", "eng": "-", "zv": "-"}]

    # 프록시(중계 장비)는 피해 장비가 아니라 외부처럼 그린다(기존 리포트와 같음)
    internal -= {v["ip"] for d in dets for v in d.get("victims") or [] if v.get("proxy")}
    start, end = data.get("start"), data.get("end")
    rng = f"{md(start)} {hm(start)} ~ {md(end)} {hm(end)}" if start else "캡처 구간 없음"
    return {"title": f"NSM 리포트 · {data.get('pcap') or 'pcap'}", "banner": f"PoC 리포트(읽기 전용) · {data.get('pcap') or 'pcap'} · {rng} (UTC{tz:+g}) · "
            f"탐지 {len(ev)}건 · 화면은 MDS Manager 목업과 같고, 대응·편집·배포 같은 Manager 기능은 빠져 있습니다",
            "day": md(start or end), "span": f"캡처 {_dur(span)}", "internal": sorted(internal), "ev": ev, "stories": stories,
            "assets": assets, "devx": devx, "peers": peers, "exc": exc, "builtin": bool(bihits), "bihits": bihits,
            "excver": "pcap 실행", "sensors": sensors, "sent": sent}


def render(mock, out_path, template=TEMPLATE):
    page = open(template, encoding="utf-8").read()
    blob = json.dumps(mock, ensure_ascii=False, default=list).replace("</", "<\\/")
    tag = f'<script type="application/json" id="report-data">{blob}</script>\n'
    assert page.count("<body>") == 1, "목업 템플릿에 <body> 가 하나여야 함"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page.replace("<body>", "<body>\n" + tag, 1))


def _nm(who):
    if not who:
        return "-"
    n = who.get("name")
    return f"{n}({who['ip']})" if n else ("외부 " if who.get("ext") else "") + who["ip"]


def _dur(sec):
    sec = int(sec or 0)
    if sec < 3600:
        return f"{sec // 60}분"
    if sec < 86400:
        return f"{sec // 3600}시간 {sec % 3600 // 60}분"
    return f"{sec // 86400}일 {sec % 86400 // 3600}시간"


def _rows(path):
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def _sigs(sigs):
    """식별 근거 표: [정보, 값, 본 통신, 신뢰도, 표시] (신호 종류 순서, 같은 값은 한 번)."""
    seen, out = set(), []
    for x in sorted(sigs, key=lambda r: (SIG_ORDER.index(r.get("signal")) if r.get("signal") in SIG_ORDER else 99, -(r.get("confidence") or 0))):
        k = (x.get("signal"), str(x.get("value")))
        if k in seen:
            continue
        seen.add(k)
        out.append([SIG_KO.get(x.get("signal"), x.get("signal")), str(x.get("value"))[:200], str(x.get("source") or ""),
                    int(x.get("confidence") or 0), "대표 키" if x.get("signal") in KEY_KO and len(out) == 0 else ""])
        if len(out) >= 20:
            break
    return out


def _sw(sigs):
    return list(dict.fromkeys(str(x.get("value")) for x in sigs if x.get("signal") == "software"))[:8]
