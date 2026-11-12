#!/usr/bin/env python3
"""tests/run_pcap.sh 결과(Zeek 로그 디렉터리)로 통합 리포트(report.html, 파일 하나)를 만든다.

  python3 tests/report_pcap.py <zeek 로그 디렉터리> -o report.html [--assets assets.json]
         [--asset-report 상대경로] [--pcap 이름] [--elapsed 초] [--tz 9]

공격 스토리(공격자별 타임라인: 확정 체인 + 확산 대상에서 이어진 탐지, 단계마다 선별 전송 로그로 추정한 '어떻게'),
탐지(탐지 요약·근거), 킬체인 상관, 예외, 자산(리졸버 assets.json 이 있으면 자산 단위, 없으면 신호 단위),
메타데이터 선별 전송, Manager 로 가는 전송량, 센서 상태를 한 페이지에 모은다. 탐지의 공격자·대상 IP 는
탐지 시각에 그 IP 를 쓰던 자산(assets.json 의 IP 점유 구간)으로 이름을 붙이고, 자산 표에는 관련 탐지 수를 센다.

리포트에는 주소·호스트명·계정 같은 원문이 들어 있다. 로컬에서 보는 용도이며 외부로 보내지 않는다.
외부 라이브러리를 쓰지 않는다(오프라인 VM 에서 그대로 열림).
"""
import argparse
import collections
import datetime
import html
import ipaddress
import json
import os
import re
import sys

MGR = ("nsm_detection", "evidence", "nsm_exception", "asset_signal")


def rows(path):
    out = []
    if not path or not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.strip() and not line.startswith("#"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def size(path):
    return os.path.getsize(path) if path and os.path.exists(path) else 0


def nlines(path):
    return sum(1 for _ in open(path, encoding="utf-8", errors="replace")) if path and os.path.exists(path) else 0


def split_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [x for x in str(v).split(",") if x and x != "-"]


class AssetIndex:
    """assets.json 의 IP 점유 구간으로 (IP, 시각) -> 자산을 찾는다."""

    def __init__(self, assets):
        self.by_ip = collections.defaultdict(list)
        for a in assets:
            for b in a.get("ips", []):
                self.by_ip[b.get("ip")].append((b.get("first", 0), b.get("last", 0), a))

    def find(self, ip, ts=None):
        cand = self.by_ip.get(ip)
        if not cand:
            return None
        if ts is not None:
            for first, last, a in cand:
                if first <= ts <= last:
                    return a
            # 구간 밖이면 가장 가까운 구간의 자산(신호가 탐지 전후에만 있는 경우)
            return min(cand, key=lambda c: min(abs(ts - c[0]), abs(ts - c[1])))[2]
        return cand[-1][2]


# ---- 공격 스토리 ----------------------------------------------------------------
# 단계 순서(색 순서와 같음). 확산·초기 침투의 내부 대상은 다음 단계의 행위자가 될 수 있다.
STAGES = ["Recon", "Initial Access", "Command and Control", "Credential Access", "Lateral Movement", "Exfiltration", "Impact"]
PIVOT_STAGES = {"Initial Access", "Lateral Movement"}
# 진단 이름(NSM.<분류>.<이름>)의 마지막 토큰 -> 스토리 문장용 짧은 한국어
NOTE_KO = {
    "PortScan": "포트 스캔", "HostScan": "호스트 스캔", "SqlInjection": "SQL 인젝션 시도", "Webshell": "웹셸 접근",
    "NtlmSpray": "NTLM 패스워드 스프레이", "KerberosSpray": "Kerberos 패스워드 스프레이",
    "KerberosBruteforce": "Kerberos 무차별 대입", "Kerberoasting": "Kerberoasting(서비스 티켓 대량 요청)",
    "AsrepRoasting": "AS-REP 로스팅", "NtlmCredentialLeak": "외부로 NTLM 인증 유출", "OutboundSmb": "외부 SMB 연결",
    "WinrmAccess": "WinRM 원격 실행", "DcomExec": "DCOM 원격 실행", "SmbRansomware": "SMB 공유 파일 대량 변경(랜섬웨어 행위)",
    "NamePoisoning": "이름 해석 응답 위조(LLMNR/NBT-NS)", "DcSync": "DCSync(디렉터리 복제 요청)",
    "NonstandardPort": "비표준 포트 통신", "LongConnection": "장시간 연결", "SmbAccess": "SMB 관리 공유 접근",
    "RdpAccess": "RDP 접속 확산", "SshAccess": "SSH 접속 확산", "HttpBeaconing": "HTTP 주기 통신(비콘)",
    "DnsTunneling": "DNS 터널링", "EncryptedChannel": "암호화 C2 의심 통신", "LargeTransfer": "대용량 외부 전송",
    "VolumeAggregate": "누적 외부 전송", "DnsTunnel": "DNS로 데이터 유출", "WebUpload": "웹 업로드 유출",
    "DgaDomain": "DGA 도메인 조회",
}
STORY_META = ("kerberos", "ntlm", "smb_mapping", "smb_files", "dce_rpc", "rdp", "ssh", "ssl", "http", "flow_summary", "dns_summary")
REACH_WINDOW = 86400   # 확산으로 닿은 host 는 닿은 뒤 이 시간 안의 탐지만 같은 스토리로 본다
SLACK = 60


def meta_index(paths):
    """선별 전송 로그를 (출발지) -> [(시각, 로그, 행)] 으로 모은다. 스토리 단계에 붙일 추정 근거용."""
    idx = collections.defaultdict(list)
    for k in STORY_META:
        for r in rows(paths.get(k)):
            src = r.get("id.orig_h") or r.get("orig_h")
            t = r.get("ts")
            if src and isinstance(t, (int, float)):
                idx[src].append((t, k, r))
    return idx


def _fmt_bytes(b):
    b = b or 0
    return f"{b/1e6:,.1f}MB" if b >= 1e6 else f"{b/1e3:,.1f}KB" if b >= 1e3 else f"{b}B"


# 탐지 종류(진단 마지막 토큰)별로 맞출 선별 전송 로그와 Kerberos 서비스 접두사(소문자). 없는 종류는 흐름 요약만.
ENRICH = {
    "Scan": ({"scan"}, None),
    "SqlInjection": ({"http", "flow_summary"}, None), "Webshell": ({"http", "flow_summary"}, None),
    "NtlmSpray": ({"ntlm", "flow_summary"}, None), "NtlmCredentialLeak": ({"ntlm", "smb_mapping", "flow_summary"}, None),
    "Kerberos": ({"kerberos", "flow_summary"}, ()), "Asrep": ({"kerberos", "flow_summary"}, ()),
    "Kerberoasting": ({"kerberos", "flow_summary"}, ()),
    "DcSync": ({"dce_rpc", "kerberos", "flow_summary"}, ("e3514235-4b06-11d1-ab04-00c04fc2dcd2/", "ldap/")),
    "WinrmAccess": ({"ntlm", "kerberos", "flow_summary"}, ("http/", "wsman/")),
    "DcomExec": ({"ntlm", "kerberos", "dce_rpc", "flow_summary"}, ("rpcss/", "host/")),
    "SmbAccess": ({"ntlm", "kerberos", "smb_mapping", "smb_files", "dce_rpc", "flow_summary"}, ("cifs/", "host/")),
    "RdpAccess": ({"ntlm", "kerberos", "rdp", "flow_summary"}, ("termsrv/",)),
    "SshAccess": ({"ssh", "flow_summary"}, None),
    "SmbRansomware": ({"ntlm", "kerberos", "smb_mapping", "smb_files", "flow_summary"}, ("cifs/",)),
    "OutboundSmb": ({"ntlm", "smb_mapping", "flow_summary"}, None),
    "HttpBeaconing": ({"http", "flow_summary"}, None), "EncryptedChannel": ({"ssl", "flow_summary"}, None),
    "NonstandardPort": ({"ssl", "http", "flow_summary"}, None), "LongConnection": ({"ssl", "flow_summary"}, None),
    "LargeTransfer": ({"ssl", "http", "flow_summary"}, None), "VolumeAggregate": ({"ssl", "http", "flow_summary"}, None),
    "WebUpload": ({"http", "flow_summary"}, None),
    "DgaDomain": ({"dns"}, None), "DnsTunneling": ({"dns"}, None), "DnsTunnel": ({"dns"}, None),
}


def enrich(det, midx):
    """탐지 한 건의 출발·대상·시간창으로 선별 전송 로그를 맞춰 '어떻게'를 추정한다(uid 가 아니라 추정 조인).
    반환: [(항목, 내용, 로그)] 와 계정 목록."""
    a = det["attacker"]["ip"] if det.get("attacker") else None
    if not a or a not in midx:
        return [], []
    tail = str(det.get("diagnosis") or "").split(".")[-1]
    use, kpre = next((v for k, v in ENRICH.items() if k in tail), ({"flow_summary"}, None))
    t0 = (det.get("first") or det["ts"]) - 600
    t1 = (det.get("last") or det["ts"]) + 600
    vic = {v["ip"] for v in det["victims"]}
    by = collections.defaultdict(list)
    for t, k, r in midx[a]:
        if (t0 - 1800 if k in ("flow_summary", "dns_summary") else t0) <= t <= t1:
            by[k].append(r)
    # 대상이 있으면 대상으로 간 행만. Kerberos 는 KDC 로 가므로 대상과 무관하게 서비스 접두사로 거른다.
    to_v = lambda r: not vic or (r.get("id.resp_h") or r.get("resp_h")) in vic
    out = []

    def add(label, vals, log, n=4):
        vals = [v for v in dict.fromkeys(vals) if v]
        if vals:
            more = f" 외 {len(vals) - n}" if len(vals) > n else ""
            out.append((label, ", ".join(vals[:n]) + more, log))

    nt = [f"{r.get('domainname') + chr(92) if r.get('domainname') else ''}{r.get('username')}"
          for r in by["ntlm"] if to_v(r) and r.get("username")] if "ntlm" in use else []
    kr = []
    if "kerberos" in use:
        for r in by["kerberos"]:
            svc = str(r.get("service") or "").lower()
            if kpre is None or not kpre or any(svc.startswith(x) for x in kpre):
                kr.append(r)
    kb = [str(r.get("client")).split("/")[0] for r in kr if r.get("client")]
    add("NTLM 계정", nt, "ntlm")
    if kpre == ():   # 자격증명 탐지: 요청한 계정·서비스 자체가 근거
        add("Kerberos 계정", kb, "kerberos", 5)
        add("요청 서비스", [r.get("service") for r in kr if r.get("request_type") == "TGS"], "kerberos", 3)
    else:
        add("Kerberos 티켓", [f"{str(r.get('client', '-')).split('/')[0]} → {r.get('service')}" for r in kr if r.get("service")], "kerberos", 3)
    if "smb_mapping" in use:
        add("SMB 공유", [r.get("path") for r in by["smb_mapping"] if to_v(r)], "smb_mapping")
    if "smb_files" in use:
        sf = [r for r in by["smb_files"] if to_v(r)]
        if sf:
            acts = collections.Counter(str(r.get("action", "")).replace("SMB::FILE_", "").lower() for r in sf)
            add("SMB 파일", [", ".join(f"{k} {v}" for k, v in acts.most_common())] + [r.get("name") for r in sf], "smb_files", 5)
    if "dce_rpc" in use:
        add("원격 호출", [f"{r.get('endpoint')}::{r.get('operation')}" for r in by["dce_rpc"] if to_v(r)], "dce_rpc")
    if "rdp" in use:
        add("RDP", [r.get("cookie") for r in by["rdp"] if to_v(r)], "rdp")
    if "ssh" in use:
        add("SSH", [f"{r.get('client', '')} 인증 시도 {r.get('auth_attempts', '-')}" for r in by["ssh"] if to_v(r)], "ssh")
    if "ssl" in use:
        sl = [r for r in by["ssl"] if to_v(r)]
        add("TLS", [f"SNI {r.get('server_name')}" if r.get("server_name") else "SNI 없음" for r in sl]
            + [f"JA3 {r.get('ja3')}" for r in sl if r.get("ja3")], "ssl", 3)
    if "http" in use:
        add("HTTP", [f"{r.get('method', '')} {r.get('host') or '(Host 없음)'}{r.get('uri_path') or ''}" for r in by["http"] if to_v(r)], "http", 3)
    if "dns" in use:
        names = []
        for r in by["dns_summary"]:
            names += split_list(r.get("sample_names"))
        add("DNS 질의 예", names, "dns_summary", 5)
    if "scan" in use and by["flow_summary"]:
        fl = by["flow_summary"]
        out.append(("연결 범위", f"대상 host {len({r.get('resp_h') for r in fl})}개, 포트 {len({r.get('resp_p') for r in fl})}개"
                    " (선별 전송은 경계·내부 관리 포트만 남음)", "flow_summary"))
    if "flow_summary" in use:
        fl = [r for r in by["flow_summary"] if vic and to_v(r)]
        if fl:
            ports = [f"{r.get('resp_p')}/{r.get('proto', '')}{'(' + r['service'] + ')' if r.get('service') else ''}" for r in fl]
            add("연결", [f"{sum(r.get('conns', 0) for r in fl):,}회, 보냄 {_fmt_bytes(sum(r.get('orig_bytes', 0) for r in fl))}"
                       f" / 받음 {_fmt_bytes(sum(r.get('resp_bytes', 0) for r in fl))}"] + ports, "flow_summary", 4)
    rc = [str(r.get("cookie")) for r in by["rdp"] if to_v(r) and r.get("cookie")] if "rdp" in use else []
    return out, list(dict.fromkeys(nt + kb + rc))


def build_stories(detections, midx, label):
    """확정 체인(상관 탐지) + 공격자에서 확산 대상으로 이어지는 후보 탐지를 공격자별 스토리로 묶는다."""
    singles = [i for i, d in enumerate(detections) if d.get("category") != "Correlated"]
    by_id = {detections[i]["id"]: i for i in singles}
    confirmed = collections.defaultdict(set)   # 공격자 IP -> 체인에 들어간 탐지
    chain_ids = collections.defaultdict(list)
    for d in detections:
        if d.get("category") == "Correlated" and d.get("attacker"):
            kids = {by_id[e] for e in d.get("eids", []) if e in by_id}
            confirmed[d["attacker"]["ip"]] |= kids
            chain_ids[d["attacker"]["ip"]].append(d["id"])
    t = lambda i: detections[i].get("first") or detections[i]["ts"] or 0
    seeds = list(dict.fromkeys(detections[i]["attacker"]["ip"] for i in sorted(singles, key=t) if detections[i].get("attacker")))
    stories = []
    for seed in seeds:
        reached = {seed: None}             # host -> 닿은 시각(None = 시작점)
        steps = set(confirmed.get(seed, ()))
        for i in steps:                    # 체인에 든 탐지의 행위자도 닿은 것으로 본다
            a = detections[i]["attacker"]["ip"]
            if a not in reached:
                reached[a] = t(i)
        changed = True
        while changed:
            changed = False
            for i in sorted(singles, key=t):
                d = detections[i]
                if i in steps or not d.get("attacker"):
                    continue
                a = d["attacker"]["ip"]
                if a not in reached:
                    continue
                r = reached[a]
                if r is not None and not (r - SLACK <= t(i) <= r + REACH_WINDOW):
                    continue
                steps.add(i)
                changed = True
            for i in list(steps):
                d = detections[i]
                if d.get("stages") in PIVOT_STAGES:
                    for v in d["victims"]:
                        if not v.get("ext") and v["ip"] not in reached:
                            reached[v["ip"]] = t(i)
                            changed = True
        order = sorted(steps, key=t)
        hosts = list(dict.fromkeys([seed] + [h for h in sorted(reached, key=lambda h: (reached[h] is not None, reached[h] or 0))]))
        others = []
        for i in order:
            for v in detections[i]["victims"]:
                if v["ip"] not in hosts and v["ip"] not in others:
                    others.append(v["ip"])
        lanes = hosts + [o for o in others if not next(v for i in order for v in detections[i]["victims"] if v["ip"] == o).get("ext")] \
            + [o for o in others if next(v for i in order for v in detections[i]["victims"] if v["ip"] == o).get("ext")]
        stories.append({"seed": seed, "steps": order, "confirmed": sorted(confirmed.get(seed, ())), "chains": chain_ids.get(seed, []),
                        "lanes": [label(h, t(order[0]) if order else None) for h in lanes]})
    # 다른 스토리에 그대로 들어 있는 작은 스토리는 뺀다(확산 대상이 뒤에 공격자로 나온 경우 등)
    stories.sort(key=lambda s: (-len(s["confirmed"]), -len(s["steps"])))
    kept = []
    for s in stories:
        if not any(set(s["steps"]) <= set(k["steps"]) for k in kept):
            kept.append(s)
    return kept


def story_coverage(detections, ev):
    """빈틈 검토용: 탐지 종류별로 스토리 단계에 무엇이 붙었는지 센다(주소 원문 없이 숫자만)."""
    ev_uid = collections.defaultdict(lambda: [0, 0])
    for e in ev:
        k = str(e.get("note", "-")).replace("NSM::", "")
        ev_uid[k][0] += 1
        ev_uid[k][1] += 1 if e.get("uid") else 0
    note_of = {v.split(".")[-1]: k for k, v in DIAG_NOTE.items()}
    rows_ = collections.OrderedDict()
    for d in sorted((d for d in detections if d.get("category") != "Correlated"), key=lambda d: STAGES.index(d["stages"]) if d.get("stages") in STAGES else 99):
        tail = str(d.get("diagnosis") or "").split(".")[-1]
        r = rows_.setdefault(tail, {"name": tail, "ko": d.get("ko", tail), "stage": d.get("stages"), "n": 0, "how": 0, "acct": 0, "eacct": 0, "facts": 0,
                                    "ext": 0, "ext_named": 0, "ev": 0, "ev_uid": 0})
        r["n"] += 1
        r["how"] += 1 if d.get("how") else 0
        r["acct"] += 1 if d.get("accounts") else 0
        r["eacct"] += 1 if d.get("ev_accounts") else 0
        r["facts"] += 1 if d.get("facts") else 0
        if any(v.get("ext") for v in d["victims"]):
            r["ext"] += 1
            named = any(k in ("TLS", "HTTP") and "SNI 없음" not in v and "(Host 없음)" not in v for k, v, _ in d.get("how", []))
            named = named or any(re.search(r"\b(host|sni|service|server_name)=(?!-)[A-Za-z0-9]", f) for f in d.get("facts", []))
            r["ext_named"] += 1 if named else 0
        n = note_of.get(tail)
        if n:
            r["ev"], r["ev_uid"] = ev_uid[n]
    return list(rows_.values())


# 진단 이름 -> notice 이름(근거 로그의 note 와 맞추는 용도)
DIAG_NOTE = {
    "Port_Scan": "PortScan", "Host_Scan": "HostScan", "SQL_Injection": "SqlInjection", "Webshell_Access": "Webshell",
    "NTLM_Spray": "NtlmSpray", "Kerberos_Spray": "KerberosSpray", "Kerberos_Bruteforce": "KerberosBruteforce",
    "Kerberoasting": "Kerberoasting", "ASREP_Roasting": "AsrepRoasting", "NTLM_Credential_Leak": "NtlmCredentialLeak",
    "Outbound_SMB": "OutboundSmb", "WinRM_Lateral": "WinrmAccess", "DCOM_Lateral": "DcomExec", "SMB_Ransomware": "SmbRansomware",
    "Name_Poisoning": "NamePoisoning", "DCSync": "DcSync", "Nonstandard_Port": "NonstandardPort", "Long_Connection": "LongConnection",
    "SMB_Admin_Share": "SmbAccess", "RDP_Lateral": "RdpAccess", "SSH_Lateral": "SshAccess", "HTTP_Beaconing": "HttpBeaconing",
    "DNS_Tunneling": "DnsTunneling", "Encrypted_C2": "EncryptedChannel", "Exfil_Large_Transfer": "LargeTransfer",
    "Exfil_Volume_Aggregate": "VolumeAggregate", "Exfil_DNS": "DnsTunnel", "Exfil_Web_Upload": "WebUpload", "DGA_Domain": "DgaDomain",
}


def collect(z, assets_path, args):
    logs = {f[:-4]: os.path.join(z, f) for f in os.listdir(z) if f.endswith(".log")}
    mdir = os.path.join(z, "meta")
    meta = {f[:-4]: os.path.join(mdir, f) for f in os.listdir(mdir) if f.endswith(".log")} if os.path.isdir(mdir) else {}

    det = rows(logs.get("nsm_detection"))
    ev = rows(logs.get("evidence"))
    notices = rows(logs.get("notice"))
    exc = rows(logs.get("nsm_exception"))
    sig = rows(logs.get("asset_signal"))
    assets = json.load(open(assets_path, encoding="utf-8")) if assets_path and os.path.exists(assets_path) else None
    if isinstance(assets, dict):
        assets = assets.get("assets", [])
    idx = AssetIndex(assets or [])

    # 내부 대역: --nets(run_pcap.sh -n) 또는 사설 대역. 대상이 외부면 자산 식별 대상이 아니다(C2·유출의 대상은 외부 서버).
    nets = []
    for n in (args.nets or "").split(","):
        n = n.strip()
        if n:
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass

    def internal(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return a.is_private or any(a in n for n in nets)

    # 리졸버 결과가 없을 때 IP 옆에 붙일 이름: 자산 신호의 호스트명 > 머신 계정 > FQDN > DNS 이름(판정 전 참고값)
    pri = {"hostname": 0, "machine_account": 1, "fqdn": 2, "dns_name": 3}
    sig_names = {}
    for x in sig:
        k = x.get("signal")
        if k in pri and x.get("value"):
            cur = sig_names.get(x.get("ip"))
            if cur is None or pri[k] < cur[0]:
                sig_names[x.get("ip")] = (pri[k], str(x["value"]))

    def label(ip, ts):
        out = {"ip": ip}
        if not internal(ip):
            out["ext"] = True
        a = idx.find(ip, ts) if assets else None
        if a:
            out.update({"asset": a.get("asset_id"), "name": a.get("display_name") or a.get("hostname") or ""})
            # 역할·OS: 탐지 행에서 바로 보이고 필터로도 찾게 한다(리졸버 판정 결과일 때만)
            if a.get("roles"):
                out["roles"] = [str(r) for r in a["roles"]]
            if a.get("os"):
                out["os"] = str(a["os"])
            if a.get("id_type"):
                out["key"] = f"{a.get('id_type')}({a.get('confidence', '')})"
        elif ip in sig_names:
            out["name"] = sig_names[ip][1]
            out["guess"] = True
        return out

    ev_by = collections.defaultdict(list)
    for e in ev:
        ev_by[e.get("evidence_id")].append({k: e.get(k) for k in ("ts", "note", "operation", "src", "dst", "account", "uid", "detail", "technique")})

    detections = []
    related = collections.Counter()
    for d in det:
        ts = d.get("ts")
        att = d.get("attacker")
        vics = split_list(d.get("victims"))
        eids = split_list(d.get("evidence_ids")) or ([d["detection_id"]] if d.get("detection_id") else [])
        evs = []
        for eid in eids:
            evs.extend(ev_by.get(eid, []))
        item = {
            "ts": ts, "id": d.get("detection_id"), "diagnosis": d.get("diagnosis"), "techniques": d.get("techniques"),
            "category": d.get("category"), "stages": d.get("killchain_stages"), "severity": d.get("severity"),
            "attacker": label(att, ts) if att else None, "victims": [label(v, ts) for v in vics],
            "evidence_count": d.get("evidence_count", 0), "disposition": d.get("disposition"),
            "exception_id": d.get("exception_id"), "evidence": sorted(evs, key=lambda e: e.get("ts") or 0)[:200],
            "first": d.get("first_seen") or ts, "last": d.get("last_seen") or ts, "eids": eids,
        }
        detections.append(item)
        for who in [item["attacker"]] + item["victims"]:
            if who and who.get("asset"):
                related[who["asset"]] += 1

    # 공격 스토리: 단계별 추정 근거(선별 전송 로그 조인)와 공격자별 묶음
    midx = meta_index({k: meta.get(k) or logs.get(k) for k in STORY_META})
    for d in detections:
        if d.get("category") != "Correlated":
            d["how"], d["accounts"] = enrich(d, midx)
            # 근거 로그(탐지 ID 로 연결된 정확한 값): 행위·내용 예 2개, 계정
            facts = []
            for e in d["evidence"]:
                f = f"{e.get('operation') or '-'}: {e.get('detail') or ''}".strip()
                if f not in facts:
                    facts.append(f)
            d["facts"] = [x[:180] for x in facts[:2]]
            d["ev_accounts"] = list(dict.fromkeys(str(e["account"]) for e in d["evidence"] if e.get("account")))[:5]
            tail = str(d.get("diagnosis") or "").split(".")[-1]
            d["ko"] = NOTE_KO.get(tail, tail)
    stories = build_stories(detections, midx, label)
    coverage = story_coverage(detections, ev)
    for d in detections:
        d.pop("eids", None)

    # 자산: 리졸버 결과가 있으면 자산 단위, 없으면 IP 별 신호 요약
    asset_rows = []
    if assets is not None:
        for a in assets:
            asset_rows.append({
                "id": a.get("asset_id"), "name": a.get("display_name") or a.get("hostname") or "",
                "key": f"{a.get('id_type', '')}({a.get('confidence', '')})", "ips": [b.get("ip") for b in a.get("ips", [])],
                "macs": a.get("macs", []), "os": a.get("os", ""), "roles": a.get("roles", []),
                "users": a.get("users", [])[:5], "signals": a.get("signal_count", 0), "detections": related.get(a.get("asset_id"), 0),
            })
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))
    else:
        per = collections.defaultdict(lambda: {"signals": collections.Counter(), "names": set()})
        for s in sig:
            p = per[s.get("ip")]
            p["signals"][s.get("signal")] += 1
            if s.get("signal") in ("hostname", "machine_account", "fqdn"):
                p["names"].add(str(s.get("value")))
        det_ips = collections.Counter()
        for d in detections:
            for who in [d["attacker"]] + d["victims"]:
                if who:
                    det_ips[who["ip"]] += 1
        for ip, p in per.items():
            asset_rows.append({"id": "", "name": ", ".join(sorted(p["names"]))[:80], "key": "", "ips": [ip], "macs": [],
                               "os": "", "roles": [], "users": [], "signals": sum(p["signals"].values()),
                               "detections": det_ips.get(ip, 0)})
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))

    # 전송량
    meta_rows = [{"name": k, "bytes": size(p), "rows": nlines(p)} for k, p in meta.items()]
    meta_rows.sort(key=lambda r: -r["bytes"])
    mgr = {k: size(logs.get(k)) for k in MGR}
    local = {k: size(p) for k, p in logs.items() if k not in MGR}
    ts_all = [r["ts"] for p in list(logs.values()) + list(meta.values()) for r in rows(p)
              if isinstance(r.get("ts"), (int, float)) and r["ts"] > 1e9]
    span = (max(ts_all) - min(ts_all)) if len(ts_all) >= 2 else 0

    # 센서 상태
    cl = rows(logs.get("capture_loss"))
    other_notes = collections.Counter(n.get("note") for n in notices if not str(n.get("note", "")).startswith("NSM::"))
    stderr = os.path.join(z, "stderr.txt")
    warn = [l.strip() for l in open(stderr, encoding="utf-8", errors="replace")
            if any(w in l.lower() for w in ("warning", "error", "fatal"))][:20] if os.path.exists(stderr) else []

    return {
        "pcap": args.pcap or "", "elapsed": args.elapsed, "tz": args.tz, "span": span,
        "start": min(ts_all) if ts_all else None, "end": max(ts_all) if ts_all else None,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "detections": detections, "stories": stories, "stage_order": STAGES, "coverage": coverage,
        "exceptions": exc,
        "assets": asset_rows, "asset_mode": "resolver" if assets is not None else "signals",
        "asset_report": args.asset_report or "",
        "signal_counts": collections.Counter(s.get("signal") for s in sig).most_common(),
        "signal_rows": len(sig), "signal_ips": len({s.get("ip") for s in sig}),
        "meta": meta_rows, "mgr": mgr, "local": local,
        "sensor": {"capture_loss_max": max((c.get("percent_lost", 0) for c in cl), default=0),
                   "other_notices": other_notes.most_common(), "warnings": warn},
    }


PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NSM 통합 리포트</title>
<style>
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--mut:#5f6b7a;--line:#e3e7ed;--acc:#2f6fde;--warn:#b35c00;--bad:#c62828;--ok:#2e7d32;--chip:#eef2f8}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--card:#1c2027;--fg:#e6e9ee;--mut:#9aa4b2;--line:#2c323b;--acc:#7aa7ff;--warn:#f0a050;--bad:#ff7a7a;--ok:#7bd07f;--chip:#262c35}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans KR",sans-serif}
header{padding:20px 24px 8px}h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px}
nav{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 24px;display:flex;gap:6px;flex-wrap:wrap}
nav a{color:var(--fg);text-decoration:none;padding:4px 10px;border-radius:14px;background:var(--chip);font-size:13px}nav a:hover{background:var(--acc);color:#fff}
main{padding:12px 24px 40px;max-width:1400px}section{margin:18px 0}h2{font-size:16px;margin:0 0 10px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.card .v{font-size:22px;font-weight:600}.card .k{color:var(--mut);font-size:12px}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;color:var(--mut);font-weight:600;white-space:nowrap;user-select:none}th:hover{color:var(--fg)}
tr.row{cursor:pointer}tr.row:hover td{background:var(--chip)}tr.det td{background:var(--bg)}
.chip.role{background:transparent;border:1px solid var(--acc);color:var(--acc)}.os{color:var(--mut);font-size:12px}
.chip.ext{background:transparent;border:1px solid var(--line);color:var(--mut)}.chip.guess{font-style:italic}
.chip{display:inline-block;white-space:nowrap;padding:1px 7px;border-radius:10px;background:var(--chip);font-size:12px;margin:1px 2px 1px 0}
.sus{color:var(--bad);font-weight:600}.sup{color:var(--warn)}.mut{color:var(--mut)}.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--acc);border-radius:4px;min-width:2px}.filter{margin:0 0 8px;padding:6px 10px;width:100%;max-width:360px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
.note{color:var(--mut);font-size:12px;margin-top:6px}code{font-size:12px}
:root{--s0:#2a78d6;--s1:#eb6834;--s2:#1baf7a;--s3:#eda100;--s4:#e87ba4;--s5:#008300;--s6:#6250d6;--surf:#fff}
@media (prefers-color-scheme: dark){:root{--s0:#3987e5;--s1:#d95926;--s2:#199e70;--s3:#c98500;--s4:#d55181;--s5:#008300;--s6:#9085e9;--surf:#1c2027}}
.st0{--c:var(--s0)}.st1{--c:var(--s1)}.st2{--c:var(--s2)}.st3{--c:var(--s3)}.st4{--c:var(--s4)}.st5{--c:var(--s5)}.st6{--c:var(--s6)}.stn{--c:var(--mut)}
svg .mk{fill:var(--c);stroke:var(--surf);stroke-width:2}svg .mk.cand{fill:var(--surf);stroke:var(--c);stroke-width:2.5}
svg .ar{stroke:var(--c);stroke-width:2;fill:none}svg .ar.cand{stroke-dasharray:4 3}svg .end{fill:var(--surf);stroke:var(--c);stroke-width:2}
svg .lane{stroke:var(--line);stroke-width:1}svg text{fill:var(--fg);font-size:13px}svg .mt{fill:var(--mut);font-size:12px}svg .gap{fill:var(--mut);font-size:12px;font-style:italic}
svg .hit{fill:transparent;cursor:pointer}svg .col.on rect.bg{fill:var(--chip)}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--c);margin-right:4px;vertical-align:-1px}.sw.cand{background:transparent;border:2px solid var(--c);width:8px;height:8px}
.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin:6px 0}
.story{margin:10px 0 0;padding:0;list-style:none}.story li{padding:8px 0;border-top:1px solid var(--line)}.story li.on{background:var(--chip)}
.story .t{color:var(--mut);font-variant-numeric:tabular-nums;margin-right:6px}.story .how{margin:4px 0 0 18px;font-size:12px;color:var(--mut)}.story .how b{color:var(--fg);font-weight:600}
.lead{font-size:14px;margin:4px 0 8px}select{padding:5px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);max-width:100%}
#tip{position:fixed;z-index:20;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;max-width:420px;box-shadow:0 4px 14px rgba(0,0,0,.15);display:none}
</style></head><body>
<header><h1>NSM 통합 리포트</h1><div class="sub" id="sub"></div></header>
<nav><a href="#sum">요약</a><a href="#story">공격 스토리</a><a href="#det">탐지</a><a href="#chain">킬체인</a><a href="#asset">자산</a><a href="#xfer">전송량</a><a href="#exc">예외</a><a href="#sensor">센서 상태</a></nav>
<main>
<section id="sum"><h2>요약</h2><div class="cards" id="cards"></div></section>
<section id="story"><h2>공격 스토리</h2><div class="box">
 <select id="storysel"></select> <label class="note"><input type="checkbox" id="storycand" checked> 체인 밖 탐지도 보기(같은 공격자·확산 대상에서 나온 후보)</label>
 <div class="lead" id="storylead"></div><div class="legend" id="storyleg"></div><div style="display:flex"><div id="storylab" style="flex:0 0 clamp(120px,32vw,230px);overflow:hidden"></div><div id="storysvg" style="overflow-x:auto;flex:1 1 auto;min-width:0"></div></div><ol class="story" id="storylist"></ol>
 <details style="margin-top:8px"><summary class="note">근거 연결률(탐지 종류별, 빈틈 검토용)</summary><div id="storycov"></div></details>
 <div class="note">세로는 host(시작 공격자 → 확산으로 닿은 순서 → 그 밖의 대상, 외부는 아래), 가로는 탐지 순서입니다(간격은 시간 비례가 아님, 사이가 10분 이상이면 경과 시간 표시). 채운 점은 상관 규칙이 이은 확정 체인, 빈 점·점선은 같은 공격자나 확산 대상에서 나온 체인 밖 탐지입니다. 단계 아래 <i>추정</i> 줄은 선별 전송 로그를 출발·대상·시간(±10분, 흐름 요약 30분)으로 맞춘 값이라 정확한 연결이 아닙니다.</div></div></section>
<section id="det"><h2>탐지</h2><div class="box"><div id="detbars"></div></div>
 <div class="box" style="margin-top:10px"><input class="filter" id="detf" placeholder="필터: 진단·IP·자산 이름·역할·OS·기법"><div id="dett"></div>
 <div class="note">행을 누르면 근거(evidence)가 펼쳐집니다. 대상은 확산·랜섬웨어 등에서는 피해 host, C2·유출·비표준 포트에서는 연결한 외부 서버입니다(<span class="chip ext">외부</span> 표시, 자산 식별 대상 아님). IP 옆 이름은 자산 판정 결과가 있으면 탐지 시각에 그 IP를 쓰던 자산(<span class="chip role">역할</span>·<span class="os">OS</span> 함께, 이름에 마우스를 올리면 자산 ID·식별 근거), 없으면 자산 신호의 호스트명(<i>기울임</i>, 판정 전 참고값)입니다. 검색 칸에 역할·OS(예: DC, Windows)를 넣으면 그 자산이 공격자·대상인 탐지만 남습니다.</div></div></section>
<section id="chain"><h2>킬체인 상관</h2><div class="box"><label class="note"><input type="checkbox" id="chainall"> 중간 단계 포함(체인이 길어질 때마다 나온 상관 탐지를 모두 보기)</label><div id="chaint"></div></div></section>
<section id="asset"><h2>자산</h2><div class="box"><input class="filter" id="asf" placeholder="필터: 이름·IP·OS·역할"><div id="ast"></div><div class="note" id="asnote"></div></div></section>
<section id="xfer"><h2>전송량</h2><div class="box" id="xft"></div></section>
<section id="exc"><h2>예외</h2><div class="box" id="exct"></div></section>
<section id="sensor"><h2>센서 상태</h2><div class="box" id="sent"></div></section>
</main>
<div id="tip"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtB=b=>b>=1e6?(b/1e6).toFixed(2)+' MB':b>=1e3?(b/1e3).toFixed(1)+' KB':b+' B';
const fmtT=t=>{if(!t)return'-';const d=new Date((t+D.tz*3600)*1000);return d.toISOString().replace('T',' ').slice(0,19)};
const whoTip=w=>w.guess?'자산 신호의 이름(판정 전)':['자산 판정 결과',w.asset&&`자산 ${w.asset}`,w.key&&`식별 ${w.key}`,w.os&&`OS ${w.os}`,w.roles&&`역할 ${w.roles.join(', ')}`].filter(Boolean).join('\\n');
const who=w=>w?`${esc(w.ip)}${(w.name||w.asset)?` <span class="chip${w.guess?' guess':''}" title="${esc(whoTip(w))}">${esc(w.name||w.asset)}</span>`:''}${(w.roles||[]).map(r=>` <span class="chip role" title="${esc(whoTip(w))}">${esc(r)}</span>`).join('')}${w.os?` <span class="os">${esc(w.os)}</span>`:''}${w.ext?' <span class="chip ext">외부</span>':''}`:'-';
const arrow=s=>esc(String(s??'').replace(/->/g,'→'));
document.getElementById('sub').textContent=`${D.pcap} · 캡처 ${fmtT(D.start)} ~ ${fmtT(D.end)} (UTC${D.tz>=0?'+':''}${D.tz}, 약 ${(D.span/60).toFixed(1)}분) · 처리 ${D.elapsed}초 · 생성 ${D.generated}`;
// 표: 열 정의 [제목, 값 함수, 정렬 키 함수, 클래스]
function table(el,cols,data,opts={}){
  let sk=null,sd=1,flt='';const host=document.getElementById(el);
  function draw(){let d=data.filter(r=>!flt||JSON.stringify(r).toLowerCase().includes(flt));
    if(sk!==null)d=[...d].sort((a,b)=>{const x=cols[sk][2](a),y=cols[sk][2](b);return (x>y?1:x<y?-1:0)*sd});
    let h='<table><thead><tr>'+cols.map((c,i)=>`<th data-i="${i}">${c[0]}${sk===i?(sd>0?' ▲':' ▼'):''}</th>`).join('')+'</tr></thead><tbody>';
    d.forEach((r,i)=>{h+=`<tr class="${opts.detail?'row':''}" data-i="${data.indexOf(r)}">`+cols.map(c=>`<td class="${c[3]||''}">${c[1](r)}</td>`).join('')+'</tr>';});
    if(!d.length)h+=`<tr><td colspan="${cols.length}" class="mut">없음</td></tr>`;
    host.innerHTML=h+'</tbody></table>';
    host.querySelectorAll('th').forEach(th=>th.onclick=()=>{const i=+th.dataset.i;sd=sk===i?-sd:1;sk=i;draw()});
    if(opts.detail)host.querySelectorAll('tr.row').forEach(tr=>tr.onclick=()=>{const n=tr.nextElementSibling;
      if(n&&n.classList.contains('det')){n.remove();return}const x=document.createElement('tr');x.className='det';
      x.innerHTML=`<td colspan="${cols.length}">${opts.detail(data[+tr.dataset.i])}</td>`;tr.after(x)});}
  if(opts.filter)document.getElementById(opts.filter).oninput=e=>{flt=e.target.value.toLowerCase();draw()};
  draw();}
// 요약 카드
const dets=D.detections,single=dets.filter(d=>d.category!=='Correlated'),chains=dets.filter(d=>d.category==='Correlated');
const mgrTotal=Object.values(D.mgr).reduce((a,b)=>a+b,0)+D.meta.reduce((a,b)=>a+b.bytes,0);
const perDay=D.span>=600?mgrTotal*86400/D.span:null;
const cards=[[single.length,'탐지(단일)'],[chains.filter(c=>!chains.some(o=>o!==c&&o.attacker&&c.attacker&&o.attacker.ip===c.attacker.ip&&String(o.stages).length>String(c.stages).length&&String(o.stages).startsWith(String(c.stages)))).length,'킬체인(최종)'],[new Set(dets.map(d=>d.attacker&&d.attacker.ip).filter(Boolean)).size,'공격자 IP'],
 [D.asset_mode==='resolver'?D.assets.length:D.signal_ips,D.asset_mode==='resolver'?'자산(판정)':'자산 신호 IP'],[D.assets.filter(a=>a.detections>0).length,'탐지 관련 자산'],
 [fmtB(mgrTotal),'Manager 전송'],[perDay?fmtB(perDay)+'/일':'-','하루 환산'],[(D.sensor.capture_loss_max||0).toFixed(2)+'%','최대 캡처 손실']];
document.getElementById('cards').innerHTML=cards.map(c=>`<div class="card"><div class="v">${esc(c[0])}</div><div class="k">${c[1]}</div></div>`).join('');
// 탐지 막대
const byDiag={};single.forEach(d=>byDiag[d.diagnosis]=(byDiag[d.diagnosis]||0)+1);const mx=Math.max(1,...Object.values(byDiag));
document.getElementById('detbars').innerHTML=Object.keys(byDiag).length?'<table>'+Object.entries(byDiag).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<tr><td style="width:40%">${esc(k)}</td><td class="num" style="width:60px">${v}</td><td><div class="bar" style="width:${100*v/mx}%"></div></td></tr>`).join('')+'</table>':'<span class="mut">탐지 없음</span>';
const evTable=d=>!d.evidence.length?'<span class="mut">근거 없음</span>':'<table>'+'<tr><th>시각</th><th>행위</th><th>출발→대상</th><th>계정</th><th>내용</th></tr>'+d.evidence.map(e=>`<tr><td>${fmtT(e.ts)}</td><td>${esc(e.operation)}</td><td>${esc(e.src)} → ${esc(e.dst)}</td><td>${esc(e.account)}</td><td>${esc(e.detail)}</td></tr>`).join('')+'</table>'+`<div class="note">탐지 ID <code>${esc(d.id)}</code>${d.exception_id?` · 예외 <code>${esc(d.exception_id)}</code>`:''}</div>`;
table('dett',[['시각',d=>fmtT(d.ts),d=>d.ts],['진단',d=>esc(d.diagnosis),d=>d.diagnosis],['기법',d=>esc(d.techniques),d=>d.techniques],
 ['단계',d=>arrow(d.stages),d=>d.stages],['공격자',d=>who(d.attacker),d=>d.attacker?d.attacker.ip:''],
 ['대상',d=>d.victims.map(who).join('<br>')||'-',d=>d.victims.length],['근거',d=>d.evidence_count,d=>d.evidence_count,'num'],
 ['처리',d=>d.disposition?`<span class="sup">${esc(d.disposition)}</span>`:'',d=>d.disposition||'']],single,{detail:evTable,filter:'detf'});
// 킬체인: 상관 탐지는 체인이 한 단계 길어질 때마다 새로 나온다. 기본은 공격자별로 다른 체인의 앞부분이 아닌 것(최종 체인)만.
const finalChains=chains.filter(c=>!chains.some(o=>o!==c&&o.attacker&&c.attacker&&o.attacker.ip===c.attacker.ip&&String(o.stages).length>String(c.stages).length&&String(o.stages).startsWith(String(c.stages))));
const chainCols=[['시각',d=>fmtT(d.ts),d=>d.ts],['단계',d=>`<span class="sus">${arrow(d.stages)}</span>`,d=>d.stages],['기법',d=>arrow(d.techniques),d=>d.techniques],
 ['공격자',d=>who(d.attacker),d=>d.attacker?d.attacker.ip:''],['대상',d=>d.victims.map(who).join('<br>')||'-',d=>d.victims.length],['근거',d=>d.evidence_count,d=>d.evidence_count,'num']];
const drawChains=()=>table('chaint',chainCols,document.getElementById('chainall').checked?chains:finalChains,{detail:evTable});
document.getElementById('chainall').onchange=drawChains;drawChains();

// 공격 스토리 ---------------------------------------------------------------
const STK={'Recon':'정찰','Initial Access':'초기 침투','Command and Control':'C2 통신','Credential Access':'자격증명 탈취','Lateral Movement':'내부 확산','Exfiltration':'유출','Impact':'영향'};
const stIdx=s=>Math.max(0,D.stage_order.indexOf(s));
const whoTxt=w=>w?`${w.ip}${w.name?` (${w.name})`:''}`:'-';
const tipEl=document.getElementById('tip');
function showTip(e,h){tipEl.innerHTML=h;tipEl.style.display='block';const x=Math.min(e.clientX+14,innerWidth-440);tipEl.style.left=x+'px';tipEl.style.top=Math.min(e.clientY+14,innerHeight-tipEl.offsetHeight-8)+'px'}
const hideTip=()=>tipEl.style.display='none';
const dur=s=>s>=3600?`${Math.floor(s/3600)}시간 ${Math.round(s%3600/60)}분`:s>=60?`${Math.round(s/60)}분`:`${Math.round(s)}초`;
const howHtml=d=>(d.facts||[]).map(f=>`<div><b>근거</b> ${esc(f)}</div>`).join('')+(d.ev_accounts&&d.ev_accounts.length?`<div><b>계정</b> ${esc(d.ev_accounts.join(', '))}</div>`:'')+
 (d.how||[]).map(([k,v])=>`<div><b>${esc(k)}</b> ${esc(v)} <i>추정</i></div>`).join('');
const ST=D.stories;
// 열 제목을 두 줄로(단어 단위, 줄당 n자, 넘치면 …)
function wrap2(t,n){const w=t.split(' ');let a='',b='';for(const x of w){if(!b&&(a+(a?' ':'')+x).length<=n)a+=(a?' ':'')+x;else b+=(b?' ':'')+x}
 if(!a){a=t.slice(0,n);b=t.slice(n)}return [a,b.length>n?b.slice(0,n-1)+'…':b]}
const sel=document.getElementById('storysel');
sel.innerHTML=ST.length?ST.map((s,i)=>{const a=s.lanes[0];const st=[...new Set(s.steps.map(j=>D.detections[j].stages))].sort((x,y)=>stIdx(x)-stIdx(y));
 return `<option value="${i}">${s.confirmed.length?'확정 체인':'후보'} · ${esc(whoTxt(a))} · ${st.map(x=>STK[x]||x).join('→')} · 탐지 ${s.steps.length}건</option>`}).join(''):'<option>스토리 없음</option>';
function drawStory(){
 const box=document.getElementById('storysvg'),list=document.getElementById('storylist'),lead=document.getElementById('storylead'),leg=document.getElementById('storyleg');
 if(!ST.length){box.innerHTML='';document.getElementById('storylab').innerHTML='';list.innerHTML='';lead.innerHTML='<span class="mut">탐지가 없습니다.</span>';leg.innerHTML='';return}
 const s=ST[+sel.value||0],conf=new Set(s.confirmed),showC=document.getElementById('storycand').checked;
 const steps=s.steps.filter(j=>showC||!conf.size||conf.has(j)).map(j=>({j,d:D.detections[j],c:conf.has(j)}));
 const used=new Set();steps.forEach(x=>{if(x.d.attacker)used.add(x.d.attacker.ip);x.d.victims.forEach(v=>used.add(v.ip))});
 const lanes=s.lanes.filter(l=>used.has(l.ip)),li={};lanes.forEach((l,i)=>li[l.ip]=i);
 // 열 폭은 화면 폭에 맞춘다(열당 124~280px, 열이 1~2개면 420px까지, 넘치면 가로 스크롤)
 const n=steps.length,avail=Math.max(300,(box.clientWidth||900)-24),CW=Math.max(124,Math.min(n<=2?420:280,Math.floor(avail/Math.max(1,n))));
 const LW=0,LH=48,TOP=78,W=Math.max(1,n)*CW+20,H=TOP+lanes.length*LH+10,wch=Math.max(10,Math.floor((CW-16)/13));
 let g=`<svg width="${W}" height="${H}" role="img" aria-label="공격 스토리 타임라인">`,lab=`<svg width="230" height="${H}" style="max-width:none">`;
 lanes.forEach((l,i)=>{const y=TOP+i*LH+LH/2;g+=`<line class="lane" x1="0" x2="${W-10}" y1="${y}" y2="${y}"/>`;
  lab+=`<text x="4" y="${y-3}">${esc(l.ip)}${l.ext?' <tspan class="mt">외부</tspan>':''}</text><text class="mt" x="4" y="${y+12}">${esc([l.name||l.asset,(l.roles||[]).join(', ')].filter(Boolean).join(' · ').slice(0,34))}</text>`});
 steps.forEach((x,k)=>{const d=x.d,cx=LW+k*CW+CW/2,cls='st'+stIdx(d.stages),cand=x.c?'':' cand';
  const prev=k?steps[k-1].d:null,gap=prev?(d.first||d.ts)-(prev.last||prev.ts):0;
  g+=`<g class="col" data-k="${k}"><rect class="bg" x="${cx-CW/2+2}" y="0" width="${CW-4}" height="${H}" rx="6" fill="transparent"/>`;
  if(gap>=600)g+=`<text class="gap" x="${cx-CW/2}" y="${TOP-54}" text-anchor="middle">+${dur(gap)}</text>`;
  const [l1,l2]=wrap2((d.ko||'').replace(/\\(.*\\)/,''),wch);
  g+=`<text class="mt" x="${cx}" y="${TOP-38}" text-anchor="middle">${fmtT(d.first||d.ts).slice(11)}</text><text x="${cx}" y="${TOP-23}" text-anchor="middle">${esc(l1)}</text><text x="${cx}" y="${TOP-9}" text-anchor="middle">${esc(l2)}</text>`;
  const ay=d.attacker&&li[d.attacker.ip]!==undefined?TOP+li[d.attacker.ip]*LH+LH/2:null;
  // 대상이 여럿이면 공격자 점에서 부채꼴로 퍼지게 그린다(가까운 줄이 왼쪽)
  const vs=ay===null?[]:d.victims.filter(v=>li[v.ip]!==undefined&&v.ip!==(d.attacker&&d.attacker.ip)).sort((a,b)=>Math.abs(li[a.ip]*LH+TOP-ay)-Math.abs(li[b.ip]*LH+TOP-ay));
  const fan=vs.length>1?Math.min(40,(CW-40)/(vs.length-1)):0;
  vs.forEach((v,m)=>{const vy=TOP+li[v.ip]*LH+LH/2,ex=cx+(m-(vs.length-1)/2)*fan,dx=ex-cx,dy=vy-ay,len=Math.hypot(dx,dy)||1;
   g+=`<line class="ar ${cls}${cand}" x1="${(cx+dx/len*9).toFixed(1)}" y1="${(ay+dy/len*9).toFixed(1)}" x2="${(ex-dx/len*6).toFixed(1)}" y2="${(vy-dy/len*6).toFixed(1)}"/><circle class="end ${cls}" cx="${ex.toFixed(1)}" cy="${vy}" r="5"/>`});
  if(ay!==null)g+=`<circle class="mk ${cls}${cand}" cx="${cx}" cy="${ay}" r="9"/>`;
  g+=`<rect class="hit" x="${cx-CW/2+2}" y="0" width="${CW-4}" height="${H}"/></g>`});
 box.innerHTML=g+'</svg>';document.getElementById('storylab').innerHTML=lab+'</svg>';
 box.querySelectorAll('g.col').forEach(el=>{const x=steps[+el.dataset.k],d=x.d;
  el.onmousemove=e=>showTip(e,`<b>${esc(d.ko)}</b> <span class="mut">${esc(STK[d.stages]||d.stages)} · ${esc(d.techniques)}${x.c?' · 확정 체인':' · 체인 밖'}</span><br>${fmtT(d.first||d.ts)}${d.last&&d.last-d.first>=1?` ~ ${fmtT(d.last).slice(11)}`:''}<br>${who(d.attacker)} → ${d.victims.map(who).join(', ')||'-'}<br>근거 ${d.evidence_count}건${!(d.ev_accounts&&d.ev_accounts.length)&&d.accounts&&d.accounts.length?` · 계정(추정) ${esc(d.accounts.slice(0,3).join(', '))}`:''}<div class="how">${howHtml(d)}</div>`);
  el.onmouseleave=hideTip;el.onclick=()=>{const li2=list.children[+el.dataset.k];if(li2){[...list.children].forEach(c=>c.classList.remove('on'));li2.classList.add('on');li2.scrollIntoView({block:'nearest',behavior:'smooth'})}}});
 const stUsed=[...new Set(steps.map(x=>x.d.stages))].sort((a,b)=>stIdx(a)-stIdx(b));
 leg.innerHTML=stUsed.map(x=>`<span class="st${stIdx(x)}"><span class="sw"></span>${esc(STK[x]||x)}</span>`).join('')+'<span class="stn" style="margin-left:8px"><span class="sw"></span>확정 체인</span><span class="stn"><span class="sw cand"></span>체인 밖(후보)</span>';
 const t0=steps.length?(steps[0].d.first||steps[0].d.ts):0,t1=steps.length?Math.max(...steps.map(x=>x.d.last||x.d.ts)):0;
 const intH=lanes.filter(l=>!l.ext).length,extH=lanes.filter(l=>l.ext).length;
 lead.innerHTML=`<b>${esc(whoTxt(s.lanes[0]))}</b>에서 시작해 ${fmtT(t0)}부터 약 ${dur(Math.max(0,t1-t0))} 동안 ${stUsed.map(x=>STK[x]||x).join(' → ')} (탐지 ${steps.length}건, 관련 내부 host ${intH}대, 외부 ${extH}곳).`+
  (s.chains.length?` <span class="mut">상관 체인 ${s.chains.length}개: <code>${esc(s.chains.slice(-1)[0])}</code>${s.chains.length>1?' 등':''}</span>`:' <span class="mut">상관 규칙이 이은 체인은 없습니다.</span>');
 list.innerHTML=steps.map(x=>{const d=x.d;const tg=d.victims.length?` → ${d.victims.slice(0,4).map(who).join(', ')}${d.victims.length>4?` 외 ${d.victims.length-4}`:''}`:'';
  return `<li class="st${stIdx(d.stages)}"><span class="sw${x.c?'':' cand'}"></span><span class="t">${fmtT(d.first||d.ts)}</span>${who(d.attacker)} <b>${esc(d.ko)}</b>${tg} <span class="mut">· ${esc(STK[d.stages]||d.stages)} · ${esc(d.techniques)} · 근거 ${d.evidence_count}건${x.c?'':' · 체인 밖'}</span><div class="how">${howHtml(d)||'<span class="mut">근거·선별 전송 기록 없음</span>'}</div></li>`}).join('');
}
table('storycov',[['단계',r=>esc(STK[r.stage]||r.stage),r=>stIdx(r.stage)],['탐지',r=>esc(r.ko),r=>r.ko],['건수',r=>r.n,r=>r.n,'num'],
 ['근거 내용',r=>`${r.facts}/${r.n}`,r=>r.facts/r.n,'num'],['근거 계정',r=>`${r.eacct}/${r.n}`,r=>r.eacct/r.n,'num'],
 ['추정 근거',r=>`${r.how}/${r.n}`,r=>r.how/r.n,'num'],['추정 계정',r=>`${r.acct}/${r.n}`,r=>r.acct/r.n,'num'],
 ['외부 대상 이름(SNI·Host)',r=>r.ext?`${r.ext_named}/${r.ext}`:'-',r=>r.ext?r.ext_named/r.ext:-1,'num'],
 ['근거 행 uid',r=>r.ev?`${r.ev_uid}/${r.ev}`:'-',r=>r.ev?r.ev_uid/r.ev:-1,'num']],D.coverage);
sel.onchange=drawStory;document.getElementById('storycand').onchange=drawStory;drawStory();
let rsz;addEventListener('resize',()=>{clearTimeout(rsz);rsz=setTimeout(drawStory,150)});
// 자산
const roleChips=a=>a.roles.map(r=>`<span class="chip">${esc(r)}</span>`).join('');
table('ast',[['관련 탐지',a=>a.detections?`<span class="sus">${a.detections}</span>`:'0',a=>a.detections,'num'],['이름',a=>esc(a.name)||`<span class="mut">${esc(a.id)||'-'}</span>`,a=>a.name||a.id],
 ['식별 키',a=>esc(a.key),a=>a.key],['IP',a=>a.ips.map(esc).join('<br>'),a=>a.ips.join()],['MAC',a=>a.macs.map(esc).join('<br>'),a=>a.macs.join()],
 ['OS',a=>esc(a.os),a=>a.os],['역할',roleChips,a=>a.roles.join()],['신호',a=>a.signals,a=>a.signals,'num']],D.assets,{filter:'asf'});
document.getElementById('asnote').innerHTML=D.asset_mode==='resolver'
 ?`자산 판정은 claudtest2 리졸버 결과입니다. 근거 신호 타임라인·식별 품질은 ${D.asset_report?`<a href="${esc(D.asset_report)}">자산 리포트</a>`:'자산 리포트'}를 보세요.`
 :`자산 판정 없이 IP별 신호만 보여 줍니다(run_pcap.sh -r &lt;claudtest2 경로&gt; 를 주면 자산 단위로 묶습니다). 신호 ${D.signal_rows}행: `+D.signal_counts.map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join('');
// 전송량
const mm=Math.max(1,...D.meta.map(m=>m.bytes));const mt=D.meta.reduce((a,b)=>a+b.bytes,0);
document.getElementById('xft').innerHTML=`<table><tr><th>구분</th><th class="num">바이트</th><th></th></tr>
 <tr><td><b>Manager 전송 합계</b></td><td class="num"><b>${fmtB(mgrTotal)}</b></td><td>${perDay?`하루 환산 약 ${fmtB(perDay)}/일 (단순 비례, 짧은 캡처는 과대평가)`:''}</td></tr>
 <tr><td>선별 전송(/log/zeek/meta)</td><td class="num">${fmtB(mt)}</td><td></td></tr>
 <tr><td>자산 신호(asset_signal)</td><td class="num">${fmtB(D.mgr.asset_signal)}</td><td></td></tr>
 <tr><td>탐지 로그(탐지·근거·예외)</td><td class="num">${fmtB(D.mgr.nsm_detection+D.mgr.evidence+D.mgr.nsm_exception)}</td><td></td></tr>
 <tr><td class="mut">센서 로컬 로그(notice·stats 등, 전송 안 함)</td><td class="num mut">${fmtB(Object.values(D.local).reduce((a,b)=>a+b,0))}</td><td></td></tr></table>
 <h2 style="margin-top:14px">선별 전송 로그별</h2><table><tr><th>로그</th><th class="num">바이트</th><th class="num">행</th><th></th></tr>`+
 D.meta.map(m=>`<tr><td>${esc(m.name)}</td><td class="num">${fmtB(m.bytes)}</td><td class="num">${m.rows.toLocaleString()}</td><td style="width:40%"><div class="bar" style="width:${100*m.bytes/mm}%"></div></td></tr>`).join('')+'</table>'+
 '<div class="note">전체 Zeek 로그 대비 비율과 처리 부하는 tests/measure_meta_export.sh 로 잽니다.</div>';
// 예외
const ek={};D.exceptions.forEach(e=>{const k=e.exception_id;ek[k]=ek[k]||{id:k,kinds:new Set(),hits:0,disp:e.disposition||'',scope:e.scope||'',msg:''};
 ek[k].kinds.add(e.kind);if(e.kind==='hits')ek[k].hits+=e.hits||0;if(e.scope)ek[k].scope=e.scope;if(e.disposition)ek[k].disp=e.disposition;if(e.msg&&e.kind!=='hits')ek[k].msg=e.msg});
table('exct',[['예외 ID',e=>`<code>${esc(e.id)}</code>`,e=>e.id],['상태',e=>[...e.kinds].filter(k=>k!=='hits').map(k=>`<span class="chip ${k==='rejected'||k==='error'?'sus':''}">${esc(k)}</span>`).join(''),e=>[...e.kinds].join()],
 ['처리',e=>esc(e.disp),e=>e.disp],['범위',e=>esc(e.scope),e=>e.scope],['적중(관측 수)',e=>e.hits.toLocaleString(),e=>e.hits,'num'],['비고',e=>esc(e.msg),e=>e.msg]],Object.values(ek));
// 센서
const S=D.sensor;document.getElementById('sent').innerHTML=`<table>
 <tr><td>최대 캡처 손실</td><td>${(S.capture_loss_max||0).toFixed(2)}% ${S.capture_loss_max>1?'<span class="sus">미러 손실 확인 필요</span>':''}</td></tr>
 <tr><td>탐지 외 notice</td><td>${S.other_notices.map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join('')||'-'}</td></tr>
 <tr><td>Zeek 경고·오류</td><td>${S.warnings.length?S.warnings.map(w=>`<div class="sus"><code>${esc(w)}</code></div>`).join(''):'없음'}</td></tr></table>`;
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zeek_dir")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--assets", help="리졸버 assets.json(있으면 자산 단위)")
    ap.add_argument("--asset-report", help="리포트에서 링크할 자산 리포트 경로(report.html 기준 상대 경로)")
    ap.add_argument("--pcap", default="")
    ap.add_argument("--elapsed", type=int, default=0)
    ap.add_argument("--tz", type=float, default=9, help="표시 시간대 UTC 오프셋(시), 기본 9(KST)")
    ap.add_argument("--nets", default="", help="내부 대역(쉼표 구분, run_pcap.sh -n 과 같음). 사설 대역은 항상 내부로 본다")
    args = ap.parse_args()
    data = collect(args.zeek_dir, args.assets, args)
    blob = json.dumps(data, ensure_ascii=False, default=list).replace("</", "<\\/")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(PAGE.replace("__DATA__", blob))
    print(f"통합 리포트: {args.out} (탐지 {len(data['detections'])}건, 자산 {len(data['assets'])}개, 공격 스토리 {len(data['stories'])}개)")
    if data["coverage"]:
        # 주소·이름 원문 없이 숫자만(공유해도 되는 형태)
        print("  스토리 근거 연결률(탐지 종류: 건수 | 근거 계정 | 추정 근거 | 추정 계정 | 외부 이름 | 근거 uid)")
        for r in data["coverage"]:
            ext = f"{r['ext_named']}/{r['ext']}" if r["ext"] else "-"
            evu = f"{r['ev_uid']}/{r['ev']}" if r["ev"] else "-"
            print(f"    {r['name']:20s} {r['n']:4d} | {r['eacct']:4d} | {r['how']:4d} | {r['acct']:4d} | {ext:>7s} | {evu:>9s}")


if __name__ == "__main__":
    sys.exit(main())
