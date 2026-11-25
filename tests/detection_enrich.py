#!/usr/bin/env python3
"""탐지 정보 보강 PoC: docs/DETECTION_ENRICH_SPEC.md 의 규칙을 그대로 구현한다.

탐지(nsm_detection) 한 건과 근거(evidence)로 선별 전송 로그(meta/*)를 조회해 탐지 상세의
한눈에 보기(판단 4종)·핵심 사실·추이·기록(정확 일치·같은 연결 묶음·같은 시간대)을 만든다.

룰별 코드는 없다. 조회 4개(Q1~Q4) · 로그별 요약기 · 판단 4개가 모든 룰에 같고,
룰마다 다른 점은 RULES 설정 표 한 줄(보여 줄 로그, Kerberos 서비스 접두사, 조회 방식, 시간 범위, 성공 판단)이다.

  idx = Index.load(meta_paths)                 # {로그 이름: 경로}
  out = enrich(det, idx, internal)             # det: report_pcap 의 탐지 항목(근거 포함)
"""
import bisect
import collections
import json
import os

ROW_LOGS = ("kerberos", "ntlm", "smb_mapping", "smb_files", "dce_rpc", "rdp", "ssh", "ssl", "http")
SUM_LOGS = ("flow_summary", "dns_summary", "http_ua_summary")
LOGS = ROW_LOGS + SUM_LOGS

NEAR = 600            # Q4 같은 시간대: 탐지 앞뒤 10분
FLOW_BEFORE = 1800    # Q2 flow_summary 는 주기(30분) 첫 연결 시각이라 30분 더 앞부터
DNS_BEFORE = 3600     # Q3 목적지 이름: 탐지 1시간 전부터
ACCT_WIN = 3600       # 계정 맥락: 앞뒤 1시간
LIVE_AFTER = 60       # 지금도 통신 중: 탐지 마지막 시각 1분 뒤부터 보인 통신
# 센서 중복 억제(SRS_METADATA_EXPORT 4.1): 근거 uid 의 행이 없을 때 같은 키의 앞선 행을 같은 연결 묶음으로 본다
DEDUP = {"ssl": 86400, "http": 600, "smb_mapping": 3600}
MAX_ROWS = 200        # 로그별 요약에 쓰는 행 상한
MAX_RECORDS = 50      # 기록 표 한 종류의 행 상한
MAX_HOSTS = 10

L_ALL = ("ntlm", "kerberos", "smb_mapping", "smb_files", "dce_rpc", "flow_summary")
SMB_K = ("cifs/", "host/")


def _r(logs, kpre=None, query="ip", window="near", result="any"):
    return {"logs": logs, "kpre": kpre, "query": query, "window": window, "result": result}


# 룰 설정 표(스펙 6장). logs: 핵심 사실에 올릴 로그와 순서. kpre: Kerberos 행을 거르는 서비스(SPN) 접두사
#   (None = 대상으로 간 행만, () = 대상과 무관하게 출발지의 모든 TGS·AS 행: 자격증명 탐지는 요청 자체가 근거).
#   query: ip | domain(DNS 계열은 dns_summary 를 도메인으로). window: near | agg(집계형, 근거 window_s 만큼 앞으로).
#   result: any | web(웹 공격은 같은 연결에서 오류 뒤 2xx 일 때만 성공 표시, 2xx 만이면 판단 안 함)
RULES = {
    "Port_Scan": _r(("flow_summary",), window="agg"),
    "Host_Scan": _r(("flow_summary",), window="agg"),
    "AD_Enumeration": _r(L_ALL, SMB_K, window="agg"),
    "SQL_Injection": _r(("http", "flow_summary"), result="web"),
    "Cross_Site_Scripting": _r(("http", "flow_summary"), result="web"),
    "Webshell_Access": _r(("http", "flow_summary")),
    "TLS_Heartbleed": _r(("ssl", "flow_summary")),
    "AI_Service_Exploit": _r(("http", "flow_summary"), result="web"),
    "HTTP_Beaconing": _r(("http", "http_ua_summary", "flow_summary"), window="agg"),
    "TLS_Beaconing": _r(("ssl", "flow_summary"), window="agg"),
    "Encrypted_C2": _r(("ssl", "flow_summary")),
    "DGA_Domain": _r(("dns_summary",), query="domain", window="agg"),
    "DNS_Tunneling": _r(("dns_summary",), query="domain", window="agg"),
    "Nonstandard_Port": _r(("ssl", "http", "flow_summary")),
    "Long_Connection": _r(("ssl", "flow_summary")),
    "Unknown_Protocol": _r(("flow_summary",)),
    "AI_API_From_Server": _r(("ssl", "http", "http_ua_summary", "flow_summary")),
    "IOC_Match": _r(("ssl", "http", "dns_summary", "flow_summary")),
    "NTLM_Spray": _r(("ntlm", "flow_summary"), window="agg"),
    "Kerberos_Spray": _r(("kerberos", "flow_summary"), (), window="agg"),
    "Kerberos_Bruteforce": _r(("kerberos", "flow_summary"), (), window="agg"),
    "Kerberoasting": _r(("kerberos", "flow_summary"), (), window="agg"),
    "ASREP_Roasting": _r(("kerberos", "flow_summary"), (), window="agg"),
    "Name_Poisoning": _r(("flow_summary",)),
    "SSH_Bruteforce": _r(("ssh", "flow_summary"), window="agg"),
    "FTP_Bruteforce": _r(("flow_summary",), window="agg"),
    "HTTP_Bruteforce": _r(("http", "flow_summary"), window="agg"),
    "Machine_Account_Misuse": _r(("ntlm", "kerberos", "flow_summary"), ()),
    "Coerced_Authentication": _r(L_ALL, SMB_K),
    "Remote_Registry_Dump": _r(L_ALL, SMB_K),
    "NTLM_Credential_Leak": _r(("ntlm", "smb_mapping", "flow_summary")),
    "DCSync": _r(("dce_rpc", "kerberos", "flow_summary"), ("e3514235-4b06-11d1-ab04-00c04fc2dcd2/", "ldap/")),
    "Zerologon_Attempt": _r(("dce_rpc", "flow_summary"), window="agg"),
    "SMB_Admin_Share": _r(L_ALL, SMB_K, window="agg"),
    "RDP_Lateral": _r(("ntlm", "kerberos", "rdp", "flow_summary"), ("termsrv/",), window="agg"),
    "SSH_Lateral": _r(("ssh", "flow_summary"), window="agg"),
    "WinRM_Lateral": _r(("ntlm", "kerberos", "flow_summary"), ("http/", "wsman/"), window="agg"),
    "DCOM_Lateral": _r(("ntlm", "kerberos", "dce_rpc", "flow_summary"), ("rpcss/", "host/"), window="agg"),
    "Remote_Service_Creation": _r(L_ALL, SMB_K + ("rpcss/",)),
    "Remote_Task_Creation": _r(L_ALL, SMB_K + ("rpcss/",)),
    "Remote_WMI_Execution": _r(("ntlm", "kerberos", "dce_rpc", "flow_summary"), ("rpcss/", "host/")),
    "Exfil_Large_Transfer": _r(("ssl", "http", "flow_summary")),
    "Exfil_Volume_Aggregate": _r(("ssl", "http", "flow_summary"), window="agg"),
    "Exfil_Web_Upload": _r(("ssl", "http", "flow_summary"), window="agg"),
    "Exfil_DNS": _r(("dns_summary",), query="domain", window="agg"),
    "Outbound_SMB": _r(("ntlm", "smb_mapping", "flow_summary")),
    "AI_Service_Upload": _r(("ssl", "http", "http_ua_summary", "flow_summary"), window="agg"),
    "SMB_Ransomware": _r(("ntlm", "kerberos", "smb_mapping", "smb_files", "flow_summary"), ("cifs/",), window="agg"),
}
DEFAULT = _r(("flow_summary",))


# ---------------------------------------------------------------- 색인
def _rows(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("{"):
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(r.get("ts"), (int, float)):
                        out.append(r)
    return out


class Index:
    """스펙 8장의 색인: 행 단위 로그 uid, (출발지, 시각), 요약 로그 (출발지, 시각). 소급검색용 지표 색인과는 별개."""

    def __init__(self):
        self.by_uid = collections.defaultdict(list)          # uid -> [(로그, 행)]
        self.by_src = collections.defaultdict(list)          # (로그, 출발지) -> 시각순 [(ts, 행)]
        self.by_user = collections.defaultdict(list)         # 소문자 계정 -> [(ts, 로그, 행)]  (kerberos·ntlm)
        self.present = set()                                 # 파일이 있는 로그(없으면 "기록 없음"과 "수집 안 함"을 구분)
        self.ts = {}                                         # (로그, 출발지) -> 시각 목록(이분 탐색)

    @classmethod
    def load(cls, paths):
        ix = cls()
        for log in LOGS:
            p = paths.get(log)
            if not p or not os.path.exists(p):
                continue
            ix.present.add(log)
            for r in _rows(p):
                src = r.get("orig_h")
                if src:
                    ix.by_src[(log, src)].append((r["ts"], r))
                if log in ROW_LOGS and r.get("uid"):
                    ix.by_uid[r["uid"]].append((log, r))
                u = _user(log, r)
                if u:
                    ix.by_user[u].append((r["ts"], log, r))
        for k, v in ix.by_src.items():
            v.sort(key=lambda x: x[0])
            ix.ts[k] = [x[0] for x in v]
        return ix

    def between(self, log, src, t0, t1):
        v = self.by_src.get((log, src), [])
        i = bisect.bisect_left(self.ts.get((log, src), []), t0)
        j = bisect.bisect_right(self.ts.get((log, src), []), t1)
        return [r for _, r in v[i:j]]

    def after(self, log, src, t):
        return [r for ts, r in self.by_src.get((log, src), []) if ts > t]


def _user(log, r):
    if log == "kerberos" and r.get("client"):
        return str(r["client"]).split("/")[0].split("@")[0].lower()
    if log == "ntlm" and r.get("username"):
        return str(r["username"]).lower()
    return None


def _acct_user(a):
    a = str(a).split(",")[0].strip()
    return a.split("\\")[-1].split("@")[0].split("/")[0].lower() if a else ""


# ---------------------------------------------------------------- 표기
def fmt_bytes(b):
    b = b or 0
    return f"{b / 1e6:,.1f}MB" if b >= 1e6 else f"{b / 1e3:,.1f}KB" if b >= 1e3 else f"{b}B"


def _top(vals, n=3):
    c = collections.Counter(v for v in vals if v not in (None, ""))
    if not c:
        return ""
    items = [f"{k} {v}번" if v > 1 else str(k) for k, v in c.most_common(n)]
    return ", ".join(items) + (f" 외 {len(c) - n}개" if len(c) > n else "")


def _runs(vals):
    """시각순 값을 연속 구간으로: [500,500,200] -> "500 × 2 → 200"."""
    out = []
    for v in vals:
        if out and out[-1][0] == v:
            out[-1][1] += 1
        else:
            out.append([v, 1])
    s = " → ".join(f"{v} × {n}" if n > 1 else str(v) for v, n in out[:6])
    return s + (" → …" if len(out) > 6 else "")


def _states(rows):
    c = collections.Counter()
    for r in rows:
        for part in str(r.get("states") or "").split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                try:
                    c[k] += int(v)
                except ValueError:
                    pass
    return c


def _dom_match(domain, names):
    d = str(domain or "").lower()
    return d and any(n == d or n.endswith("." + d) for n in names)


def line(log, r):
    """기록 표 한 줄(사람이 읽는 내용)."""
    g = r.get
    if log == "http":
        return f"{g('method', '')} {g('host') or '(Host 없음)'}{g('uri_path') or ''} → {g('status_code', '-')} ({fmt_bytes(g('response_body_len'))})"
    if log == "ssl":
        return f"TLS {g('server_name') or 'SNI 없음'} · {g('version', '-')} · {'핸드셰이크 완료' if g('established') else '핸드셰이크 미완료'}"
    if log == "kerberos":
        return f"{g('request_type', '')} {str(g('client') or '-').split('/')[0]} → {g('service') or '-'} · {g('cipher') or '-'} · {'성공' if g('success') else '실패 ' + str(g('error_msg') or '')}"
    if log == "ntlm":
        return f"로그인 {(g('domainname') + chr(92)) if g('domainname') else ''}{g('username') or '-'} · {'성공' if g('success') else '실패' if g('success') is False else '결과 모름'}"
    if log == "smb_mapping":
        return f"공유 연결 {g('path') or '-'}"
    if log == "smb_files":
        act = str(g("action") or "").replace("SMB::FILE_", "").lower()
        return f"파일 {act} {g('prev_name') + ' → ' if g('prev_name') else ''}{g('name') or ''}"
    if log == "dce_rpc":
        return f"원격 호출 {g('endpoint')}::{g('operation')}"
    if log == "rdp":
        return f"RDP {g('cookie') or '-'} · {g('result') or '-'}"
    if log == "ssh":
        return f"SSH {g('client') or '-'} · 인증 시도 {g('auth_attempts', '-')} · {'성공' if g('auth_success') else '실패' if g('auth_success') is False else '결과 모름'}"
    if log == "flow_summary":
        return f"{g('resp_p')}/{g('proto', '')} {g('conns', 0)}번 연결 · 보냄 {fmt_bytes(g('orig_bytes'))} · 상태 {g('states') or '-'}"
    if log == "dns_summary":
        return f"DNS {g('domain')} {g('queries', 0)}번 · 이름 {g('unique_names', 0)}개 · {g('rcodes') or '-'}"
    if log == "http_ua_summary":
        return f"User-Agent {g('user_agent')} · 요청 {g('requests', 0)}"
    return ""


# ---------------------------------------------------------------- 요약기(스펙 4장): 로그 하나 -> [(항목, 값)]
def summarize(log, rows):
    rows = sorted(rows, key=lambda r: r["ts"])[:MAX_ROWS]
    if not rows:
        return []
    out = []
    add = lambda k, v: v and out.append((k, v))
    if log == "http":
        add("요청 경로", _top([r.get("uri_path") for r in rows]))
        hosts = {r.get("host") for r in rows if r.get("host")}
        if len(hosts) > 1:
            add("Host", _top([r.get("host") for r in rows]))
        add("상태 코드", _runs([r.get("status_code", "-") for r in rows]))
        add("가장 큰 응답", fmt_bytes(max(r.get("response_body_len") or 0 for r in rows)))
    elif log == "ssl":
        sn = [r.get("server_name") or "SNI 없음" for r in rows]
        add("접속 도메인", _top(sn))
        est = sum(1 for r in rows if r.get("established"))
        add("TLS", f"{_top([r.get('version') for r in rows], 2) or '-'} · 핸드셰이크 완료 {est}/{len(rows)}")
        add("JA3", _top([r.get("ja3") for r in rows], 1))
    elif log == "kerberos":
        add("요청 서비스", _top([r.get("service") for r in rows]))
        add("티켓 암호", _top([r.get("cipher") for r in rows], 2))
        ok = sum(1 for r in rows if r.get("success"))
        err = _top([r.get("error_msg") for r in rows if not r.get("success")], 2)
        add("결과", f"성공 {ok} · 실패 {len(rows) - ok}" + (f" ({err})" if err else ""))
        add("계정", _top([str(r.get("client") or "").split("/")[0] for r in rows], 3))
    elif log == "ntlm":
        add("계정", _top([f"{(r.get('domainname') + chr(92)) if r.get('domainname') else ''}{r.get('username') or ''}" for r in rows if r.get("username")]))
        ok = sum(1 for r in rows if r.get("success") is True)
        bad = sum(1 for r in rows if r.get("success") is False)
        if ok or bad:
            add("결과", f"성공 {ok} · 실패 {bad}")
    elif log == "smb_mapping":
        add("공유", _top([r.get("path") for r in rows]))
    elif log == "smb_files":
        add("파일 동작", _top([str(r.get("action") or "").replace("SMB::FILE_", "").lower() for r in rows], 4))
        ex = [f"{r['prev_name']} → {r.get('name')}" if r.get("prev_name") else str(r.get("name")) for r in rows if r.get("name")]
        add("파일 예", ", ".join(list(dict.fromkeys(ex))[:2]) + (f" 외 {len(set(ex)) - 2}개" if len(set(ex)) > 2 else ""))
    elif log == "dce_rpc":
        calls = list(dict.fromkeys(f"{r.get('endpoint')}::{r.get('operation')}" for r in rows))
        add("원격 호출", " → ".join(calls[:4]) + (f" 외 {len(calls) - 4}개" if len(calls) > 4 else ""))
    elif log == "rdp":
        add("접속 계정 힌트", _top([r.get("cookie") for r in rows]))
        add("결과", _top([r.get("result") for r in rows], 2))
    elif log == "ssh":
        att = sum(r.get("auth_attempts") or 0 for r in rows)
        ok = sum(1 for r in rows if r.get("auth_success") is True)
        add("인증", f"시도 {att} · 성공한 연결 {ok}/{len(rows)}")
        add("클라이언트", _top([r.get("client") for r in rows], 2))
    elif log == "flow_summary":
        conns = sum(r.get("conns") or 0 for r in rows)
        add("연결", f"{conns:,}번 · 보냄 {fmt_bytes(sum(r.get('orig_bytes') or 0 for r in rows))} · 받음 {fmt_bytes(sum(r.get('resp_bytes') or 0 for r in rows))}")
        st = _states(rows)
        add("연결 상태", " · ".join(f"{k} {v}" for k, v in st.most_common(4)))
        ports = {(r.get("resp_p"), r.get("proto")) for r in rows}
        dsts = {r.get("resp_h") for r in rows}
        if len(ports) > 3 or len(dsts) > 1:
            add("범위", f"대상 {len(dsts)}개 · 포트 {len(ports)}개")
        else:
            add("포트", ", ".join(f"{p}/{pr}" for p, pr in sorted(ports, key=str)))
    elif log == "dns_summary":
        names = []
        for r in rows:
            names += [str(x) for x in (r.get("sample_names") or [])]
        add("질의 이름 예", ", ".join(list(dict.fromkeys(names))[:2]))
        add("고유 이름", f"{sum(r.get('unique_names') or 0 for r in rows):,}개 / 질의 {sum(r.get('queries') or 0 for r in rows):,}번")
        rc = collections.Counter()
        for r in rows:
            for part in str(r.get("rcodes") or "").split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    rc[k] += int(v) if v.isdigit() else 0
        add("결과", " · ".join(f"{k} {v}" for k, v in rc.most_common(3)))
        ans = []
        for r in rows:
            ans += [str(x) for x in (r.get("answers") or [])]
        add("응답", ", ".join(list(dict.fromkeys(ans))[:3]))
    elif log == "http_ua_summary":
        c = collections.Counter()
        for r in rows:
            c[r.get("user_agent")] += r.get("requests") or 0
        add("프로그램(User-Agent)", ", ".join(f"{k} (요청 {v:,})" for k, v in c.most_common(2)))
    return out


# ---------------------------------------------------------------- 판단(스펙 5장)
def _signals(log, rows, result_mode):
    """성공·실패 표시 수."""
    ok = bad = 0
    if log == "http":
        if result_mode == "web":
            by = collections.defaultdict(list)
            for r in rows:
                by[r.get("uid") or id(r)].append(r)
            for rs in by.values():
                codes = [int(r.get("status_code") or 0) for r in sorted(rs, key=lambda r: r["ts"])]
                err = [i for i, c in enumerate(codes) if c >= 400]
                if err and any(200 <= c < 400 for c in codes[err[0]:]):
                    ok += 1
                elif err:
                    bad += 1
        else:
            for r in rows:
                c = int(r.get("status_code") or 0)
                ok += 200 <= c < 400
                bad += c >= 400
    elif log in ("kerberos", "ntlm"):
        ok = sum(1 for r in rows if r.get("success") is True)
        bad = sum(1 for r in rows if r.get("success") is False)
    elif log == "ssh":
        ok = sum(1 for r in rows if r.get("auth_success") is True)
        bad = sum(1 for r in rows if r.get("auth_success") is False)
    elif log == "ssl":
        ok = sum(1 for r in rows if r.get("established") is True)
        bad = sum(1 for r in rows if r.get("established") is False)
    elif log == "rdp":
        ok = sum(1 for r in rows if str(r.get("result") or "").lower() == "success")
    elif log == "smb_files":
        ok = len(rows)
    elif log == "flow_summary":
        st = _states(rows)
        ok = st.get("SF", 0)
        bad = st.get("S0", 0) + st.get("REJ", 0)
    return ok, bad


def _windows(det, cfg):
    first = det.get("first") or det["ts"]
    last = det.get("last") or det["ts"]
    if cfg["window"] == "agg":
        w = max([e.get("window_s") or 0 for e in det.get("evidence", [])] + [NEAR])
        first = min(first, (det.get("first") or det["ts"]) - w + NEAR)
    return first, last


def rule_of(det, diag_note):
    """탐지의 룰 이름: 근거 note(NSM::<룰>) > 진단명 마지막 토큰을 DIAG_NOTE 로 역변환."""
    for e in det.get("evidence", []):
        n = str(e.get("note") or "")
        if n.startswith("NSM::") and n[5:] in RULES:
            return n[5:]
    tail = str(det.get("diagnosis") or "").split(".")[-1]
    return next((k for k, v in diag_note.items() if v == tail), None)


def enrich(det, idx, rule, internal=lambda ip: True):
    """탐지 한 건 -> 스펙 7장 형식(dict). 근거 연결·요약 로그가 하나도 없으면 빈 dict."""
    cfg = RULES.get(rule, DEFAULT)
    src = (det.get("attacker") or {}).get("ip")
    if not src:
        return {}
    evs = det.get("evidence", [])
    # 대상: 탐지 요약의 victims, 없으면(비커닝 등) 근거의 dst
    vic = [v["ip"] for v in det.get("victims", []) if v.get("ip")] or list(dict.fromkeys(e["dst"] for e in evs if e.get("dst") and e.get("dst") != src))
    vset = set(vic)
    names = sorted({str(e["dst_name"]).lower() for e in evs if e.get("dst_name")})
    first, last = _windows(det, cfg)
    logs = cfg["logs"]
    kpre = cfg["kpre"]

    def to_dst(log, r):
        if log == "kerberos" and kpre is not None:
            svc = str(r.get("service") or "").lower()
            return not kpre or any(svc.startswith(p) for p in kpre)
        return not vset or r.get("resp_h") in vset

    # Q1 근거 uid 와 같은 행(정확)
    uids = list(dict.fromkeys(e["uid"] for e in evs if e.get("uid")))
    exact, seen = [], set()
    for u in uids:
        for log, r in idx.by_uid.get(u, []):
            if id(r) not in seen:
                seen.add(id(r))
                exact.append((log, r))
    # Q1 대체: 센서 중복 억제로 근거 uid 의 행이 없으면 같은 키의 앞선 행(같은 연결 묶음)
    grouped = []
    have = {log for log, _ in exact}
    for log, span in DEDUP.items():
        if log not in logs or log in have:
            continue
        for e in evs:
            if not e.get("uid") or (e.get("src") or src) != src:
                continue
            t = e.get("ts") or det["ts"]
            for r in idx.between(log, src, t - span, t):
                key_ok = (r.get("resp_h") == e.get("dst")) or (log == "ssl" and names and str(r.get("server_name") or "").lower() in names) \
                    or (log == "http" and names and str(r.get("host") or "").lower() in names)
                if key_ok and id(r) not in seen:
                    seen.add(id(r))
                    grouped.append((log, r))
    # Q4 같은 시간대(추정): 출발지·대상, 앞뒤 10분(집계형은 집계 창부터)
    nearby = []
    for log in ROW_LOGS:
        if log not in logs:
            continue
        for r in idx.between(log, src, first - NEAR, last + NEAR):
            if id(r) not in seen and to_dst(log, r):
                seen.add(id(r))
                nearby.append((log, r))
    # Q2 연결 요약
    flow = [r for r in idx.between("flow_summary", src, first - FLOW_BEFORE, last + NEAR) if not vset or r.get("resp_h") in vset] \
        if "flow_summary" in logs else []
    # Q3 DNS: DNS 계열은 도메인으로, 그 밖은 목적지 이름 붙이기용
    dns = []
    if "dns_summary" in logs or cfg["query"] == "domain":
        dns = [r for r in idx.between("dns_summary", src, first - FLOW_BEFORE, last + NEAR)
               if (cfg["query"] == "domain" and _dom_match(r.get("domain"), names + [str(v).lower() for v in vic]))
               or (cfg["query"] == "ip" and set(map(str, r.get("answers") or [])) & vset)]
    ua = idx.between("http_ua_summary", src, first - 86400, last + NEAR) if "http_ua_summary" in logs else []

    # ---- 핵심 사실: 보여 줄 로그 순서대로, 그 로그의 행(Q1·대체·Q4 + 요약 로그)을 요약기에 넘긴다
    by_log = collections.defaultdict(list)
    for log, r in exact + grouped + nearby:
        by_log[log].append(r)
    by_log["flow_summary"] += flow
    by_log["dns_summary"] += dns
    by_log["http_ua_summary"] += ua
    facts = []
    for log in logs:
        for k, v in summarize(log, by_log.get(log, [])):
            facts.append({"log": log, "label": k, "value": v[:200], "rows": len(by_log[log])})

    # ---- 판단
    judge = {}
    ok = bad = 0
    why = []
    # 행 단위 로그의 성공·실패 표시를 먼저 쓰고, 하나도 없을 때만 연결 상태(flow_summary)를 쓴다
    #   (Kerberos·SMB 탐지에서 연결이 정상 종료됐다는 것만으로 성공이라 하지 않게)
    for group in ([x for x in logs if x in ROW_LOGS], ["flow_summary"] if "flow_summary" in logs else []):
        for log in group:
            o, b = _signals(log, by_log.get(log, []), cfg["result"])
            ok, bad = ok + o, bad + b
            if o or b:
                why.append(f"{log} 성공 {o}·실패 {b}")
        if ok or bad:
            break
    if ok or bad:
        judge["result"] = {"level": "hi" if ok and not bad else "mid" if ok else "no", "ok": ok, "bad": bad, "why": " · ".join(why)}
    if cfg["query"] == "domain" and dns:
        # DNS 계열: 대상이 도메인이라 같은 도메인의 dns_summary 행으로 본다
        later = [r["ts"] for r in idx.after("dns_summary", src, last + LIVE_AFTER) if _dom_match(r.get("domain"), names + [str(v).lower() for v in vic])]
        judge["live"] = {"on": bool(later), "last_seen": max(later or [r.get("ts_end") or r["ts"] for r in dns])}
    elif vset and (flow or exact or grouped or nearby):
        later = []
        for log in ("flow_summary",) + ROW_LOGS:
            later += [r["ts"] for r in idx.after(log, src, last + LIVE_AFTER) if r.get("resp_h") in vset]
        seen_ts = [r["ts"] for _, r in exact + grouped + nearby] + [r["ts"] for r in flow]
        judge["live"] = {"on": bool(later), "last_seen": max(later or seen_ts)}
    ext_ip = [v for v in vic if not internal(v) and v.replace(".", "").isdigit()]
    if ext_ip and not names and "dns_summary" in idx.present:
        cand = idx.between("dns_summary", src, first - DNS_BEFORE, last)
        hit = next((r.get("domain") for r in reversed(cand) if set(map(str, r.get("answers") or [])) & set(ext_ip)), None)
        judge["name"] = {"domain": hit, "how": "dns_answer" if hit else "not_found"}
    acct = next((e.get("account") for e in evs if e.get("account")), None)
    if acct:
        u = _acct_user(acct)
        hosts = sorted({r.get("orig_h") for ts, log, r in idx.by_user.get(u, []) if first - ACCT_WIN <= ts <= last + ACCT_WIN and r.get("orig_h")})
        if hosts:
            judge["account"] = {"name": str(acct).split(",")[0], "hosts": hosts[:MAX_HOSTS], "n": len(hosts)}

    # ---- 추이(연결 요약 30분 단위, 2구간 이상일 때)
    series = None
    if len({int(r["ts"] // 1800) for r in flow}) >= 2:
        exfil = det.get("stages") == "Exfiltration"
        b = collections.Counter()
        for r in flow:
            b[int(r["ts"] // 1800) * 1800] += (r.get("orig_bytes") or 0) if exfil else (r.get("conns") or 0)
        series = {"label": "30분별 보낸 양" if exfil else "30분별 연결 수", "unit": "bytes" if exfil else "conns",
                  "points": [[t, v] for t, v in sorted(b.items())]}

    def rec(items):
        return [{"ts": r["ts"], "log": log, "src": r.get("orig_h"), "dst": r.get("resp_h"), "text": line(log, r), "uid": r.get("uid", "")}
                for log, r in sorted(items, key=lambda x: x[1]["ts"])[:MAX_RECORDS]]

    limits = []
    if grouped:
        limits.append("같은 연결 묶음: 센서 중복 억제(ssl 24시간·http 10분·smb 공유 1시간)로 근거 연결의 행이 없어 같은 키의 앞선 행을 보여 줌")
    if "ssl" in logs or "http" in logs:
        limits.append("ssl·http 는 내부↔외부 통신만, 예외 도메인은 기록하지 않음")
    if judge.get("name"):
        limits.append("DNS 응답은 요약 행마다 3개까지만 남아 이름을 못 찾을 수 있음")
    if ua:
        limits.append("User-Agent 는 출발지 기준 요약이라 이 목적지에 쓴 것으로 단정할 수 없음")
    if any(v.get("proxy") for v in det.get("victims", [])):
        limits.append("프록시 경유: 메타데이터의 대상은 프록시이고 실제 목적지는 CONNECT 의 Host")

    accounts = []
    for log, r in exact + grouped + nearby:
        if log == "ntlm" and r.get("username"):
            accounts.append(f"{(r.get('domainname') + chr(92)) if r.get('domainname') else ''}{r['username']}")
        elif log == "kerberos" and r.get("client"):
            accounts.append(str(r["client"]).split("/")[0])
        elif log == "rdp" and r.get("cookie"):
            accounts.append(str(r["cookie"]))
    if not (facts or judge or exact or grouped or nearby):
        return {}
    return {"rule": rule, "judge": judge, "facts": facts, "series": series,
            "records": {"exact": rec(exact), "grouped": rec(grouped), "nearby": rec(nearby)},
            "limits": limits, "accounts": list(dict.fromkeys(accounts))[:5]}
