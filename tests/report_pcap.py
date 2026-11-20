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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asset_enrich  # noqa: E402  (같은 폴더의 자산 정보 보강 모듈)

MGR = ("nsm_detection", "evidence", "nsm_exception", "asset_signal")
# 운영에서도 센서에 남는 로그. 나머지(conn·dns 등)는 run_pcap.sh -k 로 남긴 원본이다(운영 전송량·구간 계산에서 뺀다).
SENSOR_LOCAL = ("notice", "capture_loss", "loaded_scripts", "stats", "reporter")


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


def chain_text(v, category):
    """nsm_detection 의 techniques·killchain_stages(배열)를 화면용 문자열로: 상관은 "A->B", 단일은 "A, B"."""
    if v is None:
        return None
    if isinstance(v, list):
        return ("->" if category == "Correlated" else ", ").join(str(x) for x in v)
    return str(v)


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
    "DgaDomain": "DGA 도메인 조회", "UnknownProtocol": "식별 안 된 프로토콜 통신",
    "SshBruteforce": "SSH 무차별 대입", "FtpBruteforce": "FTP 무차별 대입", "Heartbleed": "Heartbleed(TLS 서버 메모리 유출)",
    "Xss": "크로스 사이트 스크립팅 시도", "HttpBruteforce": "웹 로그인 무차별 대입",
    "TlsBeaconing": "HTTPS 주기 통신(비콘)", "RemoteService": "원격 서비스 생성", "RemoteTask": "원격 예약 작업 등록",
    "RemoteWmi": "원격 WMI 실행", "MachineAccountMisuse": "남의 머신 계정 사용(NTLM 릴레이)",
    "AiServiceUpload": "AI 서비스로 대량 업로드", "AiApiFromServer": "서버의 AI 서비스 접속", "IocMatch": "IOC(위협 정보) 일치", "AiServiceExploit": "AI 인프라 관리 API 호출",
    "CoercedAuth": "강제 인증 호출(PetitPotam 등)", "RemoteRegistryDump": "원격 레지스트리 하이브 저장",
    "Zerologon": "Zerologon 시도(netlogon 인증 반복)", "AdEnumeration": "AD 정보 수집(세션·로컬 관리자 조회)",
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
    "LargeTransfer": ({"ssl", "http", "flow_summary"}, None), "UnknownProtocol": ({"flow_summary"}, None), "VolumeAggregate": ({"ssl", "http", "flow_summary"}, None),
    "WebUpload": ({"ssl", "http", "flow_summary"}, None),
    "SshBruteforce": ({"ssh", "flow_summary"}, None), "FtpBruteforce": ({"flow_summary"}, None),
    "Heartbleed": ({"ssl", "flow_summary"}, None),
    "Xss": ({"http", "flow_summary"}, None), "HttpBruteforce": ({"http", "flow_summary"}, None),
    "TlsBeaconing": ({"ssl", "flow_summary"}, None),
    "RemoteService": ({"ntlm", "kerberos", "smb_mapping", "dce_rpc", "flow_summary"}, ("cifs/", "host/", "rpcss/")),
    "RemoteTask": ({"ntlm", "kerberos", "smb_mapping", "dce_rpc", "flow_summary"}, ("cifs/", "host/", "rpcss/")),
    "RemoteWmi": ({"ntlm", "kerberos", "dce_rpc", "flow_summary"}, ("rpcss/", "host/")),
    "MachineAccountMisuse": ({"ntlm", "kerberos", "flow_summary"}, ()),
    "AiServiceUpload": ({"ssl", "flow_summary"}, None), "AiApiFromServer": ({"ssl", "flow_summary"}, None), "IocMatch": ({"ssl", "http", "dns_summary", "flow_summary"}, None),
    "AiServiceExploit": ({"http", "flow_summary"}, None),
    "CoercedAuth": ({"ntlm", "kerberos", "smb_mapping", "dce_rpc", "flow_summary"}, ("cifs/", "host/")),
    "RemoteRegistryDump": ({"ntlm", "kerberos", "smb_mapping", "dce_rpc", "flow_summary"}, ("cifs/", "host/")),
    "Zerologon": ({"dce_rpc", "flow_summary"}, None),
    "AdEnumeration": ({"ntlm", "kerberos", "smb_mapping", "dce_rpc", "flow_summary"}, ("cifs/", "host/")),
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
            ports = [f"{r.get('resp_p')}/{r.get('proto', '')}{'(' + ','.join(split_list(r['service'])) + ')' if r.get('service') else ''}" for r in fl]
            add("연결", [f"{sum(r.get('conns', 0) for r in fl):,}회, 보냄 {_fmt_bytes(sum(r.get('orig_bytes', 0) for r in fl))}"
                       f" / 받음 {_fmt_bytes(sum(r.get('resp_bytes', 0) for r in fl))}"] + ports, "flow_summary", 4)
    rc = [str(r.get("cookie")) for r in by["rdp"] if to_v(r) and r.get("cookie")] if "rdp" in use else []
    return out, list(dict.fromkeys(nt + kb + rc))


def build_stories(detections, midx, label):
    """확정 체인(상관 탐지) + 공격자에서 확산 대상으로 이어지는 후보 탐지를 공격자별 스토리로 묶는다."""
    singles = [i for i, d in enumerate(detections) if d.get("category") != "Correlated"]
    by_id = {detections[i]["id"]: i for i in singles}
    for i in singles:                      # 합쳐진 같은 사건의 갱신 탐지 id 도 첫 탐지로
        for a in detections[i].get("aliases", []):
            by_id[a] = i
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
        # 닿은 host 가 공격자인 확정 체인도 이 스토리의 확정 단계다(초기 침투한 서버가 이후 체인을 만든 경우).
        conf = set()
        chains = []
        for h in reached:
            conf |= confirmed.get(h, set())
            chains += chain_ids.get(h, [])
        steps |= conf
        order = sorted(steps, key=t)
        hosts = list(dict.fromkeys([seed] + [h for h in sorted(reached, key=lambda h: (reached[h] is not None, reached[h] or 0))]))
        others = []
        for i in order:
            for v in detections[i]["victims"]:
                if v["ip"] not in hosts and v["ip"] not in others:
                    others.append(v["ip"])
        lanes = hosts + [o for o in others if not next(v for i in order for v in detections[i]["victims"] if v["ip"] == o).get("ext")] \
            + [o for o in others if next(v for i in order for v in detections[i]["victims"] if v["ip"] == o).get("ext")]
        lane_rows = [label(h, t(order[0]) if order else None) for h in lanes]
        for ln in lane_rows:
            # 프록시 대상(mark_proxy_victims)은 레인에도 같은 표시를 단다
            pv = next((v for i in order for v in detections[i]["victims"] if v["ip"] == ln["ip"] and v.get("proxy")), None)
            if pv:
                ln.update({"proxy": True, "ext": True, "targets": pv.get("targets", [])})
        stories.append({"seed": seed, "steps": order, "confirmed": sorted(conf), "chains": list(dict.fromkeys(chains)),
                        "lanes": lane_rows})
    # 다른 스토리에 그대로 들어 있는 작은 스토리는 뺀다(확산 대상이 뒤에 공격자로 나온 경우 등)
    stories.sort(key=lambda s: (-len(s["confirmed"]), -len(s["steps"])))
    kept = []
    for s in stories:
        if not any(set(s["steps"]) <= set(k["steps"]) for k in kept):
            kept.append(s)
    return kept


# 메타데이터 관측: 탐지 밖에서 스토리를 넓히는 두 가지(추정 조인, uid 아님)
#   1) 같은 공격 인프라: C2·유출 탐지의 외부 목적지(IP·SNI·Host)에 접속한 다른 내부 host
#   2) 확인이 필요한 내부 접속(예전 이름 관측된 내부 이동): 스토리 host 가 탐지 기준에는 못 미친 채 다른 내부 host 로 한 관리 접속·인증
INFRA_STAGES = {"Command and Control", "Exfiltration"}
SHARED_MAC_IPS = 2            # 자산 신호 모드: 이 수 이상의 IPv4 가 같은 MAC 이면 "공유"로 표시(이중화 VIP·IP 여러 개인 서버일 수 있음).
ROUTER_MAC_IPS = 3            # 이 수 이상이면 라우터(그 뒤 주소들)로 표시. IPv6 링크 로컬은 같은 host 라 어느 쪽에도 세지 않음
ROUTED_VIEW_RATIO = 0.5       # MAC 이 있는 IP 중 이 비율 이상이 라우터 MAC 이고
ROUTED_VIEW_MIN = 10          # 그런 IP 가 이 수 이상이면 "라우팅 뒤 구간"으로 보고 표 위에 한 번만 설명, 행 표시는 짧게
INFRA_WINDOW = 86400          # 스토리 기간 앞뒤로 같은 인프라를 찾는 시간
INFRA_POPULAR = 50            # 이보다 많은 내부 host 가 붙는 목적지는 흔한 서비스로 본다
INFRA_POPULAR_MIN = 5         # 또는 이 수 이상이면서
INFRA_POPULAR_RATIO = 0.5     # 외부로 접속한 내부 host 의 이 비율 이상이 붙으면 흔한 서비스(작은 망 대응)
RESOLVER_MIN_DOMAINS = 5      # 다른 host 들의 조회 도메인이 이 수 이상일 때만 리졸버를 가린다
RESOLVER_COVER = 0.5          # 다른 host 들이 조회한 도메인의 이 비율 이상을 자기도 조회하면 내부 리졸버로 본다
OBS_AFTER = 3600              # 스토리 마지막 탐지 뒤 확인이 필요한 내부 접속을 찾는 시간
OBS_MAX = 40
OBS_COMMON = 3                # 스토리 밖 내부 host 가 이 수 이상 같은 대상에 같은 접속을 하면 평소 통신으로 뺀다
OBS_RISKY_RPC = {"svcctl", "atsvc", "itaskschedulerservice", "iwbemservices", "iwbemlevel1login",
                 "iremotescmactivator", "winreg"}   # 원격 실행·레지스트리: 여러 host 가 해도 빼지 않는다
OBS_SKIP_PORTS = {53, 88, 123, 389, 636, 3268, 3269}   # 디렉터리·인증·이름 해석: 일상 통신
OBS_RPC = {"svcctl", "atsvc", "itaskschedulerservice", "winreg", "iwbemservices", "iwbemlevel1login",
           "iremotescmactivator", "drsuapi", "samr", "lsarpc", "netlogon", "efsrpc", "efsrpc2", "netdfs",
           "fileservervssagent", "srvsvc", "wkssvc", "spoolss"}
_HOSTKEY = re.compile(r"(?:host|sni)=([^ ,]+)")


def _norm_host(h):
    h = str(h or "").strip().lower().rstrip(".")
    if h.startswith("[") or h.count(":") > 1:
        return h
    return h.rsplit(":", 1)[0] if ":" in h else h


_VIA_PROXY = re.compile(r"via_proxy=(\[[0-9a-fA-F:]+\]|[0-9a-fA-F.:]+?):(\d+)(?:\s|$)")


def mark_proxy_victims(d):
    """유출(10·12·14)·C2·AI 룰(07·09·24·30·33)은 명시적 프록시를 거친 연결의 대상을 프록시 IP 로 두고 근거에 via_proxy=, (알면) host= 를 남긴다.
    이 대상은 피해 장비가 아니라 중계 장비이므로 외부 대상처럼 다루고(스토리·자산 관련 탐지에서 제외),
    실제 목적지는 근거의 host= 로 보여 준다. 연결 시작(CONNECT)을 못 본 연결은 목적지를 모른다."""
    via, hosts = set(), []
    for e in d.get("evidence", []):
        det = str(e.get("detail") or "")
        for ip, _port in _VIA_PROXY.findall(det):
            via.add(ip.strip("[]"))
            for m in _HOSTKEY.findall(det):
                h = _norm_host(m)
                if h and h != "-" and h not in hosts:
                    hosts.append(h)
    for v in d["victims"]:
        if v["ip"] in via:
            v.update({"proxy": True, "ext": True, "targets": hosts[:5]})


def infra_keys(d):
    """C2·유출 탐지의 외부 목적지 키(IP, 이름). 프록시 IP 는 모든 프록시 사용자가 붙으므로 넣지 않는다."""
    keys = set()
    for v in d["victims"]:
        if v.get("ext") and not v.get("proxy"):
            keys.add(v["ip"])
    for e in d.get("evidence", []):
        for m in _HOSTKEY.findall(str(e.get("detail") or "")):
            h = _norm_host(m)
            if h and h != "-":
                keys.add(h)
    return keys


def obs_sig(k, r, to_kdc):
    """확인이 필요한 내부 접속 행 하나를 (접속 종류, 표시 문구, 강한 신호, 원격 실행류) 로. 일상 통신이면 None."""
    if k == "smb_mapping":
        path = str(r.get("path") or "")
        share = path.upper().rstrip("\\").split("\\")[-1]
        admin = share in ("ADMIN$", "C$")
        if to_kdc and not admin:
            return None
        return f"smb:{share}", f"공유 {path}", admin, admin
    if k == "dce_rpc":
        ep = str(r.get("endpoint") or "").lower()
        if ep not in OBS_RPC:
            return None
        return f"rpc:{ep}", f"RPC {r.get('endpoint')}::{r.get('operation')}", True, ep in OBS_RISKY_RPC
    if k == "rdp":
        return "rdp", f"RDP {r.get('cookie') or ''}".strip(), True, False
    if k == "ssh":
        return "ssh", f"SSH {'성공' if r.get('auth_success') else '시도'}", True, False
    if k == "ntlm":
        if to_kdc:
            return None
        return "ntlm", f"NTLM {r.get('domainname') + chr(92) if r.get('domainname') else ''}{r.get('username') or ''}", False, False
    if k == "flow_summary":
        if to_kdc or r.get("resp_p") in OBS_SKIP_PORTS:
            return None
        return f"flow:{r.get('resp_p')}/{r.get('proto', '')}", f"{r.get('resp_p')}/{r.get('proto', '')} {r.get('conns', 0)}회", False, False
    return None


def meta_observe(stories, detections, midx, internal, label, sig=()):
    """스토리마다 infra(같은 인프라에 붙은 내부 host)와 observed(확인이 필요한 내부 접속)를 붙인다."""
    dindex = collections.defaultdict(list)     # 목적지 키 -> [(시각, 출발지, 로그)]
    kdc = set()
    for src, lst in midx.items():
        if not internal(src):
            continue
        for t, k, r in lst:
            dst = r.get("id.resp_h") or r.get("resp_h")
            if k == "kerberos" and dst:
                kdc.add(dst)
            ks = set()
            if dst and not internal(dst):
                ks.add(dst)
            if k == "ssl" and r.get("server_name"):
                ks.add(_norm_host(r["server_name"]))
            if k == "http" and r.get("host") and dst and not internal(dst):
                ks.add(_norm_host(r["host"]))
            if k == "dns_summary" and r.get("domain"):
                ks.add(_norm_host(r["domain"]))
            for key in ks:
                dindex[key].append((t, src, k))
    # 내부 리졸버: 다른 host 들이 조회한 도메인 대부분을 자기도 조회하는 host(대신 조회하는 DNS 서버). 같은 인프라 목록에서 뺀다
    doms = collections.defaultdict(set)
    for src, lst in midx.items():
        if internal(src):
            for t, k, r in lst:
                if k == "dns_summary" and r.get("domain"):
                    doms[src].add(r["domain"])
    # 자산 신호에서 DNS 를 제공한 IP(service udp/53·tcp/53)는 그대로 내부 DNS 서버로 본다. 도메인 기준은
    # 메타데이터의 출발지당 시간당 도메인 상한(meta_dns_max_domains_per_src)에 잘리는 큰 리졸버를 놓칠 수 있다
    resolvers = {x.get("ip") for x in sig if x.get("signal") == "service"
                 and re.match(r"^(udp|tcp)/53(/|$)", str(x.get("value") or ""))}
    for src, ds in doms.items():
        ds = ds - {"(other)"}
        rest = set().union(*(v for o, v in doms.items() if o != src)) - {"(other)"}
        if len(rest) >= RESOLVER_MIN_DOMAINS and len(ds & rest) >= RESOLVER_COVER * len(rest):
            resolvers.add(src)
    # 흔한 목적지 비율의 분모: 외부 유니캐스트 주소로 접속한 내부 host. 멀티캐스트·브로드캐스트(mDNS·SSDP·LLMNR 등)는
    # 사설 대역이 아니어서 외부로 보이지만 접속이 아니다(IPv6 링크 로컬 주소가 이것만 보내 분모가 두 배가 됨)
    def ext_unicast(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (internal(ip) or a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local)
    active = len({src for src, lst in midx.items() if internal(src)
                  and any(ext_unicast(r.get("id.resp_h") or r.get("resp_h") or "") for t, k, r in lst)})
    # 확인이 필요한 내부 접속의 평소 통신 판정: (출발, 대상, 접속 종류)의 처음 시각, (대상, 접속 종류)별 출발 host
    pair_first, sig_srcs = {}, collections.defaultdict(set)
    for src, lst in midx.items():
        if not internal(src):
            continue
        for t, k, r in lst:
            dst = r.get("id.resp_h") or r.get("resp_h")
            if not dst or dst == src or not internal(dst):
                continue
            c = obs_sig(k, r, dst in kdc)
            if c:
                key = (src, dst, c[0])
                pair_first[key] = min(pair_first.get(key, t), t)
                sig_srcs[(dst, c[0])].add(src)
    c2_actors = {d["attacker"]["ip"] for d in detections
                 if d.get("attacker") and d.get("category") != "Correlated" and d.get("stages") in INFRA_STAGES}
    tt = lambda d: d.get("first") or d["ts"] or 0
    for s in stories:
        steps = [detections[i] for i in s["steps"]]
        t0 = min(tt(d) for d in steps) if steps else 0
        t1 = max((d.get("last") or d["ts"] or 0) for d in steps) if steps else 0
        actors = {d["attacker"]["ip"] for d in steps if d.get("attacker")}
        # 1) 같은 공격 인프라
        infra = []
        for i in s["steps"]:
            d = detections[i]
            if d.get("stages") not in INFRA_STAGES or not d.get("attacker"):
                continue
            for key in sorted(infra_keys(d)):
                if any(x["key"] == key for x in infra):
                    continue
                cand = [key]
                if not re.match(r"^[0-9.]+$", key) and key.count(".") >= 2:
                    cand.append(".".join(key.split(".")[-2:]))      # 등록 도메인(DNS 요약 키)
                hosts = {}
                for ck in cand:
                    for t, src, k in dindex.get(ck, []):
                        if (src in resolvers and k == "dns_summary") or not (t0 - INFRA_WINDOW <= t <= t1 + INFRA_WINDOW):
                            continue
                        h = hosts.setdefault(src, {"first": t, "last": t, "n": 0, "logs": set()})
                        h["first"], h["last"] = min(h["first"], t), max(h["last"], t)
                        h["n"] += 1
                        h["logs"].add(k)
                if len(hosts) <= 1:
                    continue
                n = len(hosts)
                popular = n > INFRA_POPULAR or (n >= INFRA_POPULAR_MIN and n >= INFRA_POPULAR_RATIO * active)
                item = {"key": key, "total": n, "popular": popular, "omitted": 0, "hosts": []}
                for ip, h in sorted(hosts.items(), key=lambda x: x[1]["first"]):
                    status = "story" if ip in actors else "other" if ip in c2_actors else "obs"
                    if popular and status == "obs":
                        item["omitted"] += 1        # 흔한 목적지: 탐지된 host 만 남기고 관측만 host 는 수만 센다
                        continue
                    item["hosts"].append({"who": label(ip, h["first"]), "first": h["first"], "last": h["last"],
                                          "n": h["n"], "logs": sorted(h["logs"]), "status": status})
                infra.append(item)
        s["infra"] = infra
        # 외부 대상 키(IP·이름): 공유하는 host 가 없어도 요약 칸의 외부 대상 수에 쓴다
        s["ext_keys"] = sorted({k for i in s["steps"] if detections[i].get("stages") in INFRA_STAGES and detections[i].get("attacker")
                                for k in infra_keys(detections[i])})
        # 2) 확인이 필요한 내부 접속
        # host 가 스토리에 들어온 시각. 집계형 확산 탐지는 창이 끝날 때 나오므로, 공격자 -> 대상의 첫 메타데이터 행이
        # 탐지 1시간 안쪽에 있으면 그 시각을 쓴다.
        def first_contact(a, v, td):
            ts = [t for t, k, r in midx.get(a, ()) if (r.get("id.resp_h") or r.get("resp_h")) == v and td - 3600 <= t <= td + 60]
            return min(ts) if ts else td
        reach = {}
        est = {}       # 집계형 확산 탐지의 추정 첫 접속 시각(탐지 시각보다 이르면): 내러티브 순서에 쓴다
        for i in sorted(s["steps"], key=lambda j: tt(detections[j])):
            d = detections[i]
            a = d["attacker"]["ip"] if d.get("attacker") else None
            if a and internal(a) and a not in reach:
                reach[a] = tt(d)
            if d.get("stages") in PIVOT_STAGES:
                for v in d["victims"]:
                    if not v.get("ext"):
                        t = first_contact(a, v["ip"], tt(d)) if a else tt(d)
                        reach[v["ip"]] = min(reach.get(v["ip"], t), t)
                        if t < tt(d):
                            est[str(i)] = min(est.get(str(i), t), t)
        pairs = {(d["attacker"]["ip"], v["ip"]) for d in steps if d.get("attacker") for v in d["victims"]}
        story_hosts = set(reach) | actors
        edges = {}
        skipped = {"prior": set(), "common": set()}
        for h, since in reach.items():
            for t, k, r in midx.get(h, ()):
                if not (since - 600 <= t <= t1 + OBS_AFTER):
                    continue
                dst = r.get("id.resp_h") or r.get("resp_h")
                if not dst or dst == h or not internal(dst) or (h, dst) in pairs:
                    continue
                c = obs_sig(k, r, dst in kdc)
                if not c:
                    continue
                sig, what, strong, risky = c
                # 평소 통신: 스토리에 들어오기 전부터 같은 대상에 같은 접속을 했거나, 스토리 밖 여러 host 가 같은 접속을 한다
                if pair_first.get((h, dst, sig), t) < since - 600:
                    skipped["prior"].add((h, dst))
                    continue
                if not risky and len(sig_srcs.get((dst, sig), set()) - story_hosts) >= OBS_COMMON:
                    skipped["common"].add((h, dst))
                    continue
                e = edges.setdefault((h, dst), {"first": t, "last": t, "what": [], "logs": set(), "strong": False})
                e["first"], e["last"] = min(e["first"], t), max(e["last"], t)
                e["strong"] |= strong
                e["logs"].add(k)
                if what not in e["what"]:
                    e["what"].append(what)
        s["observed_skip"] = {k: len(v) for k, v in skipped.items()}
        s["est_first"] = est
        obs = sorted(edges.items(), key=lambda x: (not x[1]["strong"], x[1]["first"]))[:OBS_MAX]
        s["observed"] = [{"a": a, "b": b, "who": label(b, e["first"]), "first": e["first"], "last": e["last"],
                          "what": e["what"][:4], "logs": sorted(e["logs"]), "strong": e["strong"]}
                         for (a, b), e in sorted(obs, key=lambda x: x[1]["first"])]


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
    "Name_Poisoning": "NamePoisoning", "DCSync": "DcSync", "Nonstandard_Port": "NonstandardPort", "Long_Connection": "LongConnection", "Unknown_Protocol": "UnknownProtocol",
    "SMB_Admin_Share": "SmbAccess", "RDP_Lateral": "RdpAccess", "SSH_Lateral": "SshAccess", "HTTP_Beaconing": "HttpBeaconing",
    "DNS_Tunneling": "DnsTunneling", "Encrypted_C2": "EncryptedChannel", "Exfil_Large_Transfer": "LargeTransfer",
    "Exfil_Volume_Aggregate": "VolumeAggregate", "Exfil_DNS": "DnsTunnel", "Exfil_Web_Upload": "WebUpload", "DGA_Domain": "DgaDomain",
    "SSH_Bruteforce": "SshBruteforce", "FTP_Bruteforce": "FtpBruteforce", "TLS_Heartbleed": "Heartbleed",
    "Cross_Site_Scripting": "Xss", "HTTP_Bruteforce": "HttpBruteforce", "TLS_Beaconing": "TlsBeaconing",
    "Remote_Service_Creation": "RemoteService", "Remote_Task_Creation": "RemoteTask", "Remote_WMI_Execution": "RemoteWmi",
    "Machine_Account_Misuse": "MachineAccountMisuse", "AI_Service_Upload": "AiServiceUpload",
    "AI_API_From_Server": "AiApiFromServer", "IOC_Match": "IocMatch", "AI_Service_Exploit": "AiServiceExploit",
    "Coerced_Authentication": "CoercedAuth", "Remote_Registry_Dump": "RemoteRegistryDump",
    "Zerologon_Attempt": "Zerologon", "AD_Enumeration": "AdEnumeration",
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
    heads = {}
    chain_at = {}                          # 상관 detection_id -> detections 위치(revision 이 가장 큰 행)
    related = collections.Counter()
    for d in sorted(det, key=lambda r: r.get("ts") or 0):
        ts = d.get("ts")
        att = d.get("attacker")
        vics = split_list(d.get("victims"))
        eids = split_list(d.get("evidence_ids")) or ([d["detection_id"]] if d.get("detection_id") else [])
        evs = []
        for eid in eids:
            evs.extend(ev_by.get(eid, []))
        item = {
            "ts": ts, "id": d.get("detection_id"), "diagnosis": d.get("diagnosis"),
            "techniques": chain_text(d.get("techniques"), d.get("category")),
            "category": d.get("category"), "stages": chain_text(d.get("killchain_stages"), d.get("category")), "severity": d.get("severity"),
            "attacker": label(att, ts) if att else None, "victims": [label(v, ts) for v in vics],
            "evidence_count": d.get("evidence_count", 0), "disposition": d.get("disposition"),
            "exception_id": d.get("exception_id"), "evidence": sorted(evs, key=lambda e: e.get("ts") or 0)[:200],
            "first": d.get("first_seen") or ts, "last": d.get("last_seen") or ts, "eids": eids,
            "incident": d.get("incident_id"), "occurrences": 1,
        }
        if d.get("category") != "Correlated" and (d.get("occurrence") or 1) > 1 and item["incident"] in heads:
            # 진행 중인 같은 사건의 갱신: 첫 탐지 한 행으로 합친다(횟수·마지막 시각·근거).
            h = heads[item["incident"]]
            h["occurrences"] += 1
            h["last"] = max(h["last"] or 0, item["last"] or 0)
            h["evidence"] = (h["evidence"] + item["evidence"])[:200]
            h["evidence_count"] = (h["evidence_count"] or 0) + (item["evidence_count"] or 0)
            h["eids"] = h["eids"] + item["eids"]
            h.setdefault("aliases", []).append(item["id"])
            continue
        if item["incident"] and d.get("category") != "Correlated":
            heads[item["incident"]] = item
        if d.get("category") == "Correlated" and d.get("revision"):
            # 상관 탐지는 갱신될 때마다 갈래를 합친 체인 전체를 다시 낸다(revision 1, 2, ...).
            #   같은 체인은 revision 이 가장 큰 행 하나만 쓴다(Manager 와 같은 규칙). revision 이 없는 옛 로그는 행마다 그대로.
            item["revision"] = d.get("revision")
            k = item["id"]
            if k in chain_at:
                j = chain_at[k]
                if (detections[j].get("revision") or 0) <= item["revision"]:
                    detections[j] = item
                continue
            chain_at[k] = len(detections)
        detections.append(item)
    for item in detections:
        mark_proxy_victims(item)
        for who in [item["attacker"]] + item["victims"]:
            if who and who.get("asset") and not who.get("proxy"):
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
    meta_observe(stories, detections, midx, internal, label, sig)
    coverage = story_coverage(detections, ev)
    for d in detections:
        d.pop("eids", None)

    # 자산 정보 보강(Manager 후처리 시제품): MAC 제조사(OUI), 지문(Recog), TCP SYN OS 계열. 라우터 공유 MAC 은 제조사를 붙이지 않는다.
    mac_v4 = collections.defaultdict(set)
    for s in sig:
        if s.get("signal") == "mac" and s.get("value") and ":" not in str(s.get("ip")):
            mac_v4[str(s["value"])].add(s.get("ip"))
    shared = {m for m, ips in mac_v4.items() if len(ips) >= SHARED_MAC_IPS}
    oui = asset_enrich.Oui(args.oui or [])
    recog = asset_enrich.Recog(args.recog)
    enr = asset_enrich.enrich(sig, oui, recog, shared)
    proxies = asset_enrich.proxy_like_ips(sig)
    enrich_info = {"oui_files": oui.files, "oui_entries": len(oui.tab), "oui_empty": oui.empty, "proxy_like": len(proxies), "recog_dir": os.path.basename(os.path.normpath(args.recog)) if args.recog else "",
                   "recog_count": recog.count, "recog_bad": recog.bad}

    def add_enrich(row):
        e = next((enr[ip] for ip in row["ips"] if ip in enr), None)
        if not e:
            return
        row.update({"vendor": e["vendor"], "mac_local": e["mac_local"] and bool(e["mac"]), "fp": e["fp"], "fp_dev": e["fp_dev"],
                    "tcp_os": e["tcp_os"], "tcp_basis": e["tcp_basis"], "proxy_like": e["proxy_like"]})
        if not row.get("os"):
            if e["fp_os"]:
                row["os"], row["os_src"] = e["fp_os"], "지문(Recog)"
            elif e["tcp_os"]:
                row["os"], row["os_src"] = e["tcp_os"], "TCP SYN 추정"
        row["dev_class"], row["dev_basis"], row["dev_conf"] = asset_enrich.device_class(e, row.get("os", ""), row.get("roles") or [])

    # 자산: 리졸버 결과가 있으면 자산 단위, 없으면 IP 별 신호 요약
    asset_rows = []
    mac_summary = None
    if assets is not None:
        for a in assets:
            asset_rows.append({
                "id": a.get("asset_id"), "name": a.get("display_name") or a.get("hostname") or "",
                "key": f"{a.get('id_type', '')}({a.get('confidence', '')})", "ips": [b.get("ip") for b in a.get("ips", [])],
                "macs": a.get("macs", []), "os": a.get("os", ""), "roles": a.get("roles", []),
                "users": a.get("users", [])[:5], "agents": a.get("security_agents", []),
                "signals": a.get("signal_count", 0), "detections": related.get(a.get("asset_id"), 0),
            })
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))
        for row in asset_rows:
            add_enrich(row)
    else:
        # 리졸버 없이 신호 값을 그대로 참고값으로: MAC(여러 IP 가 같은 MAC 이면 게이트웨이로 표시), OS 힌트(신뢰도·횟수 순
        # 첫 값), 역할 대신 응답한 서비스(service 신호). 역할 판정은 리졸버가 서비스 조합으로 한다.
        per = collections.defaultdict(lambda: {"signals": collections.Counter(), "names": set(), "macs": collections.Counter(),
                                               "os": collections.Counter(), "svc": collections.Counter(), "agents": set(), "dev": set()})
        mac_ips = collections.defaultdict(set)
        for s in sig:
            p = per[s.get("ip")]
            k, v = s.get("signal"), s.get("value")
            p["signals"][k] += 1
            if k in ("hostname", "machine_account", "fqdn"):
                p["names"].add(str(v))
            elif k == "mac" and v:
                p["macs"][str(v)] += 1
                if ":" not in str(s.get("ip")):
                    mac_ips[str(v)].add(s.get("ip"))
            elif k == "os_hint" and v and not (s.get("source") == "http_server" and s.get("ip") in proxies):
                # 프록시·중계 추정 IP 의 HTTP Server OS 힌트는 뒤쪽 서버 것이라 쓰지 않는다
                p["os"][(int(s.get("confidence") or 0), str(v))] += 1
            elif k == "service" and v:
                p["svc"][str(v)] += 1
            elif k == "security_agent" and v:
                p["agents"].add(str(v))
            elif k == "device" and v:
                p["dev"].add(str(v))
        # 라우팅 뒤 구간(센서가 L3 장비를 지난 트래픽을 봄): IP 대부분이 소수의 라우터 MAC 을 공유한다
        mac_rows = [p for ip, p in per.items() if p["macs"]]
        router_rows = [p for p in mac_rows if len(mac_ips[p["macs"].most_common(1)[0][0]]) >= ROUTER_MAC_IPS]
        routed_view = len(router_rows) >= ROUTED_VIEW_MIN and len(router_rows) >= ROUTED_VIEW_RATIO * len(mac_rows)
        mac_summary = None
        if routed_view:
            router_macs = {m for m, ips in mac_ips.items() if len(ips) >= ROUTER_MAC_IPS}
            mac_summary = {"ips": len(mac_rows), "macs": len({m for p in mac_rows for m in p["macs"]}),
                           "router_macs": len(router_macs), "router_ips": len(router_rows)}
        def mac_text(m):
            n = len(mac_ips[m])
            if n >= ROUTER_MAC_IPS:
                return f"{m} (라우터)" if routed_view else f"{m} (IPv4 {n}개 공유, 라우터 추정)"
            return f"{m} (IPv4 {n}개 공유)" if n >= SHARED_MAC_IPS else m
        def best_os(c):
            return max(c.items(), key=lambda x: (x[0][0], x[1]))[0][1] if c else ""
        det_ips = collections.Counter()
        for d in detections:
            for who in [d["attacker"]] + d["victims"]:
                if who and not who.get("proxy"):
                    det_ips[who["ip"]] += 1
        for ip, p in per.items():
            asset_rows.append({"id": "", "name": ", ".join(sorted(p["names"]))[:80], "key": "", "ips": [ip],
                               "macs": [mac_text(m) for m, _ in p["macs"].most_common(2)], "os": best_os(p["os"]),
                               "roles": [], "services": sorted(p["svc"], key=lambda x: (-p["svc"][x], x))[:6], "users": [], "agents": sorted(p["agents"]), "devices": sorted(p["dev"]),
                               "signals": sum(p["signals"].values()), "detections": det_ips.get(ip, 0)})
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))
        for row in asset_rows:
            add_enrich(row)

    # 전송량
    meta_rows = [{"name": k, "bytes": size(p), "rows": nlines(p)} for k, p in meta.items()]
    meta_rows.sort(key=lambda r: -r["bytes"])
    mgr = {k: size(logs.get(k)) for k in MGR}
    local = {k: size(p) for k, p in logs.items() if k in SENSOR_LOCAL}
    raw = {k: size(p) for k, p in logs.items() if k not in MGR and k not in SENSOR_LOCAL}
    # reporter 는 오프라인 실행에서 pcap 을 읽기 전 행에 실제 시계 시각이 찍혀 캡처 구간에서 뺀다.
    # -k 원본 로그는 크고 운영 형상이 아니라 읽지 않는다.
    ts_all = [r["ts"] for k, p in list(logs.items()) + list(meta.items())
              if k != "reporter" and k not in raw for r in rows(p)
              if isinstance(r.get("ts"), (int, float)) and r["ts"] > 1e9]
    span = (max(ts_all) - min(ts_all)) if len(ts_all) >= 2 else 0

    # 센서 상태
    cl = rows(logs.get("capture_loss"))
    other_notes = collections.Counter(n.get("note") for n in notices if not str(n.get("note", "")).startswith("NSM::"))
    stderr = os.path.join(z, "stderr.txt")
    warn = [l.strip() for l in open(stderr, encoding="utf-8", errors="replace")
            if any(w in l.lower() for w in ("warning", "error", "fatal"))][:20] if os.path.exists(stderr) else []

    return {
        "pcap": args.pcap or "", "elapsed": args.elapsed, "tz": args.tz, "obs_common": OBS_COMMON, "span": span,
        "start": min(ts_all) if ts_all else None, "end": max(ts_all) if ts_all else None,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "detections": detections, "stories": stories, "stage_order": STAGES, "coverage": coverage,
        "exceptions": exc,
        "assets": asset_rows, "mac_summary": mac_summary, "enrich": enrich_info, "asset_mode": "resolver" if assets is not None else "signals",
        "asset_report": args.asset_report or "",
        "signal_counts": collections.Counter(s.get("signal") for s in sig).most_common(),
        "signal_rows": len(sig), "signal_ips": len({s.get("ip") for s in sig}),
        "meta": meta_rows, "mgr": mgr, "local": local, "raw": raw,
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
:root{--s0:#2a78d6;--s1:#eb6834;--s2:#1baf7a;--s3:#eda100;--s4:#e87ba4;--s5:#008300;--s6:#6250d6;--surf:#fff;--obs:#7a5af5;--obs-bg:#f1edff}
@media (prefers-color-scheme: dark){:root{--s0:#3987e5;--s1:#d95926;--s2:#199e70;--s3:#c98500;--s4:#d55181;--s5:#008300;--s6:#9085e9;--surf:#1c2027;--obs:#a996ff;--obs-bg:#231d3d}}
svg .lo{stroke:var(--obs);stroke-width:1.8;fill:none;stroke-dasharray:3 4}svg .lo.strong{stroke-width:2.4}svg .node.obs{fill:var(--obs-bg);stroke:var(--obs);stroke-dasharray:5 4}
.tt2{white-space:nowrap;font-variant-numeric:tabular-nums}.sw.obs{background:var(--obs-bg);border:2px dashed var(--obs);width:8px;height:8px}.ob{color:var(--obs);font-weight:600}.tag{display:inline-block;font-size:11px;border-radius:4px;padding:0 6px;border:1px solid var(--line);white-space:nowrap}.tag.obs{color:var(--obs);border:1px dashed var(--obs);background:var(--obs-bg)}
.st0{--c:var(--s0)}.st1{--c:var(--s1)}.st2{--c:var(--s2)}.st3{--c:var(--s3)}.st4{--c:var(--s4)}.st5{--c:var(--s5)}.st6{--c:var(--s6)}.stn{--c:var(--mut)}
svg text{fill:var(--fg);font-size:13px}svg .mt{fill:var(--mut);font-size:12px}svg .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
svg .node{fill:var(--card);stroke:var(--line);stroke-width:1.5}svg .node.seed{stroke:var(--fg);stroke-width:2}svg .node.ext{fill:var(--chip);stroke-dasharray:4 3}svg .node.grp{fill:var(--bg);stroke-dasharray:2 3}
svg .ln{stroke:var(--c);stroke-width:2;fill:none}svg .ln.cand{stroke-dasharray:5 4}
svg .nb{cursor:pointer}svg .nb circle{fill:var(--c);stroke:var(--c);stroke-width:2}svg .nb text{fill:#fff;font-size:10.5px;font-weight:600}
svg .nb.cand circle{fill:var(--surf)}svg .nb.cand text{fill:var(--c)}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--c);margin-right:4px;vertical-align:-1px}.sw.cand{background:transparent;border:2px solid var(--c);width:8px;height:8px}
.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--mut);margin:6px 0}
.lead{font-size:14px;margin:4px 0 8px}select{padding:5px 8px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);max-width:100%}
.sub3{font-size:13px;color:var(--mut);margin:18px 0 8px;font-weight:600}
.prog{display:flex;align-items:center;margin:2px 0 12px;min-width:700px}
.pst{display:flex;flex-direction:column;align-items:center;gap:4px;flex:1;position:relative;font-size:12px;color:var(--fg)}
.pst::before{content:"";position:absolute;top:11px;left:-50%;right:50%;height:2px;background:var(--line)}.pst:first-child::before{display:none}.pst.on::before{background:var(--mut)}
.pc{width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-size:11px;font-weight:600;color:#fff;background:var(--c);position:relative;z-index:1}
.pst.off{color:var(--mut)}.pst.off .pc{background:var(--card);border:2px dashed var(--line);color:var(--mut)}
.board{display:grid;grid-template-columns:repeat(7,minmax(140px,1fr));gap:8px;min-width:700px}
.bcol{display:flex;flex-direction:column;gap:6px;min-width:0}.bcol .none{font-size:12px;color:var(--mut);padding:4px 2px}
.bcard{border:1px solid var(--line);border-radius:8px;padding:6px 8px;font-size:12px;background:var(--card);cursor:pointer;min-width:0}.bcard:hover{background:var(--chip)}
.bcard.cand{border-style:dashed}.bcard .h{display:flex;gap:6px;align-items:baseline;font-weight:600;font-size:12.5px}.bcard .w{color:var(--mut);overflow-wrap:anywhere}
.bnum{font-size:11px;color:var(--mut);font-variant-numeric:tabular-nums}
.nar{list-style:none;margin:0;padding:0;display:flex;flex-direction:column}
.nar li{display:grid;grid-template-columns:70px 26px minmax(0,1fr);gap:0 10px;border-radius:8px}.nar li.on{background:var(--chip)}
.nar .tm{font-size:12px;color:var(--mut);padding-top:3px;text-align:right;font-variant-numeric:tabular-nums}
.nar .sp{position:relative;display:flex;justify-content:center}.nar .sp::before{content:"";position:absolute;top:0;bottom:0;width:2px;background:var(--line)}
.nar li:first-child .sp::before{top:12px}.nar li:last-child .sp::before{bottom:calc(100% - 12px)}
.nn{position:relative;z-index:1;margin-top:2px;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:10.5px;font-weight:600;color:#fff;background:var(--c);box-shadow:0 0 0 3px var(--card)}
.nn.cand{background:var(--card);color:var(--c);border:2px solid var(--c);width:18px;height:18px}
.nar .bd{padding:0 0 14px;display:flex;flex-direction:column;gap:3px;min-width:0}
.nar .tt{font-weight:600}.nar .k{font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:4px;padding:0 5px;font-weight:400;margin-left:4px}
.nar .how{font-size:12px;color:var(--mut);overflow-wrap:anywhere}.nar .how b{color:var(--fg);font-weight:600}
.nar li.ob .tt{color:var(--obs);font-weight:500}.nar .od{position:relative;z-index:1;margin-top:5px;width:9px;height:9px;border-radius:50%;background:var(--obs-bg);border:2px dashed var(--obs);box-shadow:0 0 0 3px var(--card)}
.ssum{display:flex;flex-wrap:wrap;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:6px 0 4px}
.ssum div{flex:1 1 140px;background:var(--card);padding:8px 12px;display:flex;flex-direction:column;gap:1px;min-width:0}.ssum b{font-size:17px;font-variant-numeric:tabular-nums;line-height:1.3;overflow-wrap:anywhere}
.ssum span{font-size:12px;color:var(--mut)}.ssum div:first-child{flex:2 1 260px}.ssum .o b{color:var(--obs)}
.nar li.gapr{display:grid;font-size:12px;color:var(--mut);font-style:italic}.nar li.gapr .sp::before{background:none;border-left:2px dotted var(--line)}
#tip{position:fixed;z-index:20;pointer-events:none;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;max-width:420px;box-shadow:0 4px 14px rgba(0,0,0,.15);display:none}
</style></head><body>
<header><h1>NSM 통합 리포트</h1><div class="sub" id="sub"></div></header>
<nav><a href="#sum">요약</a><a href="#story">공격 스토리</a><a href="#det">탐지</a><a href="#chain">킬체인</a><a href="#asset">자산</a><a href="#xfer">전송량</a><a href="#exc">예외</a><a href="#sensor">센서 상태</a></nav>
<main>
<section id="sum"><h2>요약</h2><div class="cards" id="cards"></div></section>
<section id="story"><h2>공격 스토리</h2><div class="box">
 <select id="storysel"></select> <label class="note"><input type="checkbox" id="storycand" checked> 체인 밖 탐지도 보기(같은 공격자·확산 대상에서 나온 후보)</label> <label class="note"><input type="checkbox" id="storyobs" checked> 메타데이터 관측 보기(점선)</label>
 <div class="lead" id="storylead"></div><div class="ssum" id="storysum"></div><div class="legend" id="storyleg"></div>
 <h3 class="sub3">어느 단계까지 왔나</h3><div id="storyprog" style="overflow-x:auto"></div>
 <h3 class="sub3">어디서 어디로 퍼졌나</h3><div id="storygraph" style="overflow-x:auto"></div>
 <div id="storymeta"></div>
 <h3 class="sub3">무슨 일이 있었나</h3><ol class="nar" id="storylist"></ol>
 <details style="margin-top:8px"><summary class="note">근거 연결률(탐지 종류별, 빈틈 검토용)</summary><div id="storycov"></div></details>
 <div class="note">번호는 탐지 순서이고 세 그림에서 같습니다(그림의 번호·카드를 누르면 아래 설명으로 이동). 확산 경로의 열은 시작 공격자에서 몇 번 건너갔는지이며, 대상이 5대를 넘는 탐지는 4대만 그리고 나머지는 "외 N대"로 묶습니다. 채운 표시는 상관 규칙이 이은 확정 체인, 빈 표시·점선은 같은 공격자나 확산 대상에서 나온 체인 밖 탐지입니다. <i>추정</i> 줄은 선별 전송 로그를 출발·대상·시간(±10분, 흐름 요약 30분)으로 맞춘 값입니다. 설명의 보라 줄(번호 없음)은 메타데이터 관측으로, 같은 공격 인프라에 붙은 host의 첫 접속과 확인이 필요한 내부 접속을 시간 순서로 끼운 것입니다. 집계형 확산 탐지는 탐지 시각(집계 창 끝)이 아니라 공격자 → 대상의 첫 접속 추정 시각에 놓습니다. 요약 칸의 최초 관측·체류는 이 관측을 포함한 값이며, 관측 보기를 끄면 탐지만으로 셉니다.</div></div></section>
<section id="det"><h2>탐지</h2><div class="box"><div id="detbars"></div></div>
 <div class="box" style="margin-top:10px"><input class="filter" id="detf" placeholder="필터: 진단·IP·자산 이름·역할·OS·기법"><div id="dett"></div>
 <div class="note">행을 누르면 근거(evidence)가 펼쳐집니다. 대상은 확산·랜섬웨어 등에서는 피해 host, C2·유출·비표준 포트에서는 연결한 외부 서버입니다(<span class="chip ext">외부</span> 표시, 자산 식별 대상 아님). IP 옆 이름은 자산 판정 결과가 있으면 탐지 시각에 그 IP를 쓰던 자산(<span class="chip role">역할</span>·<span class="os">OS</span> 함께, 이름에 마우스를 올리면 자산 ID·식별 근거), 없으면 자산 신호의 호스트명(<i>기울임</i>, 판정 전 참고값)입니다. 검색 칸에 역할·OS(예: DC, Windows)를 넣으면 그 자산이 공격자·대상인 탐지만 남습니다.</div></div></section>
<section id="chain"><h2>킬체인 상관</h2><div class="box"><label class="note"><input type="checkbox" id="chainall"> 중간 단계 포함(체인이 길어질 때마다 나온 상관 탐지를 모두 보기)</label><div id="chaint"></div></div></section>
<section id="asset"><h2>자산</h2><div class="box"><input class="filter" id="asf" placeholder="필터: 이름·IP·OS·역할"><div class="note" id="asmac"></div><div id="ast"></div><div class="note" id="asnote"></div></div></section>
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
const proxyTip='명시적 프록시를 거친 연결입니다. 프록시는 중계 장비이고, 실제 목적지는 프록시가 받은 요청(CONNECT·Host)에서 알아냅니다. 연결이 캡처 시작 전부터 열려 있으면 목적지를 알 수 없습니다.';
const whoProxy=w=>`<span class="chip" title="${esc(proxyTip)}">프록시 경유</span> ${esc(w.ip)}${w.name?` <span class="chip guess">${esc(w.name)}</span>`:''} → ${(w.targets||[]).length?w.targets.map(t=>`<b>${esc(t)}</b>`).join(', '):`<span class="sus" title="${esc(proxyTip)}">목적지 확인 안 됨</span>`}`;
const who=w=>w&&w.proxy?whoProxy(w):w?`${esc(w.ip)}${(w.name||w.asset)?` <span class="chip${w.guess?' guess':''}" title="${esc(whoTip(w))}">${esc(w.name||w.asset)}</span>`:''}${(w.roles||[]).map(r=>` <span class="chip role" title="${esc(whoTip(w))}">${esc(r)}</span>`).join('')}${w.os?` <span class="os">${esc(w.os)}</span>`:''}${w.ext?' <span class="chip ext">외부</span>':''}`:'-';
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
const occ=d=>d.occurrences>1?` <span class="k" title="같은 공격이 이어져 나온 탐지를 한 사건으로 묶음">${d.occurrences}회 · ~${fmtT(d.last).slice(11)}</span>`:'';
table('dett',[['시각',d=>fmtT(d.first||d.ts),d=>d.first||d.ts],['진단',d=>esc(d.diagnosis)+occ(d),d=>d.diagnosis],['기법',d=>esc(d.techniques),d=>d.techniques],
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
const sel=document.getElementById('storysel');
sel.innerHTML=ST.length?ST.map((s,i)=>{const a=s.lanes[0];const st=[...new Set(s.steps.map(j=>D.detections[j].stages))].sort((x,y)=>stIdx(x)-stIdx(y));
 return `<option value="${i}">${s.confirmed.length?'확정 체인':'후보'} · ${esc(whoTxt(a))} · ${st.map(x=>STK[x]||x).join('→')} · 탐지 ${s.steps.length}건</option>`}).join(''):'<option>스토리 없음</option>';
const short=t=>String(t||'').replace(/\\(.*\\)/,'').trim();
const hostLbl=l=>l.proxy?'프록시 경유':l.ext?'외부':[l.name||l.asset,(l.roles||[])[0]].filter(Boolean).join(' · ');
function jump(k){const li=document.getElementById('sn'+k);if(!li)return;document.querySelectorAll('#storylist li.on').forEach(x=>x.classList.remove('on'));li.classList.add('on');li.scrollIntoView({block:'center',behavior:'smooth'})}
const tipHtml=x=>{const d=x.d;return `<b>${x.k}. ${esc(d.ko)}</b> <span class="mut">${esc(STK[d.stages]||d.stages)} · ${esc(d.techniques)}${x.c?' · 확정 체인':' · 체인 밖'}</span><br>${fmtT(d.first||d.ts)}${d.last&&d.last-d.first>=1?` ~ ${fmtT(d.last).slice(11)}`:''}<br>${who(d.attacker)} → ${d.victims.slice(0,6).map(who).join(', ')||'-'}${d.victims.length>6?` 외 ${d.victims.length-6}`:''}<div class="how">${howHtml(d)}</div>`};
// 진행 보드: 7단계 줄 + 단계별 카드(단계마다 6장까지)
function drawProg(steps){
 const order=D.stage_order;
 const prog=order.map(st=>{const n=steps.filter(x=>x.d.stages===st).length;
  return `<div class="pst st${stIdx(st)} ${n?'on':'off'}"><span class="pc">${n||'–'}</span>${esc(STK[st]||st)}${n?'':' · 관측 없음'}</div>`}).join('');
 const cols=order.map(st=>{const xs=steps.filter(x=>x.d.stages===st),more=xs.length-6;
  return `<div class="bcol"><div class="note" style="margin:0 0 2px;font-weight:600">${esc(STK[st]||st)}</div>`+(xs.length?xs.slice(0,6).map(x=>{const d=x.d;
   return `<div class="bcard st${stIdx(st)}${x.c?'':' cand'}" data-k="${x.k}"><div class="h"><span class="sw${x.c?'':' cand'}"></span><span class="bnum">${x.k}</span>${esc(short(d.ko))}</div><div class="w">${fmtT(d.first||d.ts).slice(11)} · ${esc((d.attacker&&(d.attacker.name||d.attacker.ip))||'-')}${d.victims.length?' → '+esc(d.victims.slice(0,2).map(v=>v.name||v.ip).join(', '))+(d.victims.length>2?` 외 ${d.victims.length-2}`:''):''}</div></div>`}).join('')+(more>0?`<div class="none">외 ${more}건</div>`:''):'<div class="none">없음</div>')+'</div>'}).join('');
 const el=document.getElementById('storyprog');el.innerHTML=`<div class="prog">${prog}</div><div class="board">${cols}</div>`;
 el.querySelectorAll('.bcard').forEach(c=>{const x=steps.find(y=>y.k===+c.dataset.k);c.onclick=()=>jump(x.k);c.onmousemove=e=>showTip(e,tipHtml(x));c.onmouseleave=hideTip});
}
// 확산 경로: 열 = 시작 공격자에서 몇 번 건너갔나. 대상이 5대 넘는 탐지는 다른 데 안 나오는 대상을 묶는다
function drawGraph(s,steps){
 const L={};s.lanes.forEach(l=>L[l.ip]=l);
 const actors=new Set(steps.map(x=>x.d.attacker&&x.d.attacker.ip).filter(Boolean));
 const seen={};steps.forEach(x=>x.d.victims.forEach(v=>seen[v.ip]=(seen[v.ip]||0)+1));
 const node={},depth={},edges=[],local={};
 const seed=s.seed;depth[seed]=0;node[seed]=L[seed]||{ip:seed};
 steps.forEach(x=>{const d=x.d,a=d.attacker&&d.attacker.ip;if(!a)return;
  if(!(a in depth)){depth[a]=1;node[a]=L[a]||d.attacker}
  const vs=d.victims.filter(v=>v.ip!==a);
  if(!vs.length){(local[a]=local[a]||[]).push(x);return}
  let show=vs,grp=[];
  if(vs.length>5){show=vs.filter(v=>actors.has(v.ip)||seen[v.ip]>1||v.ip in node);const rest=vs.filter(v=>!show.includes(v));
   show=show.concat(rest.slice(0,Math.max(0,4-show.length)));grp=vs.filter(v=>!show.includes(v))}
  show.forEach(v=>{if(!(v.ip in depth)){depth[v.ip]=depth[a]+1;node[v.ip]=L[v.ip]||v}edges.push({x,a,b:v.ip})});
  if(grp.length){const id='grp:'+x.k;depth[id]=depth[a]+1;node[id]={ip:id,grp:grp.length,ext:grp.every(v=>v.ext)};edges.push({x,a,b:id})}});
 const oedges=[];
 if(document.getElementById('storyobs').checked)(s.observed||[]).forEach(o=>{if(!(o.a in depth))return;
  if(!(o.b in depth)){depth[o.b]=depth[o.a]+1;node[o.b]=Object.assign({},o.who,{obs:true})}oedges.push(o)});
 const NW=200,NH=56,CG=130,RG=16,P=6,cols={};
 Object.keys(depth).forEach(ip=>{(cols[depth[ip]]=cols[depth[ip]]||[]).push(ip)});
 const ci=Object.keys(cols).map(Number).sort((a,b)=>a-b);
 const firstSeen=ip=>steps.findIndex(x=>(x.d.attacker&&x.d.attacker.ip)===ip||x.d.victims.some(v=>v.ip===ip)||('grp:'+x.k)===ip);
 ci.forEach(c=>cols[c].sort((p,q)=>((node[p].ext?1:0)-(node[q].ext?1:0))||(firstSeen(p)-firstSeen(q))));
 // 대상 없는 탐지 번호는 상자 안 부제 아래 줄에 8개씩(최대 3줄, 넘으면 +N). 번호가 있는 상자만 그만큼 높인다
 const BPR=8,BMAX=24,nloc=ip=>(local[ip]||[]).length,brows=ip=>Math.ceil(Math.min(nloc(ip),BMAX)/BPR),hgt=ip=>NH+(nloc(ip)?6+brows(ip)*24:0);
 const colH=c=>cols[c].reduce((t,ip)=>t+hgt(ip),0)+RG*(cols[c].length-1);
 const H=Math.max(140,Math.max(...ci.map(colH))+36),pos={};
 ci.forEach((c,i)=>{let y=Math.max(18,(H-colH(c))/2);cols[c].forEach(ip=>{pos[ip]={x:P+i*(NW+CG),y,h:hgt(ip)};y+=hgt(ip)+RG})});
 const W=P+ci.length*(NW+CG)-CG+P,g=[],nb=[],pairN={};
 edges.forEach(e=>{const A=pos[e.a],B=pos[e.b],cls='st'+stIdx(e.x.d.stages),cand=e.x.c?'':' cand',key=e.a+'>'+e.b,n=pairN[key]=(pairN[key]||0)+1,off=(n-1)*14;
  let d,lx,ly;
  if(B.x>A.x){const x1=A.x+NW,y1=A.y+NH/2+off,x2=B.x,y2=B.y+NH/2+off,mx=(x1+x2)/2;d=`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2-5},${y2}`;lx=x2-20-(n-1)*20;ly=y2}
  else{const x1=A.x+NW/2+off,y1=B.y>A.y?A.y+A.h:A.y,x2=B.x+NW/2+off,y2=B.y>A.y?B.y:B.y+B.h,dy=B.y>A.y?28:-28;d=`M${x1},${y1} C${x1},${y1+dy} ${x2},${y2-dy} ${x2},${y2-Math.sign(dy)*5}`;lx=(x1+x2)/2;ly=(y1+y2)/2}
  g.push(`<path class="ln ${cls}${cand}" d="${d}"/>`);nb.push({x:e.x,lx,ly})});
 oedges.forEach(o=>{const A=pos[o.a],B=pos[o.b],key=o.a+'>'+o.b,n=pairN[key]=(pairN[key]||0)+1,off=(n-1)*14-7;let d;
  if(B.x>A.x){const x1=A.x+NW,y1=A.y+NH/2+off,x2=B.x,y2=B.y+NH/2+off,mx=(x1+x2)/2;d=`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2-5},${y2}`}
  else{const x1=A.x+NW/2+off,y1=B.y>A.y?A.y+A.h:A.y,x2=B.x+NW/2+off,y2=B.y>A.y?B.y:B.y+B.h,dy=B.y>A.y?28:-28;d=`M${x1},${y1} C${x1},${y1+dy} ${x2},${y2-dy} ${x2},${y2-Math.sign(dy)*5}`}
  g.push(`<path class="lo${o.strong?' strong':''}" d="${d}"><title>관측(추정) ${fmtT(o.first).slice(11,16)}~${fmtT(o.last).slice(11,16)} · ${o.what.join(', ')}</title></path>`)});
 Object.keys(pos).forEach(ip=>{const p=pos[ip],n=node[ip]||{ip},cls=ip===seed?' seed':n.grp?' grp':n.obs?' obs':n.ext?' ext':'';
  g.push(`<rect class="node${cls}" x="${p.x}" y="${p.y}" width="${NW}" height="${p.h}" rx="8"/>`);
  if(n.grp)g.push(`<text x="${p.x+12}" y="${p.y+22}" style="font-weight:600">외 ${n.grp}대</text><text class="mt" x="${p.x+12}" y="${p.y+40}">${n.ext?'외부':'내부'} 대상(번호의 탐지 참고)</text>`);
  else{const l=L[ip]||n,nm=l.ext?ip:(l.name||l.asset||ip);
   g.push(`<text x="${p.x+12}" y="${p.y+22}" style="font-weight:600">${esc(String(nm).slice(0,24))}</text><text class="mt" x="${p.x+12}" y="${p.y+40}">${esc((l.proxy?'프록시 경유'+((l.targets||[]).length?' → '+l.targets[0]:' · 목적지 모름'):l.ext?'외부':[nm!==ip?ip:'',n.obs?'관측만':(l.roles||[])[0]].filter(Boolean).join(' · ')).slice(0,30))}</text>`)}
  if(ip===seed)g.push(`<text class="mt" x="${p.x}" y="${p.y-6}">시작</text>`);
  const lc=local[ip]||[],shown=lc.length>BMAX?lc.slice(0,BMAX-1):lc;
  shown.forEach((x,i)=>nb.push({x,lx:p.x+21+(i%BPR)*22,ly:p.y+NH+8+Math.floor(i/BPR)*24}));
  if(lc.length>BMAX)g.push(`<text class="mt" x="${p.x+12+(BMAX-1)%BPR*22}" y="${p.y+NH+12+Math.floor((BMAX-1)/BPR)*24}">+${lc.length-BMAX+1}</text>`)});
 nb.forEach(o=>g.push(`<g class="nb st${stIdx(o.x.d.stages)}${o.x.c?'':' cand'}" data-k="${o.x.k}"><circle cx="${o.lx}" cy="${o.ly}" r="9"/><text x="${o.lx}" y="${o.ly+3.6}" text-anchor="middle">${o.x.k}</text></g>`));
 const el=document.getElementById('storygraph');el.innerHTML=`<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="확산 경로">${g.join('')}</svg>`;
 el.querySelectorAll('g.nb').forEach(c=>{const x=steps.find(y=>y.k===+c.dataset.k);c.onclick=()=>jump(x.k);c.onmousemove=e=>showTip(e,tipHtml(x));c.onmouseleave=hideTip});
}
// 메타데이터 관측 패널: 같은 공격 인프라에 붙은 내부 host, 확인이 필요한 내부 접속
function drawMeta(s){
 const el=document.getElementById('storymeta');
 if(!document.getElementById('storyobs').checked){el.innerHTML='';return}
 const ST2={story:'<span class="tag">이 스토리 탐지</span>',other:'<span class="tag">다른 탐지</span>',obs:'<span class="tag obs">관측만</span>'};
 const inf=(s.infra||[]),ob=(s.observed||[]);let h='';
 h+=`<h3 class="sub3">같은 공격 인프라에 붙은 내부 host <span class="ob">관측</span></h3>`;
 if(!inf.length)h+='<div class="note">C2·유출 탐지의 외부 목적지에 접속한 다른 내부 host가 없습니다.</div>';
 else h+='<table><thead><tr><th>외부 목적지</th><th>내부 host</th><th>처음 ~ 마지막</th><th>기록</th><th>상태</th></tr></thead><tbody>'+inf.map(x=>{
   const head=`<td><code>${esc(x.key)}</code><div class="mut">${x.total}대${x.popular?' · 흔한 목적지':''}</div></td>`;
   const rows=x.hosts.map((y,i)=>`<tr>${i?'<td></td>':head}<td>${who(y.who)}</td><td class="tt2">${fmtT(y.first).slice(5,16)} ~ ${fmtT(y.last).slice(11,16)}</td><td class="mut">${esc(y.logs.join(', '))} · ${y.n}행</td><td>${ST2[y.status]}</td></tr>`);
   if(x.omitted)rows.push(`<tr>${rows.length?'<td></td>':head}<td colspan="4" class="mut">관측만 host ${x.omitted}대는 생략(내부 host 상당수가 접속하는 흔한 목적지)</td></tr>`);
   return rows.join('')}).join('')+'</tbody></table>';
 h+=`<h3 class="sub3">확인이 필요한 내부 접속 <span class="ob">관측</span> <span class="mut" style="font-weight:400">탐지 기준에는 못 미친 관리 접속 · 통신 기록으로 찾음</span></h3>`;
 const sk=s.observed_skip||{},skn=(sk.prior||0)+(sk.common||0);
 if(!ob.length)h+='<div class="note">스토리 host가 다른 내부 host로 한 관리 접속·인증 가운데 확인이 필요한 것이 없습니다(디렉터리·인증 서버로 가는 일상 통신은 뺌).</div>';
 else h+='<table><thead><tr><th>출발</th><th>대상</th><th>처음 ~ 마지막</th><th>관측 내용</th></tr></thead><tbody>'+ob.map(o=>{const a=(s.lanes.find(l=>l.ip===o.a))||{ip:o.a};
   return `<tr><td>${who(a)}</td><td>${who(o.who)}</td><td class="tt2">${fmtT(o.first).slice(11,16)} ~ ${fmtT(o.last).slice(11,16)}</td><td>${esc(o.what.join(' · '))}${o.strong?'':' <span class="mut">(연결·인증만)</span>'}</td></tr>`}).join('')+'</tbody></table>';
 if(skn)h+=`<div class="note">평소 통신으로 보고 뺀 출발·대상 ${skn}쌍: 스토리에 들어오기 전부터 같은 대상에 같은 접속을 하던 ${sk.prior||0}쌍, 스토리 밖 host ${D.obs_common}대 이상이 같은 대상에 같은 접속을 하는 ${sk.common||0}쌍(원격 실행·관리 공유는 빼지 않음).</div>`;
 h+='<div class="note">관측은 uid가 아니라 출발지·대상·시간으로 맞춘 추정입니다. 같은 인프라는 스토리 기간 앞뒤 24시간, 확인이 필요한 내부 접속은 host가 스토리에 들어온 10분 전부터 마지막 탐지 1시간 뒤까지 봅니다.</div>';
 el.innerHTML=h;
}
// 내러티브: 번호·시각·문장·근거, 10분 넘는 공백 표시
function drawNarr(steps,s){
 const out=[],est=(s&&s.est_first)||{},items=steps.map(x=>({t:Math.min(x.d.first||x.d.ts,est[x.j]||Infinity),last:x.d.last||x.d.ts,x})).concat(obsEvents(s||{})).sort((a,b)=>a.t-b.t||(a.x?-1:1));
 const lane=ip=>((s&&s.lanes)||[]).find(l=>l.ip===ip)||{ip};
 items.forEach((it,k)=>{
  if(k){const gap=it.t-Math.max(...items.slice(0,k).map(p=>p.last||p.t));if(gap>=600)out.push(`<li class="gapr"><span></span><span class="sp"></span><span>${dur(gap)} 뒤</span></li>`)}
  if(!it.x){
   const range=`${fmtT(it.t).slice(11,16)} ~ ${fmtT(it.last).slice(11,16)}`;
   if(it.kind==='move'){const o=it.o;
    out.push(`<li class="ob"><span class="tm">${fmtT(it.t).slice(11)}</span><span class="sp"><i class="od"></i></span><div class="bd">
     <div class="tt">${who(lane(o.a))} → ${who(o.who)} ${esc(o.what.join(' · '))}<span class="k">관측</span>${o.strong?'':'<span class="k">연결·인증만</span>'}</div>
     <div class="how">확인이 필요한 내부 접속 · ${esc(o.logs.join(', '))} · ${range}</div></div></li>`)}
   else{const y=it.y,st={story:'이 스토리 host',other:'다른 스토리에서 탐지된 host',obs:'탐지 없이 관측만 된 host'}[y.status];
    out.push(`<li class="ob"><span class="tm">${fmtT(it.t).slice(11)}</span><span class="sp"><i class="od"></i></span><div class="bd">
     <div class="tt">${who(y.who)} → ${it.keys.map(k=>`<code>${esc(k)}</code>`).join(', ')} 같은 공격 인프라에 접속<span class="k">관측</span></div>
     <div class="how">${esc(st)} · ${esc(y.logs.join(', '))} ${y.n}행 · ${range}</div></div></li>`)}
   return}
  const x=it.x,d=x.d;
  const vs=d.victims.filter(v=>!d.attacker||v.ip!==d.attacker.ip);
  out.push(`<li id="sn${x.k}" class="st${stIdx(d.stages)}"><span class="tm">${fmtT(it.t).slice(11)}</span><span class="sp"><span class="nn${x.c?'':' cand'}">${x.k}</span></span><div class="bd">
   <div class="tt">${esc(d.ko)}${est[x.j]?`<span class="k">첫 접속 ${fmtT(est[x.j]).slice(11)} 추정 · 탐지 ${fmtT(d.first||d.ts).slice(11)}</span>`:''}${d.occurrences>1?`<span class="k">${d.occurrences}회 이어짐 · ~${fmtT(d.last).slice(11)}</span>`:''}<span class="k">${esc(STK[d.stages]||d.stages)}</span><span class="k">${esc(d.techniques)}</span>${x.c?'':'<span class="k">체인 밖</span>'}</div>
   <div>${who(d.attacker)}${vs.length?' → '+vs.slice(0,4).map(who).join(', ')+(vs.length>4?` 외 ${vs.length-4}`:''):''} <span class="mut">· 근거 ${d.evidence_count}건</span></div>
   <div class="how">${howHtml(d)||'근거·선별 전송 기록 없음'}</div></div></li>`)});
 document.getElementById('storylist').innerHTML=out.join('');
}
// 관측 사건: 확인이 필요한 내부 접속(observed)과 같은 인프라에 붙은 다른 host(흔한 목적지 제외)의 첫 접속
function obsEvents(s){
 if(!document.getElementById('storyobs').checked)return[];
 const ev=(s.observed||[]).map(o=>({t:o.first,last:o.last,kind:'move',o}));
 const byHost={};   // host 하나가 같은 C2 의 IP·이름 여러 키에 붙으면 한 줄로
 (s.infra||[]).forEach(x=>{if(x.popular)return;x.hosts.forEach(y=>{const ip=y.who.ip,e=byHost[ip];
  if(!e)byHost[ip]={t:y.first,last:y.last,kind:'infra',keys:[x.key],y:{...y,logs:[...y.logs]}};
  else{e.t=Math.min(e.t,y.first);e.last=Math.max(e.last,y.last);e.keys.push(x.key);e.y.n+=y.n;y.logs.forEach(g=>{if(!e.y.logs.includes(g))e.y.logs.push(g)})}})});
 return ev.concat(Object.values(byHost)).sort((a,b)=>a.t-b.t);
}
// 스토리 요약 칸: 기간(최초 관측부터), 탐지 전 관측 시간, 탐지·host·외부 수, 관측으로만 드러난 host
function drawSum(s,steps,t0,t1,intH,extH,used){
 const ev=obsEvents(s),f=ev.length?Math.min(t0,ev[0].t):t0,l=Math.max(t1,...ev.map(e=>e.last||e.t));
 const only=new Set();ev.forEach(e=>{const ip=e.kind==='move'?e.o.b:e.y.who.ip;if(!used.has(ip)&&(e.kind==='move'||e.y.status==='obs'))only.add(ip)});
 const other=new Set();ev.forEach(e=>{if(e.kind==='infra'&&e.y.status==='other'&&!used.has(e.y.who.ip))other.add(e.y.who.ip)});
 const sameDay=fmtT(f).slice(0,10)===fmtT(l).slice(0,10),nconf=steps.filter(x=>x.c).length,lead_=t0-f,obsOn=document.getElementById('storyobs').checked;
 const c=[[`${fmtT(f).slice(5,16)} ~ ${fmtT(l).slice(sameDay?11:5,16)}`,ev.length?'최초 관측 ~ 마지막 활동':'첫 탐지 ~ 마지막 탐지',lead_>0],
  [`${dur(Math.max(0,l-f))}`,ev.length?'관측 포함 전체 기간':'탐지 기간',false]];
 if(obsOn)c.push([lead_>0?dur(lead_):'-',lead_>0?'최초 관측에서 첫 탐지까지':'첫 탐지보다 앞선 관측 없음',lead_>0]);
 c.push([`${steps.length}건`,nconf?`탐지(확정 체인 ${nconf})`:'탐지',false],[`${intH}대`,'탐지로 확인된 내부 host',false]);
 if(obsOn)c.push([`+${only.size}대`,'관측으로만 드러난 내부 host'+(other.size?` · 다른 스토리 탐지 host ${other.size}대`:''),only.size>0]);
 c.push([`${extH}곳`,'외부 대상(IP·이름)',false]);
 document.getElementById('storysum').innerHTML=c.map(([v,k,o])=>`<div${o?' class="o"':''}><b>${esc(v)}</b><span>${esc(k)}</span></div>`).join('');
}
function drawStory(){
 const lead=document.getElementById('storylead'),leg=document.getElementById('storyleg');
 if(!ST.length){['storyprog','storygraph','storylist','storysum'].forEach(i=>document.getElementById(i).innerHTML='');lead.innerHTML='<span class="mut">탐지가 없습니다.</span>';leg.innerHTML='';return}
 const s=ST[+sel.value||0],conf=new Set(s.confirmed),showC=document.getElementById('storycand').checked;
 const steps=s.steps.filter(j=>showC||!conf.size||conf.has(j)).map((j,i)=>({j,k:i+1,d:D.detections[j],c:conf.has(j)}));
 const stUsed=[...new Set(steps.map(x=>x.d.stages))].sort((a,b)=>stIdx(a)-stIdx(b));
 leg.innerHTML=stUsed.map(x=>`<span class="st${stIdx(x)}"><span class="sw"></span>${esc(STK[x]||x)}</span>`).join('')+'<span class="stn" style="margin-left:8px"><span class="sw"></span>확정 체인</span><span class="stn"><span class="sw cand"></span>체인 밖(후보)</span>'+(document.getElementById('storyobs').checked?'<span><span class="sw obs"></span>메타데이터 관측(추정)</span>':'');
 const t0=steps.length?(steps[0].d.first||steps[0].d.ts):0,t1=steps.length?Math.max(...steps.map(x=>x.d.last||x.d.ts)):0;
 const used=new Set();steps.forEach(x=>{if(x.d.attacker)used.add(x.d.attacker.ip);x.d.victims.forEach(v=>used.add(v.ip))});
 const lanes=s.lanes.filter(l=>used.has(l.ip)),intH=lanes.filter(l=>!l.ext).length,extH=new Set(lanes.filter(l=>l.ext).map(l=>l.ip).concat(s.ext_keys||[])).size;
 lead.innerHTML=`<b>${esc(whoTxt(s.lanes[0]))}</b>에서 시작해 ${fmtT(t0)}부터 약 ${dur(Math.max(0,t1-t0))} 동안 ${stUsed.map(x=>STK[x]||x).join(' → ')} (탐지 ${steps.length}건, 관련 내부 host ${intH}대, 외부 ${extH}곳).`+
  (s.chains.length?` <span class="mut">상관 체인 ${s.chains.length}개: <code>${esc(s.chains.slice(-1)[0])}</code>${s.chains.length>1?' 등':''}</span>`:' <span class="mut">상관 규칙이 이은 체인은 없습니다.</span>');
 drawSum(s,steps,t0,t1,intH,extH,used);
 drawProg(steps);drawGraph(s,steps);drawMeta(s);drawNarr(steps,s);
}
table('storycov',[['단계',r=>esc(STK[r.stage]||r.stage),r=>stIdx(r.stage)],['탐지',r=>esc(r.ko),r=>r.ko],['건수',r=>r.n,r=>r.n,'num'],
 ['근거 내용',r=>`${r.facts}/${r.n}`,r=>r.facts/r.n,'num'],['근거 계정',r=>`${r.eacct}/${r.n}`,r=>r.eacct/r.n,'num'],
 ['추정 근거',r=>`${r.how}/${r.n}`,r=>r.how/r.n,'num'],['추정 계정',r=>`${r.acct}/${r.n}`,r=>r.acct/r.n,'num'],
 ['외부 대상 이름(SNI·Host)',r=>r.ext?`${r.ext_named}/${r.ext}`:'-',r=>r.ext?r.ext_named/r.ext:-1,'num'],
 ['근거 행 uid',r=>r.ev?`${r.ev_uid}/${r.ev}`:'-',r=>r.ev?r.ev_uid/r.ev:-1,'num']],D.coverage);
sel.onchange=drawStory;document.getElementById('storycand').onchange=drawStory;document.getElementById('storyobs').onchange=drawStory;drawStory();
// 자산
const roleChips=a=>a.roles.length?a.roles.map(r=>`<span class="chip">${esc(r)}</span>`).join(''):(a.devices||[]).map(r=>`<span class="chip" title="장비 종류(인증서·syslog·에이전트 통신)">${esc(r)}</span>`).join('')+(a.services||[]).map(r=>`<span class="chip guess" title="응답한 서비스(역할 판정 전)">${esc(r)}</span>`).join('');
table('ast',[['관련 탐지',a=>a.detections?`<span class="sus">${a.detections}</span>`:'0',a=>a.detections,'num'],['이름',a=>esc(a.name)||`<span class="mut">${esc(a.id)||'-'}</span>`,a=>a.name||a.id],
 ['식별 키',a=>esc(a.key),a=>a.key],['IP',a=>a.ips.map(esc).join('<br>'),a=>a.ips.join()],['MAC·제조사',a=>a.macs.map(esc).join('<br>')+(a.vendor?`<div class="mut">${esc(a.vendor)}</div>`:a.mac_local?'<div class="mut" title="로컬 관리 비트가 켜진 MAC: 모바일 랜덤 MAC·가상 머신·직접 정한 주소">로컬·랜덤 MAC</div>':''),a=>a.macs.join()+' '+(a.vendor||'')],
 ['OS',a=>esc(a.os)+(a.os_src?` <span class="mut" title="센서 OS 힌트가 없어 ${esc(a.os_src)}로 채움">(${esc(a.os_src)})</span>`:'')+(a.tcp_os&&!a.os_src&&a.os?`<div class="mut" title="${esc(a.tcp_basis)}">TCP: ${esc(a.tcp_os)}</div>`:''),a=>a.os],
 ['장비 유형',a=>a.dev_class?`<span class="chip${a.dev_conf==='낮음'?' guess':''}" title="${esc((a.dev_basis||'')+(a.dev_conf?' · 신뢰도 '+a.dev_conf:''))}">${esc(a.dev_class)}</span>`:'',a=>a.dev_class||''],
 ['지문(제품·장비)',a=>(a.proxy_like?'<span class="chip sus" title="서로 다른 HTTP Server 값으로 응답: 투명 프록시·로드밸런서·NAT 뒤 여러 서버로 추정. HTTP로 얻은 OS는 쓰지 않음">프록시·중계 추정</span>':'')+(a.fp||[]).map(f=>`<span class="chip" style="white-space:normal;max-width:220px" title="${esc(f.src)}">${esc(f.text)}</span>`).join(''),a=>(a.fp||[]).map(f=>f.text).join()],['보안 제품',a=>(a.agents||[]).map(g=>`<span class="chip">${esc(g.replace(/^ahnlab:/,'AhnLab '))}</span>`).join(''),a=>(a.agents||[]).join()],[D.asset_mode==='resolver'?'역할':'역할·서비스',roleChips,a=>(a.roles.length?a.roles:(a.devices||[]).concat(a.services||[])).join()],['신호',a=>a.signals,a=>a.signals,'num']],D.assets,{filter:'asf'});
const ms=D.mac_summary,mdsN=D.assets.filter(a=>(a.agents||[]).includes('ahnlab:mds-agent')).length;
document.getElementById('asmac').innerHTML=ms?`<b>MAC으로는 자산을 구분할 수 없는 캡처 지점입니다.</b> MAC이 관측된 IP ${ms.ips.toLocaleString('en-US')}개 중 ${ms.router_ips.toLocaleString('en-US')}개가 라우터로 보이는 MAC ${ms.router_macs}개를 나눠 씁니다(MAC은 모두 ${ms.macs}개). 센서가 라우팅을 거친 뒤 구간을 보고 있어 이 MAC은 PC가 아니라 라우터(L3 스위치) 것이며, 표에는 <i>(라우터)</i>로만 적었습니다. 자산 구분은 이름·OS 힌트·에이전트 같은 다른 신호로 합니다.`:'';
const DC={};D.assets.forEach(a=>{if(a.dev_class)DC[a.dev_class]=(DC[a.dev_class]||0)+1});
const EI=D.enrich||{},einfo=(Object.keys(DC).length?`<div style="margin-top:4px">장비 유형: ${Object.entries(DC).sort((x,y)=>y[1]-x[1]).map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join('')} <span class="mut">(기울임은 신뢰도 낮음. 노트북·데스크톱은 기본 컴퓨터 이름·기기 모델이 있을 때만 구분)</span></div>`:'')+((EI.oui_empty||[]).length?`<div class="sus" style="margin-top:4px">OUI 파일에서 제조사를 한 줄도 읽지 못했습니다: ${esc(EI.oui_empty.join(', '))}. 접두어·제조사 열(IEEE: Assignment·Organization Name, maclookup: Mac Prefix·Vendor Name)이 있는 CSV인지 확인하세요.</div>`:'')+(EI.proxy_like?`<div style="margin-top:4px">서로 다른 HTTP Server 값으로 응답한 IP ${EI.proxy_like}개는 프록시·중계 장비로 보고 HTTP로 얻은 OS를 쓰지 않았습니다.</div>`:'')+`<div style="margin-top:4px">자산 정보 보강(Manager 후처리 시제품): 제조사는 ${EI.oui_entries?`IEEE OUI 목록 ${EI.oui_entries.toLocaleString('en-US')}개(${esc((EI.oui_files||[]).join(', '))})`:'OUI 목록 미지정(run_pcap.sh -u, 로컬·랜덤 MAC 여부만 표시)'}, 지문은 ${EI.recog_count?`Recog ${EI.recog_count.toLocaleString('en-US')}개${EI.recog_bad?` (Python 정규식으로 못 옮긴 ${EI.recog_bad}개 제외)`:''}`:'Recog 미지정(run_pcap.sh -g)'}, OS 칸이 비면 지문 OS나 TCP SYN 모양(초기 TTL·윈도·옵션, 계열 수준)으로 채웁니다. 라우터 공유 MAC에는 제조사를 붙이지 않습니다.</div>`;
document.getElementById('asnote').innerHTML=einfo+(D.asset_mode==='resolver'
 ?`자산 판정은 claudtest2 리졸버 결과입니다. 근거 신호 타임라인·식별 품질은 ${D.asset_report?`<a href="${esc(D.asset_report)}">자산 리포트</a>`:'자산 리포트'}를 보세요.`
 :`자산 판정 없이 IP별 신호만 보여 줍니다(run_pcap.sh -r &lt;claudtest2 경로&gt; 를 주면 자산 단위로 묶고 OS·역할을 판정합니다). 이름·MAC·OS·서비스는 신호 값을 그대로 옮긴 참고값입니다. MAC은 많이 관측된 2개, OS는 신뢰도가 가장 높은 힌트이며, 역할 칸에는 판정 대신 장비 종류와 응답한 서비스(기울임)를 보입니다. IPv4 2개가 같은 MAC이면 공유(이중화 VIP나 IP가 여러 개인 서버일 수 있음), 3개 이상이면 라우터(또는 라우터 뒤 주소)로 표시합니다. ${mdsN?`AhnLab MDS Agent 통신(에이전트 포트 연결)이 보인 IP는 ${mdsN}개입니다. 신호가 없다고 미설치는 아닙니다(경로·관측 시간). `:''}신호 ${D.signal_rows}행: `+D.signal_counts.map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join(''));
// 전송량
const mm=Math.max(1,...D.meta.map(m=>m.bytes));const mt=D.meta.reduce((a,b)=>a+b.bytes,0);
document.getElementById('xft').innerHTML=`<table><tr><th>구분</th><th class="num">바이트</th><th></th></tr>
 <tr><td><b>Manager 전송 합계</b></td><td class="num"><b>${fmtB(mgrTotal)}</b></td><td>${perDay?`하루 환산 약 ${fmtB(perDay)}/일 (단순 비례, 짧은 캡처는 과대평가)`:''}</td></tr>
 <tr><td>선별 전송(/log/zeek/meta)</td><td class="num">${fmtB(mt)}</td><td></td></tr>
 <tr><td>자산 신호(asset_signal)</td><td class="num">${fmtB(D.mgr.asset_signal)}</td><td></td></tr>
 <tr><td>탐지 로그(탐지·근거·예외)</td><td class="num">${fmtB(D.mgr.nsm_detection+D.mgr.evidence+D.mgr.nsm_exception)}</td><td></td></tr>
 <tr><td class="mut">센서 로컬 로그(notice·stats 등, 전송 안 함)</td><td class="num mut">${fmtB(Object.values(D.local).reduce((a,b)=>a+b,0))}</td><td></td></tr>${Object.keys(D.raw||{}).length?`
 <tr><td class="mut">원본 로그(run_pcap.sh -k, 운영에서는 남기지 않음)</td><td class="num mut">${fmtB(Object.values(D.raw).reduce((a,b)=>a+b,0))}</td><td class="mut">${Object.keys(D.raw).length}개: ${esc(Object.keys(D.raw).sort().join(', '))}</td></tr>`:''}</table>
 <h2 style="margin-top:14px">선별 전송 로그별</h2><table><tr><th>로그</th><th class="num">바이트</th><th class="num">행</th><th></th></tr>`+
 D.meta.map(m=>`<tr><td>${esc(m.name)}</td><td class="num">${fmtB(m.bytes)}</td><td class="num">${m.rows.toLocaleString()}</td><td style="width:40%"><div class="bar" style="width:${100*m.bytes/mm}%"></div></td></tr>`).join('')+'</table>'+
 '<div class="note">전체 Zeek 로그 대비 비율과 처리 부하는 tests/measure_meta_export.sh 로 잽니다.</div>';
// 예외
const ek={};D.exceptions.forEach(e=>{const k=e.exception_id;ek[k]=ek[k]||{id:k,kinds:new Set(),hits:0,disp:e.disposition||'',scope:e.scope||'',msg:''};
 ek[k].kinds.add(e.kind);if(e.kind==='hits')ek[k].hits+=e.hits||0;if(e.scope)ek[k].scope=e.scope;if(e.disposition)ek[k].disp=e.disposition;if(e.msg&&e.kind!=='hits')ek[k].msg=e.msg});
table('exct',[['예외 ID',e=>`<code>${esc(e.id)}</code>`,e=>e.id],['상태',e=>[...e.kinds].filter(k=>k!=='hits').map(k=>`<span class="chip ${k==='rejected'||k==='error'?'sus':''}">${esc(k)}</span>`).join(''),e=>[...e.kinds].join()],
 ['처리',e=>esc(e.disp),e=>e.disp],['범위',e=>esc([].concat(e.scope||[]).join(', ')),e=>[].concat(e.scope||[]).join()],['적중(관측 수)',e=>e.hits.toLocaleString(),e=>e.hits,'num'],['비고',e=>esc(e.msg),e=>e.msg]],Object.values(ek));
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
    ap.add_argument("--oui", action="append", help="IEEE OUI 목록 CSV(MA-L·MA-M·MA-S, 여러 번 줄 수 있음). MAC 제조사 표시")
    ap.add_argument("--recog", help="Recog 지문 xml 폴더(github.com/rapid7/recog 의 xml/). 배너·헤더로 제품·장비 종류 표시")
    ap.add_argument("--mockup-out", help="목업형 리포트 경로(기본: -o 이름에 _mockup 을 붙임)")
    ap.add_argument("--no-mockup", action="store_true", help="목업형 리포트를 만들지 않음")
    args = ap.parse_args()
    data = collect(args.zeek_dir, args.assets, args)
    blob = json.dumps(data, ensure_ascii=False, default=list).replace("</", "<\\/")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(PAGE.replace("__DATA__", blob))
    print(f"통합 리포트: {args.out} (탐지 {len(data['detections'])}건, 자산 {len(data['assets'])}개, 공격 스토리 {len(data['stories'])}개)")
    if not args.no_mockup:
        # 같은 데이터를 MDS Manager 목업 화면으로(ui/mockup/mdsm_nsm_mockup.html 을 템플릿으로)
        import report_mockup
        mo = args.mockup_out or re.sub(r"(\.html?)?$", "_mockup.html", args.out, count=1)
        if os.path.exists(report_mockup.TEMPLATE):
            mock = report_mockup.build(data, args.zeek_dir, args.tz)
            report_mockup.render(mock, mo)
            print(f"목업형 리포트: {mo} (탐지 {len(mock['ev'])}건, 공격 스토리 {len(mock['stories'])}개, 자산 {len(mock['assets'])}개)")
        else:
            print(f"  경고: 목업 템플릿이 없어 목업형 리포트를 건너뜀({report_mockup.TEMPLATE})")
    ei = data.get("enrich") or {}
    if ei.get("oui_empty"):
        print(f"  경고: OUI 파일에서 제조사를 한 줄도 읽지 못함({', '.join(ei['oui_empty'])}). 접두어·제조사 열이 있는 CSV 인지 확인")
    if ei.get("oui_files") or ei.get("recog_count"):
        print(f"  자산 정보 보강: OUI {ei.get('oui_entries', 0)}개, Recog 지문 {ei.get('recog_count', 0)}개, 프록시·중계 추정 IP {ei.get('proxy_like', 0)}개")
    if data["coverage"]:
        # 주소·이름 원문 없이 숫자만(공유해도 되는 형태)
        print("  스토리 근거 연결률(탐지 종류: 건수 | 근거 계정 | 추정 근거 | 추정 계정 | 외부 이름 | 근거 uid)")
        for r in data["coverage"]:
            ext = f"{r['ext_named']}/{r['ext']}" if r["ext"] else "-"
            evu = f"{r['ev_uid']}/{r['ev']}" if r["ev"] else "-"
            print(f"    {r['name']:20s} {r['n']:4d} | {r['eacct']:4d} | {r['how']:4d} | {r['acct']:4d} | {ext:>7s} | {evu:>9s}")


if __name__ == "__main__":
    sys.exit(main())
