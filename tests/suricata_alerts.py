#!/usr/bin/env python3
"""Suricata 경보 -> 시그니처 탐지(리포트용). Manager 정규화 규칙(docs/SURICATA_INTEGRATION_DESIGN.md 3~4장)의 PoC 구현.

입력은 센서 경보 파일(eve-alert.json, Suricata eve 줄) 또는 전송 스트림(suricata_alert envelope JSONL).
  - 단계: SID 지정(stage_map) -> 룰 메타데이터 mitre_tactic_id -> 분류(classtype) -> 단계 없음(Suricata_Other)
  - 출발지·대상: 경보의 source·target(룰 target 키워드) -> C2·유출은 내부 쪽이 출발지 -> 응답 방향(to_client)이면 뒤집음
  - 연결 찾기: community_id 로 선별 전송 연결 로그(ssl·http 등)와 원본 conn.log -> uid·목적지 이름·프록시(CONNECT)
  - 반복 묶기: (탐지 종류, 출발지, 대상)이 15분 안에 다시 나오면 한 탐지(occ)
위험도 변환(우선순위 1 High, 2 Medium, 3·4 Low)과 목적지 역할로 올리기는 화면에 보일 값(sig_sev)만 만든다.
리포트의 등급(Information·Suspicious)은 센서 값 체계를 그대로 쓴다. 시그니처 예외(Manager 적용)는 pcap 실행에 없다.
표준 라이브러리만 쓴다.
"""
import datetime as dt
import json
import os

GROUP_GAP = 15 * 60        # 반복 묶기 간격(Manager 사건 묶기와 같음)

STAGE_NOTE = {"Recon": "Suricata_Recon", "Initial Access": "Suricata_Initial_Access", "Command and Control": "Suricata_C2",
              "Credential Access": "Suricata_Credential", "Lateral Movement": "Suricata_Lateral",
              "Exfiltration": "Suricata_Exfil", "Impact": "Suricata_Impact", "": "Suricata_Other"}
DIAG = {"Recon": "Recon", "Initial Access": "InitialAccess", "Command and Control": "C2", "Credential Access": "CredentialAccess",
        "Lateral Movement": "Lateral", "Exfiltration": "Exfil", "Impact": "Impact", "": "Other"}
TACTIC_STAGE = {"TA0043": "Recon", "TA0007": "Recon", "TA0001": "Initial Access", "TA0011": "Command and Control",
                "TA0006": "Credential Access", "TA0008": "Lateral Movement", "TA0010": "Exfiltration", "TA0040": "Impact"}
# 설계 4.2절 표. 없는 분류는 다음 순서(단계 없음)로
CLASSTYPE_STAGE = {"trojan-activity": "Command and Control", "command-and-control": "Command and Control",
                   "web-application-attack": "Initial Access", "attempted-admin": "Initial Access", "attempted-user": "Initial Access",
                   "attempted-recon": "Recon", "network-scan": "Recon", "credential-theft": "Credential Access",
                   "policy-violation": "", "misc-activity": ""}
# eve 의 category 는 classification.config 의 설명 문장이다(Suricata 8.0.6 기본값). 설명 -> 분류 이름
CLASSTYPE_DESC = {
    "Not Suspicious Traffic": "not-suspicious", "Unknown Traffic": "unknown", "Potentially Bad Traffic": "bad-unknown",
    "Attempted Information Leak": "attempted-recon", "Information Leak": "successful-recon-limited",
    "Large Scale Information Leak": "successful-recon-largescale", "Attempted Denial of Service": "attempted-dos",
    "Denial of Service": "successful-dos", "Attempted User Privilege Gain": "attempted-user",
    "Unsuccessful User Privilege Gain": "unsuccessful-user", "Successful User Privilege Gain": "successful-user",
    "Attempted Administrator Privilege Gain": "attempted-admin", "Successful Administrator Privilege Gain": "successful-admin",
    "Decode of an RPC Query": "rpc-portmap-decode", "Executable code was detected": "shellcode-detect",
    "A suspicious string was detected": "string-detect", "A suspicious filename was detected": "suspicious-filename-detect",
    "An attempted login using a suspicious username was detected": "suspicious-login", "A system call was detected": "system-call-detect",
    "A TCP connection was detected": "tcp-connection", "A Network Trojan was detected": "trojan-activity",
    "A client was using an unusual port": "unusual-client-port-connection", "Detection of a Network Scan": "network-scan",
    "Detection of a Denial of Service Attack": "denial-of-service", "Detection of a non-standard protocol or event": "non-standard-protocol",
    "Generic Protocol Command Decode": "protocol-command-decode", "access to a potentially vulnerable web application": "web-application-activity",
    "Web Application Attack": "web-application-attack", "Misc activity": "misc-activity", "Misc Attack": "misc-attack",
    "Generic ICMP event": "icmp-event", "Inappropriate Content was Detected": "inappropriate-content",
    "Potential Corporate Privacy Violation": "policy-violation", "Attempt to login by a default username and password": "default-login-attempt",
    "Targeted Malicious Activity was Detected": "targeted-activity", "Exploit Kit Activity Detected": "exploit-kit",
    "Device Retrieving External IP Address Detected": "external-ip-check", "Domain Observed Used for C2 Detected": "domain-c2",
    "Possibly Unwanted Program Detected": "pup-activity", "Successful Credential Theft Detected": "credential-theft",
    "Possible Social Engineering Attempted": "social-engineering", "Crypto Currency Mining Activity Detected": "coin-mining",
    "Malware Command and Control Activity Detected": "command-and-control",
}
SEVERITY = {1: "High", 2: "Medium", 3: "Low", 4: "Low"}
# 연결 단위 선별 전송 로그(community_id 가 있음, SRS_METADATA_EXPORT FR-M17)
META_CONN_LOGS = ("http", "ssl", "ssh", "rdp", "kerberos", "ntlm", "smb_mapping", "smb_files", "dce_rpc")


def parse_ts(s):
    """Suricata 시각 '2026-11-09T00:01:00.025000+0000' -> epoch 초."""
    if s.endswith("Z"):
        s = s[:-1] + "+0000"
    if len(s) > 6 and s[-3] == ":" and s[-6] in "+-":
        s = s[:-3] + s[-2:]
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def load(paths):
    """eve 경보 파일·envelope JSONL -> eve 경보 dict 목록(시각순)."""
    out = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                ev = rec.get("data") if rec.get("stream") == "suricata_alert" else rec
                if not isinstance(ev, dict) or "alert" not in ev or (ev.get("event_type") not in (None, "alert")):
                    continue
                try:
                    ev["_ts"] = parse_ts(ev["timestamp"])
                except (KeyError, ValueError):
                    continue
                out.append(ev)
    return sorted(out, key=lambda e: e["_ts"])


def _meta_list(md, key):
    v = (md or {}).get(key) or []
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def stage_of(alert, stage_map=None):
    """(단계, 근거, 분류 이름). 근거: sid_map·mitre·classtype."""
    a = alert["alert"]
    sid = a.get("signature_id")
    if stage_map and sid in stage_map:
        return stage_map[sid], "sid_map", CLASSTYPE_DESC.get(a.get("category") or "", "")
    for t in _meta_list(a.get("metadata"), "mitre_tactic_id"):
        if t in TACTIC_STAGE:
            return TACTIC_STAGE[t], "mitre", CLASSTYPE_DESC.get(a.get("category") or "", "")
    cls = CLASSTYPE_DESC.get(a.get("category") or "", "")
    return CLASSTYPE_STAGE.get(cls, ""), "classtype", cls


def endpoints(alert, stage, internal):
    """(출발 IP, 출발 포트, 대상 IP, 대상 포트)."""
    a = alert["alert"]
    s, sp, d, dp = alert.get("src_ip"), alert.get("src_port"), alert.get("dest_ip"), alert.get("dest_port")
    src, tgt = a.get("source") or {}, a.get("target") or {}
    if src.get("ip") and tgt.get("ip"):
        return src["ip"], src.get("port"), tgt["ip"], tgt.get("port")
    if stage in ("Command and Control", "Exfiltration") and internal(s) != internal(d):
        return (s, sp, d, dp) if internal(s) else (d, dp, s, sp)
    if alert.get("direction") == "to_client":
        return d, dp, s, sp
    return s, sp, d, dp


def conn_index(zeek_dir):
    """community_id -> {uid, logs, names, connect}. 선별 전송 연결 로그와(있으면) 원본 conn.log."""
    idx = {}

    def add(cid, r, log):
        if not cid:
            return
        x = idx.setdefault(cid, {"uid": "", "logs": [], "names": [], "connect": None})
        x["uid"] = x["uid"] or r.get("uid") or ""
        if log not in x["logs"]:
            x["logs"].append(log)
        name = r.get("host") or r.get("server_name")
        if name and name not in x["names"]:
            x["names"].append(name)
        if log == "http" and r.get("method") == "CONNECT" and r.get("host"):
            x["connect"] = r["host"]

    for log in META_CONN_LOGS:
        p = os.path.join(zeek_dir, "meta", log + ".log")
        for r in _rows(p):
            add(r.get("community_id"), r, log)
    for r in _rows(os.path.join(zeek_dir, "conn.log")):
        add(r.get("community_id"), r, "conn")
    return idx


def _rows(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def normalize(alerts, zeek_dir, internal, stage_map=None):
    """eve 경보 목록 -> 시그니처 탐지 목록(반복 묶기 뒤, 시각순)."""
    conns = conn_index(zeek_dir)
    groups, open_ = [], {}
    for al in alerts:
        a = al["alert"]
        if not al.get("src_ip") and not al.get("dest_ip"):
            continue                    # IP 가 없는 경보(디코더 이벤트 등): 출발지·대상이 없어 탐지로 만들지 않음
        stage, by, cls = stage_of(al, stage_map)
        rule = STAGE_NOTE[stage]
        s, sp, d, dp = endpoints(al, stage, internal)
        key = (rule, s, d)
        g = open_.get(key)
        if g is None or al["_ts"] - g["last"] > GROUP_GAP:
            pri = int(a.get("severity") or 3)
            g = {"ts": al["_ts"], "last": al["_ts"], "rule": rule, "stage": stage, "stage_by": by,
                 "sid": a.get("signature_id"), "rev": a.get("rev"), "signature": a.get("signature") or "",
                 "category": a.get("category") or "", "classtype": cls, "priority": pri, "sig_sev": SEVERITY.get(pri, "Low"),
                 "technique": _meta_list(a.get("metadata"), "mitre_technique_id"),
                 "src": s, "src_port": sp, "dst": d, "dst_port": dp, "proto": (al.get("proto") or "").lower(),
                 "app_proto": al.get("app_proto") or "", "community_ids": [], "uid": "", "dst_name": "", "proxy": "",
                 "occ": 0, "signatures": {}, "defs": {}}
            groups.append(g)
            open_[key] = g
        g["last"] = al["_ts"]
        g["occ"] += 1
        sg = g["signatures"].setdefault(a.get("signature_id"), [a.get("signature") or "", 0])
        sg[1] += 1
        if a.get("signature_id") not in g["defs"]:
            # 시그니처별 정의(화면의 시그니처 정보): 같은 탐지로 묶인 다른 시그니처도 각자 단계 근거·분류를 가진다
            g["defs"][a.get("signature_id")] = {"rev": a.get("rev"), "msg": a.get("signature") or "", "cat": a.get("category") or "",
                                                "cls": cls or "-", "pri": int(a.get("severity") or 3), "stage": stage, "by": by,
                                                "tech": ",".join(_meta_list(a.get("metadata"), "mitre_technique_id"))}
        cid = al.get("community_id")
        if cid and cid not in g["community_ids"]:
            g["community_ids"].append(cid)
            c = conns.get(cid)
            if c:
                g["uid"] = g["uid"] or c["uid"]
                if c["connect"] and not g["proxy"]:
                    # 명시적 프록시 경유: 대상은 프록시, 실제 목적지는 CONNECT 대상(Zeek 룰과 같음, 설계 3.5)
                    g["proxy"] = f"{al.get('dest_ip')}:{al.get('dest_port')}"
                    g["dst_name"] = c["connect"]
                elif c["names"] and not g["dst_name"]:
                    g["dst_name"] = c["names"][0]
    for g in groups:
        g["signatures"] = [[sid, v[0], v[1]] for sid, v in g["signatures"].items()]
        g["src_internal"], g["dst_internal"] = bool(g["src"] and internal(g["src"])), bool(g["dst"] and internal(g["dst"]))
    return groups
