"""자산 정보 보강 — Manager 후처리 시제품(PoC 리포트용).

센서 asset_signal.log 의 신호를 외부 지문 DB 로 해석한다. DB 는 저장소에 넣지 않고 실행 때 경로로 준다.

- OUI: IEEE 공개 목록 CSV(MA-L·MA-M·MA-S, 열: Registry,Assignment,Organization Name,...) → MAC 제조사.
  로컬 관리 비트가 켜진 MAC(랜덤·가상)은 제조사가 없으므로 따로 표시한다. 라우터 공유 MAC 은 호출하는 쪽이 뺀다.
- Recog(Rapid7, BSD-2): xml/*.xml 지문 → 제조사·제품·버전·OS·장비 종류. 입력은 센서 신호
    software ssh:SSH-2.0-<배너>      → ssh.banner (SSH-x.y- 접두어 뗌)
    software http_server:<값>        → http_header.server
    software smb_os:/smb_lm:<값>     → smb.native_os / smb.native_lm
    software snmp_sysdescr:<값>      → snmp.sys_description
    software snmp_sysobjid:<OID>     → snmp.sys_object_id
    software x509_subject:/x509_issuer:<DN> → x509.subject / x509.issuer (Zeek 순서와 CN 먼저 순서 둘 다 시도)
    dhcp_vendor_class                → dhcp_vendor_class
  Recog 정규식은 Ruby 문법이라 Python 으로 옮길 수 없는 지문은 건너뛰고 수를 센다.
- TCP SYN 지문(tcp_fp): p0f DB 를 그대로 쓰지 않고(Zeek 값에 옵션 순서가 없음) 초기 TTL·윈도·옵션으로 OS 계열만 추정한다.
"""
import csv
import glob
import os
import re
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------- OUI


def mac_is_local(mac):
    """로컬 관리 비트(첫 바이트 0x02)가 켜진 MAC: 모바일 랜덤 MAC, 가상 머신·컨테이너, 직접 정한 주소."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


class Oui:
    def __init__(self, paths=()):
        self.tab = {}            # 접두어(16진 대문자, 6·7·9자리) -> 제조사
        self.files = []
        for p in paths or ():
            with open(p, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    a = (r.get("Assignment") or "").strip().upper()
                    org = (r.get("Organization Name") or "").strip()
                    if re.fullmatch(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}", a) and org:
                        self.tab[a] = org
            self.files.append(os.path.basename(p))

    def vendor(self, mac):
        h = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
        if len(h) != 12:
            return ""
        for n in (9, 7, 6):          # MA-S, MA-M, MA-L 순으로 긴 접두어 먼저
            if h[:n] in self.tab:
                return self.tab[h[:n]]
        return ""


# ---------------------------------------------------------------- Recog

RECOG_FLAGS = {"REG_ICASE": re.I, "REG_DOT_NEWLINE": re.S, "REG_MULTILINE": re.M, "REG_LINE_ANY_CRLF": 0}


def _ruby_to_py(p):
    """Recog(Ruby) 정규식에서 자주 쓰는 Python 비호환 문법만 바꾼다. 나머지는 컴파일 실패로 센다."""
    p = p.replace(r"\h", "[0-9a-fA-F]").replace(r"\z", r"\Z").replace("(?<", "(?P<").replace("(?P<=", "(?<=").replace("(?P<!", "(?<!")
    # Ruby 는 패턴 중간의 (?i) 를 허용한다. 맨 앞으로 옮긴다.
    flags = ""
    m = re.match(r"^\(\?([imx]+)\)", p)
    if m:
        flags, p = m.group(1), p[m.end():]
    if "(?i)" in p:
        flags += "i"
        p = p.replace("(?i)", "")
    return (f"(?{''.join(sorted(set(flags)))})" if flags else "") + p


class Recog:
    def __init__(self, xml_dir=None):
        self.db = {}             # matches -> [(regex, params, description)]
        self.count = 0
        self.bad = 0
        self.dir = xml_dir or ""
        if not xml_dir:
            return
        for path in sorted(glob.glob(os.path.join(xml_dir, "*.xml"))):
            try:
                root = ET.parse(path).getroot()
            except ET.ParseError:
                continue
            key = root.get("matches")
            if not key:
                continue
            for fp in root.findall("fingerprint"):
                flags = 0
                for f in (fp.get("flags") or "").split(","):
                    flags |= RECOG_FLAGS.get(f.strip(), 0)
                try:
                    rx = re.compile(_ruby_to_py(fp.get("pattern", "")), flags)
                except re.error:
                    self.bad += 1
                    continue
                params = [(int(x.get("pos", "0")), x.get("name"), x.get("value")) for x in fp.findall("param")]
                desc = (fp.findtext("description") or "").strip()
                self.db.setdefault(key, []).append((rx, params, desc))
                self.count += 1

    def match(self, key, text):
        """Recog 처럼 순서대로 처음 맞는 지문 하나. 결과: {이름: 값} + _desc"""
        for rx, params, desc in self.db.get(key, ()):
            m = rx.search(text)
            if not m:
                continue
            out = {"_desc": desc}
            for pos, name, val in params:
                if pos == 0:
                    v = val or ""
                else:
                    try:
                        v = m.group(pos) or ""
                    except (IndexError, re.error):
                        v = ""
                if v:
                    out[name] = v
            # 값 안의 {이름} 은 다른 값으로 채운다(cpe 등)
            for k, v in list(out.items()):
                if isinstance(v, str) and "{" in v:
                    out[k] = re.sub(r"\{([\w.]+)\}", lambda g: out.get(g.group(1), g.group(0)), v)
            return out
        return None


def _dn_variants(dn):
    """Zeek 은 인증서 이름을 인코딩 순서(C=..,O=..,CN=..)로, Recog 은 CN 먼저 순서로 쓴다. 둘 다 시도."""
    parts = re.split(r"(?<!\\),", dn)
    rev = ",".join(reversed(parts))
    return [dn] if rev == dn else [dn, rev]


def recog_inputs(signal, value):
    """센서 신호 -> [(Recog matches, 문자열, 출처 이름)]"""
    if signal == "dhcp_vendor_class":
        return [("dhcp_vendor_class", value, "DHCP vendor class")]
    if signal != "software" or ":" not in value:
        return []
    k, v = value.split(":", 1)
    if k == "ssh":
        return [("ssh.banner", re.sub(r"^SSH-\d+\.\d+-", "", v), "SSH 배너")]
    if k == "http_server":
        return [("http_header.server", v, "HTTP Server")]
    if k == "smb_os":
        return [("smb.native_os", v, "SMB native OS")]
    if k == "smb_lm":
        return [("smb.native_lm", v, "SMB native LM")]
    if k == "snmp_sysdescr":
        return [("snmp.sys_description", v, "SNMP sysDescr")]
    if k == "snmp_sysobjid":
        return [("snmp.sys_object_id", v, "SNMP sysObjectID")]
    if k in ("x509_subject", "x509_issuer"):
        key = "x509.subject" if k == "x509_subject" else "x509.issuer"
        return [(key, d, "인증서 주체" if k == "x509_subject" else "인증서 발급자") for d in _dn_variants(v)]
    return []


def fp_summary(r):
    """Recog 결과 하나 -> 화면용 한 줄(제조사·제품·버전, 장비 종류, OS)."""
    hw = " ".join(x for x in (r.get("hw.vendor"), r.get("hw.product") or r.get("hw.family"), r.get("hw.model")) if x)
    sv = " ".join(x for x in (r.get("service.vendor"), r.get("service.product"), r.get("service.version")) if x)
    os_ = " ".join(x for x in (r.get("os.vendor"), r.get("os.product") or r.get("os.family"), r.get("os.version")) if x)
    dev = r.get("hw.device") or r.get("os.device") or ""
    parts = [x for x in (hw, sv, os_) if x]
    s = " · ".join(dict.fromkeys(parts)) or r.get("_desc", "")
    return f"{s} [{dev}]" if dev else s


def fp_os(r):
    return " ".join(x for x in (r.get("os.vendor"), r.get("os.product") or r.get("os.family"), r.get("os.version")) if x)


# ---------------------------------------------------------------- TCP SYN 지문


def tcp_os(values):
    """tcp_fp 값들 -> (OS 계열, 근거). SYN 을 SYN-ACK 보다 먼저 본다. 옵션 없는 SYN 은 판단하지 않는다."""
    best = None
    for v in sorted(values, key=lambda x: (not x.startswith("syn "), x)):
        f = dict(kv.split("=", 1) for kv in v.split()[1:] if "=" in kv)
        if f.get("mss", "-") == "-":
            continue                  # 실제 OS 스택은 MSS 를 보낸다. 없으면 스캐너·직접 만든 패킷일 수 있다
        ittl, win, ws, ts = int(f.get("ittl", 0)), int(f.get("win", 0)), f.get("ws", "-"), f.get("ts") == "1"
        if ittl == 128:
            g = "Windows 계열"
        elif ittl == 255:
            g = "네트워크 장비 계열"
        elif ittl == 64 and win == 65535 and ts:
            g = "macOS·iOS·BSD 계열"
        elif ittl == 64:
            g = "Linux·Unix 계열"
        elif ittl == 32:
            g = "구형·임베디드 장비"
        else:
            continue
        best = (g, v)
        break
    return best or ("", "")


# ---------------------------------------------------------------- 묶기


def enrich(sig_rows, oui=None, recog=None, shared_macs=()):
    """IP -> {"vendor", "mac", "mac_local", "fp": [{"src","text"}], "fp_os", "fp_dev", "tcp_os", "tcp_basis"}"""
    oui = oui or Oui()
    recog = recog or Recog()
    per = {}
    tcp = {}
    for s in sig_rows:
        ip, k, v, src = s.get("ip"), s.get("signal"), str(s.get("value") or ""), s.get("source")
        if not ip or not v:
            continue
        e = per.setdefault(ip, {"vendor": "", "mac": "", "mac_local": False, "fp": [], "fp_os": "", "fp_dev": "", "tcp_os": "", "tcp_basis": ""})
        if k == "mac" and v not in shared_macs and (not e["mac"] or src in ("arp", "dhcp")):
            e["mac"] = v
        if k == "tcp_fp":
            tcp.setdefault(ip, set()).add(v)
        if recog.count:
            for key, text, name in recog_inputs(k, v):
                r = recog.match(key, text)
                if r:
                    t = fp_summary(r)
                    if t and all(x["text"] != t for x in e["fp"]):
                        e["fp"].append({"src": name, "text": t})
                    e["fp_os"] = e["fp_os"] or fp_os(r)
                    e["fp_dev"] = e["fp_dev"] or r.get("hw.device") or r.get("os.device") or ""
                    break
    for ip, e in per.items():
        if e["mac"]:
            e["mac_local"] = mac_is_local(e["mac"])
            e["vendor"] = "" if e["mac_local"] else oui.vendor(e["mac"])
        e["tcp_os"], e["tcp_basis"] = tcp_os(tcp.get(ip, ()))
    return per
