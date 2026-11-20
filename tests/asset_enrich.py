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
    software http_wwwauth:<값>       → http_header.wwwauth
    software sip_ua:/sip_server:<값> → sip_header.user_agent / sip_header.server
    software ftp_banner:/smtp_banner:/pop3_banner:<값> → ftp.banner / smtp.banner / pop3.banner
    software mysql:<버전>            → mysql.banners
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


# 접두어·제조사 열 이름(소문자). IEEE 원본(Assignment, Organization Name)과 maclookup.app 내보내기(Mac Prefix, Vendor Name) 등.
OUI_PREFIX_COLS = ("assignment", "mac prefix", "macprefix", "prefix", "oui")
OUI_VENDOR_COLS = ("organization name", "vendor name", "vendor", "organization", "company")


class Oui:
    def __init__(self, paths=()):
        self.tab = {}            # 접두어(16진 대문자, 6·7·9자리) -> 제조사
        self.files = []
        self.counts = {}         # 파일 이름 -> 읽은 항목 수(0 이면 형식이 다른 파일)
        for p in paths or ():
            name, n = os.path.basename(p), 0
            with open(p, encoding="utf-8-sig", newline="") as f:
                rd = csv.DictReader(f)
                cols = {c.strip().lower(): c for c in (rd.fieldnames or [])}
                pc = next((cols[c] for c in OUI_PREFIX_COLS if c in cols), None)
                vc = next((cols[c] for c in OUI_VENDOR_COLS if c in cols), None)
                if pc and vc:
                    for r in rd:
                        a = re.sub(r"[^0-9A-Fa-f]", "", r.get(pc) or "").upper()   # 00:00:0C, 00-00-0C, 00000C 모두
                        org = (r.get(vc) or "").strip()
                        if len(a) in (6, 7, 9) and org:
                            self.tab[a] = org
                            n += 1
            self.files.append(name)
            self.counts[name] = n

    @property
    def empty(self):
        """주었지만 한 줄도 못 읽은 파일(열 이름이 다른 형식)"""
        return [f for f, n in self.counts.items() if n == 0]

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
    simple = {"http_wwwauth": ("http_header.wwwauth", "HTTP 인증 realm"), "sip_ua": ("sip_header.user_agent", "SIP User-Agent"),
              "sip_server": ("sip_header.server", "SIP Server"), "ftp_banner": ("ftp.banner", "FTP 접속 인사"),
              "smtp_banner": ("smtp.banner", "SMTP 접속 인사"), "pop3_banner": ("pop3.banner", "POP3 접속 인사"),
              "mysql": ("mysql.banners", "MySQL 버전")}
    if k in simple:
        return [(simple[k][0], v, simple[k][1])]
    if k in ("x509_subject", "x509_issuer"):
        key = "x509.subject" if k == "x509_subject" else "x509.issuer"
        return [(key, d, "인증서 주체" if k == "x509_subject" else "인증서 발급자") for d in _dn_variants(v)]
    return []


def fp_summary(r):
    """Recog 결과 하나 -> 화면용 한 줄(제조사·제품·버전, 장비 종류, OS)."""
    def name(vendor, product, version):
        # 제품명이 제조사로 시작하면 제조사는 한 번만("Postfix Postfix" -> "Postfix")
        if vendor and product and product.lower().startswith(vendor.lower()):
            vendor = ""
        return " ".join(x for x in (vendor, product, version) if x)
    hw = name(r.get("hw.vendor"), r.get("hw.product") or r.get("hw.family"), r.get("hw.model"))
    sv = name(r.get("service.vendor"), r.get("service.product"), r.get("service.version"))
    os_ = name(r.get("os.vendor"), r.get("os.product") or r.get("os.family"), r.get("os.version"))
    dev = r.get("hw.device") or r.get("os.device") or ""
    parts = list(dict.fromkeys(x for x in (hw, sv, os_) if x))
    # 다른 부분에 통째로 들어 있는 부분은 뺀다("Cisco · Cisco IOS 15.2" -> "Cisco IOS 15.2")
    parts = [x for x in parts if not any(x != y and x in y for y in parts)]
    s = " · ".join(parts) or r.get("_desc", "")
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


# 한 IP 가 서로 다른 HTTP Server 값으로 이만큼 이상 응답하면 실제 서버가 아니라 프록시·중계 장비(투명 프록시, 로드밸런서,
# NAT 뒤 여러 서버)로 본다. 이때 HTTP 로 얻은 OS(지문·센서 OS 힌트)는 그 IP 의 OS 가 아니다.
PROXY_HTTP_SERVERS = 3
HTTP_SOURCES = ("HTTP Server", "HTTP 인증 realm")


def proxy_like_ips(sig_rows):
    srv = {}
    for s in sig_rows:
        v = str(s.get("value") or "")
        if s.get("signal") == "software" and v.startswith("http_server:"):
            srv.setdefault(s.get("ip"), set()).add(v)
    return {ip for ip, vs in srv.items() if len(vs) >= PROXY_HTTP_SERVERS}


def enrich(sig_rows, oui=None, recog=None, shared_macs=()):
    """IP -> {"vendor", "mac", "mac_local", "fp": [{"src","text"}], "fp_os", "fp_dev", "tcp_os", "tcp_basis", "proxy_like"}"""
    oui = oui or Oui()
    recog = recog or Recog()
    proxies = proxy_like_ips(sig_rows)
    per = {}
    tcp = {}
    for s in sig_rows:
        ip, k, v, src = s.get("ip"), s.get("signal"), str(s.get("value") or ""), s.get("source")
        if not ip or not v:
            continue
        e = per.setdefault(ip, {"vendor": "", "mac": "", "mac_local": False, "fp": [], "fp_os": "", "fp_dev": "", "tcp_os": "", "tcp_basis": "",
                                "proxy_like": ip in proxies, "forms": set(), "os_hints": set(), "names": set(), "svcs": set(), "devs": set()})
        if k == "form_factor":
            e["forms"].add(v)
        elif k == "os_hint":
            e["os_hints"].add(v.lower())
        elif k in ("hostname", "machine_account", "fqdn"):
            e["names"].add(v.lower())
        elif k == "service":
            e["svcs"].add("/".join(v.split("/")[:2]))
        elif k == "device":
            e["devs"].add(v)
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
                    if not (e["proxy_like"] and name in HTTP_SOURCES):
                        e["fp_os"] = e["fp_os"] or fp_os(r)
                    e["fp_dev"] = e["fp_dev"] or r.get("hw.device") or r.get("os.device") or ""
                    break
    for ip, e in per.items():
        if e["mac"]:
            e["mac_local"] = mac_is_local(e["mac"])
            e["vendor"] = "" if e["mac_local"] else oui.vendor(e["mac"])
        e["tcp_os"], e["tcp_basis"] = tcp_os(tcp.get(ip, ()))
    return per


# ---------------------------------------------------------------- 장비 유형

NET_DEVICES = {"cisco-asa", "cisco-ftd", "cisco-ios", "fortinet-fortigate", "fortinet", "paloalto", "utm"}
NET_HW = ("router", "switch", "firewall", "access point", "wireless", "vpn", "network")
SERVER_PORTS = {"tcp/22", "tcp/80", "tcp/443", "tcp/8080", "tcp/8443", "tcp/1433", "tcp/1521", "tcp/3306", "tcp/5432",
                "tcp/6379", "tcp/27017", "tcp/9200", "tcp/25", "tcp/465", "tcp/587", "tcp/110", "tcp/143", "tcp/993",
                "tcp/995", "tcp/21", "tcp/53", "udp/53", "tcp/88", "tcp/389", "tcp/636", "tcp/3268", "udp/67",
                "tcp/514", "udp/514"}
DC_PORTS = {"tcp/88", "tcp/389", "tcp/636", "tcp/3268"}
MOBILE_NAME = re.compile(r"iphone|ipad|ipod|galaxy|android|^sm-[a-z]\d|pixel|redmi|xiaomi")
FORM_KO = {"phone": "모바일(스마트폰)", "tablet": "모바일(태블릿)", "mobile": "모바일"}


def device_class(e, os_best="", roles=()):
    """IP 하나의 장비 유형 -> (유형, 근거, 신뢰도). 앞 규칙이 이긴다. 노트북·데스크톱은 기본 컴퓨터 이름이나 기기 모델이 있을 때만 가른다."""
    names = e.get("names", set())
    nm = " ".join(sorted(names))
    hints = e.get("os_hints", set())
    svcs, devs = e.get("svcs", set()), e.get("devs", set())
    fp_dev = (e.get("fp_dev") or "").lower()
    os_l = (os_best or "").lower()
    if e.get("proxy_like"):
        return "프록시·중계", "서로 다른 HTTP Server 값으로 응답", "보통"
    if devs & NET_DEVICES or any(w in fp_dev for w in NET_HW):
        return "네트워크 장비", "장비 종류 " + (", ".join(sorted(devs & NET_DEVICES)) or e.get("fp_dev")), "높음"
    if "print" in fp_dev or "mfp" in fp_dev or svcs & {"tcp/9100", "tcp/515", "tcp/631"}:
        return "프린터", "지문 " + e.get("fp_dev") if fp_dev else "프린터 포트 응답(9100·515·631)", "높음" if fp_dev else "보통"
    if devs & {"ahnlab-mds", "ahnlab-epp"}:
        return "보안 장비", "장비 종류 " + ", ".join(sorted(devs & {"ahnlab-mds", "ahnlab-epp"})), "높음"
    if devs & {"vmware-esxi", "vmware"}:
        return "서버(가상화)", "VMware 인증서·syslog", "높음"
    if devs & {"dell-idrac", "hpe-ilo"}:
        return "서버 관리 포트(BMC)", "장비 종류 " + ", ".join(sorted(devs & {"dell-idrac", "hpe-ilo"})), "높음"
    if "synology" in devs or "nas" in fp_dev:
        return "NAS", "장비 종류·지문", "높음"
    if "camera" in fp_dev:
        return "카메라·IoT", "지문 " + e.get("fp_dev"), "높음"
    if "voip" in fp_dev or "phone" in fp_dev:
        return "IP 전화기", "지문 " + e.get("fp_dev"), "높음"
    for f in ("phone", "tablet", "mobile"):
        if f in e.get("forms", set()):
            return FORM_KO[f], "User-Agent 기기 형태", "높음" if f != "mobile" else "보통"
    if any(h.startswith(("android", "ios")) for h in hints):
        return "모바일", "OS 힌트 " + ", ".join(sorted(h for h in hints if h.startswith(("android", "ios")))), "보통"
    if MOBILE_NAME.search(nm):
        return ("모바일(태블릿)" if "ipad" in nm else "모바일"), "호스트 이름", "보통"
    # 기본 컴퓨터 이름(Windows 는 설치 때 본체 종류로 LAPTOP-/DESKTOP- 를 붙임)·기기 모델이 든 이름은 OS 근거 없이도 쓴다
    if re.search(r"(^|\s)laptop-", nm) or "macbook" in nm:
        return "PC(노트북)", "호스트 이름(기본 이름·기기 모델)", "보통"
    if re.search(r"(^|\s)desktop-", nm) or re.search(r"imac|mac-?mini|mac-?pro", nm):
        return "PC(데스크톱)", "호스트 이름(기본 이름·기기 모델)", "보통"
    server_roles = [x for x in roles or () if x and "PC" not in str(x)]
    if "server" in os_l or server_roles or svcs & DC_PORTS:
        return "서버", ("역할 " + ", ".join(map(str, server_roles))) if server_roles else ("OS " + os_best if "server" in os_l else "도메인 컨트롤러 포트 응답"), "높음"
    client = any(w in os_l for w in ("windows 10", "windows 11", "windows 7", "windows 8", "windows xp", "macos", "mac os", "chromeos")) \
        or os_l in ("windows", "apple") or os_l.startswith("windows nt") or os_l == "windows 계열"
    unix_like = os_l == "" or any(w in os_l for w in ("linux", "unix", "bsd", "ubuntu", "debian", "centos"))
    if unix_like and svcs & SERVER_PORTS:
        return "서버(추정)", "서비스 응답 " + ", ".join(sorted(svcs & SERVER_PORTS)[:4]), "보통" if os_l else "낮음"
    if client or "macos·ios·bsd" in os_l:
        if "macos·ios·bsd" in os_l:
            return "PC 또는 모바일(Apple)", "TCP SYN 모양(macOS·iOS 구분 불가)", "낮음"
        if os_l == "apple":
            return "PC 또는 모바일(Apple)", "Apple 연결 확인 요청(iPhone·Mac 공통)", "보통"
        return "PC", "OS " + os_best, "낮음" if "계열" in os_l else "보통"
    if "linux" in os_l or "unix" in os_l:
        return "알 수 없음(Linux 계열)", "OS " + os_best, "낮음"
    return "알 수 없음", "", ""
