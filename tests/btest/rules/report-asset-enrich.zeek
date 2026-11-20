# @TEST-DOC: 통합 리포트 자산 정보 보강(Manager 후처리 시제품) — OUI 제조사(MA-M 이 MA-L 보다 우선, 로컬·랜덤 MAC 표시), Recog 형식 지문(SNMP sysDescr·SSH 배너·HTTP Server·인증서 주체, 인증서는 CN 먼저 순서로 뒤집어 맞춤), OS 칸이 비면 지문 OS·TCP SYN 계열로 채움. DB 를 안 주면 제조사·지문 없이 TCP 추정만
# @TEST-EXEC: zeek -C -r $TRACES/asset_fingerprint.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html --oui oui.csv --recog . > /dev/null
# @TEST-EXEC: python3 check.py report.html full
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o bare.html > /dev/null
# @TEST-EXEC: python3 check.py bare.html bare

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
fp = lambda ip: [f["text"] for f in a[ip].get("fp", [])]
# TCP SYN 계열은 DB 없이도 나온다. 센서 OS 힌트가 없을 때만 OS 칸을 채운다
assert a["10.0.56.30"]["os"] == "Windows 계열" and a["10.0.56.30"]["os_src"] == "TCP SYN 추정", a["10.0.56.30"]
assert a["10.0.56.32"]["tcp_os"] == "macOS·iOS·BSD 계열", a["10.0.56.32"]
assert a["10.0.56.33"]["os"] == "windows server 2016+" and "os_src" not in a["10.0.56.33"], a["10.0.56.33"]
assert a["10.0.56.30"]["mac_local"] is True, a["10.0.56.30"]
if sys.argv[2] == "bare":
    assert d["enrich"]["recog_count"] == 0 and d["enrich"]["oui_entries"] == 0, d["enrich"]
    assert not a["10.0.56.20"].get("vendor") and not fp("10.0.56.20"), a["10.0.56.20"]
    print("ok"); sys.exit(0)
assert d["enrich"]["recog_count"] == 5 and d["enrich"]["recog_bad"] == 0 and d["enrich"]["oui_entries"] == 3, d["enrich"]
# OUI: 스위치는 MA-L, 프린터는 MA-M(MA-L 보다 긴 접두어가 이김)
assert a["10.0.56.20"]["vendor"] == "Example Networks Inc", a["10.0.56.20"]
assert a["10.0.56.21"]["vendor"] == "Example Printers (MA-M)", a["10.0.56.21"]
# Recog: SNMP·SSH·HTTP·인증서
assert fp("10.0.56.20") == ["Example Networks IOS 15.0(2)SE11 [Switch]"], fp("10.0.56.20")
assert a["10.0.56.20"]["os"] == "Example Networks IOS 15.0(2)SE11" and a["10.0.56.20"]["os_src"] == "지문(Recog)", a["10.0.56.20"]
assert fp("10.0.56.21") == ["Example Printers JD153 [Printer]"], fp("10.0.56.21")
assert fp("10.0.56.31") == ["OpenBSD OpenSSH 8.9p1 · Ubuntu Linux"], fp("10.0.56.31")
assert fp("10.0.56.33") == ["Microsoft IIS 10.0 · Microsoft Windows"], fp("10.0.56.33")
assert fp("10.0.56.34") == ["Example NAS Corp [NAS]"], fp("10.0.56.34")
print("ok")
# @TEST-END-FILE

# @TEST-START-FILE oui.csv
Registry,Assignment,Organization Name,Organization Address
MA-L,001B54,Example Networks Inc,Example Street
MA-L,3C2AF4,Example Wrong Vendor,Example Street
MA-M,3C2AF41,Example Printers (MA-M),Example Street
# @TEST-END-FILE

# @TEST-START-FILE snmp_sysdescr.xml
<?xml version="1.0"?>
<fingerprints matches="snmp.sys_description" protocol="snmp" database_type="service">
  <fingerprint pattern="^Example IOS Software, (\S+) Software, Version ([^,]+),">
    <description>Example IOS switch</description>
    <param pos="0" name="os.vendor" value="Example Networks"/>
    <param pos="0" name="os.product" value="IOS"/>
    <param pos="2" name="os.version"/>
    <param pos="0" name="hw.device" value="Switch"/>
  </fingerprint>
  <fingerprint pattern="^EXAMPLE ETHERNET MULTI-ENVIRONMENT.*,JETDIRECT,(\w+)" flags="REG_ICASE">
    <description>Example print server</description>
    <param pos="0" name="hw.vendor" value="Example Printers"/>
    <param pos="1" name="hw.product"/>
    <param pos="0" name="hw.device" value="Printer"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE ssh_banners.xml
<?xml version="1.0"?>
<fingerprints matches="ssh.banner" protocol="ssh" database_type="service">
  <fingerprint pattern="^OpenSSH_([\w.]+) Ubuntu">
    <description>OpenSSH on Ubuntu</description>
    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="os.vendor" value="Ubuntu"/>
    <param pos="0" name="os.product" value="Linux"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE http_servers.xml
<?xml version="1.0"?>
<fingerprints matches="http_header.server" protocol="http" database_type="service">
  <fingerprint pattern="^Microsoft-IIS/([\d.]+)$">
    <description>Microsoft IIS</description>
    <param pos="0" name="service.vendor" value="Microsoft"/>
    <param pos="0" name="service.product" value="IIS"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="os.vendor" value="Microsoft"/>
    <param pos="0" name="os.product" value="Windows"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE x509_subjects.xml
<?xml version="1.0"?>
<fingerprints matches="x509.subject" protocol="x509">
  <fingerprint pattern="^CN=([^,]+),OU=NAS,O=Example NAS Corp">
    <description>Example NAS</description>
    <param pos="0" name="hw.vendor" value="Example NAS Corp"/>
    <param pos="0" name="hw.device" value="NAS"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE
