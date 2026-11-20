# @TEST-DOC: 통합 리포트 지문 보강 — 서비스 배너 신호(HTTP 인증 realm, SIP User-Agent·Server, FTP·SMTP·POP3 접속 인사, MySQL 버전)를 Recog 형식 지문(테스트 안에 작성)과 맞춘다
# @TEST-EXEC: zeek -C -r $TRACES/asset_banners.pcap $PKG $SETUP
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html --recog . > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
fp = lambda ip: [(f["src"], f["text"]) for f in a[ip].get("fp", [])]
assert d["enrich"]["recog_count"] == 8, d["enrich"]
assert fp("10.0.57.10") == [("HTTP 인증 realm", "Example Router [Router]")], fp("10.0.57.10")
assert fp("10.0.57.12") == [("HTTP 인증 realm", "Example Cam [IP Camera]")], fp("10.0.57.12")
assert fp("10.0.57.20") == [("SIP User-Agent", "Example IP Phone 7841 · 12.8.1 [VoIP]")], fp("10.0.57.20")
assert fp("10.0.57.21") == [("SIP Server", "Example PBX 16.0")], fp("10.0.57.21")
assert fp("10.0.57.30") == [("FTP 접속 인사", "Example FTP 3.0")], fp("10.0.57.30")
assert fp("10.0.57.31") == [("SMTP 접속 인사", "ExampleMail 9.1")], fp("10.0.57.31")
assert fp("10.0.57.32") == [("POP3 접속 인사", "Example POP3 2.3")], fp("10.0.57.32")
assert fp("10.0.57.33") == [("MySQL 버전", "Oracle MySQL 8.0.36")], fp("10.0.57.33")
assert not a.get("10.0.57.11", {}).get("fp") and not a.get("10.0.57.5", {}).get("fp"), (a.get("10.0.57.11"), a.get("10.0.57.5"))
print("ok")
# @TEST-END-FILE

# @TEST-START-FILE http_wwwauth.xml
<?xml version="1.0"?>
<fingerprints matches="http_header.wwwauth" protocol="http">
  <fingerprint pattern="^Basic realm=&quot;Example Router&quot;$">
    <description>Example router</description>
    <param pos="0" name="hw.vendor" value="Example"/>
    <param pos="0" name="hw.product" value="Router"/>
    <param pos="0" name="hw.device" value="Router"/>
  </fingerprint>
  <fingerprint pattern="^Digest realm=&quot;Example Cam&quot;$">
    <description>Example camera</description>
    <param pos="0" name="hw.vendor" value="Example"/>
    <param pos="0" name="hw.product" value="Cam"/>
    <param pos="0" name="hw.device" value="IP Camera"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE sip.xml
<?xml version="1.0"?>
<fingerprints matches="sip_header.user_agent" protocol="sip">
  <fingerprint pattern="^Example IP Phone (\d+)/([\d.]+)$">
    <description>Example IP phone</description>
    <param pos="0" name="hw.vendor" value="Example"/>
    <param pos="0" name="hw.product" value="IP Phone"/>
    <param pos="1" name="hw.model"/>
    <param pos="2" name="os.version"/>
    <param pos="0" name="hw.device" value="VoIP"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE sip_server.xml
<?xml version="1.0"?>
<fingerprints matches="sip_header.server" protocol="sip">
  <fingerprint pattern="^Example PBX ([\d.]+)$">
    <description>Example PBX</description>
    <param pos="0" name="service.vendor" value="Example"/>
    <param pos="0" name="service.product" value="PBX"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE banners.xml
<?xml version="1.0"?>
<fingerprints matches="ftp.banner" protocol="ftp">
  <fingerprint pattern="Example FTP Service \(Version ([\d.]+)\)">
    <description>Example FTP</description>
    <param pos="0" name="service.vendor" value="Example"/>
    <param pos="0" name="service.product" value="FTP"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE smtp.xml
<?xml version="1.0"?>
<fingerprints matches="smtp.banner" protocol="smtp">
  <fingerprint pattern="ESMTP ExampleMail ([\d.]+) ready$">
    <description>ExampleMail</description>
    <param pos="0" name="service.product" value="ExampleMail"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE pop.xml
<?xml version="1.0"?>
<fingerprints matches="pop3.banner" protocol="pop3">
  <fingerprint pattern="^Example POP3 server v([\d.]+) ready$">
    <description>Example POP3</description>
    <param pos="0" name="service.vendor" value="Example"/>
    <param pos="0" name="service.product" value="POP3"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE

# @TEST-START-FILE mysql.xml
<?xml version="1.0"?>
<fingerprints matches="mysql.banners" protocol="mysql">
  <fingerprint pattern="^(\d+\.\d+\.\d+)$">
    <description>MySQL</description>
    <param pos="0" name="service.vendor" value="Oracle"/>
    <param pos="0" name="service.product" value="MySQL"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE
