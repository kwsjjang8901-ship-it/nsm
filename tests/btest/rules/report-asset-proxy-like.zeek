# @TEST-DOC: 통합 리포트 — 서로 다른 HTTP Server 값 3개 이상으로 응답한 IP(.5)는 프록시·중계 추정으로 표시하고, HTTP Server 지문 OS 와 센서의 http_server OS 힌트를 쓰지 않는다(SSH 등 다른 근거는 그대로). 값이 2개인 IP(.6)와 하나인 서버(.7)는 그대로
# @TEST-EXEC: python3 $PKG/../tests/report_pcap.py . -o report.html --recog . > /dev/null
# @TEST-EXEC: python3 check.py report.html

# @TEST-START-FILE check.py
import json, re, sys
d = json.loads(re.search(r'id="data"[^>]*>(.*?)</script>', open(sys.argv[1], encoding="utf-8").read(), re.S).group(1).replace("<\\/", "</"))
a = {r["ips"][0]: r for r in d["assets"]}
assert d["enrich"]["proxy_like"] == 1, d["enrich"]
p = a["10.0.70.5"]
assert p["proxy_like"] is True, p
assert p["os"] == "", p                                  # IIS 힌트(windows server 2016+)·Akamai 지문 OS 모두 안 씀
assert len(p["fp"]) == 2, p                              # 지문 자체는 보여 줌(어떤 서버들이 응답했는지)
assert a["10.0.70.6"]["proxy_like"] is False and a["10.0.70.6"]["os"] == "windows server 2016+", a["10.0.70.6"]
assert a["10.0.70.7"]["os"] == "Example Linux" and a["10.0.70.7"]["os_src"] == "지문(Recog)", a["10.0.70.7"]
print("ok")
# @TEST-END-FILE

# @TEST-START-FILE asset_signal.log
{"ts":1762646400.0,"ip":"10.0.70.5","signal":"software","value":"http_server:Microsoft-IIS/10.0","source":"http_server","confidence":50}
{"ts":1762646400.0,"ip":"10.0.70.5","signal":"os_hint","value":"windows server 2016+","source":"http_server","confidence":45}
{"ts":1762646401.0,"ip":"10.0.70.5","signal":"software","value":"http_server:ExampleGHost","source":"http_server","confidence":50}
{"ts":1762646402.0,"ip":"10.0.70.5","signal":"software","value":"http_server:nginx","source":"http_server","confidence":50}
{"ts":1762646400.0,"ip":"10.0.70.6","signal":"software","value":"http_server:Microsoft-IIS/10.0","source":"http_server","confidence":50}
{"ts":1762646400.0,"ip":"10.0.70.6","signal":"os_hint","value":"windows server 2016+","source":"http_server","confidence":45}
{"ts":1762646401.0,"ip":"10.0.70.6","signal":"software","value":"http_server:nginx","source":"http_server","confidence":50}
{"ts":1762646400.0,"ip":"10.0.70.7","signal":"software","value":"http_server:ExampleGHost","source":"http_server","confidence":50}
# @TEST-END-FILE

# @TEST-START-FILE http_servers.xml
<?xml version="1.0"?>
<fingerprints matches="http_header.server" protocol="http">
  <fingerprint pattern="^Microsoft-IIS/([\d.]+)$">
    <description>IIS</description>
    <param pos="0" name="service.vendor" value="Microsoft"/>
    <param pos="0" name="service.product" value="IIS"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="os.vendor" value="Microsoft"/>
    <param pos="0" name="os.product" value="Windows"/>
  </fingerprint>
  <fingerprint pattern="^ExampleGHost$">
    <description>Example edge</description>
    <param pos="0" name="service.product" value="ExampleGHost"/>
    <param pos="0" name="os.vendor" value="Example"/>
    <param pos="0" name="os.product" value="Linux"/>
    <param pos="0" name="hw.device" value="Web Proxy"/>
  </fingerprint>
</fingerprints>
# @TEST-END-FILE
