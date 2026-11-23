# @TEST-DOC: 센서 상태 로그(S1) — 공격 스토리 7단계 pcap에서 1분마다 한 행과 종료 행(패킷이 끊긴 동안은 한 행이 더 긴 구간을 덮음). 행들의 pkts 합은 pcap 의 패킷 수, 구간 합은 첫 패킷부터 마지막 패킷까지, 놓친 패킷 0, 스키마 버전은 schema/build.py 가 만든 값, 패키지·Zeek 버전, 데이터 파일을 읽지 않으면 지문 칸 없음
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: python3 check.py $TRACES/killchain_story.pcap $PKG/sensor/schema_version.zeek

# @TEST-START-FILE check.py
import json, re, struct, sys

def pcap_packets(p):
    d = open(p, "rb").read()
    e = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    n, off = 0, 24
    while off + 16 <= len(d):
        incl = struct.unpack(e + "I", d[off + 8:off + 12])[0]
        off += 16 + incl
        n += 1
    return n

def pcap_times(p):
    d = open(p, "rb").read()
    e = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = d[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    ts, off = [], 24
    while off + 16 <= len(d):
        sec, frac, incl = struct.unpack(e + "III", d[off:off + 12])
        ts.append(sec + frac / (1e9 if nano else 1e6))
        off += 16 + incl
    return min(ts), max(ts)

rows = [json.loads(l) for l in open("nsm_sensor.log")]
ver = re.search(r'schema_version = "([0-9a-f]{12})"', open(sys.argv[2]).read()).group(1)
assert len(rows) >= 2, rows
assert sum(r["pkts"] for r in rows) == pcap_packets(sys.argv[1]), (sum(r["pkts"] for r in rows), pcap_packets(sys.argv[1]))
# 구간: 1분마다(패킷이 끊긴 동안은 다음 패킷까지 길어짐), 빈 구간 없음, 합은 첫 패킷부터 마지막 패킷까지
iv = [r["interval_s"] for r in rows]
first, last = pcap_times(sys.argv[1])
assert all(x >= 59.0 for x in iv[:-1]) and all(x > 0 for x in iv) and abs(sum(iv) - (last - first)) < 1.0, (iv, last - first)
assert abs(rows[-1]["ts"] - last) < 1.0
assert all(r["pkts_dropped"] == 0 and r["drop_pct"] == 0 for r in rows)
assert all(r["schema_version"] == ver and r["pkg_version"] and re.match(r"^\d+\.\d+", r["zeek_version"]) and r["node"] == "zeek" for r in rows), rows[0]
assert not [r for r in rows if "exc_sha1" in r or "ioc_sha1" in r or "policy_sha1" in r]
assert sum(r["bytes"] for r in rows) > 0 and any("gap_pct" in r for r in rows)
print("ok", len(rows))
# @TEST-END-FILE
