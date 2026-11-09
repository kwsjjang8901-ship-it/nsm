#!/usr/bin/env python3
"""Zeek 공개 테스트 trace 에서 nsm_rules 테스트에 필요한 세션만 추출한다.

  원본: zeek/zeek v9.0.1 testing/btest/Traces (BSD 라이선스, tests/pcaps/zeek/README.md 참고)
  합성 pcap 으로 만들기 어려운 "실제 프로토콜 동작"(예: SSH 인증 성공 판정)을 검증하는 데 쓴다.

사용법:
  curl -sSLo /tmp/ssh.pcap https://raw.githubusercontent.com/zeek/zeek/v9.0.1/testing/btest/Traces/ssh/ssh.pcap
  python3 tests/extract_zeek_traces.py --ssh /tmp/ssh.pcap tests/pcaps/zeek
"""

import argparse
import os

from scapy.all import IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap

# ssh.pcap 의 내부(사설)->내부 SSH 인증 성공 세션 (Zeek 9.0.1 baseline ssh.log 의 auth_success=T)
SSH_AUTH_FLOWS = {
    ("192.168.2.1", 57189, "192.168.2.158", 22),
    ("192.168.2.1", 55179, "192.168.2.158", 2200),   # 비표준 포트
    ("192.168.2.1", 59246, "192.168.2.158", 22),
    ("192.168.1.31", 52294, "192.168.1.32", 22),
    ("192.168.1.31", 51489, "192.168.1.32", 22),
}


def flow_key(p):
    if not (p.haslayer(IP) and p.haslayer(TCP)):
        return None
    a = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
    b = (p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport)
    return a if a in SSH_AUTH_FLOWS else (b if b in SSH_AUTH_FLOWS else None)


def extract_ssh(src, outdir):
    pkts = [p for p in rdpcap(src) if flow_key(p)]
    last = max(float(p.time) for p in pkts)
    # SumStats epoch(1분) 종료용 tick
    tick = Ether(src="02:00:0a:ff:00:01", dst="02:00:0a:ff:00:02") / IP(src="10.255.0.1", dst="10.255.0.2") \
        / UDP(sport=40000, dport=9) / Raw(b"tick")
    tick.time = last + 300
    pkts.append(tick)
    out = os.path.join(outdir, "ssh_auth_internal.pcap")
    wrpcap(out, pkts)
    print("%s: %d packets, %d bytes" % (out, len(pkts), os.path.getsize(out)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ssh", required=True, help="zeek testing/btest/Traces/ssh/ssh.pcap")
    ap.add_argument("outdir")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    extract_ssh(a.ssh, a.outdir)


if __name__ == "__main__":
    main()
