#!/usr/bin/env python3
"""nsm_rules 회귀 테스트용 합성 pcap 생성기.

각 pcap 은 한 룰(또는 상관 시나리오)을 대상으로 하며, 같은 파일 안에
  - 탐지되어야 하는 호스트(positive)
  - 비슷하지만 탐지되면 안 되는 호스트(negative)
를 함께 넣는다. 호스트 IP 별 기대 결과는 tests/btest/rules/*.zeek 에 적혀 있다.

  내부망: 10.0.0.0/8 (Zeek 기본 사설 대역 = local)
  외부망: 93.184.215.0/24 (공인 대역. 192.0.2/24 등 문서용 대역은 Zeek 가 사설로 취급하므로 쓰지 않는다)

SumStats epoch 판정 룰(06/13/15/16)은 epoch 가 끝나야 결과가 나오므로,
마지막에 무관한 "tick" 패킷을 넣어 네트워크 시각을 epoch 이후로 진행시킨다.

사용법:
  pip install scapy cryptography
  python3 tests/gen_pcaps.py tests/pcaps
"""

import argparse
import datetime as dt
import os
import random
import string
import struct

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

T0 = dt.datetime(2026, 11, 9, 0, 0, 0, tzinfo=dt.timezone.utc).timestamp()
RNG = random.Random(20261109)

DNS_SERVER = "10.0.0.53"
TICK_SRC, TICK_DST = "10.255.0.1", "10.255.0.2"


def mac_of(ip):
    """IP 로부터 결정적인 로컬 MAC 을 만든다."""
    parts = [int(x) for x in ip.split(".")]
    return "02:00:%02x:%02x:%02x:%02x" % tuple(parts)


class Capture:
    def __init__(self):
        self.pkts = []

    def add(self, pkt, t):
        pkt.time = t
        self.pkts.append(pkt)

    def l3(self, src, dst):
        return Ether(src=mac_of(src), dst=mac_of(dst)) / IP(src=src, dst=dst)

    def tick(self, t):
        """네트워크 시각을 진행시키기 위한 무관한 UDP 패킷."""
        self.add(self.l3(TICK_SRC, TICK_DST) / UDP(sport=40000, dport=9) / Raw(b"tick"), t)

    def write(self, path):
        self.pkts.sort(key=lambda p: float(p.time))
        wrpcap(path, self.pkts)


class Tcp:
    """시퀀스 번호를 추적하는 TCP 세션 헬퍼."""

    MSS = 1400

    def __init__(self, cap, cli, srv, dport, sport=None):
        self.cap, self.cli, self.srv, self.dport = cap, cli, srv, dport
        self.sport = sport or RNG.randint(40000, 60000)
        self.cseq = RNG.randint(1, 2**31)
        self.sseq = RNG.randint(1, 2**31)

    def _c(self, flags, t, data=b""):
        p = self.cap.l3(self.cli, self.srv) / TCP(sport=self.sport, dport=self.dport, flags=flags,
                                                   seq=self.cseq, ack=self.sseq if "A" in flags else 0)
        if data:
            p = p / Raw(data)
        self.cap.add(p, t)

    def _s(self, flags, t, data=b""):
        p = self.cap.l3(self.srv, self.cli) / TCP(sport=self.dport, dport=self.sport, flags=flags,
                                                   seq=self.sseq, ack=self.cseq)
        if data:
            p = p / Raw(data)
        self.cap.add(p, t)

    def handshake(self, t):
        self._c("S", t)
        self.cseq += 1
        self._s("SA", t + 0.001)
        self.sseq += 1
        self._c("A", t + 0.002)
        return t + 0.003

    def rejected(self, t):
        """SYN -> RST/ACK (닫힌 포트)."""
        self._c("S", t)
        self.cseq += 1
        self._s("RA", t + 0.001)
        return t + 0.002

    def client_send(self, data, t, skip=0):
        """클라이언트 데이터 전송. skip 바이트만큼 시퀀스를 건너뛴다(대용량 전송 모사)."""
        self.cseq += skip
        for i in range(0, len(data), self.MSS):
            chunk = data[i:i + self.MSS]
            self._c("PA", t, chunk)
            self.cseq += len(chunk)
            t += 0.0005
        self._s("A", t)
        return t + 0.001

    def server_send(self, data, t):
        for i in range(0, len(data), self.MSS):
            chunk = data[i:i + self.MSS]
            self._s("PA", t, chunk)
            self.sseq += len(chunk)
            t += 0.0005
        self._c("A", t)
        return t + 0.001

    def close(self, t):
        self._c("FA", t)
        self.cseq += 1
        self._s("FA", t + 0.001)
        self.sseq += 1
        self._c("A", t + 0.002)
        return t + 0.003


def rand_bytes(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


# --------------------------------------------------------------------------- 01/02 스캔

def port_scan(cap, scanner, target, ports, t):
    for p in ports:
        Tcp(cap, scanner, target, p).rejected(t)
        t += 0.05
    return t


def host_scan(cap, scanner, targets, port, t):
    for dst in targets:
        Tcp(cap, scanner, dst, port).rejected(t)
        t += 0.05
    return t


def gen_port_scan(out):
    cap = Capture()
    port_scan(cap, "10.0.0.5", "10.0.0.9", range(1000, 1030), T0)      # 30 포트: 탐지
    port_scan(cap, "10.0.0.6", "10.0.0.9", range(2000, 2010), T0 + 5)  # 10 포트: 미탐
    cap.tick(T0 + 90)
    cap.write(os.path.join(out, "port_scan.pcap"))


def gen_host_scan(out):
    cap = Capture()
    hosts = ["10.0.1.%d" % i for i in range(1, 31)]
    host_scan(cap, "10.0.0.5", hosts, 445, T0)       # 445 30대: 탐지
    host_scan(cap, "10.0.0.6", hosts, 443, T0 + 5)   # 443 은 기본 제외 포트: 미탐
    cap.tick(T0 + 90)
    cap.write(os.path.join(out, "host_scan.pcap"))


# --------------------------------------------------------------------------- 06 SMB

def smb2_tree_connect(path, msg_id):
    path_b = path.encode("utf-16-le")
    hdr = (b"\xfeSMB" + struct.pack("<HHI", 64, 0, 0) + struct.pack("<HH", 3, 1)
           + struct.pack("<II", 0, 0) + struct.pack("<Q", msg_id) + struct.pack("<II", 0, 0)
           + struct.pack("<Q", 0x1000 + msg_id) + b"\x00" * 16)
    body = struct.pack("<HHHH", 9, 0, 64 + 8, len(path_b)) + path_b
    msg = hdr + body
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg   # NetBIOS session header


def smb_tree_connect(cap, src, dst, share, t):
    s = Tcp(cap, src, dst, 445)
    t = s.handshake(t)
    t = s.client_send(smb2_tree_connect("\\\\%s\\%s" % (dst, share), 2), t)
    return s.close(t + 0.01)


def gen_smb(out):
    cap = Capture()
    t = T0
    # 10.0.0.20: 관리 공유를 3대에 접근 -> 탐지 (설정 임계 2대)
    for dst, share in (("10.0.0.21", "ADMIN$"), ("10.0.0.22", "ADMIN$"), ("10.0.0.23", "C$")):
        t = smb_tree_connect(cap, "10.0.0.20", dst, share, t + 1)
    # 10.0.0.30: IPC$ 와 일반 공유만 3대 -> 미탐
    for dst, share in (("10.0.0.21", "IPC$"), ("10.0.0.22", "IPC$"), ("10.0.0.23", "share")):
        t = smb_tree_connect(cap, "10.0.0.30", dst, share, t + 1)
    # 10.0.0.31: 관리 공유지만 1대뿐 -> 미탐
    t = smb_tree_connect(cap, "10.0.0.31", "10.0.0.21", "ADMIN$", t + 1)
    cap.tick(T0 + 200)
    cap.write(os.path.join(out, "smb_admin_share.pcap"))


# --------------------------------------------------------------------------- 15 RDP

def rdp_connect_request(user):
    cookie = ("Cookie: mstshash=%s\r\n" % user).encode()
    neg = b"\x01\x00\x08\x00\x03\x00\x00\x00"
    var = cookie + neg
    x224 = bytes([6 + len(var), 0xE0, 0, 0, 0, 0, 0]) + var
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def rdp_connect(cap, src, dst, user, t):
    s = Tcp(cap, src, dst, 3389)
    t = s.handshake(t)
    t = s.client_send(rdp_connect_request(user), t)
    return s.close(t + 0.01)


def gen_rdp(out):
    cap = Capture()
    t = T0
    for i in range(41, 45):                       # 10.0.0.40 -> 4대: 탐지 (임계 3대)
        t = rdp_connect(cap, "10.0.0.40", "10.0.0.%d" % i, "administrator", t + 1)
    for i in range(41, 43):                       # 10.0.0.45 -> 2대: 미탐
        t = rdp_connect(cap, "10.0.0.45", "10.0.0.%d" % i, "helpdesk", t + 1)
    cap.tick(T0 + 200)
    cap.write(os.path.join(out, "rdp_lateral.pcap"))


# --------------------------------------------------------------------------- 16 SSH

def ssh_session(cap, src, dst, t):
    s = Tcp(cap, src, dst, 22)
    t = s.handshake(t)
    t = s.server_send(b"SSH-2.0-OpenSSH_9.6\r\n", t + 0.01)
    t = s.client_send(b"SSH-2.0-OpenSSH_9.6\r\n" + rand_bytes(1500), t + 0.01)
    t = s.server_send(rand_bytes(1200), t + 0.02)
    t = s.client_send(rand_bytes(600), t + 0.05)
    return s.close(t + 0.1)


def ssh_syn_only(cap, src, dst, t):
    return Tcp(cap, src, dst, 22).rejected(t)


def gen_ssh(out):
    cap = Capture()
    t = T0
    for i in range(51, 55):                       # 10.0.0.50 -> 4대 세션 성립: 탐지 (임계 3대)
        t = ssh_session(cap, "10.0.0.50", "10.0.0.%d" % i, t + 1)
    for i in range(51, 55):                       # 10.0.0.55 -> 4대 SYN 만(거부): 미탐
        t = ssh_syn_only(cap, "10.0.0.55", "10.0.0.%d" % i, t + 1)
    cap.tick(T0 + 200)
    cap.write(os.path.join(out, "ssh_lateral.pcap"))


# --------------------------------------------------------------------------- 07 HTTP 비커닝

def http_get(cap, src, dst, host, t):
    s = Tcp(cap, src, dst, 80)
    t = s.handshake(t)
    req = ("GET /c2/%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
           % (RNG.randint(1, 9999), host)).encode()
    t = s.client_send(req, t)
    t = s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok", t + 0.05)
    return s.close(t + 0.01)


def beacon(cap, src, dst, host, start, intervals):
    t = start
    http_get(cap, src, dst, host, t)
    for iv in intervals:
        t += iv
        http_get(cap, src, dst, host, t)
    return t


def gen_beacon(out):
    cap = Capture()
    # 10.0.0.60: 30초 주기 14회 -> 탐지 (연속 12회)
    beacon(cap, "10.0.0.60", "93.184.215.14", "update.beacon-c2.net", T0, [30] * 13)
    # 10.0.0.61: 불규칙 간격 14회 -> 미탐
    irregular = [5, 47, 13, 90, 22, 61, 8, 120, 35, 17, 75, 40, 9]
    beacon(cap, "10.0.0.61", "93.184.215.15", "news.example.org", T0 + 3, irregular)
    cap.tick(T0 + 900)
    cap.write(os.path.join(out, "http_beacon.pcap"))


# --------------------------------------------------------------------------- 09/12 TLS

def tls_record(ct, payload, ver=0x0303):
    return bytes([ct]) + struct.pack(">HH", ver, len(payload)) + payload


def tls_hs(htype, body):
    return bytes([htype]) + struct.pack(">I", len(body))[1:] + body


def tls_ext(etype, data):
    return struct.pack(">HH", etype, len(data)) + data


def client_hello(sni=None, ciphers=(0xC02F, 0xC030, 0x009C), groups=(0x001D, 0x0017)):
    exts = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        exts += tls_ext(0x0000, struct.pack(">H", len(entry)) + entry)
    exts += tls_ext(0x000A, struct.pack(">H", 2 * len(groups)) + b"".join(struct.pack(">H", g) for g in groups))
    exts += tls_ext(0x000B, b"\x01\x00")
    exts += tls_ext(0x000D, b"\x00\x04\x04\x01\x05\x01")
    body = (b"\x03\x03" + rand_bytes(32) + b"\x00"
            + struct.pack(">H", 2 * len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    return tls_record(22, tls_hs(1, body), ver=0x0301)


def server_hello(cert_der=None, cipher=0xC02F):
    body = b"\x03\x03" + rand_bytes(32) + b"\x00" + struct.pack(">H", cipher) + b"\x00"
    msgs = tls_hs(2, body)
    if cert_der:
        one = struct.pack(">I", len(cert_der))[1:] + cert_der
        msgs += tls_hs(11, struct.pack(">I", len(one))[1:] + one)
    msgs += tls_hs(14, b"")
    return tls_record(22, msgs)


def self_signed_cert_der(cn):
    """결정적인 자체서명 인증서 (Ed25519 고정 키 + 고정 유효기간)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(20261109)
            .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
            .sign(key, None))
    return cert.public_bytes(serialization.Encoding.DER)


def tls_session(cap, src, dst, t, sni=None, cert_der=None, ciphers=(0xC02F, 0xC030, 0x009C),
                upload_skip=0, dport=443):
    """TLS 1.2 핸드셰이크 완료(ssl_established)까지 + 선택적 대용량 업로드."""
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    t = s.client_send(client_hello(sni, ciphers), t)
    t = s.server_send(server_hello(cert_der), t + 0.02)
    t = s.client_send(tls_record(20, b"\x01") + tls_record(22, rand_bytes(40)), t + 0.01)
    t = s.server_send(tls_record(20, b"\x01") + tls_record(22, rand_bytes(40)), t + 0.01)
    t = s.client_send(tls_record(23, rand_bytes(200)), t + 0.01)
    if upload_skip:
        t = s.client_send(tls_record(23, rand_bytes(200)), t + 1, skip=upload_skip)
    t = s.server_send(tls_record(23, rand_bytes(100)), t + 0.01)
    return s.close(t + 0.01)


def gen_tls_c2(out):
    cap = Capture()
    t = T0
    # 10.0.0.70: SNI 없음 + 자체서명 인증서 -> 점수 3 (탐지)
    #   같은 목적지로 2초 뒤 한 번 더 -> 억제창(suppress_enc_c2) 안이므로 notice 는 1건이어야 함
    cert = self_signed_cert_der("c2.invalid")
    t = tls_session(cap, "10.0.0.70", "93.184.215.20", t + 1, sni=None, cert_der=cert)
    t = tls_session(cap, "10.0.0.70", "93.184.215.20", t + 2, sni=None, cert_der=cert)
    # 10.0.0.71: SNI 있음, 인증서 없음 -> 점수 0 (미탐)
    t = tls_session(cap, "10.0.0.71", "93.184.215.21", t + 1, sni="www.example.com")
    # 10.0.0.72: SNI 없음, 고유한 ClientHello -> 점수 1 (기본 미탐, JA3 차단목록 추가 시 탐지)
    t = tls_session(cap, "10.0.0.72", "93.184.215.22", t + 1, sni=None,
                    ciphers=(0x0035, 0x002F, 0x000A))
    cap.tick(t + 180)   # notice_aggregation dedup_window(1분) 만료까지 진행
    cap.write(os.path.join(out, "tls_c2.pcap"))


# --------------------------------------------------------------------------- 10/12 대용량 유출

def bulk_upload(cap, src, dst, dport, skip, t):
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    t = s.client_send(rand_bytes(500), t)
    t = s.client_send(rand_bytes(500), t + 1, skip=skip)
    return s.close(t + 0.01)


def gen_exfil(out):
    mb = 1024 * 1024
    cap = Capture()
    t = T0
    t = bulk_upload(cap, "10.0.0.80", "93.184.215.30", 8443, 60 * mb, t + 1)   # 외부 60MB: 10 탐지
    t = bulk_upload(cap, "10.0.0.81", "93.184.215.31", 8443, 10 * mb, t + 1)   # 외부 10MB: 미탐
    t = bulk_upload(cap, "10.0.0.82", "10.0.0.83", 8443, 60 * mb, t + 1)       # 내부 60MB: 미탐
    # 10.0.0.84: 클라우드(SNI uploads.dropboxapi.com) 60MB -> 12 탐지 (+10 도 함께)
    t = tls_session(cap, "10.0.0.84", "93.184.215.32", t + 1, sni="uploads.dropboxapi.com",
                    upload_skip=60 * mb)
    # 10.0.0.85: 일반 사이트(SNI www.example.com) 60MB -> 12 미탐 (10 은 탐지)
    t = tls_session(cap, "10.0.0.85", "93.184.215.33", t + 1, sni="www.example.com",
                    upload_skip=60 * mb)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "exfil.pcap"))


# --------------------------------------------------------------------------- 14 볼륨 집계

def gen_volume(out):
    cap = Capture()
    t = T0
    s = Tcp(cap, "10.0.0.90", "93.184.215.40", 9000)      # 80KB 실제 전송: 탐지(테스트 임계 50KB)
    t = s.handshake(t)
    t = s.client_send(rand_bytes(80 * 1024), t)
    t = s.close(t)
    s = Tcp(cap, "10.0.0.91", "93.184.215.41", 9000)      # 20KB: 미탐
    t = s.handshake(t + 1)
    t = s.client_send(rand_bytes(20 * 1024), t)
    t = s.close(t)
    cap.tick(T0 + 200)
    cap.write(os.path.join(out, "volume_aggregate.pcap"))


# --------------------------------------------------------------------------- 13 DGA

def dns_exchange(cap, client, qname, rcode, t, answer=None):
    qid = RNG.randint(1, 65535)
    sport = RNG.randint(20000, 60000)
    q = cap.l3(client, DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname))
    cap.add(q, t)
    an = DNSRR(rrname=qname, type="A", ttl=60, rdata=answer) if answer else None
    r = cap.l3(DNS_SERVER, client) / UDP(sport=53, dport=sport) / DNS(
        id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname), an=an)
    cap.add(r, t + 0.002)


def rand_label(n):
    return "".join(RNG.choice(string.ascii_lowercase) for _ in range(n))


def gen_dga(out):
    cap = Capture()
    t = T0
    for i in range(60):   # 10.0.0.100: 30자 무작위 라벨 NXDOMAIN 60건 -> 탐지
        dns_exchange(cap, "10.0.0.100", rand_label(30) + ".com", 3, t + i * 2)
    for i in range(60):   # 10.0.0.101: 10자 무작위 라벨 NXDOMAIN 60건 -> 현재 미탐(검토 H4)
        dns_exchange(cap, "10.0.0.101", rand_label(10) + ".com", 3, t + 1 + i * 2)
    names = ["www.example.com", "mail.example.org", "intranet.corp.local", "update.example.net"]
    for i in range(60):   # 10.0.0.102: 정상 조회(NXDOMAIN 5건) -> 미탐
        if i % 12 == 0:
            dns_exchange(cap, "10.0.0.102", "typo-%d.example.com" % i, 3, t + 0.5 + i * 2)
        else:
            dns_exchange(cap, "10.0.0.102", names[i % len(names)], 0, t + 0.5 + i * 2,
                         answer="93.184.215.%d" % (100 + i % 50))
    cap.tick(T0 + 25 * 60)      # dga_interval(10분) epoch 를 두 번 넘긴다
    cap.write(os.path.join(out, "dga.pcap"))


# --------------------------------------------------------------------------- 상관: 정찰 -> C2

def gen_chain(out):
    cap = Capture()
    port_scan(cap, "10.0.0.5", "10.0.0.9", range(1000, 1030), T0)
    beacon(cap, "10.0.0.5", "93.184.215.14", "update.beacon-c2.net", T0 + 60, [30] * 13)
    # 비교군: 10.0.0.7 은 스캔 없이 비커닝만 -> 단일 탐지만, 상관 없음
    beacon(cap, "10.0.0.7", "93.184.215.16", "cdn.beacon-c2.net", T0 + 61, [30] * 13)
    cap.tick(T0 + 900)
    cap.write(os.path.join(out, "chain_recon_c2.pcap"))


GENERATORS = [gen_port_scan, gen_host_scan, gen_smb, gen_rdp, gen_ssh, gen_beacon,
              gen_tls_c2, gen_exfil, gen_volume, gen_dga, gen_chain]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    for g in GENERATORS:
        g(args.outdir)
    for f in sorted(os.listdir(args.outdir)):
        if f.endswith(".pcap"):
            print("%-28s %8d bytes" % (f, os.path.getsize(os.path.join(args.outdir, f))))


if __name__ == "__main__":
    main()
