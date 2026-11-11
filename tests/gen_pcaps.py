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
import uuid as uuidlib

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

    def server_send(self, data, t, ack_each=False):
        for i in range(0, len(data), self.MSS):
            chunk = data[i:i + self.MSS]
            self._s("PA", t, chunk)
            self.sseq += len(chunk)
            t += 0.0005
            if ack_each:                       # 다운로드: 내부 클라이언트가 세그먼트마다 ACK
                self._c("A", t)
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
    # 10.0.0.32: 프린터 드라이버 공유 print$ 를 3대에 접근(정상 숨김 공유) -> 미탐
    for dst in ("10.0.0.21", "10.0.0.22", "10.0.0.23"):
        t = smb_tree_connect(cap, "10.0.0.32", dst, "print$", t + 1)
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

def ssh_session(cap, src, dst, t, dport=22):
    s = Tcp(cap, src, dst, dport)
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

def http_get(cap, src, dst, host, t, dport=80):
    s = Tcp(cap, src, dst, dport)
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
    # 10.0.0.62: 30초 주기인데 중간 비콘 2개가 빠짐(60초 간격) -> 누락 허용으로 탐지
    missed = [30, 30, 60, 30, 30, 30, 60, 30, 30, 30, 30, 30, 30]
    beacon(cap, "10.0.0.62", "93.184.215.17", "sync.beacon-c2.net", T0 + 7, missed)
    cap.tick(T0 + 1200)
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


def self_signed_cert_der(cn, sans=()):
    """결정적인 자체서명 인증서 (Ed25519 고정 키 + 고정 유효기간, 선택적 SAN)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(20261109)
               .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
               .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in sans]), critical=False)
    cert = builder.sign(key, None)
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
    # SNI-인증서 일치 판정(sni_matches_cert) 케이스. 셋 다 자체서명(+2)이라 불일치(+1)면 점수 3 으로 탐지.
    # 10.0.0.73: 와일드카드 인증서 *.example.com 이 SNI www.example.com 과 일치 -> 미탐
    t = tls_session(cap, "10.0.0.73", "93.184.215.23", t + 1, sni="www.example.com",
                    cert_der=self_signed_cert_der("*.example.com"))
    # 10.0.0.74: 인증서 CN attacker.invalid 가 SNI login.bank.example 과 불일치 -> 탐지
    t = tls_session(cap, "10.0.0.74", "93.184.215.24", t + 1, sni="login.bank.example",
                    cert_der=self_signed_cert_der("attacker.invalid"))
    # 10.0.0.75: CN 은 example.org 지만 SAN 에 www.example.com 이 있어 일치 -> 미탐
    t = tls_session(cap, "10.0.0.75", "93.184.215.25", t + 1, sni="www.example.com",
                    cert_der=self_signed_cert_der("example.org", sans=("example.org", "www.example.com")))
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
    # 10.0.0.92: 500KB 다운로드(내부는 ACK 만 보냄) -> 미탐 (ACK 헤더를 전송량으로 세지 않아야 함)
    s = Tcp(cap, "10.0.0.92", "93.184.215.42", 9000)
    t = s.handshake(t + 1)
    t = s.client_send(b"GET /big HTTP/1.1\r\n\r\n", t)
    t = s.server_send(rand_bytes(500 * 1024), t, ack_each=True)
    t = s.close(t)
    # 10.0.0.93: 장기 연결. T0+10초에 80KB 업로드 후 150초 동안 열려 있다가 종료 -> 종료 전(첫 1분 안) 탐지
    s = Tcp(cap, "10.0.0.93", "93.184.215.43", 9001)
    lt = s.handshake(T0 + 10)
    lt = s.client_send(rand_bytes(80 * 1024), lt)
    lt = s.client_send(b"keepalive", T0 + 150)
    s.close(T0 + 160)
    cap.tick(T0 + 300)
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
    for i in range(60):   # 10.0.0.101: 10자 무작위 라벨 NXDOMAIN 60건 -> 탐지 (이전 지표로는 미탐, 검토 H4)
        dns_exchange(cap, "10.0.0.101", rand_label(10) + ".com", 3, t + 1 + i * 2)
    words = ["mail", "file", "print", "portal", "server", "old", "backup", "test", "dev", "web",
             "shop", "news", "cloud", "data", "intra", "office", "home", "smart", "global", "korea"]
    for i in range(60):   # 10.0.0.103: 단어 조합형 미등록 도메인 NXDOMAIN 60건(설정 오류 등) -> 미탐
        dns_exchange(cap, "10.0.0.103", RNG.choice(words) + RNG.choice(words) + ".com", 3, t + 1.2 + i * 2)
    for i in range(60):   # 10.0.0.104: 9자 무작위 라벨 + co.kr 접미사 NXDOMAIN 60건 -> 탐지
        dns_exchange(cap, "10.0.0.104", "www." + rand_label(9) + ".co.kr", 3, t + 1.4 + i * 2)
    for i in range(60):   # 10.0.0.105: 12자 16진수 라벨 NXDOMAIN 60건 -> 탐지
        hexlabel = "".join(RNG.choice("0123456789abcdef") for _ in range(12))
        dns_exchange(cap, "10.0.0.105", hexlabel + ".net", 3, t + 1.6 + i * 2)
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


# --------------------------------------------------------------------------- 08 DNS 터널링·유출

def dns_query_only(cap, client, qname, qtype, t):
    q = cap.l3(client, DNS_SERVER) / UDP(sport=RNG.randint(20000, 60000), dport=53) / DNS(
        id=RNG.randint(1, 65535), rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    cap.add(q, t)


def rand_from(alphabet, n):
    return "".join(RNG.choice(alphabet) for _ in range(n))


def gen_dns_tunnel(out):
    cap = Capture()
    t = T0
    hexchars = "0123456789abcdef"
    b32 = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(80):   # 10.0.0.110: 40자 hex 라벨 TXT 질의 80건 -> 터널링 탐지
        dns_query_only(cap, "10.0.0.110", "%s.t.evil-tunnel.com" % rand_from(hexchars, 40), "TXT", t + i * 1.5)
    for i in range(680):  # 10.0.0.111: 50자 base32 라벨 680건(약 34KB) -> 유출 탐지(테스트 임계 32KB)
        dns_query_only(cap, "10.0.0.111", "%s.x.exfil-dns.net" % rand_from(b32, 50), "A", t + 0.3 + i * 0.15)
    for i in range(80):   # 10.0.0.112: CDN형 짧은 무작위 서브도메인 80건 -> 미탐
        dns_query_only(cap, "10.0.0.112", "r%d---sn-%s.cdn-video.example.com" % (i % 9, rand_from(hexchars + "xyz", 8)),
                       "A", t + 0.6 + i * 1.5)
    words = ["shop", "news", "bank", "mall", "game", "food", "book", "tour", "car", "home"]
    for i in range(80):   # 10.0.0.113: 국내 사이트 80곳(www.<단어><n>.co.kr) -> 미탐 (co.kr 은 사이트별로 집계)
        dns_query_only(cap, "10.0.0.113", "www.%s%d.co.kr" % (words[i % 10], i), "A", t + 0.9 + i * 1.5)
    for i in range(80):   # 10.0.0.114: AV 평판 조회(sophosxl.net) 80건 -> 미탐 (기본 예외)
        dns_query_only(cap, "10.0.0.114", "%s.sxl.sophosxl.net" % rand_from(hexchars, 40), "A", t + 1.2 + i * 1.5)
    cap.tick(T0 + 11 * 60)      # dnstun_interval(5분) epoch 를 두 번 넘긴다
    cap.write(os.path.join(out, "dns_tunnel.pcap"))


# --------------------------------------------------------------------------- 03/04 웹 공격

WEB_SERVER = "10.0.10.80"


def http_req(cap, src, dst, method, uri, t, body=b"", host="intranet.corp.example"):
    s = Tcp(cap, src, dst, 80)
    t = s.handshake(t)
    head = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n" % (method, uri, host)
    if body:
        head += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n" % len(body)
    t = s.client_send(head.encode() + b"\r\n" + body, t)
    t = s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\n\r\nok", t + 0.02)
    return s.close(t + 0.01)


def gen_web_attack(out):
    cap = Capture()
    t = T0
    reqs = [
        # SQLi
        ("10.0.0.120", WEB_SERVER, "GET", "/item.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", b""),
        ("10.0.0.121", WEB_SERVER, "GET", "/search?q=select%20from%20the%20list%20%23top", b""),
        ("10.0.0.122", WEB_SERVER, "POST", "/login", b"user=admin%27+or+1%3D1--&pw=x"),
        ("10.0.0.123", WEB_SERVER, "GET", "/p?id=1%2527%2520or%25201%253D1", b""),
        ("10.0.0.124", "93.184.215.50", "GET", "/item.php?id=1%27%20UNION%20SELECT%20a,b%20FROM%20t--", b""),
        # 웹쉘
        ("10.0.0.125", WEB_SERVER, "GET", "/uploads/shell.php?cmd=whoami", b""),
        ("10.0.0.126", WEB_SERVER, "GET", "/app/view?c=blue&cmd=refresh", b""),
        ("10.0.0.127", WEB_SERVER, "POST", "/images/x.php",
         b"z0=%40ini_set%28%22display_errors%22%2C%220%22%29%3B%40set_time_limit%280%29%3Becho%28%22ok%22%29%3B"),
        ("10.0.0.128", WEB_SERVER, "GET", "/index.php?page=about", b""),
        ("10.0.0.129", WEB_SERVER, "GET", "/static/js/shell.js", b""),
    ]
    for src, dst, method, uri, body in reqs:
        t = http_req(cap, src, dst, method, uri, t + 1, body)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "web_attack.pcap"))


# --------------------------------------------------------------------------- 05 NTLM 스프레이

NTLM_SERVER = "10.0.0.5"
SPNEGO_OID = bytes.fromhex("2b0601050502")
NTLMSSP_OID = bytes.fromhex("2b06010401823702020a")
STATUS_MORE_PROCESSING = 0xC0000016
STATUS_LOGON_FAILURE = 0xC000006D


def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack(">H", n)
    return bytes([tag]) + ln + body


def ntlm_negotiate():
    return b"NTLMSSP\x00" + struct.pack("<II", 1, 0x00000207) + b"\x00" * 16


def ntlm_challenge(target="CORP"):
    name = target.encode("utf-16-le")
    flags = 0x00000207 | 0x00010000                       # unicode·oem·request_target·ntlm + target_type_domain
    head = b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", len(name), len(name), 48)
    head += struct.pack("<I", flags) + rand_bytes(8) + b"\x00" * 8 + struct.pack("<HHI", 0, 0, 48 + len(name))
    return head + name


def ntlm_authenticate(domain, user, workstation="WS01"):
    d, u, w = (x.encode("utf-16-le") for x in (domain, user, workstation))
    lm, nt = b"\x00" * 24, rand_bytes(24)
    off = 64
    fields, payload = b"", b""
    for blob in (lm, nt, d, u, w, b""):
        fields += struct.pack("<HHI", len(blob), len(blob), off + len(payload))
        payload += blob
    return b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + struct.pack("<I", 0x00000201) + payload


def spnego_init(mech_token):
    mech_types = der(0xa0, der(0x30, der(0x06, NTLMSSP_OID)))
    body = der(0x30, mech_types + der(0xa2, der(0x04, mech_token)))
    return der(0x60, der(0x06, SPNEGO_OID) + der(0xa0, body))


def spnego_resp(neg_state=None, mech_token=None, with_mech=False):
    args = b""
    if neg_state is not None:
        args += der(0xa0, der(0x0a, bytes([neg_state])))
    if with_mech:
        args += der(0xa1, der(0x06, NTLMSSP_OID))
    if mech_token is not None:
        args += der(0xa2, der(0x04, mech_token))
    return der(0xa1, der(0x30, args))


def smb2_hdr(command, msg_id, status=0, response=False, session_id=0):
    return (b"\xfeSMB" + struct.pack("<HHIHHII", 64, 1, status, command, 1, 1 if response else 0, 0)
            + struct.pack("<QII", msg_id, 0xFEFF, 0) + struct.pack("<Q", session_id) + b"\x00" * 16)


def nbss(msg):
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


def smb2_session_setup_req(msg_id, blob, session_id=0):
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 1, 0, 64 + 24, len(blob), 0) + blob
    return nbss(smb2_hdr(1, msg_id, session_id=session_id) + body)


def smb2_session_setup_resp(msg_id, status, blob, session_id):
    if status in (0, STATUS_MORE_PROCESSING):
        body = struct.pack("<HHHH", 9, 0, 64 + 8, len(blob)) + blob
    else:                                                   # SMB2 ERROR 응답(보안 버퍼 없음)
        body = struct.pack("<HBBI", 9, 0, 0, 0) + b"\x00"
    return nbss(smb2_hdr(1, msg_id, status=status, response=True, session_id=session_id) + body)


def ntlm_smb_login(cap, src, dst, domain, user, ok, t):
    """SMB2 세션 설정 2왕복(NEGOTIATE/CHALLENGE, AUTHENTICATE/결과)."""
    s = Tcp(cap, src, dst, 445)
    t = s.handshake(t)
    sid = RNG.randint(1, 2**40)
    t = s.client_send(smb2_session_setup_req(1, spnego_init(ntlm_negotiate())), t)
    t = s.server_send(smb2_session_setup_resp(1, STATUS_MORE_PROCESSING,
                                              spnego_resp(1, ntlm_challenge(), with_mech=True), sid), t + 0.002)
    t = s.client_send(smb2_session_setup_req(2, spnego_resp(mech_token=ntlm_authenticate(domain, user)), sid),
                      t + 0.002)
    if ok:
        t = s.server_send(smb2_session_setup_resp(2, 0, spnego_resp(0), sid), t + 0.01)
    else:
        t = s.server_send(smb2_session_setup_resp(2, STATUS_LOGON_FAILURE, b"", sid), t + 0.01)
    return s.close(t + 0.01)


def gen_ntlm_spray(out):
    cap = Capture()
    t = T0
    users = ["user%02d" % i for i in range(1, 13)]
    # .140: 12개 계정 실패(스프레이) -> 탐지 (임계 10)
    for u in users:
        t = ntlm_smb_login(cap, "10.0.0.140", NTLM_SERVER, "CORP", u, False, t + 1)
    # .141: 12개 계정 모두 성공(터미널 서버 등 정상) -> 미탐
    for u in users:
        t = ntlm_smb_login(cap, "10.0.0.141", NTLM_SERVER, "CORP", u, True, t + 1)
    # .142: 한 계정만 15회 실패(무차별 대입, 스프레이 아님) -> 미탐
    for _ in range(15):
        t = ntlm_smb_login(cap, "10.0.0.142", NTLM_SERVER, "CORP", "administrator", False, t + 1)
    # .143: 6개 계정을 대소문자만 바꿔 2번씩 실패 = 고유 6개 -> 미탐
    for u in users[:6]:
        for v in (u, u.upper()):
            t = ntlm_smb_login(cap, "10.0.0.143", NTLM_SERVER, "corp", v, False, t + 1)
    # .144: 외부 서버 대상 12개 계정 실패 -> 미탐(내부 서버 대상만)
    for u in users:
        t = ntlm_smb_login(cap, "10.0.0.144", "93.184.215.60", "CORP", u, False, t + 1)
    # .145: 예외 출발지(테스트에서 allowlist 등록) 12개 계정 실패 -> 미탐
    for u in users:
        t = ntlm_smb_login(cap, "10.0.0.145", NTLM_SERVER, "CORP", u, False, t + 1)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "ntlm_spray.pcap"))


# --------------------------------------------------------------------------- 17/18 Kerberos

KDC = "10.0.0.10"
REALM = "CORP.EXAMPLE"
KRB_AES256, KRB_RC4 = 18, 23


def asn_int(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return der(0x02, v.to_bytes(n, "big", signed=True))


def ctx(i, body):
    return der(0xa0 + i, body)


def krb_str(sv):
    return der(0x1b, sv.encode())                                       # GeneralString


def krb_time(t):
    return der(0x18, dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y%m%d%H%M%SZ").encode())


def principal(name_type, *names):
    return der(0x30, ctx(0, asn_int(name_type)) + ctx(1, der(0x30, b"".join(krb_str(n) for n in names))))


def enc_data(etype, cipher, kvno=None):
    body = ctx(0, asn_int(etype))
    if kvno is not None:
        body += ctx(1, asn_int(kvno))
    return der(0x30, body + ctx(2, der(0x04, cipher)))


def krb_ticket(spn, etype):
    return der(0x61, der(0x30, ctx(0, asn_int(5)) + ctx(1, krb_str(REALM)) + ctx(2, principal(2, *spn.split("/")))
                         + ctx(3, enc_data(etype, rand_bytes(64), kvno=2))))


def padata(ptype, value):
    return der(0x30, ctx(1, asn_int(ptype)) + ctx(2, der(0x04, value)))


def kdc_req_body(t, cname=None, sname=("krbtgt", REALM), etypes=(KRB_AES256, 17, KRB_RC4)):
    body = ctx(0, der(0x03, b"\x00\x40\x81\x00\x10"))                  # forwardable·renewable·canonicalize·renewable-ok
    if cname:
        body += ctx(1, principal(1, cname))
    body += ctx(2, krb_str(REALM)) + ctx(3, principal(2, *sname)) + ctx(5, krb_time(t + 36000))
    body += ctx(7, asn_int(RNG.randint(1, 2**31 - 1))) + ctx(8, der(0x30, b"".join(asn_int(e) for e in etypes)))
    return der(0x30, body)


def as_req(t, user, preauth, etypes=(KRB_AES256, 17, KRB_RC4)):
    pa = b""
    if preauth:
        pa = ctx(3, der(0x30, padata(2, enc_data(KRB_AES256, rand_bytes(52)))))   # PA-ENC-TIMESTAMP
    return der(0x6a, der(0x30, ctx(1, asn_int(5)) + ctx(2, asn_int(10)) + pa
                         + ctx(4, kdc_req_body(t, cname=user, etypes=etypes))))


def tgs_req(t, spn, etypes=(KRB_AES256, 17, KRB_RC4)):
    authn = enc_data(KRB_AES256, rand_bytes(96))
    ap_req = der(0x6e, der(0x30, ctx(0, asn_int(5)) + ctx(1, asn_int(14)) + ctx(2, der(0x03, b"\x00\x00\x00\x00\x00"))
                           + ctx(3, krb_ticket("krbtgt/" + REALM, KRB_AES256)) + ctx(4, authn)))
    pa = ctx(3, der(0x30, padata(1, ap_req)))                                       # PA-TGS-REQ
    return der(0x6c, der(0x30, ctx(1, asn_int(5)) + ctx(2, asn_int(12)) + pa
                         + ctx(4, kdc_req_body(t, sname=tuple(spn.split("/")), etypes=etypes))))


def kdc_rep(app, msg_type, user, spn, ticket_etype, enc_etype):
    return der(app, der(0x30, ctx(0, asn_int(5)) + ctx(1, asn_int(msg_type)) + ctx(3, krb_str(REALM))
                        + ctx(4, principal(1, user)) + ctx(5, krb_ticket(spn, ticket_etype))
                        + ctx(6, enc_data(enc_etype, rand_bytes(120), kvno=3))))


def krb_error(t, code, user=None, sname=("krbtgt", REALM)):
    body = ctx(0, asn_int(5)) + ctx(1, asn_int(30)) + ctx(4, krb_time(t)) + ctx(5, asn_int(0)) + ctx(6, asn_int(code))
    if user:
        body += ctx(7, krb_str(REALM)) + ctx(8, principal(1, user))
    body += ctx(9, krb_str(REALM)) + ctx(10, principal(2, *sname))
    return der(0x7e, der(0x30, body))


def krb_udp(cap, client, req, rep, t):
    sport = RNG.randint(49152, 65000)
    cap.add(cap.l3(client, KDC) / UDP(sport=sport, dport=88) / Raw(req), t)
    cap.add(cap.l3(KDC, client) / UDP(sport=88, dport=sport) / Raw(rep), t + 0.003)
    return t + 0.01


def krb_logon_fail(cap, client, user, code, t):
    return krb_udp(cap, client, as_req(t, user, True), krb_error(t, code, user), t)


def krb_logon_ok(cap, client, user, t):
    """정상 Windows 로그온: 사전인증 없는 AS-REQ -> PREAUTH_REQUIRED(25) -> 사전인증 AS-REQ -> AS-REP(AES)."""
    t = krb_udp(cap, client, as_req(t, user, False), krb_error(t, 25, user), t)
    return krb_udp(cap, client, as_req(t, user, True),
                   kdc_rep(0x6b, 11, user, "krbtgt/" + REALM, KRB_AES256, KRB_AES256), t + 0.01)


def krb_asrep_nopreauth(cap, client, user, enc_etype, t):
    return krb_udp(cap, client, as_req(t, user, False, etypes=(enc_etype,)),
                   kdc_rep(0x6b, 11, user, "krbtgt/" + REALM, KRB_AES256, enc_etype), t)


def krb_service_ticket(cap, client, user, spn, etype, t):
    return krb_udp(cap, client, tgs_req(t, spn, etypes=(etype,) if etype == KRB_RC4 else (KRB_AES256, 17, KRB_RC4)),
                   kdc_rep(0x6d, 13, user, spn, etype, KRB_AES256), t)


def gen_kerberos(out):
    cap = Capture()
    t = T0
    users = ["user%02d" % i for i in range(1, 13)]
    spns = ["MSSQLSvc/db%02d.corp.example:1433" % i for i in range(1, 7)]
    # 17 스프레이
    for u in users:                                               # .150: 12개 계정 사전인증 실패 -> 스프레이
        t = krb_logon_fail(cap, "10.0.0.150", u, 24, t + 1)
    for u in users:                                               # .151: 12개 계정 정상 로그온 -> 미탐
        t = krb_logon_ok(cap, "10.0.0.151", u, t + 1)
    for _ in range(25):                                           # .152: 1개 계정 25회 실패 -> 무차별 대입
        t = krb_logon_fail(cap, "10.0.0.152", "administrator", 24, t + 1)
    for u in users:                                               # .153: 예외 출발지 12개 실패 -> 미탐
        t = krb_logon_fail(cap, "10.0.0.153", u, 24, t + 1)
    for i, u in enumerate(users):                                 # .159: 없는 계정·실패 섞어 12개 -> 스프레이
        t = krb_logon_fail(cap, "10.0.0.159", "x" + u, 6 if i % 2 else 24, t + 1)
    # 18 AS-REP Roasting
    for u in ("svc_backup", "svc_legacy", "svc_scan"):            # .154: 사전인증 없이 RC4 AS-REP 3건 -> 계정마다 탐지
        t = krb_asrep_nopreauth(cap, "10.0.0.154", u, KRB_RC4, t + 1)
    t = krb_asrep_nopreauth(cap, "10.0.0.155", "svc_nopreauth_aes", KRB_AES256, t + 1)   # .155: AES -> 미탐
    # 18 Kerberoasting
    for spn in spns:                                              # .156: 6개 SPN RC4 티켓 -> 탐지
        t = krb_service_ticket(cap, "10.0.0.156", "user01", spn, KRB_RC4, t + 1)
    for spn in spns:                                              # .157: 6개 SPN AES 티켓 -> 미탐
        t = krb_service_ticket(cap, "10.0.0.157", "user02", spn, KRB_AES256, t + 1)
    for spn in spns[:2]:                                          # .158: RC4 레거시 서비스 2개 -> 미탐
        t = krb_service_ticket(cap, "10.0.0.158", "user03", spn, KRB_RC4, t + 1)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "kerberos.pcap"))


# --------------------------------------------------------------------------- 19 외부향 SMB / NTLM

def tcp_established(cap, src, dst, dport, t):
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    return s.close(t + 0.05)


def gen_outbound_smb(out):
    cap = Capture()
    t = T0
    # .160: 외부 445 연결 + NTLM 인증(강제 인증으로 해시 유출) -> Outbound_SMB + NTLM_Credential_Leak
    t = ntlm_smb_login(cap, "10.0.0.160", "93.184.215.70", "CORP", "kim.jh", False, t + 1)
    # .161: 외부 445 SYN 이 경계에서 막힘(RST) -> 미탐
    t = Tcp(cap, "10.0.0.161", "93.184.215.71", 445).rejected(t + 1)
    # .162: 내부 파일 서버 445 + NTLM -> 미탐
    t = ntlm_smb_login(cap, "10.0.0.162", NTLM_SERVER, "CORP", "lee.sm", True, t + 1)
    # .163: 외부 139 연결만(인증 없음) -> Outbound_SMB 만
    t = tcp_established(cap, "10.0.0.163", "93.184.215.72", 139, t + 1)
    # .164: 허용한 외부 SMB 서버(테스트에서 allowed_dsts 등록) + NTLM -> 미탐
    t = ntlm_smb_login(cap, "10.0.0.164", "93.184.215.73", "CORP", "park.ys", True, t + 1)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "outbound_smb.pcap"))


# --------------------------------------------------------------------------- 20 WinRM / DCOM

ISYSTEMACTIVATOR = "000001a0-0000-0000-c000-000000000046"
IOXID_RESOLVER = "99fcfec4-5260-101b-bbcb-00aa0021347a"
NDR_SYNTAX = "8a885d04-1ceb-11c9-9fe8-08002b104860"


def dce_hdr(ptype, body, call_id):
    return struct.pack("<BBBB4sHHI", 5, 0, ptype, 0x03, b"\x10\x00\x00\x00", 16 + len(body), 0, call_id) + body


def dce_syntax(u, major=0, minor=0):
    return uuidlib.UUID(u).bytes_le + struct.pack("<HH", major, minor)


def dce_bind(iface, call_id=1):
    ctxs = struct.pack("<BBH", 1, 0, 0) + struct.pack("<HBB", 0, 1, 0) + dce_syntax(iface) + dce_syntax(NDR_SYNTAX, 2)
    return dce_hdr(11, struct.pack("<HHI", 4280, 4280, 0) + ctxs, call_id)


def dce_bind_ack(call_id=1):
    sec = b"135\x00"
    body = struct.pack("<HHIH", 4280, 4280, 0x1234, len(sec)) + sec
    body += b"\x00" * ((-(16 + len(body))) % 4)
    body += struct.pack("<BBH", 1, 0, 0) + struct.pack("<HH", 0, 0) + dce_syntax(NDR_SYNTAX, 2)
    return dce_hdr(12, body, call_id)


def dce_request(opnum, stub, call_id=2):
    return dce_hdr(0, struct.pack("<IHH", len(stub), 0, opnum) + stub, call_id)


def dce_response(stub, call_id=2):
    return dce_hdr(2, struct.pack("<IHBB", len(stub), 0, 0, 0) + stub, call_id)


def dcom_call(cap, src, dst, iface, opnum, t, dport=135):
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    t = s.client_send(dce_bind(iface), t)
    t = s.server_send(dce_bind_ack(), t + 0.002)
    t = s.client_send(dce_request(opnum, rand_bytes(120)), t + 0.002)
    t = s.server_send(dce_response(rand_bytes(80)), t + 0.01)
    return s.close(t + 0.01)


def winrm_session(cap, src, dst, t, dport=5985):
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    if dport == 5985:
        body = b"<s:Envelope>" + rand_bytes(200).hex().encode() + b"</s:Envelope>"
        t = s.client_send(b"POST /wsman HTTP/1.1\r\nHost: %s:5985\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n"
                          b"Content-Length: %d\r\n\r\n" % (dst.encode(), len(body)) + body, t)
        t = s.server_send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", t + 0.01)
    else:
        t = s.client_send(rand_bytes(300), t)
        t = s.server_send(rand_bytes(600), t + 0.01)
    return s.close(t + 0.01)


def gen_winrm_dcom(out):
    cap = Capture()
    t = T0
    targets = ["10.0.20.%d" % i for i in range(11, 15)]
    for i, dst in enumerate(targets):                        # .170: WinRM 4대(5985·5986 섞어) -> 탐지
        t = winrm_session(cap, "10.0.0.170", dst, t + 2, 5985 if i % 2 == 0 else 5986)
    for dst in targets[:2]:                                  # .171: WinRM 2대 -> 미탐(임계 3)
        t = winrm_session(cap, "10.0.0.171", dst, t + 2)
    for dst in targets:                                      # .172: 관리 서버(예외) WinRM 4대 -> 미탐
        t = winrm_session(cap, "10.0.0.172", dst, t + 2)
    for dst in targets:                                      # .173: DCOM RemoteCreateInstance 4대 -> 탐지
        t = dcom_call(cap, "10.0.0.173", dst, ISYSTEMACTIVATOR, 4, t + 2)
    for dst in targets:                                      # .174: 135 포트 다른 인터페이스(IOXIDResolver) 4대 -> 미탐
        t = dcom_call(cap, "10.0.0.174", dst, IOXID_RESOLVER, 5, t + 2)
    for dst in targets:                                      # .175: ISystemActivator 의 다른 opnum(3) 4대 -> 미탐
        t = dcom_call(cap, "10.0.0.175", dst, ISYSTEMACTIVATOR, 3, t + 2)
    cap.tick(T0 + 900)                                       # 5분 epoch 종료
    cap.write(os.path.join(out, "winrm_dcom.pcap"))


# --------------------------------------------------------------------------- 21 랜섬웨어성 SMB

FILE_SERVER = "10.0.0.6"


class Smb2Session:
    """하나의 TCP 연결 위 SMB2 세션(트리 연결 후 파일 열기·이름 바꾸기·만들기)."""

    def __init__(self, cap, src, dst, share, t):
        self.s = Tcp(cap, src, dst, 445)
        self.t = self.s.handshake(t)
        self.mid, self.tid, self.sid = 1, 0, RNG.randint(1, 2**40)
        path = ("\\\\%s\\%s" % (dst, share)).encode("utf-16-le")
        self._xchg(3, struct.pack("<HHHH", 9, 0, 64 + 8, len(path)) + path,
                   struct.pack("<HBxIII", 16, 1, 0, 0, 0x001F01FF), new_tid=1)

    def _hdr(self, cmd, status=0, response=False):
        return (b"\xfeSMB" + struct.pack("<HHIHHII", 64, 1, status, cmd, 1, 1 if response else 0, 0)
                + struct.pack("<QII", self.mid, 0xFEFF, self.tid) + struct.pack("<Q", self.sid) + b"\x00" * 16)

    def _xchg(self, cmd, req_body, rep_body, new_tid=None):
        self.t = self.s.client_send(nbss(self._hdr(cmd) + req_body), self.t + 0.001)
        if new_tid is not None:
            self.tid = new_tid
        self.t = self.s.server_send(nbss(self._hdr(cmd, response=True) + rep_body), self.t + 0.001)
        self.mid += 1

    def create(self, name, disposition=1):
        n = name.encode("utf-16-le")
        req = (struct.pack("<HBBI", 57, 0, 0, 2) + b"\x00" * 16
               + struct.pack("<IIIII", 0x00130197, 0, 7, disposition, 0x40)
               + struct.pack("<HHII", 64 + 56, len(n), 0, 0) + n)
        fid = (RNG.getrandbits(64), RNG.getrandbits(64))
        ft = 133000000000000000
        rep = (struct.pack("<HBBI", 89, 0, 0, 1 if disposition == 1 else 2) + struct.pack("<QQQQ", ft, ft, ft, ft)
               + struct.pack("<QQII", 4096, 1234, 0x20, 0) + struct.pack("<QQ", *fid) + struct.pack("<II", 0, 0))
        self._xchg(5, req, rep)
        return fid

    def rename(self, fid, new_name):
        n = new_name.encode("utf-16-le")
        buf = struct.pack("<B7xQI", 0, 0, len(n)) + n
        req = struct.pack("<HBBIHHI", 33, 1, 0x0a, len(buf), 64 + 32, 0, 0) + struct.pack("<QQ", *fid) + buf
        self._xchg(0x11, req, struct.pack("<H", 2))

    def close(self):
        return self.s.close(self.t + 0.01)


def gen_smb_ransomware(out):
    cap = Capture()
    t = T0
    dirs = ["finance", "hr", "sales", "legal", "it", "ops"]
    # .180: 40개 파일을 .lockd 로 이름 변경 + 6개 폴더에 랜섬 노트 -> 탐지
    s = Smb2Session(cap, "10.0.0.180", FILE_SERVER, "data", t + 1)
    for i in range(40):
        name = "%s\\report_%02d.docx" % (dirs[i % 6], i)
        s.rename(s.create(name), name + ".lockd")
    for d in dirs:
        s.create("%s\\README_DECRYPT_FILES.txt" % d, disposition=2)
    t = s.close()
    # .181: 40개 파일 이름만 변경(확장자 유지) -> 미탐
    s = Smb2Session(cap, "10.0.0.181", FILE_SERVER, "data", t + 1)
    for i in range(40):
        name = "%s\\memo_%02d.docx" % (dirs[i % 6], i)
        s.rename(s.create(name), name.replace(".docx", "_v2.docx"))
    t = s.close()
    # .182: Office 저장 패턴 20회(원본 -> ~WRL.tmp, ~WRD.tmp -> 원본) -> 미탐
    s = Smb2Session(cap, "10.0.0.182", FILE_SERVER, "data", t + 1)
    for i in range(20):
        name = "sales\\plan_%02d.xlsx" % i
        s.rename(s.create(name), "sales\\~WRL%04d.tmp" % i)
        s.rename(s.create("sales\\~WRD%04d.tmp" % i), name)
    t = s.close()
    # .183: 백업 서버(예외) 40개 확장자 변경 -> 미탐
    s = Smb2Session(cap, "10.0.0.183", FILE_SERVER, "data", t + 1)
    for i in range(40):
        name = "it\\log_%02d.txt" % i
        s.rename(s.create(name), name + ".bak")
    t = s.close()
    # .184: 랜섬 노트만 6개 폴더 -> 탐지 / .185: 일반 readme.txt 6개 폴더 -> 미탐
    s = Smb2Session(cap, "10.0.0.184", FILE_SERVER, "data", t + 1)
    for d in dirs:
        s.create("%s\\HOW_TO_RESTORE_FILES.html" % d, disposition=2)
    t = s.close()
    s = Smb2Session(cap, "10.0.0.185", FILE_SERVER, "data", t + 1)
    for d in dirs:
        s.create("%s\\readme.txt" % d, disposition=2)
    t = s.close()
    cap.tick(t + 120)
    cap.write(os.path.join(out, "smb_ransomware.pcap"))


# --------------------------------------------------------------------------- 22 LLMNR / NBT-NS / mDNS 포이즈닝

def netbios_encode(name, suffix=0x20):
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    return b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)]) for b in raw)


def nbns_packet(tid, flags, name, answer_ip=None):
    qname = b"\x20" + netbios_encode(name) + b"\x00"
    if answer_ip is None:                                   # 질의: QD 1
        return struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0) + qname + struct.pack(">HH", 32, 1)
    rdata = struct.pack(">H", 0) + bytes(int(x) for x in answer_ip.split("."))
    return (struct.pack(">HHHHHH", tid, flags, 0, 1, 0, 0) + qname
            + struct.pack(">HHIH", 32, 1, 300, len(rdata)) + rdata)   # 응답: 질문 없이 NB 레코드


def nbns_exchange(cap, querier, responder, name, t):
    tid = RNG.randint(1, 65535)
    cap.add(cap.l3(querier, "10.0.0.255") / UDP(sport=137, dport=137) / Raw(nbns_packet(tid, 0x0110, name)), t)
    cap.add(cap.l3(responder, querier) / UDP(sport=137, dport=137)
            / Raw(nbns_packet(tid, 0x8500, name, answer_ip=responder)), t + 0.002)
    return t + 0.01


def llmnr_exchange(cap, querier, responder, name, t):
    tid = RNG.randint(1, 65535)
    sport = RNG.randint(49152, 65000)
    q = DNS(id=tid, qd=DNSQR(qname=name, qtype="A"))
    cap.add(cap.l3(querier, "224.0.0.252") / UDP(sport=sport, dport=5355) / q, t)
    r = DNS(id=tid, qr=1, qd=DNSQR(qname=name, qtype="A"), an=DNSRR(rrname=name, type="A", ttl=30, rdata=responder))
    cap.add(cap.l3(responder, querier) / UDP(sport=5355, dport=sport) / r, t + 0.002)
    return t + 0.01


def mdns_announce(cap, responder, an, t):
    cap.add(cap.l3(responder, "224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(id=0, qr=1, aa=1, qd=[], an=an), t)
    return t + 0.01


def gen_name_poisoning(out):
    cap = Capture()
    t = T0
    # .190: Responder — LLMNR 3개 이름 + NBNS 3개 이름에 모두 자기 주소로 응답 -> 탐지
    for querier, name in (("10.0.0.201", "fileserv01"), ("10.0.0.202", "printsrv"), ("10.0.0.203", "wpad")):
        t = llmnr_exchange(cap, querier, "10.0.0.190", name, t + 1)
    for name in ("FILESHARE", "SQLDB", "BACKUPSRV"):
        t = nbns_exchange(cap, "10.0.0.204", "10.0.0.190", name, t + 1)
    # .191: mDNS 프린터 — 자기 이름 A 10회 + 서비스 PTR 10종 -> 미탐
    for i in range(10):
        t = mdns_announce(cap, "10.0.0.191", DNSRR(rrname="printer-3f.local", type="A", ttl=120, rdata="10.0.0.191"), t + 1)
        t = mdns_announce(cap, "10.0.0.191", DNSRR(rrname="_svc%02d._tcp.local" % i, type="PTR", ttl=4500,
                                                  rdata="printer-3f._svc%02d._tcp.local" % i), t + 0.5)
    # .192: 정상 LLMNR host — 5대가 물은 자기 이름(ws-192)에만 응답 -> 미탐
    for i in range(5):
        t = llmnr_exchange(cap, "10.0.0.%d" % (205 + i), "10.0.0.192", "ws-192", t + 1)
    # .193: WINS 서버(예외) — NBNS 8개 이름 응답 -> 미탐
    for i in range(8):
        t = nbns_exchange(cap, "10.0.0.204", "10.0.0.193", "HOST%02d" % i, t + 1)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "name_poisoning.pcap"))


# --------------------------------------------------------------------------- 23 DCSync

DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"


def krb_as_ok_to(cap, client, kdc, user, t):
    """임의 KDC 와의 사전인증 AS 교환(성공). DC 자동 학습용."""
    sport = RNG.randint(49152, 65000)
    cap.add(cap.l3(client, kdc) / UDP(sport=sport, dport=88) / Raw(as_req(t, user, True)), t)
    cap.add(cap.l3(kdc, client) / UDP(sport=88, dport=sport)
            / Raw(kdc_rep(0x6b, 11, user, "krbtgt/" + REALM, KRB_AES256, KRB_AES256)), t + 0.003)
    return t + 0.01


def gen_dcsync(out):
    cap = Capture()
    t = T0
    # DC 학습: 10.0.0.10, 10.0.0.11 이 Kerberos 응답
    t = krb_as_ok_to(cap, "10.0.0.220", KDC, "user01", t + 1)
    t = krb_as_ok_to(cap, "10.0.0.220", "10.0.0.11", "user02", t + 1)
    # .210: 일반 host 가 DC 에 DRSGetNCChanges (동적 포트) -> 탐지
    t = dcom_call(cap, "10.0.0.210", KDC, DRSUAPI, 3, t + 1, dport=49667)
    # 10.0.0.11: 학습된 DC 간 복제 -> 미탐
    t = dcom_call(cap, "10.0.0.11", KDC, DRSUAPI, 3, t + 1, dport=49667)
    # 10.0.0.12: 설정 목록의 DC(테스트 redef) -> 미탐
    t = dcom_call(cap, "10.0.0.12", KDC, DRSUAPI, 3, t + 1, dport=49667)
    # .211: DRSCrackNames(opnum 12) — 관리 도구의 이름 변환 -> 미탐
    t = dcom_call(cap, "10.0.0.211", KDC, DRSUAPI, 12, t + 1, dport=49667)
    # .212: Azure AD Connect(예외) DRSGetNCChanges -> 미탐
    t = dcom_call(cap, "10.0.0.212", KDC, DRSUAPI, 3, t + 1, dport=49667)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "dcsync.pcap"))


# --------------------------------------------------------------------------- 24 비표준 포트 / 장기 연결

def ssh_str(b):
    return struct.pack(">I", len(b)) + b


def ssh_pkt(payload):
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def ssh_kexinit():
    lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256",
             b"hmac-sha2-256", b"none", b"none", b"", b""]
    return ssh_pkt(bytes([20]) + rand_bytes(16) + b"".join(ssh_str(x) for x in lists) + b"\x00" + b"\x00" * 4)


def ssh_kex_session(cap, src, dst, t, dport=22):
    """버전 교환 -> KEXINIT -> ECDH(curve25519) -> NEWKEYS 까지 진행하는 SSH 세션.
    Zeek SSH 분석기는 NEWKEYS 에서 프로토콜을 확인(analyzer_confirmation)한다."""
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    t = s.server_send(b"SSH-2.0-OpenSSH_9.6\r\n", t + 0.01)
    t = s.client_send(b"SSH-2.0-OpenSSH_9.6\r\n", t + 0.01)
    t = s.client_send(ssh_kexinit(), t + 0.01)
    t = s.server_send(ssh_kexinit(), t + 0.01)
    t = s.client_send(ssh_pkt(bytes([30]) + ssh_str(rand_bytes(32))), t + 0.01)
    hostkey = ssh_str(b"ssh-ed25519") + ssh_str(rand_bytes(32))
    sig = ssh_str(b"ssh-ed25519") + ssh_str(rand_bytes(64))
    t = s.server_send(ssh_pkt(bytes([31]) + ssh_str(hostkey) + ssh_str(rand_bytes(32)) + ssh_str(sig))
                      + ssh_pkt(bytes([21])), t + 0.01)
    t = s.client_send(ssh_pkt(bytes([21])) + rand_bytes(96), t + 0.01)
    t = s.server_send(rand_bytes(160), t + 0.02)
    return s.close(t + 0.1)


def long_session(cap, src, dst, dport, t, minutes):
    """minutes 분 동안 60초마다 양방향 소량 데이터(keepalive)가 오가는 TCP 연결."""
    s = Tcp(cap, src, dst, dport)
    t = s.handshake(t)
    for _ in range(minutes):
        t = s.client_send(rand_bytes(64), t + 60)
        t = s.server_send(rand_bytes(48), t + 0.05)
    return s.close(t + 1)


def gen_nonstd_port(out):
    cap = Capture()
    t = T0
    # 비표준 포트: HTTP 8081(.230), TLS 4444(.230), SSH 2222(.230) -> 각각 탐지
    t = http_get(cap, "10.0.0.230", "93.184.215.80", "update.example.net", t + 1, dport=8081)
    t = tls_session(cap, "10.0.0.230", "93.184.215.81", t + 1, sni="cdn.example.net", dport=4444)
    t = ssh_kex_session(cap, "10.0.0.230", "93.184.215.82", t + 1, dport=2222)
    # .231: 표준 포트 HTTP 80 / TLS 443 / SSH 22 -> 미탐
    t = http_get(cap, "10.0.0.231", "93.184.215.83", "www.example.net", t + 1)
    t = tls_session(cap, "10.0.0.231", "93.184.215.83", t + 1, sni="www.example.net")
    t = ssh_kex_session(cap, "10.0.0.231", "93.184.215.83", t + 1)
    # .235: 내부 서버의 HTTP 8081 -> 미탐 / .236: 허용한 외부 서비스 HTTP 8081 -> 미탐
    t = http_get(cap, "10.0.0.235", "10.0.30.5", "intranet.example", t + 1, dport=8081)
    t = http_get(cap, "10.0.0.236", "93.184.215.84", "partner.example", t + 1, dport=8081)
    # 장기 연결(테스트 기준 10분): .232 외부 12분 -> 탐지, .233 외부 5분 -> 미탐, .234 내부 12분 -> 미탐
    long_session(cap, "10.0.0.232", "93.184.215.85", 443, t + 1, 12)
    long_session(cap, "10.0.0.233", "93.184.215.86", 443, t + 2, 5)
    t = long_session(cap, "10.0.0.234", "10.0.30.6", 443, t + 3, 12)
    cap.tick(t + 60)
    cap.write(os.path.join(out, "nonstd_port.pcap"))


# --------------------------------------------------------------------------- 상관: 5단계 체인(정찰 -> DGA -> C2 -> 확산 -> 유출)

def gen_chain_full(out):
    """실제 룰을 끝까지 돌려 kill-chain 5단계를 만든다(T = pcap 시작 기준 초).

    A(.240): 포트 스캔(T1, Port_Scan 즉시) -> DGA NXDOMAIN 60건(T20~140, 10분 창 끝 T~601 DGA_Domain)
             -> HTTP 비커닝(T420 시작, 12번째 콜백 T~750 HTTP_Beaconing)
             -> .241/.242 ADMIN$ 접근(T800, 1분 창 끝 T~841 SMB_Admin_Share, 피해 host 2대)
    피해 .241(T900)/.242(T950) 외부 60MB 업로드 -> Exfil_Large_Transfer(10) + Exfil_Volume_Aggregate(14)
                                   -> 5단계 체인 4갈래(피해 host 2 x 유출 룰 2)
    비교군: B(.245) 비커닝 후 스캔(순서 반대), C(.246) 스캔 후 1시간 넘어 비커닝(창 초과),
            D(.247) 확산 없이 업로드만 -> 상관 없음
    """
    mb = 1024 * 1024
    cap = Capture()
    a, b, c, d = "10.0.0.240", "10.0.0.245", "10.0.0.246", "10.0.0.247"
    v1, v2 = "10.0.0.241", "10.0.0.242"
    port_scan(cap, a, "10.0.0.9", range(2000, 2030), T0 + 1)
    port_scan(cap, c, "10.0.0.9", range(3000, 3030), T0 + 5)
    for i in range(60):
        dns_exchange(cap, a, rand_label(30) + ".com", 3, T0 + 20 + i * 2)
    beacon(cap, b, "93.184.215.91", "cdn.chain-b.net", T0 + 30, [30] * 13)
    beacon(cap, a, "93.184.215.90", "update.chain-a.net", T0 + 420, [30] * 13)
    smb_tree_connect(cap, a, v1, "ADMIN$", T0 + 800)
    smb_tree_connect(cap, a, v2, "C$", T0 + 802)
    port_scan(cap, b, "10.0.0.9", range(4000, 4030), T0 + 900)
    bulk_upload(cap, v1, "93.184.215.92", 443, 60 * mb, T0 + 900)
    bulk_upload(cap, v2, "93.184.215.93", 443, 60 * mb, T0 + 950)
    bulk_upload(cap, d, "93.184.215.94", 443, 60 * mb, T0 + 1000)
    beacon(cap, c, "93.184.215.95", "cdn.chain-c.net", T0 + 3700, [30] * 13)
    cap.tick(T0 + 4200)
    cap.write(os.path.join(out, "chain_full.pcap"))


# --------------------------------------------------------------------------- 상관: 8단계 체인(정찰 -> C2 -> 자격증명 -> 도메인 장악 -> 확산 -> 유출 -> 영향)

def gen_chain_ext(out):
    """단계 묶음 전이로 kill-chain 8단계를 만든다(T = pcap 시작 기준 초, 실제 룰로 끝까지).

    A(.250): 포트 스캔(T1) -> DGA NXDOMAIN 60건(T20~140, ~T601 DGA_Domain)
             -> HTTP 비커닝(T420~, ~T750) -> Kerberoasting RC4 SPN 6개(T800)
             -> DCSync(T850, 동적 포트 DRSUAPI) -> WinRM .251/.252/.253(T910, 5분 창 끝 ~T1201)
    피해 .251: 외부 60MB 업로드(T1250, 10·14) -> 파일 서버 40개 .lockd 이름 변경(T1300, 21)
    비교군: .254 Kerberoasting 만, .255 랜섬웨어 SMB 만 -> 상관 없음
    """
    mb = 1024 * 1024
    cap = Capture()
    a, v1, v2, v3 = "10.0.0.250", "10.0.0.251", "10.0.0.252", "10.0.0.253"
    spns = ["MSSQLSvc/sql%02d.corp.example:1433" % i for i in range(1, 7)]
    port_scan(cap, a, "10.0.0.9", range(5000, 5030), T0 + 1)
    for i in range(60):
        dns_exchange(cap, a, rand_label(30) + ".com", 3, T0 + 20 + i * 2)
    t = T0 + 100
    for spn in spns:                                          # 비교군 .254: Kerberoasting 만
        t = krb_service_ticket(cap, "10.0.0.254", "user09", spn, KRB_RC4, t + 1)
    s = Smb2Session(cap, "10.0.0.255", FILE_SERVER, "data", T0 + 200)   # 비교군 .255: 랜섬웨어 만
    for i in range(40):
        name = "hr\\pay_%02d.xlsx" % i
        s.rename(s.create(name), name + ".enc")
    s.close()
    beacon(cap, a, "93.184.215.96", "update.chain-x.net", T0 + 420, [30] * 13)
    t = T0 + 800
    for spn in spns:
        t = krb_service_ticket(cap, a, "user01", spn, KRB_RC4, t + 1)
    dcom_call(cap, a, KDC, DRSUAPI, 3, T0 + 850, dport=49667)
    for i, v in enumerate((v1, v2, v3)):
        winrm_session(cap, a, v, T0 + 910 + 2 * i)
    bulk_upload(cap, v1, "93.184.215.97", 443, 60 * mb, T0 + 1250)
    s = Smb2Session(cap, v1, FILE_SERVER, "data", T0 + 1300)
    for i in range(40):
        name = "finance\\q%02d.docx" % i
        s.rename(s.create(name), name + ".lockd")
    s.close()
    cap.tick(T0 + 1500)
    cap.write(os.path.join(out, "chain_ext.pcap"))



# --------------------------------------------------------------------------- 메타데이터 선별 전송(T1)

def gen_meta_export(out):
    """선별 전송 대상 프로토콜과 범위·중복 억제·분당 상한 검증용 트래픽.
    .60 클라이언트: Kerberos 로그온 성공 1, RC4 서비스 티켓 1 / NTLM 로그온 성공 1·실패 1
                    SMB 같은 공유 2번 연결(중복 억제) + 파일 이름 변경 1·열기만 1
                    RPC drsuapi 1, ISystemActivator 같은 호출 2번(중복 억제), IOXIDResolver 1(인터페이스 제외)
                    RDP 1, SSH 1
    범위(conn): .61 -> 외부 443(경계), .61 -> 내부 445(관리 포트), .61 -> 내부 8080(제외),
                외부 -> 내부 22(경계)
    분당 상한(conn): .62 -> 외부 443 연결 30개(1분 안)
    """
    cap = Capture()
    c, srv = "10.0.0.60", "10.0.30.5"
    t = T0 + 1
    t = krb_logon_ok(cap, c, "user01", t)
    t = krb_service_ticket(cap, c, "user01", "MSSQLSvc/db01.corp.example:1433", KRB_RC4, t + 1)
    t = ntlm_smb_login(cap, c, srv, "CORP", "user01", True, t + 1)
    t = ntlm_smb_login(cap, c, srv, "CORP", "user02", False, t + 1)
    s = Smb2Session(cap, c, srv, "share", t + 1)
    s.rename(s.create("docs\\a.txt"), "docs\\b.txt")
    s.create("docs\\c.txt")
    t = s.close()
    s = Smb2Session(cap, c, srv, "share", t + 1)
    t = s.close()
    t = dcom_call(cap, c, KDC, DRSUAPI, 3, t + 1, dport=49667)
    t = dcom_call(cap, c, srv, ISYSTEMACTIVATOR, 4, t + 1)
    t = dcom_call(cap, c, srv, ISYSTEMACTIVATOR, 4, t + 1)
    t = dcom_call(cap, c, srv, IOXID_RESOLVER, 5, t + 1)
    t = rdp_connect(cap, c, srv, "administrator", t + 1)
    t = ssh_session(cap, c, srv, t + 1)
    t = tcp_established(cap, "10.0.0.61", "93.184.215.120", 443, t + 1)
    t = tcp_established(cap, "10.0.0.61", srv, 445, t + 1)
    t = tcp_established(cap, "10.0.0.61", srv, 8080, t + 1)
    t = tcp_established(cap, "93.184.215.121", "10.0.0.61", 22, t + 1)
    t = T0 + 125                                    # 새 분 구간에서 시작
    for i in range(30):
        t = tcp_established(cap, "10.0.0.62", "93.184.215.122", 443, t + 1)
    cap.tick(t + 10)                                # 연결 종료 타이머가 같은 분 안에 돌도록
    cap.tick(T0 + 300)
    cap.write(os.path.join(out, "meta_export.pcap"))


def gen_meta_summary(out):
    """선별 전송 2차(ssl·http 행 선별, conn·dns 요약) 검증용.
    DNS: .70 같은 질의 5번(요약 1행) + 다른 질의 1, 역방향 조회·예외 도메인(제외), 리졸버 .54 의 질의(제외)
    HTTP: .71 -> 외부 쿼리 문자열 있는 GET 2번(중복 억제 1행, 쿼리 제거), 예외 호스트·내부 서버(제외)
    TLS: .72 -> 외부 SNI 2번(중복 억제 1행), 예외 SNI·내부 서버(제외)
    conn: .73 -> 외부 443 3번(요약 1행 conns=3), 내부 445 2번(관리 포트, 요약 1행), 내부 8080(제외)
    """
    cap = Capture()
    t = T0 + 1
    for i in range(5):
        dns_exchange(cap, "10.0.0.70", "www.example-news.com", 0, t + i, answer="93.184.215.130")
    dns_exchange(cap, "10.0.0.70", "mail.partner.example", 3, t + 6)
    dns_exchange(cap, "10.0.0.70", "5.0.0.10.in-addr.arpa", 3, t + 7)
    dns_exchange(cap, "10.0.0.70", "telemetry.vendor.example", 0, t + 8, answer="93.184.215.139")
    dns_exchange(cap, "10.0.0.54", "www.example-news.com", 0, t + 9, answer="93.184.215.130")
    t = T0 + 20
    for i in range(2):
        t = http_req(cap, "10.0.0.71", "93.184.215.131", "GET", "/download/file.zip?token=SECRET123", t + 1,
                     host="files.example-cdn.net")
    t = http_req(cap, "10.0.0.71", "93.184.215.134", "GET", "/update.bin?id=1", t + 1, host="update.vendor.example")
    t = http_req(cap, "10.0.0.71", "10.0.30.5", "GET", "/intranet?q=1", t + 1)
    for i in range(2):
        t = tls_session(cap, "10.0.0.72", "93.184.215.132", t + 1, sni="api.example-saas.com")
    t = tls_session(cap, "10.0.0.72", "93.184.215.135", t + 1, sni="cdn.vendor.example")
    t = tls_session(cap, "10.0.0.72", "10.0.30.6", t + 1, sni="portal.corp.example")
    for i in range(3):
        t = tcp_established(cap, "10.0.0.73", "93.184.215.133", 443, t + 1)
    for i in range(2):
        t = tcp_established(cap, "10.0.0.73", "10.0.30.5", 445, t + 1)
    t = tcp_established(cap, "10.0.0.73", "10.0.30.5", 8080, t + 1)
    cap.tick(T0 + 300)
    cap.write(os.path.join(out, "meta_summary.pcap"))


def gen_meta_dedup(out):
    """중복 억제 기간 검증용: .80 -> 외부 같은 SNI TLS 를 T+1, T+60, T+3700(1시간 지난 뒤) 세 번."""
    cap = Capture()
    for dt in (1, 60, 3700):
        tls_session(cap, "10.0.0.80", "93.184.215.140", T0 + dt, sni="app.example-saas.com")
    cap.tick(T0 + 3800)
    cap.write(os.path.join(out, "meta_dedup.pcap"))


def gen_meta_dns_qtypes(out):
    """dns_summary 가 (출발지, 등록 도메인) 하나로 질의 유형·결과를 묶는지: .90 이 같은 도메인에 A·AAAA(성공), 다른 이름 A(NXDOMAIN)."""
    cap = Capture()
    c, t = "10.0.0.90", T0 + 1
    for qname, qtype, rcode, ans in (("www.example-mixed.com", "A", 0, "93.184.215.150"),
                                     ("www.example-mixed.com", "AAAA", 0, "2001:db8::150"),
                                     ("api.example-mixed.com", "A", 3, None)):
        qid, sport = RNG.randint(1, 65535), RNG.randint(20000, 60000)
        cap.add(cap.l3(c, DNS_SERVER) / UDP(sport=sport, dport=53)
                / DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype)), t)
        an = DNSRR(rrname=qname, type=qtype, ttl=60, rdata=ans) if ans else None
        cap.add(cap.l3(DNS_SERVER, c) / UDP(sport=53, dport=sport)
                / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an), t + 0.002)
        t += 1
    cap.tick(T0 + 60)
    cap.write(os.path.join(out, "meta_dns_qtypes.pcap"))

GENERATORS = [gen_port_scan, gen_host_scan, gen_smb, gen_rdp, gen_ssh, gen_beacon,
              gen_tls_c2, gen_exfil, gen_volume, gen_dga, gen_chain, gen_dns_tunnel, gen_web_attack,
              gen_ntlm_spray, gen_kerberos, gen_outbound_smb,
              gen_winrm_dcom, gen_smb_ransomware,
              gen_name_poisoning, gen_dcsync,
              gen_nonstd_port, gen_chain_full,
              gen_chain_ext, gen_meta_export, gen_meta_summary, gen_meta_dedup,
              gen_meta_dns_qtypes]


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
