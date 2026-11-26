#!/usr/bin/env python3
"""센서 처리 성능 측정(docs/SENSOR_SIZING_GUIDE.md 2·3장) — 코어 하나가 감당하는 트래픽과 메모리.

    사용: tests/measure_perf.py [-n 반복=3] [-p 구성,...] [-l 내부 대역] [-z "zeek 인자"] [-o 결과.json] <pcap> ...

같은 pcap 을 구성마다 오프라인(zeek -r)으로 돌려 CPU 시간(user+sys)과 최대 메모리(RSS)를 잰다.
    full    nsm_rules 없이 Zeek 기본 스크립트 + JSON 로그 전체(일반 Zeek 센서와 비교하는 기준점)
    detect  nsm_rules 탐지만(선별 전송 끔, 자산 식별 끔)
    asset   탐지 + 자산 식별(선별 전송 끔). detect→asset 이 자산 식별, asset→ops 가 선별 전송의 몫
    ops     운영 형상(탐지 + 예외 엔진 + 자산 식별 + 선별 전송, tests/run_pcap.sh 와 같은 설정)
회차마다 구성 순서를 번갈아 실행하고 중앙값을 쓴다. 결과:
    시작 비용     = 패킷 없는 pcap 으로 잰 CPU 시간·RSS(스크립트 읽기·초기화). 처리량 계산에서 뺀다
    코어당 처리량 = pcap 의 패킷·바이트(회선 길이) / (CPU 시간 - 시작 비용)  (pps, Mbps)
    실시간 배수   = pcap 이 담은 시간 / (CPU 시간 - 시작 비용) (1보다 커야 코어 하나로 실시간 처리 가능)
    메모리        = Zeek 프로세스 최대 RSS(시작 직후 RSS 와 함께)
오프라인 측정이라 패킷 수집(AF_PACKET) 비용은 빠진다. 운영 코어 수는 가이드 4장의 여유율을 곱해 정한다.
로컬 zeek(8.x 이상)가 없으면 Docker(ZEEK_IMAGE, 기본 zeek/zeek:9.0.1)로 실행한다.
화면에는 주소·도메인 원문을 출력하지 않는다(파일 이름·수치만).
"""
import argparse
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "nsm_rules")
PROFILES = ("full", "detect", "asset", "ops")
LOCAL = ("redef NSM::log_paths = {}; redef NSM::create_log_dirs = F; "
         "redef Log::default_rotation_interval = 0secs; redef NSM::meta_path_prefix = \"meta/\";")

# 컨테이너·로컬 공통: zeek 를 자식 프로세스로 돌리고 자식의 CPU 시간·최대 RSS 를 JSON 한 줄로 낸다
WRAP = r"""
import json, os, resource, subprocess, sys, time
os.chdir(sys.argv[1])
t = time.time()
with open("stderr.txt", "w") as err:
    rc = subprocess.call(sys.argv[2:], stdout=subprocess.DEVNULL, stderr=err)
r = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"rc": rc, "wall": time.time() - t, "user": r.ru_utime, "sys": r.ru_stime, "rss_kb": r.ru_maxrss}))
"""


def pcap_stats(path):
    """패킷 수, 회선 바이트(orig_len), 처음·마지막 시각. pcap(마이크로·나노초)·pcapng(EPB·SPB) 지원."""
    n = byts = 0
    first = last = None
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
            f.read(20)
            while True:
                h = f.read(16)
                if len(h) < 16:
                    break
                s, frac, incl, orig = struct.unpack(e + "IIII", h)
                f.seek(incl, 1)
                ts = s + frac / div
                first = ts if first is None else first
                last = ts
                n += 1
                byts += orig
        elif magic == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            e, res = "<", {}
            while True:
                h = f.read(8)
                if len(h) < 8:
                    break
                btype, blen = struct.unpack(e + "II", h)
                if btype == 0x0A0D0D0A:
                    bom = f.read(4)
                    e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                    blen = struct.unpack(e + "I", h[4:])[0]
                    f.seek(blen - 12, 1)
                    res = {}
                    continue
                body = f.read(blen - 8)
                if btype == 1:      # IDB: if_tsresol 옵션(9)
                    iface, i = len(res), 8
                    div = 1e6
                    while i + 4 <= len(body) - 4:
                        code, ln = struct.unpack(e + "HH", body[i:i + 4])
                        if code == 0:
                            break
                        if code == 9:
                            v = body[i + 4]
                            div = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                        i += 4 + ((ln + 3) & ~3)
                    res[iface] = div
                elif btype == 6:    # EPB
                    iface, hi, lo, cap, orig = struct.unpack(e + "IIIII", body[:20])
                    ts = ((hi << 32) | lo) / res.get(iface, 1e6)
                    first = ts if first is None else first
                    last = ts
                    n += 1
                    byts += orig
                elif btype == 3:    # SPB
                    n += 1
                    byts += struct.unpack(e + "I", body[:4])[0]
        else:
            sys.exit(f"pcap 형식을 모릅니다: {path}")
    return {"packets": n, "bytes": byts, "duration": (last - first) if first is not None else 0.0}


def zeek_runner(image):
    """('local', None) 또는 ('docker', image). 로컬 zeek 8.x 이상이면 로컬."""
    if shutil.which("zeek"):
        m = re.search(r"(\d+)\.", subprocess.run(["zeek", "--version"], capture_output=True, text=True).stdout)
        if m and int(m.group(1)) >= 8:
            return "local", None
    if not shutil.which("docker"):
        sys.exit("zeek 8.x 이상 또는 docker 가 필요합니다.")
    return "docker", image


def noasset():
    # 자산 식별 끄기: config.zeek 의 신호 소스별 option(enable_*)을 모두 F 로(measure_meta_export.sh 와 같은 방식)
    src = open(os.path.join(PKG, "asset-id", "config.zeek"), encoding="utf-8").read()
    return " ".join(f"redef AssetID::{n} = F;" for n in re.findall(r"^\s*option\s+(enable_[a-z0-9_]+)\s*=", src, re.M))


def profile_args(name, pkg, extra_e):
    if name == "full":
        return ["policy/tuning/json-logs"] + (["-e", extra_e] if extra_e else [])
    e = LOCAL + " " + extra_e
    if name == "detect":
        return [pkg, "-e", e + " redef NSM::meta_export_enable = F; " + noasset()]
    if name == "asset":
        return [pkg, "-e", e + " redef NSM::meta_export_enable = F;"]
    return [pkg, "-e", e + " redef NSM::meta_export_enable = T;"]


def run_once(runner, pcap, name, work, extra_e, zargs):
    d = os.path.join(work, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "meta"))
    if runner[0] == "local":
        cmd = [sys.executable, "-c", WRAP, d, "zeek", "-C", "-r", pcap] + profile_args(name, PKG, extra_e) + zargs
    else:
        cmd = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "-v", f"{PKG}:/pkg/nsm_rules:ro", "-v", f"{os.path.dirname(pcap)}:/pcap:ro", "-v", f"{d}:/out",
               runner[1], "python3", "-c", WRAP, "/out", "zeek", "-C", "-r", "/pcap/" + os.path.basename(pcap)] \
            + profile_args(name, "/pkg/nsm_rules", extra_e) + zargs
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        r = json.loads(p.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        sys.exit(f"실행 실패({name}): {p.stderr.strip()[-500:]}")
    err = open(os.path.join(d, "stderr.txt"), encoding="utf-8", errors="replace").read()
    if r["rc"] != 0 or re.search(r"\b(error|fatal)\b", err, re.I):
        sys.exit(f"Zeek 오류({name}, 종료 코드 {r['rc']}): {err.strip()[-500:]}")
    logs = [os.path.join(dp, f) for dp, _, fs in os.walk(d) for f in fs if f.endswith(".log")]
    r["log_bytes"] = sum(os.path.getsize(x) for x in logs)
    return r


def human(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024 or u == "GB":
            return f"{b:.1f}{u}" if u != "B" else f"{b}B"
        b /= 1024.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("-n", "--runs", type=int, default=3)
    ap.add_argument("-p", "--profiles", default=",".join(PROFILES))
    ap.add_argument("-l", "--local-nets", default="", help="내부 대역(쉼표 구분). Site::local_nets 에 더한다")
    ap.add_argument("-z", "--zeek-args", default="", help="zeek 에 넘길 추가 인자")
    ap.add_argument("-o", "--json", help="결과를 JSON 으로 저장")
    a = ap.parse_args()
    profiles = [x for x in a.profiles.split(",") if x]
    for x in profiles:
        if x not in PROFILES:
            sys.exit(f"구성 이름: {', '.join(PROFILES)}")
    extra_e = f"redef Site::local_nets += {{ {', '.join(a.local_nets.split(','))} }};" if a.local_nets else ""
    runner = zeek_runner(os.environ.get("ZEEK_IMAGE", "zeek/zeek:9.0.1"))
    cpu = subprocess.run(["sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"], capture_output=True, text=True).stdout.strip()
    print(f"실행: {'로컬 zeek' if runner[0] == 'local' else 'Docker ' + runner[1]}, CPU {cpu or '(모름)'}, 반복 {a.runs}회")
    results = []
    for pcap in a.pcaps:
        pcap = os.path.realpath(pcap)
        st = pcap_stats(pcap)
        print(f"\n{os.path.basename(pcap)}: 패킷 {st['packets']:,}, 회선 {human(st['bytes'])}, 담은 시간 {st['duration']:.0f}초"
              f" (평균 {st['bytes'] * 8 / max(st['duration'], 1e-9) / 1e6:.1f}Mbps)")
        work = tempfile.mkdtemp(prefix="perf-")
        runs = {p: [] for p in profiles}
        try:
            empty = os.path.join(work, "pcap0", "empty.pcap")
            os.makedirs(os.path.dirname(empty))
            with open(empty, "wb") as f:
                f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            start = {p: run_once(runner, empty, p, work, extra_e, a.zeek_args.split()) for p in profiles}
            for i in range(a.runs):
                order = profiles if i % 2 == 0 else list(reversed(profiles))
                for p in order:
                    runs[p].append(run_once(runner, pcap, p, work, extra_e, a.zeek_args.split()))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        print(f"  {'구성':8s} {'CPU초':>8s} {'범위':>13s} {'시작':>6s} {'pps/코어':>11s} {'Mbps/코어':>10s} {'실시간배수':>9s} {'시작RSS':>8s} {'최대RSS':>8s} {'로그':>9s}")
        base = None
        for p in profiles:
            cs = [r["user"] + r["sys"] for r in runs[p]]
            c = statistics.median(cs)
            c0 = start[p]["user"] + start[p]["sys"]
            net = max(c - c0, 1e-3)
            rss = statistics.median(r["rss_kb"] for r in runs[p]) / 1024
            rss0 = start[p]["rss_kb"] / 1024
            row = {"pcap": os.path.basename(pcap), "profile": p, **st, "cpu_s": c, "cpu_min": min(cs), "cpu_max": max(cs),
                   "start_cpu_s": c0, "net_cpu_s": net, "pps_core": st["packets"] / net, "mbps_core": st["bytes"] * 8 / net / 1e6,
                   "realtime_x": st["duration"] / net if st["duration"] else None, "start_rss_mb": rss0, "rss_mb": rss,
                   "log_bytes": runs[p][-1]["log_bytes"]}
            results.append(row)
            rt = f"{row['realtime_x']:.1f}" if row["realtime_x"] else "-"
            print(f"  {p:8s} {c:8.2f} {min(cs):6.2f}~{max(cs):6.2f} {c0:6.2f} {row['pps_core']:11,.0f} {row['mbps_core']:10.0f} {rt:>9s}"
                  f" {rss0:7.0f}M {rss:7.0f}M {human(row['log_bytes']):>9s}")
            base = base or (p, net)
        if len(profiles) > 1:
            print("  CPU 비율: " + ", ".join(f"{r['profile']} {r['net_cpu_s'] / base[1]:.2f}x" for r in results if r["pcap"] == os.path.basename(pcap))
                  + f" ({base[0]} 기준, 시작 비용 뺀 값)")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=1)
        print(f"\n결과: {a.json}")


if __name__ == "__main__":
    main()
