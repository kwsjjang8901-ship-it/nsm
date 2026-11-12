#!/usr/bin/env bash
# 메타데이터 선별 전송(T1) 측정 — docs/METADATA_EXPORT_PLAN.md 4장 "측정 방법"
#
#   사용: tests/measure_meta_export.sh <pcap> [반복 횟수=3]
#
#   같은 pcap 을 세 가지로 실행해 비교한다.
#     full : nsm_rules 없이 Zeek 기본 스크립트 + JSON 로그 전체(= "Zeek 전체 로그")
#     off  : nsm_rules, 선별 전송 끔(현재 운영 형상)
#     on   : nsm_rules, 선별 전송 켬
#   처리 시간: 회차마다 세 구성을 번갈아(홀수 회차 off→on→full, 짝수 회차 on→off→full) 실행해
#         VM 부하 변화가 한 구성에만 몰리지 않게 한다. 같은 회차의 off·on 쌍으로 증가율을 구해
#         중앙값과 범위를 보고한다(반복이 많을수록 믿을 만하다. 5회 이상 권장).
#   출력: 선별 전송 로그(meta/*.log)의 스트림별 바이트·행 수, 전체 로그 대비 비율, 압축 후 크기,
#         python3 가 있으면 조정 근거(로그별 필드 비중, 요약 로그의 키 분포)와
#         조정 후보 추정(③ HTTP 묶기 두 안, ⑩ DNS 표본 1개). 주소·도메인 원문은 출력하지 않는다.
#   KEEP_DIR=<디렉터리> 를 주면 on 실행의 선별 로그를 그 디렉터리에 복사해 남긴다.
#   pcap 과 TMPDIR 은 로컬 디스크에 둔다(공유 폴더는 처리 시간이 흔들린다).
#   운영 판단에는 운영 미러 구간 pcap(1시간 이상, DC 구간 포함)을 쓴다.
set -euo pipefail

if [ $# -lt 1 ]; then
    sed -n '2,20p' "$0"
    exit 2
fi

PCAP=$(realpath "$1")
RUNS=${2:-3}
PKG=$(realpath "$(dirname "$0")/../nsm_rules")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

LOCAL='redef NSM::log_paths = {}; redef NSM::create_log_dirs = F; redef Log::default_rotation_interval = 0secs;'

# run_once <구성> : 한 번 실행해 경과 시간(초)을 $WORK/times.<구성> 에 덧붙인다. 로그는 마지막 실행 것이 남는다.
run_once() {
    local name=$1 dir="$WORK/$1" s e
    rm -rf "$dir"; mkdir -p "$dir/meta"
    case $name in
        full) set -- policy/tuning/json-logs ;;
        off)  set -- "$PKG" -e "$LOCAL redef NSM::meta_export_enable = F;" ;;
        on)   set -- "$PKG" -e "$LOCAL redef NSM::meta_export_enable = T; redef NSM::meta_path_prefix = \"meta/\";" ;;
    esac
    s=$(date +%s.%N)
    ( cd "$dir" && zeek -C -r "$PCAP" "$@" > /dev/null 2> stderr.txt )
    e=$(date +%s.%N)
    awk -v s="$s" -v e="$e" 'BEGIN {printf "%.3f\n", e - s}' >> "$WORK/times.$name"
}

for i in $(seq "$RUNS"); do
    if [ $((i % 2)) -eq 1 ]; then order="off on full"; else order="on off full"; fi
    for cfg in $order; do run_once "$cfg"; done
done

bytes() { find "$@" -maxdepth 1 -name '*.log' -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'; }
stat_of() { sort -n "$WORK/times.$1" | awk '{v[NR]=$1} END {m=(NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2; printf "%.3f %.3f", v[1], m}'; }

full=$(bytes "$WORK/full")
meta=$(bytes "$WORK/on/meta")

echo "pcap: $PCAP (반복 $RUNS회, 구성을 번갈아 실행)"
echo
printf '%-22s %12s %10s\n' "선별 전송 로그" "바이트" "행"
for f in "$WORK"/on/meta/*.log; do
    [ -e "$f" ] || continue
    printf '%-22s %12d %10d\n' "$(basename "$f" .log)" "$(stat -c %s "$f")" "$(grep -c . "$f" || true)"
done
echo
awk -v f="$full" -v m="$meta" 'BEGIN {
    printf "Zeek 전체 로그(full)   %12d 바이트\n", f
    printf "선별 전송 합계(on)     %12d 바이트  (전체 대비 %.2f%%)\n", m, (f > 0 ? 100.0 * m / f : 0)
}'

# 처리 시간: 구성별 최솟값·중앙값, 같은 회차 off·on 쌍의 증가율 중앙값과 범위
read -r full_min full_med <<< "$(stat_of full)"
read -r off_min off_med <<< "$(stat_of off)"
read -r on_min on_med <<< "$(stat_of on)"
pairs=$(paste "$WORK/times.off" "$WORK/times.on" | awk '{printf "%.1f\n", ($1 > 0 ? 100.0 * ($2 - $1) / $1 : 0)}' | sort -n)
pair_med=$(echo "$pairs" | awk '{v[NR]=$1} END {m=(NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2; printf "%.1f", m}')
pair_lo=$(echo "$pairs" | head -1); pair_hi=$(echo "$pairs" | tail -1)
printf '처리 시간(최솟값/중앙값)  full %.3f/%.3fs  off %.3f/%.3fs  on %.3f/%.3fs\n' \
    "$full_min" "$full_med" "$off_min" "$off_med" "$on_min" "$on_med"
echo "on/off 증가(같은 회차 쌍)  중앙값 ${pair_med}%  범위 ${pair_lo}% ~ ${pair_hi}%  (쌍 $RUNS개)"
if awk -v lo="$pair_lo" -v hi="$pair_hi" 'BEGIN {exit !(hi - lo > 10)}'; then
    echo "  주의: 쌍별 증가율 범위가 10%p 를 넘습니다. 측정 환경이 흔들립니다(공유 폴더·다른 작업). 반복을 늘리거나 로컬 디스크에서 다시 재세요."
fi
if grep -qiE "error|fatal" "$WORK"/*/stderr.txt; then
    echo
    echo "경고: Zeek 오류 출력이 있습니다."
    grep -iE "error|fatal" "$WORK"/*/stderr.txt | head -5
fi

# zstd 명령이 있으면 함께 잰다(압축은 파일마다 따로 = 수집 에이전트가 파일 단위로 보낼 때와 같음)
zst() { local s=0 f; for f in "$@"; do [ -e "$f" ] && s=$((s + $(zstd -q -3 -c "$f" | wc -c))); done; echo "$s"; }
if command -v zstd > /dev/null 2>&1; then
    full_z=$(zst "$WORK"/full/*.log); meta_z=$(zst "$WORK"/on/meta/*.log)
    awk -v f="$full" -v fz="$full_z" -v mz="$meta_z" 'BEGIN {
        printf "압축(zstd -3)          선별 %d 바이트: 전체 원본 대비 %.2f%%, 전체 압축본 대비 %.2f%%\n", mz, 100.0*mz/f, 100.0*mz/fz
    }'
fi

if command -v python3 > /dev/null 2>&1; then
    echo
    python3 - "$WORK/on/meta" "$WORK/full" <<'PY'
import collections, gzip, ipaddress, json, os, sys
d, fulldir = sys.argv[1], sys.argv[2]
J = lambda v: len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode())
ROW = lambda r: J(r) + 1   # 한 행 바이트(줄바꿈 포함)
def rows(n):
    p = os.path.join(d, n + ".log")
    if not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
def private(a):
    try:
        return ipaddress.ip_address(a).is_private
    except ValueError:
        return False
def logs(dirpath):
    return [os.path.join(dirpath, f) for f in sorted(os.listdir(dirpath)) if f.endswith(".log")]
def gz(paths):
    return sum(len(gzip.compress(open(p, "rb").read(), 6)) for p in paths)

full = sum(os.path.getsize(p) for p in logs(fulldir))
sizes = {os.path.basename(p)[:-4]: os.path.getsize(p) for p in logs(d)}
total = sum(sizes.values())
pct = lambda b: 100.0 * b / full if full else 0.0

# 압축 후 크기(파일마다 gzip -6). 기준을 "전송 바이트(압축 후)"로 볼 때 쓴다.
full_gz, meta_gz = gz(logs(fulldir)), gz(logs(d))
if meta_gz and full_gz:
  print(f"압축(gzip -6)          선별 {meta_gz:,} 바이트: 전체 원본 대비 {pct(meta_gz):.2f}%, "
        f"전체 압축본 대비 {100.0*meta_gz/full_gz:.2f}% (압축률 {total/meta_gz:.1f}배)")
print()

print("조정 근거(로그별 필드 비중 상위 4)")
for name, sz in sorted(sizes.items(), key=lambda x: -x[1])[:6]:
    rs = rows(name)
    if not rs:
        continue
    fb = collections.Counter()
    for r in rs:
        for k, v in r.items():
            fb[k] += J(v) + len(k) + 4
    tot = sum(fb.values()) or 1
    top = ", ".join(f"{k} {100*v/tot:.0f}%" for k, v in fb.most_common(4))
    print(f"  {name:16s} 행 {len(rs):>8,}  행당 {sz/len(rs):6.0f}B  | {top}")
fl = rows("flow_summary")
if fl:
    inner = sum(1 for r in fl if private(r["orig_h"]) and private(r["resp_h"]))
    one = sum(1 for r in fl if r.get("conns", 0) == 1)
    ports = collections.Counter(r["resp_p"] for r in fl).most_common(5)
    print(f"  flow_summary: 내부↔내부 {100*inner/len(fl):.0f}%, 연결 1개뿐인 행 {100*one/len(fl):.0f}%, "
          f"행 많은 목적지 포트 {', '.join(f'{p}({100*n/len(fl):.0f}%)' for p, n in ports)}")
dn = rows("dns_summary")
if dn:
    one = sum(1 for r in dn if r.get("queries", 0) == 1)
    other = sum(1 for r in dn if r.get("domain") == "(other)")
    srcs = collections.Counter(r["orig_h"] for r in dn)
    top = srcs.most_common(1)[0][1]
    print(f"  dns_summary: 출발지 {len(srcs):,}개, 출발지당 평균 {len(dn)/len(srcs):.1f}행(최대 {top}), "
          f"질의 1건뿐인 행 {100*one/len(dn):.0f}%, (other) 행 {other}")
ht = rows("http")
if ht:
    hosts = len({(r["id.orig_h"], r.get("host")) for r in ht})
    print(f"  http: (출발지, Host) 조합 {hosts:,}개, 조합당 평균 {len(ht)/hosts:.1f}행")
sl = rows("ssl")
if sl:
    sni = sum(1 for r in sl if not r.get("server_name"))
    print(f"  ssl: SNI 없는 행 {100*sni/len(sl):.0f}%")

# ---- 조정 후보 추정: 지금 선별 로그를 실제로 다시 묶어 계산한다 -----------------------
print()
print("조정 후보 추정(지금 선별 로그를 다시 묶어 계산)")
cur_http = sizes.get("http", 0)
if ht:
    RISKY = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".msi", ".scr", ".vbs", ".js", ".hta", ".jar", ".sh", ".elf", ".bin")
    risky = lambda r: r.get("method") in ("POST", "PUT") or str(r.get("uri_path", "")).lower().endswith(RISKY)
    key = lambda r: (r["id.orig_h"], r.get("host"), r.get("method"), r.get("status_code"), int(r["ts"] // 600))
    groups = collections.OrderedDict()
    for r in ht:
        groups.setdefault(key(r), []).append(r)
    posts = sum(1 for r in ht if r.get("method") in ("POST", "PUT"))
    execs = sum(1 for r in ht if str(r.get("uri_path", "")).lower().endswith(RISKY))
    # 단순안: (출발지, Host, 메서드, 상태, 10분) 첫 요청만
    simple = sum(ROW(g[0]) for g in groups.values())
    # 절충안: 위험 요청(POST·PUT·실행 파일)은 행 그대로, 나머지는 묶음 요약 1행
    comp = 0
    for g in groups.values():
        keep = [r for r in g if risky(r)]
        rest = [r for r in g if not risky(r)]
        comp += sum(ROW(r) for r in keep)
        if rest:
            paths = list(dict.fromkeys(str(r.get("uri_path", "")) for r in rest))
            s = {"ts": rest[0]["ts"], "ts_end": rest[-1]["ts"], "id.orig_h": rest[0]["id.orig_h"],
                 "host": rest[0].get("host"), "method": rest[0].get("method"),
                 "status_code": rest[0].get("status_code"), "requests": len(rest),
                 "unique_paths": len(paths), "sample_paths": paths[:3],
                 "request_body_len": sum(r.get("request_body_len", 0) or 0 for r in rest),
                 "response_body_len": sum(r.get("response_body_len", 0) or 0 for r in rest)}
            comp += ROW(s)
    print(f"  ③ http: 행 {len(ht):,}, 10분 묶음 {len(groups):,}, POST·PUT {posts:,}, 실행 파일 경로 {execs:,}")
    print(f"     단순안(묶음 첫 요청만)    http {cur_http:,} -> {simple:,} B, 합계 {pct(total):.2f}% -> {pct(total - cur_http + simple):.2f}%")
    print(f"     절충안(요약 + 위험 요청)  http {cur_http:,} -> {comp:,} B, 합계 {pct(total):.2f}% -> {pct(total - cur_http + comp):.2f}%")
else:
    simple = comp = cur_http
cur_dns = sizes.get("dns_summary", 0)
if dn:
    one = 0
    for r in dn:
        t = dict(r)
        for f in ("sample_names", "answers"):
            if isinstance(t.get(f), list):
                t[f] = t[f][:1]
        one += ROW(t)
    print(f"  ⑩ dns_summary 표본 3개 -> 1개  dns {cur_dns:,} -> {one:,} B, 합계 {pct(total):.2f}% -> {pct(total - cur_dns + one):.2f}%")
    if ht:
        print(f"  ③ 절충안 + ⑩ 함께            합계 {pct(total):.2f}% -> {pct(total - cur_http + comp - cur_dns + one):.2f}%")
PY
fi

if [ -n "${KEEP_DIR:-}" ]; then
    mkdir -p "$KEEP_DIR"
    cp "$WORK"/on/meta/*.log "$KEEP_DIR"/ 2> /dev/null || true
    echo
    echo "선별 로그를 $KEEP_DIR 에 남겼습니다."
fi
