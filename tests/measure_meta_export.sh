#!/usr/bin/env bash
# 메타데이터 선별 전송(T1) 측정 — docs/METADATA_EXPORT_PLAN.md 4장 "측정 방법"
#
#   사용: tests/measure_meta_export.sh <pcap> [반복 횟수=3]
#
#   같은 pcap 을 세 가지로 실행해 비교한다.
#     full : nsm_rules 없이 Zeek 기본 스크립트 + JSON 로그 전체(= "Zeek 전체 로그")
#     off  : nsm_rules, 선별 전송 끔(현재 운영 형상)
#     on   : nsm_rules, 선별 전송 켬
#   출력: 선별 전송 로그(meta/*.log)의 스트림별 바이트·행 수, 전체 로그 대비 비율,
#         off 대비 on 의 처리 시간 증가율(반복 중 최솟값 기준),
#         python3 가 있으면 조정 근거(로그별 필드 비중, 요약 로그의 키 분포). 주소·도메인 원문은 출력하지 않는다.
#   KEEP_DIR=<디렉터리> 를 주면 on 실행의 선별 로그를 그 디렉터리에 복사해 남긴다.
#   pcap 과 TMPDIR 은 로컬 디스크에 둔다(공유 폴더는 처리 시간이 흔들린다).
#   운영 판단에는 운영 미러 구간 pcap(1시간 이상, DC 구간 포함)을 쓴다.
set -euo pipefail

if [ $# -lt 1 ]; then
    sed -n '2,16p' "$0"
    exit 2
fi

PCAP=$(realpath "$1")
RUNS=${2:-3}
PKG=$(realpath "$(dirname "$0")/../nsm_rules")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

LOCAL='redef NSM::log_paths = {}; redef NSM::create_log_dirs = F; redef Log::default_rotation_interval = 0secs;'

# run <이름> <zeek 인자...> : 반복 실행해 최소 경과 시간(초)을 출력하고 마지막 실행의 로그를 남긴다
run() {
    local name=$1; shift
    local dir="$WORK/$name" best="" i s e d
    for i in $(seq "$RUNS"); do
        rm -rf "$dir"; mkdir -p "$dir/meta"
        s=$(date +%s.%N)
        ( cd "$dir" && zeek -C -r "$PCAP" "$@" > /dev/null 2> stderr.txt )
        e=$(date +%s.%N)
        d=$(awk -v s="$s" -v e="$e" 'BEGIN {printf "%.3f", e - s}')
        if [ -z "$best" ] || awk -v d="$d" -v b="$best" 'BEGIN {exit !(d < b)}'; then best=$d; fi
    done
    echo "$best"
}

bytes() { find "$@" -maxdepth 1 -name '*.log' -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}'; }

t_full=$(run full policy/tuning/json-logs)
t_off=$(run off "$PKG" -e "$LOCAL redef NSM::meta_export_enable = F;")
t_on=$(run on "$PKG" -e "$LOCAL redef NSM::meta_export_enable = T; redef NSM::meta_path_prefix = \"meta/\";")

full=$(bytes "$WORK/full")
meta=$(bytes "$WORK/on/meta")

echo "pcap: $PCAP (반복 $RUNS회, 처리 시간은 최솟값)"
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
awk -v a="$t_off" -v b="$t_on" -v c="$t_full" 'BEGIN {
    printf "처리 시간  full %.3fs  off %.3fs  on %.3fs  (on/off 증가 %.1f%%)\n", c, a, b, (a > 0 ? 100.0 * (b - a) / a : 0)
}'
if grep -qiE "error|fatal" "$WORK"/*/stderr.txt; then
    echo
    echo "경고: Zeek 오류 출력이 있습니다."
    grep -iE "error|fatal" "$WORK"/*/stderr.txt | head -5
fi

# 조정 근거: 로그별 필드 비중, 요약 로그의 키 분포(숫자만)
if command -v python3 > /dev/null 2>&1; then
    echo
    python3 - "$WORK/on/meta" <<'PY'
import collections, ipaddress, json, os, sys
d = sys.argv[1]
J = lambda v: len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode())
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
print("조정 근거(로그별 필드 비중 상위 4)")
sizes = {f[:-4]: os.path.getsize(os.path.join(d, f)) for f in os.listdir(d) if f.endswith(".log")}
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
PY
fi

if [ -n "${KEEP_DIR:-}" ]; then
    mkdir -p "$KEEP_DIR"
    cp "$WORK"/on/meta/*.log "$KEEP_DIR"/ 2> /dev/null || true
    echo
    echo "선별 로그를 $KEEP_DIR 에 남겼습니다."
fi
