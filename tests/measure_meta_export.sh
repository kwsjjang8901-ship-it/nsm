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
#         off 대비 on 의 처리 시간 증가율(반복 중 최솟값 기준).
#   운영 판단에는 운영 미러 구간 pcap(1시간 이상, DC 구간 포함)을 쓴다.
set -euo pipefail

if [ $# -lt 1 ]; then
    sed -n '2,13p' "$0"
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
