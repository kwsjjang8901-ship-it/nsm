#!/usr/bin/env bash
# pcap 하나를 운영과 같은 설정으로 한 번 돌려 탐지·자산 식별·메타데이터 선별 전송 결과를 한 화면에 요약한다.
#
#   사용: tests/run_pcap.sh [-o 출력 디렉터리] [-n 내부 대역] [-x 예외 파일] [-r claudtest2 경로] [-z "zeek 인자"] <pcap | 디렉터리> ...
#
#     디렉터리나 pcap 여러 개를 주면 파일마다 따로 실행한다(하위 디렉터리 포함 *.pcap·*.pcapng·*.cap).
#       결과는 DIR/<파일 이름>/ 에 파일별로 남고(하위 디렉터리 파일은 경로를 _ 로 이어 붙인 이름),
#       끝에 파일별 결과 표와 DIR/index.html(각 report.html 링크)을 만든다. 한 파일이 실패해도 나머지는 계속한다.
#     -o DIR    출력 디렉터리(기본: out/<pcap 이름>, 여러 개면 out/<디렉터리 이름> 또는 out/batch).
#               Zeek 로그는 DIR/zeek/, 선별 전송은 DIR/zeek/meta/
#     -n CIDRS  내부 대역(쉼표 구분). Site::local_nets 에 더하며 자산 식별 대상 대역도 이 값을 따른다.
#               생략하면 사설 대역. 내부에 공인 IP 를 쓰면 반드시 지정한다.
#     -x FILE   예외 파일(docs/SRS.md 7.8절). NSM::exception_file 로 넘긴다.
#     -r DIR    자산 식별 PoC(claudtest2) 경로. 주면 asset_signal.log 로 리졸버를 돌려 DIR 출력에
#               자산 리포트(report.html·report.txt·assets.csv)를 만든다(리졸버는 이 저장소에 없다).
#     -z ARGS   zeek 에 넘길 추가 인자. 예) -z "AssetID::suppress_interval=30min"
#
#   화면 요약에는 주소·도메인 원문을 출력하지 않는다(탐지 종류·건수, 신호 종류별 건수, 로그 크기만).
#   출력 디렉터리의 report.html(통합 리포트: 공격 스토리·탐지·킬체인·자산·전송량·예외·센서 상태)과 로그에는 원문이 있다. 처리 부하·전체 로그 대비 비율은 tests/measure_meta_export.sh 로 잰다.
#   로컬 zeek(8.x 이상)가 없으면 Docker(ZEEK_IMAGE, 기본 zeek/zeek:9.0.1)로 실행한다.
set -euo pipefail

usage() { sed -n '2,21p' "$0"; exit 2; }
OUT=""; NETS=""; EXC=""; RESOLVER_DIR=""; ZARGS=""; PASS=()
while getopts "o:n:x:r:z:h" opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        n) NETS=$OPTARG; PASS+=(-n "$OPTARG") ;;
        x) EXC=$OPTARG; PASS+=(-x "$(realpath "$OPTARG")") ;;
        r) RESOLVER_DIR=$OPTARG; PASS+=(-r "$(realpath "$OPTARG")") ;;
        z) ZARGS=$OPTARG; PASS+=(-z "$OPTARG") ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage

# 디렉터리 또는 여러 파일: 파일마다 이 스크립트를 다시 불러 따로 실행하고, 끝에 결과 표와 index.html 을 만든다.
if [ $# -gt 1 ] || [ -d "$1" ]; then
    if [ $# -eq 1 ]; then BASE_NAME=$(basename "$(realpath "$1")"); else BASE_NAME=batch; fi
    BASE=$(realpath -m "${OUT:-out/$BASE_NAME}")
    mkdir -p "$BASE"
    LIST=()   # "출력 이름<TAB>pcap 경로"
    for a in "$@"; do
        if [ -d "$a" ]; then
            d=$(realpath "$a")
            while IFS= read -r -d '' f; do
                rel=${f#"$d"/}; rel=${rel%.*}
                LIST+=("${rel//\//_}"$'\t'"$f")
            done < <(find "$d" -type f \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' \) -print0 | sort -z)
        elif [ -f "$a" ]; then
            n=$(basename "$a"); LIST+=("${n%.*}"$'\t'"$(realpath "$a")")
        else
            echo "건너뜀(없는 파일): $a" >&2
        fi
    done
    [ ${#LIST[@]} -gt 0 ] || { echo "pcap 파일이 없습니다: $*" >&2; exit 1; }
    dup=$(printf '%s\n' "${LIST[@]}" | cut -f1 | sort | uniq -d | head -3)
    [ -z "$dup" ] || { echo "출력 이름이 겹칩니다(파일 이름이 같음): $dup" >&2; exit 1; }

    echo "pcap ${#LIST[@]}개를 파일마다 따로 실행합니다. 결과: $BASE"
    RES=()   # "이름<TAB>상태<TAB>탐지 건수"
    i=0
    for ent in "${LIST[@]}"; do
        i=$((i + 1)); name=${ent%%$'\t'*}; f=${ent#*$'\t'}
        echo ""; echo "================ [$i/${#LIST[@]}] $name"
        mkdir -p "$BASE/$name"
        if "$0" ${PASS[@]+"${PASS[@]}"} -o "$BASE/$name" "$f" 2>&1 | tee "$BASE/$name/run.txt"; then st=ok; else st=FAIL; fi
        if [ $st = FAIL ] && [ -s "$BASE/$name/zeek/stderr.txt" ]; then
            echo "  Zeek 오류:"; tail -3 "$BASE/$name/zeek/stderr.txt" | sed 's/^/    /' | tee -a "$BASE/$name/run.txt"
        fi
        det=-; [ -f "$BASE/$name/zeek/nsm_detection.log" ] && det=$(grep -vc '^#' "$BASE/$name/zeek/nsm_detection.log" || true)
        RES+=("$name"$'\t'"$st"$'\t'"$det")
    done

    echo ""; echo "================ 결과 (${#LIST[@]}개)"
    printf '%-40s %-5s %s\n' "pcap" "상태" "탐지 건수"
    {
        echo '<!doctype html><meta charset="utf-8"><title>run_pcap 결과</title>'
        echo '<style>body{font:14px system-ui,sans-serif;margin:24px}td,th{padding:4px 12px;text-align:left;border-bottom:1px solid #ddd}.FAIL{color:#c00}</style>'
        echo "<h1>run_pcap 결과 (${#LIST[@]}개)</h1><table><tr><th>pcap</th><th>상태</th><th>탐지 건수</th><th>리포트</th><th>실행 출력</th></tr>"
    } > "$BASE/index.html"
    nfail=0
    for r in "${RES[@]}"; do
        IFS=$'\t' read -r name st det <<< "$r"
        [ "$st" = ok ] || nfail=$((nfail + 1))
        printf '%-40s %-5s %s\n' "$name" "$st" "$det"
        link=-; [ -f "$BASE/$name/report.html" ] && link="<a href=\"$name/report.html\">report.html</a>"
        echo "<tr><td>$name</td><td class=\"$st\">$st</td><td>$det</td><td>$link</td><td><a href=\"$name/run.txt\">run.txt</a></td></tr>" >> "$BASE/index.html"
    done
    echo "</table>" >> "$BASE/index.html"
    echo ""; echo "목록: $BASE/index.html"
    [ $nfail -eq 0 ] || { echo "실패 ${nfail}개(각 run.txt 참고)" >&2; exit 1; }
    exit 0
fi

ROOT=$(realpath "$(dirname "$0")/..")
PCAP=$(realpath "$1")
NAME=$(basename "$PCAP"); NAME=${NAME%.*}
OUT=$(realpath -m "${OUT:-out/$NAME}")
ZDIR="$OUT/zeek"
rm -rf "$ZDIR"; mkdir -p "$ZDIR/meta"   # create_log_dirs = F 라 선별 전송 디렉터리를 미리 만든다
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.1}"

# 운영과 같은 형상: nsm_rules 전체(탐지 + 예외 엔진 + 자산 식별 + 선별 전송 켬). 경로만 출력 디렉터리로.
{
    echo 'redef NSM::log_paths = {};'
    echo 'redef NSM::create_log_dirs = F;'
    echo 'redef Log::default_rotation_interval = 0secs;'
    echo 'redef NSM::meta_export_enable = T;'
    echo 'redef NSM::meta_path_prefix = "meta/";'
    [ -n "$NETS" ] && echo "redef Site::local_nets += { ${NETS//,/, } };"
    [ -n "$EXC" ] && echo "redef NSM::exception_file = \"exceptions.tsv\";"
} > "$ZDIR/run_local.zeek"
[ -n "$EXC" ] && cp "$EXC" "$ZDIR/exceptions.tsv"

use_docker=1
if command -v zeek > /dev/null 2>&1; then
    major=$(zeek --version 2>/dev/null | sed -E 's/.* ([0-9]+)\..*/\1/')
    [ "${major:-0}" -ge 8 ] && use_docker=0
fi

echo "[1/3] Zeek 실행: $PCAP"
start=$(date +%s)
# shellcheck disable=SC2086
if [ "$use_docker" -eq 0 ]; then
    echo "      (로컬 $(zeek --version))"
    ( cd "$ZDIR" && zeek -C -r "$PCAP" "$ROOT/nsm_rules" run_local.zeek $ZARGS > /dev/null 2> stderr.txt )
else
    command -v docker > /dev/null || { echo "zeek 8.x 이상 또는 docker 가 필요합니다." >&2; exit 1; }
    echo "      (Docker $ZEEK_IMAGE)"
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$ROOT/nsm_rules:/pkg/nsm_rules:ro" -v "$(dirname "$PCAP"):/pcap:ro" -v "$ZDIR:/out" -w /out \
        "$ZEEK_IMAGE" zeek -C -r "/pcap/$(basename "$PCAP")" /pkg/nsm_rules run_local.zeek $ZARGS \
        > /dev/null 2> "$ZDIR/stderr.txt"
fi
elapsed=$(( $(date +%s) - start ))
echo "      완료 (${elapsed}초)"
if grep -qiE "warning|error|fatal" "$ZDIR/stderr.txt"; then
    echo "      주의: Zeek 경고·오류 출력이 있습니다($ZDIR/stderr.txt)."
    grep -iE "warning|error|fatal" "$ZDIR/stderr.txt" | head -3 | sed 's/^/        /'
fi

echo
python3 - "$ZDIR" "$elapsed" <<'PY'
import collections, json, os, sys
z, elapsed = sys.argv[1], int(sys.argv[2])

def rows(path):
    if not os.path.exists(path):
        return []
    out = []
    for l in open(path, encoding="utf-8", errors="replace"):
        if l.strip() and not l.startswith("#"):
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
    return out
size = lambda p: os.path.getsize(p) if os.path.exists(p) else 0
logs = {f[:-4]: os.path.join(z, f) for f in os.listdir(z) if f.endswith(".log")}
meta_dir = os.path.join(z, "meta")
meta = {f[:-4]: os.path.join(meta_dir, f) for f in os.listdir(meta_dir) if f.endswith(".log")} if os.path.isdir(meta_dir) else {}

# 캡처 구간: 로그에 남은 ts 의 처음·끝
# (예외 적재 행처럼 패킷 처리 전에 쓴 행은 ts 가 0 이라 빼고, reporter 는 pcap 을 읽기 전 행에 실제 시계 시각이 찍혀 뺀다)
ts = [r["ts"] for k, p in list(logs.items()) + list(meta.items()) if k != "reporter" for r in rows(p)
      if isinstance(r.get("ts"), (int, float)) and r["ts"] > 1e9]
span = (max(ts) - min(ts)) if len(ts) >= 2 else 0
print(f"캡처 구간 약 {span/60:.1f}분, 처리 {elapsed}초")
print()

# ---- 탐지 --------------------------------------------------------------------
notices = rows(logs.get("notice", ""))
det = rows(logs.get("nsm_detection", ""))
print(f"[탐지] 탐지 요약 {len(det):,}건(상관 {sum(1 for d in det if d.get('category') == 'Correlated'):,}, "
      f"suppress 표시 {sum(1 for d in det if d.get('disposition') == 'suppressed'):,}), 근거 {len(rows(logs.get('evidence', ''))):,}행")
by = collections.defaultdict(lambda: [0, set()])
for n in notices:
    k = n.get("note", "-")
    by[k][0] += 1
    if n.get("src"):
        by[k][1].add(n["src"])
for k, (c, s) in sorted(by.items(), key=lambda x: -x[1][0]):
    print(f"  {k:36s} {c:>6,}건  출발지 {len(s):>4,}개")
if not by:
    print("  (탐지 없음)")
ex = rows(logs.get("nsm_exception", ""))
if ex:
    kinds = collections.Counter(e.get("kind") for e in ex)
    hits = collections.Counter()
    for e in ex:
        if e.get("kind") == "hits":
            hits[e.get("exception_id")] += e.get("hits", 0)
    print(f"  예외: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())) +
          ("" if not hits else "  | 적중 상위: " + ", ".join(f"{k} {v:,}" for k, v in hits.most_common(5))))
print()

# ---- 자산 식별 ------------------------------------------------------------------
sig = rows(logs.get("asset_signal", ""))
print(f"[자산 식별] 신호 {len(sig):,}행, IP {len({s.get('ip') for s in sig}):,}개, {size(logs.get('asset_signal', '')):,} 바이트")
sc = collections.Counter(s.get("signal") for s in sig)
for k, v in sc.most_common():
    print(f"  {k:24s} {v:>7,}")
if not sig:
    print("  (신호 없음: 내부 대역(-n)을 확인하세요)")
print()

# ---- 메타데이터 선별 전송 -----------------------------------------------------------
print("[선별 전송] /log/zeek/meta")
mt = 0
for k in sorted(meta, key=lambda k: -size(meta[k])):
    b = size(meta[k]); mt += b
    print(f"  {k:24s} {b:>12,} 바이트 {sum(1 for _ in open(meta[k], encoding='utf-8', errors='replace')):>9,}행")
print(f"  {'합계':24s} {mt:>12,} 바이트")
print()

# ---- Manager 로 가는 로그(/log/zeek) 합계 --------------------------------------------
det_b = sum(size(logs.get(k, "")) for k in ("nsm_detection", "evidence", "nsm_exception"))
asset_b = size(logs.get("asset_signal", ""))
total = mt + asset_b + det_b
local_b = sum(size(p) for k, p in logs.items() if k not in ("nsm_detection", "evidence", "nsm_exception", "asset_signal"))
print(f"[전송량] Manager 로 가는 로그 {total:,} 바이트 = 선별 전송 {mt:,} + 자산 신호 {asset_b:,} + 탐지 로그 {det_b:,}")
print(f"         센서 로컬 로그(notice·stats 등) {local_b:,} 바이트")
if span >= 600:
    day = total * 86400 / span
    unit = f"{day/1e9:,.2f} GB" if day >= 1e9 else f"{day/1e6:,.1f} MB" if day >= 1e6 else f"{day/1e3:,.1f} KB"
    print(f"         하루 환산(단순 비례) 약 {unit}/일  ※ 캡처 구간이 짧으면 요약 로그 때문에 과대평가됨")
PY

REPORT_ARGS=()
if [ -n "$RESOLVER_DIR" ]; then
    echo
    echo "[2/3] 자산 판정(claudtest2 리졸버)"
    [ -f "$ZDIR/asset_signal.log" ] || touch "$ZDIR/asset_signal.log"
    python3 "$RESOLVER_DIR/tools/asset_resolver.py" "$ZDIR/asset_signal.log" -o "$OUT/asset_report" -z "$ZDIR" -q
    echo "      자산 리포트: $OUT/asset_report/report.html (report.txt, assets.csv)"
    REPORT_ARGS=(--assets "$OUT/asset_report/assets.json" --asset-report asset_report/report.html)
else
    echo
    echo "[2/3] 자산 판정: 건너뜀(-r <claudtest2 경로> 를 주면 자산 단위로 묶는다)"
fi
echo
echo "[3/3] 통합 리포트"
python3 "$ROOT/tests/report_pcap.py" "$ZDIR" -o "$OUT/report.html" --pcap "$(basename "$PCAP")" --elapsed "$elapsed" --nets "$NETS" ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"} | sed 's/^/      /'
echo
echo "결과: $OUT"
echo "  - report.html    통합 리포트(공격 스토리·탐지·킬체인·자산·전송량·예외·센서 상태). 주소·호스트명 원문이 들어 있으니 외부로 보내지 않는다"
echo "  - zeek/          Zeek 로그(nsm_detection·evidence·notice·asset_signal·nsm_exception 등)"
echo "  - zeek/meta/     메타데이터 선별 전송 로그"
