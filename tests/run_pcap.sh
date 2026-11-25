#!/usr/bin/env bash
# pcap 하나를 운영과 같은 설정으로 한 번 돌려 탐지·자산 식별·메타데이터 선별 전송 결과를 한 화면에 요약한다.
#
#   사용: tests/run_pcap.sh [-o 출력 디렉터리] [-n 내부 대역] [-x 예외 파일] [-r claudtest2 경로] [-z "zeek 인자"] [-u OUI.csv] [-g Recog xml 폴더]
#                            [-s Suricata 경보 파일 | -S -R 룰 파일|et [-y surica 경로]] [-k] <pcap | 디렉터리> ...
#
#     디렉터리나 pcap 여러 개를 주면 파일마다 따로 실행한다(하위 디렉터리 포함 *.pcap·*.pcapng·*.cap).
#       결과는 DIR/<파일 이름>/ 에 파일별로 남고(하위 디렉터리 파일은 경로를 _ 로 이어 붙인 이름),
#       끝에 파일별 결과 표와 DIR/index.html(각 <pcap 이름>_report.html 링크)을 만든다. 한 파일이 실패해도 나머지는 계속한다.
#     -o DIR    출력 디렉터리(기본: out/<pcap 이름>, 여러 개면 out/<디렉터리 이름> 또는 out/batch).
#               Zeek 로그는 DIR/zeek/, 선별 전송은 DIR/zeek/meta/
#     -n CIDRS  내부 대역(쉼표 구분). Site::local_nets 에 더하며 자산 식별 대상 대역도 이 값을 따른다.
#               생략하면 사설 대역. 내부에 공인 IP 를 쓰면 반드시 지정한다.
#     -x FILE   예외 파일(docs/SRS.md 7.8절). NSM::exception_file 로 넘긴다.
#     -r DIR    자산 식별 PoC(claudtest2) 경로. 주면 asset_signal.log 로 리졸버를 돌려 DIR 출력에
#               자산 리포트(report.html·report.txt·assets.csv)를 만든다(리졸버는 이 저장소에 없다).
#     -z ARGS   zeek 에 넘길 추가 인자. 예) -z "AssetID::suppress_interval=30min"
#     -u FILE   IEEE OUI 목록 CSV(MA-L·MA-M·MA-S, 여러 번 가능). 리포트 자산 표에 MAC 제조사를 붙인다.
#     -g DIR    Recog 지문 xml 폴더(github.com/rapid7/recog 의 xml/). 배너·헤더로 제품·장비 종류를 붙인다.
#               (-u·-g 는 Manager 후처리 시제품. DB 는 저장소에 넣지 않으며 라이선스는 docs/asset-id/SPEC.md 4.11)
#     -s FILE   같은 pcap 을 Suricata 로 돌린 경보 파일(eve-alert.json 또는 suricata_alert envelope JSONL, 여러 번 가능).
#               Manager 규칙(docs/SURICATA_INTEGRATION_DESIGN.md 3~5장)으로 시그니처 탐지를 만들어 목업형 리포트에 넣는다.
#               pcap 하나일 때만 쓴다(여러 pcap 이면 무시). 만드는 법은 docs/REPORT_SPEC.md "Suricata 경보"
#     -S        같은 pcap 을 Suricata 로도 돌려 경보를 바로 리포트에 넣는다. 로컬 suricata(7 이상)가 있으면 로컬로
#               (설정 SURICATA_CONF, 기본 /etc/suricata/suricata.yaml), 없으면 Docker(SURICATA_IMAGE, 기본 jasonish/suricata:8.0.6).
#               SURICATA_DOCKER=1 이면 Docker. 여러 pcap 이면 파일마다. Suricata 가 실패해도 Zeek 결과·리포트는 그대로 만든다.
#     -R FILE   -S 의 룰 파일(여러 번 가능). "-R et" 는 suricata-update(로컬 또는 컨테이너)로 ET Open 을 받는다
#               (rules.emergingthreats.net 접근 필요, ET_URL 로 다른 주소·로컬 tar.gz). -y 가 있으면 surica disable.conf 적용
#     -y DIR    surica 저장소 경로. 주면 센서와 같은 설정(tools/render_config.py: 경보·통계 파일 분리, threshold.config,
#               Community ID)으로 돌린다. 없으면 이미지 기본 설정 + HOME_NET + Community ID
#     -k        Zeek 원본 로그를 모두 남긴다(conn·dns·http·ssl·files·weird 등, DIR/zeek/ 에 기본 이름으로).
#               운영 형상은 원본을 끄므로 기본은 남기지 않는다. 탐지·선별 전송 결과는 같고 디스크만 더 쓴다.
#
#   화면 요약에는 주소·도메인 원문을 출력하지 않는다(탐지 종류·건수, 신호 종류별 건수, 로그 크기만).
#   출력 디렉터리의 <pcap 이름>_report.html(통합 리포트)·<pcap 이름>_report_mockup.html(같은 데이터를 MDS Manager 목업 화면으로)(통합 리포트, pcap 이름은 확장자를 뺀 파일 이름: 공격 스토리·탐지·킬체인·자산·전송량·예외·센서 상태)과 로그에는 원문이 있다. 처리 부하·전체 로그 대비 비율은 tests/measure_meta_export.sh 로 잰다.
#   로컬 zeek(8.x 이상)가 없으면 Docker(ZEEK_IMAGE, 기본 zeek/zeek:9.0.1)로 실행한다.
set -euo pipefail

usage() { sed -n '2,36p' "$0"; exit 2; }
OUT=""; NETS=""; EXC=""; RESOLVER_DIR=""; ZARGS=""; KEEP_RAW=""; PASS=(); ENRICH=(); SURI=()
SURI_RUN=""; SURI_RULES=(); SURICA=""
while getopts "o:n:x:r:z:u:g:s:SR:y:kh" opt; do
    case $opt in
        o) OUT=$OPTARG ;;
        n) NETS=$OPTARG; PASS+=(-n "$OPTARG") ;;
        x) EXC=$OPTARG; PASS+=(-x "$(realpath "$OPTARG")") ;;
        r) RESOLVER_DIR=$OPTARG; PASS+=(-r "$(realpath "$OPTARG")") ;;
        z) ZARGS=$OPTARG; PASS+=(-z "$OPTARG") ;;
        k) KEEP_RAW=1; PASS+=(-k) ;;
        u) ENRICH+=(--oui "$(realpath "$OPTARG")"); PASS+=(-u "$(realpath "$OPTARG")") ;;
        g) ENRICH+=(--recog "$(realpath "$OPTARG")"); PASS+=(-g "$(realpath "$OPTARG")") ;;
        s) [ -f "$OPTARG" ] || { echo "Suricata 경보 파일 없음: $OPTARG" >&2; exit 2; }; SURI+=(--suricata-eve "$(realpath "$OPTARG")") ;;
        S) SURI_RUN=1; PASS+=(-S) ;;
        R) if [ "$OPTARG" = et ]; then SURI_RULES+=(et); PASS+=(-R et)
           else [ -f "$OPTARG" ] || { echo "룰 파일 없음: $OPTARG" >&2; exit 2; }; SURI_RULES+=("$(realpath "$OPTARG")"); PASS+=(-R "$(realpath "$OPTARG")"); fi ;;
        y) [ -f "$OPTARG/tools/render_config.py" ] || { echo "surica 저장소가 아닙니다(tools/render_config.py 없음): $OPTARG" >&2; exit 2; }
           SURICA=$(realpath "$OPTARG"); PASS+=(-y "$SURICA") ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage
if [ -n "$SURI_RUN" ]; then
    [ ${#SURI_RULES[@]} -gt 0 ] || { echo "-S 는 룰이 필요합니다: -R <룰 파일> 또는 -R et" >&2; exit 2; }
    [ ${#SURI[@]} -eq 0 ] || { echo "-s(경보 파일)와 -S(Suricata 실행)는 함께 쓰지 않습니다" >&2; exit 2; }
    SURI_LOCAL=""
    if [ "${SURICATA_DOCKER:-}" != 1 ] && command -v suricata > /dev/null 2>&1; then
        sv=$(suricata -V 2>/dev/null | sed -nE 's/.*version ([0-9]+)\..*/\1/p')
        [ "${sv:-0}" -ge 7 ] && SURI_LOCAL=1
    fi
    [ -n "$SURI_LOCAL" ] || command -v docker > /dev/null || { echo "-S 는 Suricata 7 이상(로컬 설치) 또는 docker 가 필요합니다" >&2; exit 2; }
fi

# 디렉터리 또는 여러 파일: 파일마다 이 스크립트를 다시 불러 따로 실행하고, 끝에 결과 표와 index.html 을 만든다.
if [ $# -gt 1 ] || [ -d "$1" ]; then
    [ ${#SURI[@]} -eq 0 ] || echo "경고: -s(Suricata 경보 파일)는 pcap 하나일 때만 씁니다. 이번 실행에서는 무시합니다." >&2
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
        rf=$(basename "$f"); rf="${rf%.*}_report.html"   # 하위 실행이 만드는 통합 리포트 이름
        RES+=("$name"$'\t'"$st"$'\t'"$det"$'\t'"$rf")
    done

    echo ""; echo "================ 결과 (${#LIST[@]}개)"
    printf '%-40s %-5s %s\n' "pcap" "상태" "탐지 건수"
    {
        echo '<!doctype html><meta charset="utf-8"><title>run_pcap 결과</title>'
        echo '<style>body{font:14px system-ui,sans-serif;margin:24px}td,th{padding:4px 12px;text-align:left;border-bottom:1px solid #ddd}.FAIL{color:#c00}</style>'
        echo "<h1>run_pcap 결과 (${#LIST[@]}개)</h1><table><tr><th>pcap</th><th>상태</th><th>탐지 건수</th><th>리포트</th><th>목업형 리포트</th><th>실행 출력</th></tr>"
    } > "$BASE/index.html"
    nfail=0
    for r in "${RES[@]}"; do
        IFS=$'\t' read -r name st det rf <<< "$r"
        [ "$st" = ok ] || nfail=$((nfail + 1))
        printf '%-40s %-5s %s\n' "$name" "$st" "$det"
        link=-; [ -f "$BASE/$name/$rf" ] && link="<a href=\"$name/$rf\">$rf</a>"
        mf="${rf%.html}_mockup.html"; mlink=-; [ -f "$BASE/$name/$mf" ] && mlink="<a href=\"$name/$mf\">$mf</a>"
        echo "<tr><td>$name</td><td class=\"$st\">$st</td><td>$det</td><td>$link</td><td>$mlink</td><td><a href=\"$name/run.txt\">run.txt</a></td></tr>" >> "$BASE/index.html"
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
    [ -n "$KEEP_RAW" ] && echo 'redef NSM::keep_all_log_streams = T;'
} > "$ZDIR/run_local.zeek"
[ -n "$EXC" ] && cp "$EXC" "$ZDIR/exceptions.tsv"

use_docker=1
if command -v zeek > /dev/null 2>&1; then
    major=$(zeek --version 2>/dev/null | sed -E 's/.* ([0-9]+)\..*/\1/')
    [ "${major:-0}" -ge 8 ] && use_docker=0
fi

echo "[1/4] Zeek 실행: $PCAP"
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

# -k 로 남긴 원본 로그(운영에서는 남지 않음). 크기만 보고 내용은 읽지 않는다.
MGR = ("nsm_detection", "evidence", "nsm_exception", "asset_signal")
SENSOR_LOCAL = ("notice", "capture_loss", "loaded_scripts", "stats", "reporter")
raw = {k: p for k, p in logs.items() if k not in MGR and k not in SENSOR_LOCAL}

# 캡처 구간: 로그에 남은 ts 의 처음·끝
# (예외 적재 행처럼 패킷 처리 전에 쓴 행은 ts 가 0 이라 빼고, reporter 는 pcap 을 읽기 전 행에 실제 시계 시각이 찍혀 뺀다)
# (예외 로그는 적중 행만: 적재·오류·파일 행은 실제 시계 시각. nsm_ioc·asset_agent_policy 도 실제 시계 — report_pcap.py WALLCLOCK_LOGS)
WALL = ("reporter", "nsm_ioc", "asset_agent_policy")
ts = [r["ts"] for k, p in list(logs.items()) + list(meta.items()) if k not in WALL and k not in raw for r in rows(p)
      if isinstance(r.get("ts"), (int, float)) and r["ts"] > 1e9 and (k != "nsm_exception" or r.get("kind") == "hits")]
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
local_b = sum(size(p) for k, p in logs.items() if k in SENSOR_LOCAL)
print(f"[전송량] Manager 로 가는 로그 {total:,} 바이트 = 선별 전송 {mt:,} + 자산 신호 {asset_b:,} + 탐지 로그 {det_b:,}")
print(f"         센서 로컬 로그(notice·stats 등) {local_b:,} 바이트")
if raw:
    print(f"         원본 로그(-k, 운영에서는 남기지 않음) {sum(size(p) for p in raw.values()):,} 바이트, {len(raw)}개: {', '.join(sorted(raw))}")
if span >= 600:
    day = total * 86400 / span
    unit = f"{day/1e9:,.2f} GB" if day >= 1e9 else f"{day/1e6:,.1f} MB" if day >= 1e6 else f"{day/1e3:,.1f} KB"
    print(f"         하루 환산(단순 비례) 약 {unit}/일  ※ 캡처 구간이 짧으면 요약 로그 때문에 과대평가됨")
PY

# ---------------------------------------------------------------- Suricata (-S)
# 로컬 suricata(7 이상)가 있으면 로컬로, 없으면 Docker 로 돌린다(Zeek 와 같은 방식). SURICATA_DOCKER=1 이면 Docker.
# 로컬은 설치본 설정(SURICATA_CONF, 기본 /etc/suricata/suricata.yaml)을 바탕으로 쓰고, 경로는 실제 경로 그대로다.
SURICATA_IMAGE="${SURICATA_IMAGE:-jasonish/suricata:8.0.6}"
SURICATA_CONF="${SURICATA_CONF:-/etc/suricata/suricata.yaml}"
echo
if [ -n "$SURI_RUN" ]; then
    SDIR="$OUT/suricata"
    rm -rf "$SDIR"; mkdir -p "$SDIR/rules" "$SDIR/cfg" "$SDIR/log"
    : > "$SDIR/rules/suricata.rules"; : > "$SDIR/rules/local.rules"
    sfail=""
    if [ -n "$SURI_LOCAL" ]; then
        echo "[2/4] Suricata 실행: 로컬 $(suricata -V 2>/dev/null | sed -nE 's/.*(version [0-9.]+).*/\1/p') (설정 $SURICATA_CONF)${SURICA:+, surica 센서 설정}"
        RULEP="$SDIR/rules"; CFGP="$SDIR/cfg"; LOGP="$SDIR/log"; PCAPP="$PCAP"; BASECONF="$SURICATA_CONF"
    else
        echo "[2/4] Suricata 실행: $SURICATA_IMAGE${SURICA:+ (surica 센서 설정)}"
        RULEP=/rules; CFGP=/cfg; LOGP=/out; PCAPP="/pcap/$(basename "$PCAP")"; BASECONF=/etc/suricata/suricata.yaml
    fi
    # suricata 를 로컬 또는 컨테이너에서 실행(경로는 위 *P 변수로)
    suri() {
        if [ -n "$SURI_LOCAL" ]; then suricata "$@"
        else docker run --rm --user "$(id -u):$(id -g)" -v "$SDIR/rules:/rules:ro" -v "$SDIR/cfg:/cfg:ro" \
                -v "$(dirname "$PCAP"):/pcap:ro" -v "$SDIR/log:/out" --entrypoint suricata "$SURICATA_IMAGE" "$@"; fi
    }
    for r in "${SURI_RULES[@]}"; do
        if [ "$r" = et ]; then
            # ET Open: suricata-update. ET_URL 이 로컬 파일이면 그 파일을, 주소면 그 주소를 쓴다(없으면 기본 et/open)
            mkdir -p "$SDIR/sud" "$SDIR/rules/et"
            if [ -n "$SURI_LOCAL" ]; then
                uargs=(--data-dir "$SDIR/sud" -o "$SDIR/rules/et" --no-test --no-reload)
                [ -n "$SURICA" ] && uargs+=(--disable-conf "$SURICA/suricata/update/disable.conf")
                if [ -n "${ET_URL:-}" ] && [ -f "$ET_URL" ]; then uargs+=(--url "file://$(realpath "$ET_URL")")
                elif [ -n "${ET_URL:-}" ]; then uargs+=(--url "$ET_URL"); fi
                ucmd=(suricata-update "${uargs[@]}")
            else
                uargs=(--data-dir /w/sud -o /w/rules/et --no-test --no-reload); umount=()
                [ -n "$SURICA" ] && { umount+=(-v "$SURICA/suricata/update:/u:ro"); uargs+=(--disable-conf /u/disable.conf); }
                if [ -n "${ET_URL:-}" ] && [ -f "$ET_URL" ]; then
                    umount+=(-v "$(dirname "$(realpath "$ET_URL")"):/et:ro"); uargs+=(--url "file:///et/$(basename "$ET_URL")")
                elif [ -n "${ET_URL:-}" ]; then
                    uargs+=(--url "$ET_URL")
                fi
                penv=(); for v in HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NO_PROXY no_proxy; do [ -n "${!v:-}" ] && penv+=(-e "$v"); done
                ucmd=(docker run --rm --user "$(id -u):$(id -g)" ${penv[@]+"${penv[@]}"} -v "$SDIR:/w" ${umount[@]+"${umount[@]}"}
                      --entrypoint suricata-update "$SURICATA_IMAGE" "${uargs[@]}")
            fi
            if "${ucmd[@]}" > "$SDIR/suricata-update.log" 2>&1; then
                cat "$SDIR/rules/et/suricata.rules" >> "$SDIR/rules/suricata.rules"
            else
                echo "      ET 룰 받기 실패($SDIR/suricata-update.log). rules.emergingthreats.net 접근이나 ET_URL 을 확인하세요." >&2
                tail -3 "$SDIR/suricata-update.log" | sed 's/^/        /' >&2
                sfail=1
            fi
        else
            cat "$r" >> "$SDIR/rules/local.rules"
        fi
    done
    nrules=$( { grep -hcE '^(alert|drop|pass|reject)' "$SDIR/rules/suricata.rules" "$SDIR/rules/local.rules" || true; } | awk '{s+=$1} END {print s+0}')
    # HOME_NET 은 Zeek 의 내부 판정과 같게: 사설 대역 + -n
    HOME_NETS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16${NETS:+,$NETS}"
    sargs=()
    if [ -n "$SURI_LOCAL" ] && [ ! -r "$SURICATA_CONF" ]; then
        echo "      Suricata 설정을 읽을 수 없습니다($SURICATA_CONF, SURICATA_CONF 로 지정)" >&2; sfail=1
    elif [ -z "$SURI_LOCAL" ] && ! docker run --rm --entrypoint cat "$SURICATA_IMAGE" /etc/suricata/suricata.yaml > "$SDIR/cfg/base.yaml" 2> "$SDIR/image.log"; then
        echo "      Suricata 이미지를 쓸 수 없습니다($SURICATA_IMAGE, $SDIR/image.log)" >&2; sfail=1
    elif [ -n "$SURICA" ]; then
        [ -n "$SURI_LOCAL" ] && cp "$SURICATA_CONF" "$SDIR/cfg/base.yaml"
        # 센서와 같은 설정: surica 렌더러(PyYAML 필요)로 배포본을 읽어 경보·통계 파일 분리·threshold·Community ID 반영
        python3 - "$SDIR/cfg/sensor.json" "$NAME" "$HOME_NETS" <<'PY'
import json, sys
path, name, nets = sys.argv[1:4]
json.dump({"sensor_id": name, "asset_nets": nets.split(","), "community_id_seed": 0, "suricata": {"enabled": True}},
          open(path, "w"), indent=1)
PY
        if python3 "$SURICA/tools/render_config.py" -c "$SDIR/cfg/sensor.json" -o "$SDIR/cfg/r" --base "$SDIR/cfg/base.yaml" \
                --rule-path "$RULEP" --threshold-file "$CFGP/r/suricata/threshold.config" > "$SDIR/render.log" 2>&1; then
            cp "$SURICA/suricata/threshold.config" "$SDIR/cfg/r/suricata/threshold.config"
            sargs=(-c "$CFGP/r/suricata/suricata.yaml")
        else
            echo "      surica 설정 생성 실패($SDIR/render.log, PyYAML 필요)" >&2; sfail=1
        fi
    else
        # 설치본(또는 이미지) 기본 설정 + 이 실행의 룰만(-S) + HOME_NET. 출력은 경보 파일 하나로 바꾼다(--include 는 최상위
        # outputs 를 통째로 바꿈): 설치본이 켜 둔 프로토콜 로그(http·dns·flow 등)·fast.log 를 쓰지 않아 큰 pcap 에서도 빠르다
        cat "$SDIR/rules/suricata.rules" "$SDIR/rules/local.rules" > "$SDIR/rules/all.rules"
        cat > "$SDIR/cfg/outputs.yaml" <<'YAML'
%YAML 1.1
---
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alert.json
      community-id: yes
      community-id-seed: 0
      types:
        - alert:
            payload: no
            packet: no
            metadata:
              app-layer: no
              flow: no
              rule:
                metadata: yes
                raw: no
YAML
        sargs=(-c "$BASECONF" --include "$CFGP/outputs.yaml" -S "$RULEP/all.rules" --set "vars.address-groups.HOME_NET=[$HOME_NETS]")
    fi
    sstart=$(date +%s)
    if [ -z "$sfail" ] && suri "${sargs[@]}" -r "$PCAPP" -k none -l "$LOGP" > "$SDIR/run.log" 2>&1; then
        # 경보 파일(두 모드 모두 eve-alert.json): 센서와 같은 필드만 남기고 시각순
        src="$SDIR/log/eve-alert.json"
        [ -f "$src" ] || : > "$src"
        python3 "$ROOT/tests/suricata/slim.py" "$src" > "$SDIR/eve-alert.json"
        SURI=(--suricata-eve "$SDIR/eve-alert.json")
        nbad=$(grep -c "error parsing signature" "$SDIR/run.log" || true)
        echo "      완료 ($(( $(date +%s) - sstart ))초), 룰 ${nrules}개${nbad:+$([ "$nbad" -gt 0 ] && echo ", 읽지 못한 룰 ${nbad}개($SDIR/run.log)")}"
        if grep -q "no rules were loaded" "$SDIR/run.log"; then echo "      주의: 읽은 룰이 하나도 없습니다(룰 문법·파일을 확인하세요)." >&2; fi
        # 화면 요약: 주소·이름 없이 단계별 경보 수만
        python3 - "$ROOT/tests" "$SDIR/eve-alert.json" <<'PY'
import collections, sys
sys.path.insert(0, sys.argv[1])
import suricata_alerts as sa
al = sa.load([sys.argv[2]])
ko = {"Recon": "정찰", "Initial Access": "초기 침투", "Command and Control": "외부 연락(C2)", "Credential Access": "계정 탈취",
      "Lateral Movement": "내부 확산", "Exfiltration": "정보 유출", "Impact": "피해", "": "단계 없음"}
c = collections.Counter(sa.stage_of(a)[0] for a in al)
print(f"      경보 {len(al):,}건, 시그니처 {len({a['alert'].get('signature_id') for a in al}):,}종"
      + (": " + ", ".join(f"{ko[k]} {v:,}" for k, v in c.most_common()) if c else ""))
PY
    else
        [ -n "$sfail" ] || { echo "      Suricata 실행 실패($SDIR/run.log)" >&2; { grep -iE "error|fatal" "$SDIR/run.log" || true; } | head -3 | sed 's/^/        /' >&2; }
        echo "      Suricata 없이 계속합니다(Zeek 결과·리포트는 그대로)." >&2
    fi
else
    echo "[2/4] Suricata: 건너뜀(-S -R <룰> 을 주면 같은 pcap 을 Suricata 로도 돌린다)"
fi

REPORT_ARGS=()
if [ -n "$RESOLVER_DIR" ]; then
    echo
    echo "[3/4] 자산 판정(claudtest2 리졸버)"
    [ -f "$ZDIR/asset_signal.log" ] || touch "$ZDIR/asset_signal.log"
    python3 "$RESOLVER_DIR/tools/asset_resolver.py" "$ZDIR/asset_signal.log" -o "$OUT/asset_report" -z "$ZDIR" -q
    echo "      자산 리포트: $OUT/asset_report/report.html (report.txt, assets.csv)"
    REPORT_ARGS=(--assets "$OUT/asset_report/assets.json" --asset-report asset_report/report.html)
else
    echo
    echo "[3/4] 자산 판정: 건너뜀(-r <claudtest2 경로> 를 주면 자산 단위로 묶는다)"
fi
echo
echo "[4/4] 통합 리포트"
REPORT="$OUT/${NAME}_report.html"
python3 "$ROOT/tests/report_pcap.py" "$ZDIR" -o "$REPORT" --pcap "$(basename "$PCAP")" --elapsed "$elapsed" --nets "$NETS" ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"} ${ENRICH[@]+"${ENRICH[@]}"} ${SURI[@]+"${SURI[@]}"} | sed 's/^/      /'
echo
echo "결과: $OUT"
echo "  - $(basename "$REPORT")    통합 리포트(공격 스토리·탐지·킬체인·자산·전송량·예외·센서 상태). 주소·호스트명 원문이 들어 있으니 외부로 보내지 않는다"
echo "  - $(basename "${REPORT%.html}_mockup.html")    목업형 리포트(같은 데이터를 MDS Manager 목업 화면으로, ui/mockup/). 원문이 들어 있으니 외부로 보내지 않는다"
echo "  - zeek/          Zeek 로그(nsm_detection·evidence·notice·asset_signal·nsm_exception 등)"
echo "  - zeek/meta/     메타데이터 선별 전송 로그"
if [ -n "$KEEP_RAW" ]; then echo "  - zeek/*.log     Zeek 원본 로그(-k: conn·dns·http·ssl 등)"; fi
if [ -n "$SURI_RUN" ]; then echo "  - suricata/      Suricata 경보(eve-alert.json), 룰(rules/), 설정(cfg/), 원본 출력(log/), 실행 로그"; fi
