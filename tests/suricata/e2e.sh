#!/usr/bin/env bash
# Zeek + Suricata 한 번에(tests/run_pcap.sh -S) 통합 테스트. Docker 가 필요해 CI(btest)에서는 돌지 않는다.
#   1. 기본 설정: 경보가 고정본(killchain_story.eve-alert.json)과 같은지(시그니처·출발지·대상별 건수), 목업형 리포트에 시그니처 7건
#   2. surica 센서 설정(-y): 경보·통계 파일 분리, threshold 기본값으로 경보 수는 줄어도 시그니처 탐지 7건   (SURICA_ROOT 가 있을 때)
#   3. ET 룰 받기(-R et): surica 표본(tests/rules/et_sample)을 ET_URL 로 받아 disable.conf 뒤 4개만             (SURICA_ROOT 가 있을 때)
#   4. 장애 격리: 깨진 룰은 경고, 없는 이미지는 Suricata 없이 계속(종료 코드 0, 리포트는 Zeek 탐지만)
#
# 사용법: [SURICA_ROOT=<surica 경로>] tests/suricata/e2e.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PCAP="$ROOT/tests/pcaps/killchain_story.pcap"
RULES="$ROOT/tests/suricata/test.rules"
fail=0
ok()  { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fail=1; }
run() { local out=$1; shift; "$ROOT/tests/run_pcap.sh" -o "$TMP/$out" "$@" "$PCAP" > "$TMP/$out.log" 2>&1; }
nsig() { grep -o '그중 시그니처 [0-9]*건' "$TMP/$1.log" | grep -o '[0-9]*' || echo 0; }

echo "[1] 기본 설정"
if run a -S -R "$RULES"; then
	same=$(python3 - "$TMP/a/suricata/eve-alert.json" "$ROOT/tests/suricata/killchain_story.eve-alert.json" <<'PY'
import collections, json, sys
f = lambda p: collections.Counter((r["alert"]["signature_id"], r["src_ip"], r["dest_ip"]) for r in map(json.loads, open(p)))
print("yes" if f(sys.argv[1]) == f(sys.argv[2]) else "no")
PY
)
	[ "$same" = yes ] && ok "경보가 고정본과 같음" || bad "경보가 고정본과 다름(룰·pcap·이미지를 바꿨으면 tests/suricata/gen_eve.sh)"
	[ "$(nsig a)" = 7 ] && ok "목업형 리포트에 시그니처 7건" || bad "시그니처 $(nsig a)건"
else
	cat "$TMP/a.log"; bad "run_pcap.sh -S 실패"
fi

if [ -n "${SURICA_ROOT:-}" ]; then
	echo "[2] surica 센서 설정 (-y)"
	if run b -S -R "$RULES" -y "$SURICA_ROOT"; then
		[ -s "$TMP/b/suricata/log/eve-alert.json" ] && [ -s "$TMP/b/suricata/log/eve-stats.json" ] && [ ! -e "$TMP/b/suricata/log/eve.json" ] \
			&& ok "경보·통계 파일 분리" || bad "eve 파일 구성이 다름"
		[ "$(nsig b)" = 7 ] && ok "시그니처 7건(threshold 로 경보 $(grep -c . "$TMP/b/suricata/eve-alert.json")건)" || bad "시그니처 $(nsig b)건"
	else
		cat "$TMP/b.log"; bad "run_pcap.sh -S -y 실패"
	fi
	echo "[3] ET 룰 받기 (-R et, 표본)"
	tar czf "$TMP/et.tar.gz" -C "$SURICA_ROOT/tests/rules/et_sample" rules
	if ET_URL="$TMP/et.tar.gz" run c -S -R et -y "$SURICA_ROOT"; then
		n=$(grep -vc '^#' "$TMP/c/suricata/rules/suricata.rules" || true)
		[ "$n" = 4 ] && ok "disable.conf 뒤 룰 4개" || bad "룰 ${n}개"
	else
		cat "$TMP/c.log"; bad "run_pcap.sh -R et 실패"
	fi
else
	echo "[2][3] 건너뜀: SURICA_ROOT(surica 경로)가 없음"
fi

echo "[4] 장애 격리"
echo 'alert tcp any any -> any any (msg:"broken"; nosuchkeyword; sid:1;)' > "$TMP/bad.rules"
if run d -S -R "$TMP/bad.rules" && grep -q "읽지 못한 룰 1개" "$TMP/d.log" && grep -q "읽은 룰이 하나도 없습니다" "$TMP/d.log"; then
	ok "깨진 룰: 경고 후 계속"
else
	cat "$TMP/d.log"; bad "깨진 룰 처리"
fi
if SURICATA_IMAGE=local/no-such-suricata:0 run e -S -R "$RULES" && grep -q "Suricata 없이 계속" "$TMP/e.log" && [ "$(nsig e)" = 0 ] \
	&& [ -s "$TMP/e/killchain_story_report_mockup.html" ]; then
	ok "없는 이미지: Suricata 없이 리포트"
else
	cat "$TMP/e.log"; bad "없는 이미지 처리"
fi

echo
[ "$fail" -eq 0 ] && echo "통합 테스트 통과" || { echo "통합 테스트 실패"; exit 1; }
