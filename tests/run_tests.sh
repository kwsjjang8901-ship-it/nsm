#!/usr/bin/env bash
# nsm_rules 회귀 테스트(btest).
# 로컬에 zeek + btest 가 없으면 Docker(zeek/zeek) 이미지로 실행한다.
#
#   tests/run_tests.sh                              # 기본 zeek/zeek:9.0.1
#   ZEEK_IMAGE=zeek/zeek:8.0.9 tests/run_tests.sh   # 다른 버전
#   tests/run_tests.sh rules/13-dga.zeek            # 일부만
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.1}"

# CRLF 검사: Windows 에서 받은 사본(core.autocrlf=true, VMware 공유 폴더 등)은 줄바꿈이 CRLF 가 되어
#   테스트 도구 셔뱅이 "/usr/bin/env: 'bash\r'" 로 실패한다(모든 assert-rows 가 exit 127).
crlf=$(grep -rlI $'\r' "$ROOT/tests/btest/tools" "$ROOT/tests/btest/btest.cfg" "$ROOT/tests/btest/setup.zeek" \
	"$ROOT/tests/btest/rules" "$ROOT/tests/btest/cluster" "$ROOT/tests/btest/files" 2>/dev/null || true)
if [ -n "$crlf" ]; then
	echo "오류: 다음 파일의 줄바꿈이 CRLF 입니다(Windows 줄바꿈). LF 로 바꾼 뒤 다시 실행하세요." >&2
	echo "$crlf" | sed 's/^/  /' >&2
	echo "" >&2
	echo "  바로 고치기:  sed -i 's/\r\$//' <위 파일들>" >&2
	echo "  근본 해결:    git config core.autocrlf input  후  git rm -r --cached -q . && git reset --hard" >&2
	exit 2
fi

if command -v btest >/dev/null 2>&1 && command -v zeek >/dev/null 2>&1; then
	(cd "$ROOT/tests/btest" && btest -d "$@")
else
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:/w" -w /w/tests/btest "$ZEEK_IMAGE" btest -d "$@"
fi
