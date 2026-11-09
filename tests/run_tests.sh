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

if command -v btest >/dev/null 2>&1 && command -v zeek >/dev/null 2>&1; then
	(cd "$ROOT/tests/btest" && btest -d "$@")
else
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:/w" -w /w/tests/btest "$ZEEK_IMAGE" btest -d "$@"
fi
