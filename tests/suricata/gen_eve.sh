#!/usr/bin/env bash
# Suricata 경보 고정본 만들기: tests/suricata/<pcap 이름>.eve-alert.json
#   CI 에는 Suricata 가 없어 결과를 저장소에 둔다. 룰(test.rules)이나 pcap 을 바꿨을 때만 다시 만든다.
#   flow_id 는 실행마다 달라 다시 만들면 그 값만 바뀐다(테스트는 flow_id 를 쓰지 않음).
# 사용법: tests/suricata/gen_eve.sh [pcap 이름 ...]   (기본 killchain_story, docker 필요)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${SURICATA_IMAGE:-jasonish/suricata:8.0.6}"
[ $# -gt 0 ] || set -- killchain_story
for name in "$@"; do
	tmp="$(mktemp -d)"
	docker run --rm --user "$(id -u):$(id -g)" -v "$HERE:/t:ro" -v "$HERE/../pcaps:/p:ro" -v "$tmp:/o" \
		--entrypoint suricata "$IMG" -c /etc/suricata/suricata.yaml -S /t/test.rules -k none --runmode single \
		--set 'vars.address-groups.HOME_NET=[10.0.0.0/8]' --set outputs.1.eve-log.community-id=true \
		-r "/p/$name.pcap" -l /o > "$tmp/run.log" 2>&1 || { cat "$tmp/run.log"; exit 1; }
	python3 "$HERE/slim.py" "$tmp/eve.json" > "$HERE/$name.eve-alert.json"
	echo "$name: 경보 $(wc -l < "$HERE/$name.eve-alert.json")건 -> tests/suricata/$name.eve-alert.json"
	rm -rf "$tmp"
done
