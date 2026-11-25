#!/usr/bin/env python3
"""Suricata eve.json -> 센서 경보 파일(eve-alert.json)과 같은 모양.

surica 렌더러가 만드는 센서 설정(경보만, 앱 계층·페이로드 없음, 룰 메타데이터 있음)과 같은 필드만 남기고 시각순으로 쓴다.
"""
import json
import sys

KEYS = ("timestamp", "flow_id", "in_iface", "event_type", "src_ip", "src_port", "dest_ip", "dest_port",
        "proto", "app_proto", "direction", "community_id", "tx_id")
ALERT = ("action", "gid", "signature_id", "rev", "signature", "category", "severity", "source", "target", "metadata")

out = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    if '"alert"' not in line:          # 큰 eve 파일에서 경보가 아닌 줄은 풀지 않는다
        continue
    try:
        ev = json.loads(line)
    except ValueError:
        continue
    if ev.get("event_type") != "alert" or "alert" not in ev:
        continue
    r = {k: ev[k] for k in KEYS if k in ev}
    r["alert"] = {k: ev["alert"][k] for k in ALERT if k in ev["alert"]}
    out.append(r)
# IP 가 없는 경보(Suricata 8 의 일부 디코더·이상 이벤트)도 남긴다. 정렬 키는 없는 값을 빈 값으로
out.sort(key=lambda r: (r.get("timestamp", ""), r["alert"].get("signature_id") or 0, r.get("src_ip", ""), r.get("src_port") or 0))
for r in out:
    print(json.dumps(r, ensure_ascii=False))
