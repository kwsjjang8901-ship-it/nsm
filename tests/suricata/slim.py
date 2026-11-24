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
for line in open(sys.argv[1], encoding="utf-8"):
    ev = json.loads(line)
    if ev.get("event_type") != "alert":
        continue
    r = {k: ev[k] for k in KEYS if k in ev}
    r["alert"] = {k: ev["alert"][k] for k in ALERT if k in ev["alert"]}
    out.append(r)
out.sort(key=lambda r: (r["timestamp"], r["alert"]["signature_id"], r["src_ip"], r.get("src_port", 0)))
for r in out:
    print(json.dumps(r, ensure_ascii=False))
