#!/usr/bin/env python3
"""suricata_alerts.normalize() 규칙 단위 테스트(설계 3~4장). btest rules/report-suricata 가 실행한다."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import suricata_alerts as sa  # noqa: E402


def alert(ts, src, dst, sid=1, cat="Web Application Attack", pri=1, md=None, direction="to_server", cid="1:a", **extra):
    ev = {"timestamp": "2026-11-09T00:%02d:%02d.000000+0000" % divmod(ts, 60), "event_type": "alert",
          "src_ip": src, "src_port": 40000, "dest_ip": dst, "dest_port": 80, "proto": "TCP", "direction": direction,
          "community_id": cid, "alert": {"signature_id": sid, "rev": 1, "signature": "T%d" % sid, "category": cat,
                                         "severity": pri, "metadata": md or {}}}
    ev.update(extra)
    return ev


def internal(ip):
    return ip.startswith("10.")


class TestNormalize(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "meta"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_n(self, evs, stage_map=None):
        p = os.path.join(self.tmp, "eve.json")
        with open(p, "w") as f:
            for e in evs:
                f.write(json.dumps(e) + "\n")
        return sa.normalize(sa.load([p]), self.tmp, internal, stage_map)

    def test_stage_order(self):
        # SID 지정 > 메타데이터 > 분류 > 단계 없음
        g = self.run_n([alert(0, "1.1.1.1", "10.0.0.1", sid=1, md={"mitre_tactic_id": ["TA0011"]})], {1: "Impact"})[0]
        self.assertEqual((g["rule"], g["stage_by"]), ("Suricata_Impact", "sid_map"))
        g = self.run_n([alert(0, "1.1.1.1", "10.0.0.1", md={"mitre_tactic_id": ["TA0002", "TA0008"]})])[0]
        self.assertEqual((g["stage"], g["stage_by"]), ("Lateral Movement", "mitre"))   # 매핑 없는 전술은 건너뜀
        g = self.run_n([alert(0, "1.1.1.1", "10.0.0.1", cat="A Network Trojan was detected")])[0]
        self.assertEqual((g["rule"], g["stage_by"], g["classtype"]), ("Suricata_C2", "classtype", "trojan-activity"))
        g = self.run_n([alert(0, "10.0.0.2", "10.0.0.1", cat="Potentially Bad Traffic", pri=2)])[0]
        self.assertEqual((g["rule"], g["stage"], g["sig_sev"]), ("Suricata_Other", "", "Medium"))

    def test_endpoints(self):
        # 응답 방향: 연결을 시작한 쪽이 출발지
        g = self.run_n([alert(0, "10.0.0.1", "1.1.1.1", direction="to_client")])[0]
        self.assertEqual((g["src"], g["dst"]), ("1.1.1.1", "10.0.0.1"))
        # C2: 내부 쪽이 출발지(경보 방향과 상관없이)
        g = self.run_n([alert(0, "8.8.8.8", "10.0.0.9", md={"mitre_tactic_id": ["TA0011"]})])[0]
        self.assertEqual((g["src"], g["dst"], g["src_internal"], g["dst_internal"]), ("10.0.0.9", "8.8.8.8", True, False))
        # target 키워드가 있으면 그대로
        a = alert(0, "10.0.0.1", "10.0.0.2")
        a["alert"]["source"], a["alert"]["target"] = {"ip": "10.0.0.2", "port": 445}, {"ip": "10.0.0.1", "port": 5000}
        g = self.run_n([a])[0]
        self.assertEqual((g["src"], g["dst"], g["dst_port"]), ("10.0.0.2", "10.0.0.1", 5000))

    def test_grouping(self):
        # 같은 (탐지 종류, 출발지, 대상)은 15분 안에서 한 건, 넘으면 새 건. 시그니처는 여러 개 담김
        evs = [alert(0, "1.1.1.1", "10.0.0.1", sid=1, cid="1:a"), alert(60, "1.1.1.1", "10.0.0.1", sid=2, cid="1:b"),
               alert(60 + 15 * 60 + 1, "1.1.1.1", "10.0.0.1", sid=1, cid="1:c")]
        gs = self.run_n(evs)
        self.assertEqual([g["occ"] for g in gs], [2, 1])
        self.assertEqual(sorted(s[0] for s in gs[0]["signatures"]), [1, 2])
        self.assertEqual(gs[0]["community_ids"], ["1:a", "1:b"])
        self.assertEqual(set(gs[0]["defs"]), {1, 2})

    def test_connection_and_proxy(self):
        with open(os.path.join(self.tmp, "meta", "ssl.log"), "w") as f:
            f.write(json.dumps({"uid": "Cssl", "community_id": "1:s", "server_name": "evil.example"}) + "\n")
        with open(os.path.join(self.tmp, "meta", "http.log"), "w") as f:
            f.write(json.dumps({"uid": "Cpx", "community_id": "1:p", "method": "CONNECT", "host": "c2.example:443"}) + "\n")
        c2 = {"mitre_tactic_id": ["TA0011"]}
        g = self.run_n([alert(0, "10.0.0.5", "1.2.3.4", md=c2, cid="1:s")])[0]
        self.assertEqual((g["uid"], g["dst_name"], g["proxy"]), ("Cssl", "evil.example", ""))
        # 명시적 프록시(CONNECT): 대상은 프록시, 실제 목적지는 CONNECT 대상
        g = self.run_n([alert(0, "10.0.0.5", "10.0.0.250", md=c2, cid="1:p", dest_port=3128)])[0]
        self.assertEqual((g["dst"], g["dst_name"], g["proxy"]), ("10.0.0.250", "c2.example:443", "10.0.0.250:3128"))

    def test_envelope_input(self):
        p = os.path.join(self.tmp, "suricata_alert.jsonl")
        with open(p, "w") as f:
            f.write(json.dumps({"sensor_id": "s", "engine": "suricata", "stream": "suricata_alert",
                                "data": alert(0, "1.1.1.1", "10.0.0.1")}) + "\n")
            f.write(json.dumps({"stream": "suricata_stats", "data": {"timestamp": "2026-11-09T00:00:00.000000+0000"}}) + "\n")
            f.write("not json\n")
        self.assertEqual(len(sa.load([p])), 1)


if __name__ == "__main__":
    unittest.main()
