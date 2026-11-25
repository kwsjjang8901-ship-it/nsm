#!/usr/bin/env python3
"""detection_enrich(탐지 정보 보강, docs/DETECTION_ENRICH_SPEC.md) 규칙 단위 테스트. btest rules/report-enrich 가 실행한다."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detection_enrich as de  # noqa: E402
import report_pcap  # noqa: E402

T = 1_800_000_000.0


def det(rule, src, dsts, ev, first=T, last=None, stages=""):
    return {"ts": first, "first": first, "last": last or first, "diagnosis": "NSM.X." + report_pcap.DIAG_NOTE[rule],
            "attacker": {"ip": src}, "victims": [{"ip": d} for d in dsts], "evidence": ev, "stages": stages}


class TestEnrich(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def idx(self, rows):
        paths = {}
        for log, rs in rows.items():
            p = os.path.join(self.tmp, log + ".log")
            with open(p, "w") as f:
                for r in rs:
                    f.write(json.dumps(r) + "\n")
            paths[log] = p
        return de.Index.load(paths)

    def run_e(self, d, rows, internal=lambda ip: ip.startswith("10.")):
        return de.enrich(d, self.idx(rows), de.rule_of(d, report_pcap.DIAG_NOTE), internal)

    def test_rule_table_covers_all_rules(self):
        # 설정 표는 단독 탐지 룰 전체(48개)와 같아야 한다(룰을 추가하면 표에도 한 줄)
        self.assertEqual(set(de.RULES), set(report_pcap.DIAG_NOTE))

    def test_exact_uid_and_kerberos_success(self):
        # Q1: 근거 uid 와 같은 행은 정확 일치. Kerberoasting 은 대상(DC)과 무관하게 출발지의 티켓 요청(kpre=())
        krb = [{"ts": T + i, "uid": f"Ck{i}", "orig_h": "10.0.0.5", "resp_h": "10.0.0.10", "request_type": "TGS", "client": "svc/CORP",
                "service": f"MSSQLSvc/db{i}", "success": True, "cipher": "rc4-hmac"} for i in range(3)]
        flow = [{"ts": T, "orig_h": "10.0.0.5", "resp_h": "10.0.0.10", "resp_p": 88, "proto": "udp", "conns": 3, "orig_bytes": 900, "resp_bytes": 700, "states": "SF:3"}]
        d = det("Kerberoasting", "10.0.0.5", ["10.0.0.10"], [{"ts": T, "uid": "Ck0", "src": "10.0.0.5", "dst": "10.0.0.10", "account": "svc@CORP"}], last=T + 2)
        o = self.run_e(d, {"kerberos": krb, "flow_summary": flow})
        self.assertEqual([r["uid"] for r in o["records"]["exact"]], ["Ck0"])
        self.assertEqual(len(o["records"]["nearby"]), 2)
        f = {x["label"]: x["value"] for x in o["facts"] if x["log"] == "kerberos"}
        self.assertEqual((f["티켓 암호"], f["결과"]), ("rc4-hmac 3번", "성공 3 · 실패 0"))
        # 성공 흔적은 행 단위 로그(kerberos)로만 센다(연결 정상 종료 SF 는 세지 않음)
        self.assertEqual((o["judge"]["result"]["level"], o["judge"]["result"]["ok"]), ("hi", 3))
        self.assertEqual(o["judge"]["account"]["hosts"], ["10.0.0.5"])

    def test_dedup_grouped(self):
        # 센서 중복 억제: 근거 uid 의 ssl 행이 없으면 같은 출발지·SNI 의 24시간 안 앞선 행을 같은 연결 묶음으로
        ssl = [{"ts": T - 3600, "uid": "Cfirst", "orig_h": "10.0.0.5", "resp_h": "203.0.113.9", "server_name": "c2.example", "version": "TLSv12", "established": True}]
        d = det("TLS_Beaconing", "10.0.0.5", ["203.0.113.9"],
                [{"ts": T, "uid": "Clater", "src": "10.0.0.5", "dst": "203.0.113.9", "dst_name": "c2.example"}])
        o = self.run_e(d, {"ssl": ssl})
        self.assertEqual((o["records"]["exact"], [r["uid"] for r in o["records"]["grouped"]]), ([], ["Cfirst"]))
        self.assertTrue(any("중복 억제" in x for x in o["limits"]))
        # 25시간 전이면 묶지 않는다
        ssl[0]["ts"] = T - 25 * 3600
        self.assertEqual(self.run_e(d, {"ssl": ssl}).get("records", {}).get("grouped", []), [])

    def test_web_result_mode(self):
        # 웹 공격: 같은 연결에서 오류 뒤 2xx 일 때만 성공 흔적. 2xx 만이면 판단 안 함
        def http(uid, codes):
            return [{"ts": T + i, "uid": uid, "orig_h": "198.51.100.1", "resp_h": "10.0.0.80", "method": "GET", "host": "w",
                     "uri_path": "/item.php", "status_code": c, "response_body_len": 100} for i, c in enumerate(codes)]
        ev = [{"ts": T, "uid": "Cw", "src": "198.51.100.1", "dst": "10.0.0.80"}]
        o = self.run_e(det("SQL_Injection", "198.51.100.1", ["10.0.0.80"], ev), {"http": http("Cw", [500, 500, 200])})
        self.assertEqual(o["judge"]["result"]["level"], "hi")
        self.assertIn("500 × 2 → 200", next(x["value"] for x in o["facts"] if x["label"] == "상태 코드"))
        o = self.run_e(det("SQL_Injection", "198.51.100.1", ["10.0.0.80"], ev), {"http": http("Cw", [200, 200])})
        self.assertNotIn("result", o["judge"])
        o = self.run_e(det("SQL_Injection", "198.51.100.1", ["10.0.0.80"], ev), {"http": http("Cw", [500, 403])})
        self.assertEqual(o["judge"]["result"]["level"], "no")

    def test_flow_only_and_live(self):
        # 행 단위 로그가 없는 룰은 연결 상태로(SF 성공, S0·REJ 실패). 탐지 뒤 연결이 있으면 지금도 통신 중
        flow = [{"ts": T, "orig_h": "10.0.0.5", "resp_h": "10.0.0.9", "resp_p": p, "proto": "tcp", "conns": 1, "states": s}
                for p, s in ((22, "SF:1"), (23, "S0:1"), (24, "REJ:1"))]
        o = self.run_e(det("Port_Scan", "10.0.0.5", ["10.0.0.9"], []), {"flow_summary": flow})
        self.assertEqual((o["judge"]["result"]["level"], o["judge"]["live"]["on"]), ("mid", False))
        flow.append({"ts": T + 1800, "orig_h": "10.0.0.5", "resp_h": "10.0.0.9", "resp_p": 22, "proto": "tcp", "conns": 1, "states": "SF:1"})
        o = self.run_e(det("Port_Scan", "10.0.0.5", ["10.0.0.9"], []), {"flow_summary": flow})
        self.assertTrue(o["judge"]["live"]["on"])

    def test_name_from_dns_answer(self):
        # IP 만 있는 외부 목적지: 탐지 전 1시간 출발지의 DNS 응답에 그 IP 가 있으면 이름, 없으면 not_found
        flow = [{"ts": T, "orig_h": "10.0.0.5", "resp_h": "203.0.113.7", "resp_p": 8443, "proto": "tcp", "conns": 2, "states": "SF:2"}]
        dns = [{"ts": T - 1200, "ts_end": T - 1100, "orig_h": "10.0.0.5", "domain": "partner.example", "answers": ["203.0.113.7"]}]
        d = det("Nonstandard_Port", "10.0.0.5", ["203.0.113.7"], [])
        self.assertEqual(self.run_e(d, {"flow_summary": flow, "dns_summary": dns})["judge"]["name"]["domain"], "partner.example")
        dns[0]["answers"] = ["203.0.113.8"]
        self.assertEqual(self.run_e(d, {"flow_summary": flow, "dns_summary": dns})["judge"]["name"], {"domain": None, "how": "not_found"})

    def test_dns_rule_by_domain(self):
        # DNS 계열은 dns_summary 를 도메인으로 조회하고, 탐지 뒤 같은 도메인 질의가 있으면 통신 중
        dns = [{"ts": T, "ts_end": T + 60, "orig_h": "10.0.0.5", "domain": "tun.example", "queries": 90, "unique_names": 86,
                "rcodes": "NOERROR:71,NXDOMAIN:15", "sample_names": ["a1.tun.example"]},
               {"ts": T + 3600, "orig_h": "10.0.0.5", "domain": "tun.example", "queries": 3, "unique_names": 3}]
        d = det("DNS_Tunneling", "10.0.0.5", [], [{"ts": T, "src": "10.0.0.5", "dst_name": "x.tun.example"}])
        o = self.run_e(d, {"dns_summary": dns})
        f = {x["label"]: x["value"] for x in o["facts"]}
        self.assertEqual((f["고유 이름"], f["결과"]), ("86개 / 질의 90번", "NOERROR 71 · NXDOMAIN 15"))
        self.assertTrue(o["judge"]["live"]["on"])

    def test_nothing(self):
        self.assertEqual(self.run_e(det("Unknown_Protocol", "10.0.0.5", ["203.0.113.1"], []), {}), {})


if __name__ == "__main__":
    unittest.main()
