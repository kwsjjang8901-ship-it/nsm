# @TEST-DOC: 로그 스키마 — 코드의 필드 정의와 저장소의 스키마·문서가 같고(schema/build.py --check), 공격 스토리 7단계 pcap 의 탐지·근거·예외·자산·선별 전송 로그가 스키마에 맞는다. 검증기는 스키마에 없는 필드, 정해지지 않은 값, 빠진 필수 필드, 타입·형식 오류를 잡는다
# @TEST-EXEC: python3 $SCHEMA/build.py --check
# @TEST-EXEC: zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: python3 $SCHEMA/validate.py --min-rows 50 . > valid.out
# @TEST-EXEC: grep -q "nsm_detection " valid.out && grep -q "evidence " valid.out && grep -q "asset_signal " valid.out
# 하나씩 고장 낸 행은 각각 실패해야 한다
# @TEST-EXEC: python3 bad.py

@TEST-START-FILE bad.py
import json, os, shutil, subprocess, sys

det = json.loads(open("nsm_detection.log").readline())
ev = next(json.loads(l) for l in open("evidence.log") if "community_id" in l)
cases = [
    ("nsm_detection", dict(det, new_field=1), "스키마에 없는 필드"),
    ("nsm_detection", dict(det, category="Other"), "정해진 값이 아님"),
    ("nsm_detection", {k: v for k, v in det.items() if k != "severity"}, "필수 필드 severity"),
    ("nsm_detection", dict(det, evidence_count="3"), "타입 integer"),
    ("nsm_detection", dict(det, attacker="not-an-ip"), "anyOf"),
    ("nsm_detection", dict(det, rule="No_Such_Rule"), "정해진 값이 아님"),
    ("evidence", dict(ev, community_id="1:short"), "형식"),
    ("evidence", dict(ev, dst_port=70000), "최대"),
]
for i, (log, row, want) in enumerate(cases):
    d = "bad%d" % i
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, log + ".log"), "w").write(json.dumps(row) + "\n")
    r = subprocess.run([sys.executable, os.path.join(os.environ["SCHEMA"], "validate.py"), d], capture_output=True, text=True)
    assert r.returncode != 0 and want in r.stderr, (i, want, r.returncode, r.stderr)
    # 일부러 만든 잘못된 행은 지운다(CI 가 btest 출력 전체를 스키마로 검사하므로)
    shutil.rmtree(d)
print("ok", len(cases))
@TEST-END-FILE
