# @TEST-DOC: 묶기 보류 모드 폐기 — dedup_emit_first = F 로 두어도 경고만 하고 무시한다(첫 건을 바로 기록). 보류 모드에서는 첫 건이 기록되지 않아 킬체인 상관이 돌지 않았다. 7단계 공격 pcap 에서 F 로 둔 결과(notice·탐지 요약·상관)가 기본값과 같다
# @TEST-EXEC: mkdir d && cd d && zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP
# @TEST-EXEC: mkdir f && cd f && zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP NSM::dedup_emit_first=F
# @TEST-EXEC: grep -q 'dedup_emit_first = F' f/reporter.log
# @TEST-EXEC: ! grep -q 'dedup_emit_first' d/reporter.log 2>/dev/null
# @TEST-EXEC: assert-rows f/nsm_detection.log ge 1 category=Correlated
# @TEST-EXEC: python3 same.py

@TEST-START-FILE same.py
import json
def rows(p):
    out = []
    for l in open(p):
        r = json.loads(l)
        out.append((r.get("note") or r.get("diagnosis"), r.get("src") or r.get("attacker"), r.get("dst"), tuple(r.get("killchain_stages", []))))
    return sorted(out, key=repr)
for f in ("notice.log", "nsm_detection.log"):
    a, b = rows("d/" + f), rows("f/" + f)
    assert a == b, (f, len(a), len(b))
@TEST-END-FILE
