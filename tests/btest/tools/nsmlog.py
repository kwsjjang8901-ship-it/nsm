"""btest 도구 공용: Zeek 로그(JSON 한 줄 = 한 레코드, 또는 TSV)를 읽어 zeek-cut 과 같은 표기로 값을 돌려준다.

  표기 규칙(zeek-cut / TSV 와 동일하게 맞춘다)
    값 없음(필드 미설정)  -> "-"
    bool                  -> "T" / "F"
    집합·벡터             -> 쉼표로 이음, 비었으면 "(empty)"
    실수(double·interval·time) -> 소수 6자리 (예: 3600.000000)
    그 외                 -> 문자열 그대로
"""

import json
import sys


def render(v):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "T" if v else "F"
    if isinstance(v, list):
        return ",".join(render(x) for x in v) if v else "(empty)"
    if isinstance(v, float):
        return "%.6f" % v
    return str(v)


def read_records(stream):
    """레코드(dict: 필드명 -> 표기 문자열)를 차례로 낸다. JSON·TSV 모두 지원."""
    fields = None
    unset = "-"
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("{"):
            obj = json.loads(line)
            yield {k: render(v) for k, v in obj.items()}
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#unset_field"):
                unset = line.split("\t")[1]
            continue
        if fields is None:
            continue
        rec = {}
        for k, v in zip(fields, line.split("\t")):
            if v != unset:
                rec[k] = v
        yield rec


def read_file(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(read_records(f))


def get(rec, field):
    return rec.get(field, "-")


def fail(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)
