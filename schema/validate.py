#!/usr/bin/env python3
"""Zeek JSON 로그를 schema/logs 의 JSON Schema 로 검사한다(표준 라이브러리만 사용).

  python3 schema/validate.py <디렉터리> [...]      # 아래 모든 *.log 중 스키마가 있는 로그를 검사
  python3 schema/validate.py --min-rows N <디렉터리>  # 검사한 행이 N 보다 적으면 실패

로그 이름은 파일 이름(확장자 제외), meta/ 디렉터리 아래는 "meta/<이름>". TSV 로그는 건너뛴다.
지원하는 키워드: type, properties, required, additionalProperties(false), items, enum, pattern,
minimum, maximum, anyOf, format(ipv4·ipv6). 스키마에 다른 검증 키워드를 쓰면 실패해서 알려 준다.
"""
import argparse
import collections
import ipaddress
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_DIR = os.path.join(ROOT, "schema", "logs")
KNOWN = {"type", "properties", "required", "additionalProperties", "items", "enum", "pattern", "minimum",
         "maximum", "anyOf", "format", "description", "title", "$schema", "x-zeek-type", "x-path"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool}


def load_schemas():
    out = {}
    for d, _s, fs in os.walk(SCHEMA_DIR):
        for f in fs:
            if f.endswith(".schema.json"):
                name = os.path.relpath(os.path.join(d, f), SCHEMA_DIR)[:-len(".schema.json")].replace(os.sep, "/")
                out[name] = json.load(open(os.path.join(d, f), encoding="utf-8"))
    return out


def type_ok(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, TYPES[t])


def fmt_ok(v, f):
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return False
    return a.version == (4 if f == "ipv4" else 6)


def check(v, s, path, errs):
    unknown = set(s) - KNOWN
    if unknown:
        errs.append("%s: 검사기가 모르는 스키마 키워드 %s" % (path, sorted(unknown)))
    if "type" in s and not type_ok(v, s["type"]):
        errs.append("%s: 타입 %s 이어야 함, 값 %r" % (path, s["type"], v))
        return
    if "enum" in s and v not in s["enum"]:
        errs.append("%s: 정해진 값이 아님 %r" % (path, v))
    if "pattern" in s and isinstance(v, str) and not re.search(s["pattern"], v):
        errs.append("%s: 형식 %s 에 맞지 않음 %r" % (path, s["pattern"], v))
    if "minimum" in s and v < s["minimum"]:
        errs.append("%s: %r < 최소 %s" % (path, v, s["minimum"]))
    if "maximum" in s and v > s["maximum"]:
        errs.append("%s: %r > 최대 %s" % (path, v, s["maximum"]))
    if "format" in s and not fmt_ok(v, s["format"]):
        errs.append("%s: %s 형식이 아님 %r" % (path, s["format"], v))
    if "anyOf" in s:
        if not any(not check_list(v, sub, path) for sub in s["anyOf"]):
            errs.append("%s: anyOf 중 맞는 것이 없음 %r" % (path, v))
    if "items" in s and isinstance(v, list):
        for i, x in enumerate(v):
            check(x, s["items"], "%s[%d]" % (path, i), errs)
    if "properties" in s and isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append("%s: 필수 필드 %s 없음" % (path, k))
        for k, x in v.items():
            if k in s["properties"]:
                check(x, s["properties"][k], "%s.%s" % (path, k) if path else k, errs)
            elif s.get("additionalProperties") is False:
                errs.append("%s: 스키마에 없는 필드 %s" % (path or "(행)", k))


def check_list(v, s, path):
    e = []
    check(v, s, path, e)
    return e


def log_name(path):
    stem = os.path.basename(path)[:-4]
    parent = os.path.basename(os.path.dirname(path))
    return "meta/" + stem if parent == "meta" else stem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--min-rows", type=int, default=1)
    ap.add_argument("--max-errors", type=int, default=30)
    a = ap.parse_args()
    schemas = load_schemas()
    rows, files, skipped = collections.Counter(), collections.Counter(), 0
    errors = []
    for top in a.dirs:
        for d, _s, fs in os.walk(top):
            for f in sorted(fs):
                if not f.endswith(".log"):
                    continue
                p = os.path.join(d, f)
                name = log_name(p)
                if name not in schemas:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    first = fh.readline()
                    if not first.startswith("{"):
                        skipped += 1          # TSV(자산 식별 단독 테스트 등)
                        continue
                    files[name] += 1
                    fh.seek(0)
                    for n, line in enumerate(fh, 1):
                        line = line.strip()
                        if not line:
                            continue
                        rows[name] += 1
                        try:
                            v = json.loads(line)
                        except ValueError as e:
                            errors.append("%s:%d: JSON 아님 (%s)" % (p, n, e))
                            continue
                        e = check_list(v, schemas[name], "")
                        errors.extend("%s:%d: %s" % (p, n, x) for x in e)
    total = sum(rows.values())
    for name in sorted(rows):
        print("  %-28s 파일 %3d  행 %6d" % (name, files[name], rows[name]))
    print("검사: 로그 %d종, 행 %d, 오류 %d (TSV 건너뜀 %d개 파일)" % (len(rows), total, len(errors), skipped))
    if errors:
        print("\n".join(errors[:a.max_errors]), file=sys.stderr)
        if len(errors) > a.max_errors:
            print("... 외 %d건" % (len(errors) - a.max_errors), file=sys.stderr)
        sys.exit(1)
    if total < a.min_rows:
        sys.exit("검사한 행이 %d 로 최소 %d 보다 적습니다" % (total, a.min_rows))


if __name__ == "__main__":
    main()
