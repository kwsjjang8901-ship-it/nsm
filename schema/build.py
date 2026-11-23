#!/usr/bin/env python3
"""Manager 로 가는 로그의 JSON Schema 와 문서를 만든다.

  python3 schema/build.py            # schema/logs/**.schema.json, docs/LOG_SCHEMA.md 를 다시 쓴다
  python3 schema/build.py --check    # 다시 만든 결과가 저장소 파일과 다르면 실패(CI)
  python3 schema/build.py --fields fields.json   # Zeek 를 실행하지 않고 저장해 둔 필드 정의를 쓴다

필드 목록·타입·필수 여부는 Zeek 를 실행해 레코드 정의에서 뽑는다(schema/fields.zeek).
설명·열거값·형식은 schema/overlay.json 에 적는다. 코드에서 필드를 더하거나 빼면 --check 가 실패하고,
NSM 로그에 설명이 없는 필드가 생기면 생성 자체가 실패한다.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_DIR = os.path.join(ROOT, "schema", "logs")
DOC = os.path.join(ROOT, "docs", "LOG_SCHEMA.md")
OVERLAY = os.path.join(ROOT, "schema", "overlay.json")

ADDR = {"anyOf": [{"format": "ipv4"}, {"format": "ipv6"}]}


def zeek_fields():
    with tempfile.TemporaryDirectory() as d:
        out = subprocess.run(["zeek", os.path.join(ROOT, "nsm_rules"), os.path.join(ROOT, "schema", "fields.zeek")],
                             cwd=d, capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        sys.exit("zeek 실행 실패:\n" + out.stderr)
    return json.loads(out.stdout.strip().splitlines()[-1])


def json_type(zt):
    """Zeek 타입 이름 -> (JSON Schema 조각, 문서용 타입 이름)"""
    if zt.startswith("vector of ") or zt.startswith("set["):
        inner = zt[len("vector of "):] if zt.startswith("vector of ") else zt[4:-1]
        s, name = json_type(inner)
        return {"type": "array", "items": s}, "array<%s>" % name
    if zt in ("time", "double", "interval"):
        return {"type": "number"}, {"time": "time(epoch 초)", "interval": "number(초)"}.get(zt, "number")
    if zt in ("count", "port"):
        return {"type": "integer", "minimum": 0}, "integer"
    if zt == "int":
        return {"type": "integer"}, "integer"
    if zt == "bool":
        return {"type": "boolean"}, "boolean"
    if zt == "addr":
        return dict({"type": "string"}, **ADDR), "string(IP)"
    if zt == "subnet":
        return {"type": "string", "pattern": "^[0-9a-fA-F:.]+/[0-9]+$"}, "string(대역)"
    return {"type": "string"}, "string"


def resolve(spec, enums):
    """overlay 의 형식 정의를 JSON Schema 조각으로(enum_ref·format ip 풀기)."""
    out = {}
    for k, v in spec.items():
        if k in ("desc",):
            continue
        if k == "enum_ref":
            out["enum"] = sorted(enums[v])
        elif k == "format" and v == "ip":
            out.update(ADDR)
        elif k == "anyOf":
            out["anyOf"] = [resolve(x, enums) for x in v]
        elif k == "items":
            out["items"] = resolve(v, enums)
        else:
            out[k] = v
    return out


def merge(base, extra):
    s = dict(base)
    for k, v in extra.items():
        if k == "items" and "items" in s:
            s["items"] = merge(s["items"], v)
        else:
            s[k] = v
    return s


def build(fields, overlay):
    enums = {e["name"]: e["values"] for e in fields["enums"]}
    order = list(overlay["logs"])   # 문서 순서: overlay 에 적은 순서, 나머지(선별 전송 Zeek 로그)는 이름순
    logs = sorted(fields["logs"], key=lambda l: (order.index(l["log"]) if l["log"] in order else len(order), l["log"]))
    schemas, problems = {}, []
    for l in logs:
        name = l["log"]
        ov = overlay["logs"].get(name)
        is_nsm = ov is not None
        ofields = (ov or {}).get("fields", {})
        props, required, doc_rows = {}, [], []
        for f in l["fields"]:
            s, tname = json_type(f["zeek_type"])
            o = ofields.get(f["name"], {})
            if is_nsm and not o.get("desc"):
                problems.append("%s.%s: overlay.json 에 설명(desc)이 없습니다" % (name, f["name"]))
            s = merge(s, resolve(o, enums))
            if o.get("desc"):
                s["description"] = o["desc"]
            s["x-zeek-type"] = f["zeek_type"]
            props[f["name"]] = s
            # 기본값(&default)이 있는 필드는 Zeek 가 optional 로 보고하지만 로그에는 항상 쓰인다
            req = not f["optional"] or f["has_default"]
            if req:
                required.append(f["name"])
            doc_rows.append((f["name"], tname, req, s, o.get("desc", "")))
        for k in ofields:
            if k not in props:
                problems.append("%s.%s: overlay.json 에 있는데 로그에 없는 필드" % (name, k))
        title = ov["title"] if ov else overlay["meta_default"]["title_prefix"] + name.split("/", 1)[1]
        desc = ov["desc"] if ov else overlay["meta_default"]["desc"]
        path = ov["path"] if ov else "/log/zeek/%s.log" % name
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "%s (%s)" % (title, name),
            "description": desc,
            "x-path": path,
            "type": "object",
            "properties": props,
            "required": required,
            "additionalProperties": False,
        }
        schemas[name] = (schema, doc_rows, title, desc, path)
    for k in overlay["logs"]:
        if k not in schemas:
            problems.append("%s: overlay.json 에 있는데 Zeek 출력에 없는 로그" % k)
    return schemas, enums, problems


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def values_text(s):
    if "enum" in s:
        v = s["enum"]
        return ", ".join("`%s`" % x for x in v) if len(v) <= 8 else "열거값 %d개(아래 표)" % len(v)
    if "items" in s and "enum" in s["items"]:
        v = s["items"]["enum"]
        return "각 값: " + (", ".join("`%s`" % x for x in v) if len(v) <= 8 else "열거값 %d개(아래 표)" % len(v))
    parts = []
    for k in ("minimum", "maximum"):
        if k in s and not (k == "minimum" and s[k] == 0 and s.get("type") == "integer" and "maximum" not in s):
            parts.append("%s %s" % ("최소" if k == "minimum" else "최대", s[k]))
    if "pattern" in s and s.get("x-zeek-type") != "subnet":
        parts.append("형식 `%s`" % s["pattern"])
    if "anyOf" in s and "format" not in s["anyOf"][0]:
        parts.append("열거값 또는 형식")
    return ", ".join(parts)


def render_doc(schemas, enums, fields):
    out = []
    w = out.append
    w("# 센서 로그 스키마 (Manager 연동 기준)")
    w("")
    w("이 문서는 `schema/build.py`가 만듭니다. 직접 고치지 말고 `schema/overlay.json`(설명·열거값)이나 Zeek 코드(필드)를 고친 뒤 다시 만드세요. 기계가 읽는 정의는 `schema/logs/`의 JSON Schema(draft 2020-12)입니다.")
    w("")
    w("- 형식: JSON 한 줄 = 한 행. 값이 없는 선택 필드는 쓰지 않습니다(키가 없음). 필수 필드는 항상 있습니다.")
    w("- 타입: `time`은 epoch 초(소수), IP는 문자열, 목록은 JSON 배열, 정해 두지 않은 필드는 없습니다(`additionalProperties: false`).")
    w("- 검증: CI가 btest 전체 출력의 해당 로그를 이 스키마로 검사하고(`schema/validate.py`), 코드의 필드가 스키마와 달라지면 실패합니다(`schema/build.py --check`).")
    w("- 근거 문서: 탐지 로그는 [SRS 6장](SRS.md), 자산 신호는 [자산 식별 SPEC 2장](asset-id/SPEC.md), 선별 전송은 [메타데이터 SRS](SRS_METADATA_EXPORT.md). 형식 결정 배경은 [로그 형식 검토](LOG_SCHEMA_REVIEW.md).")
    w("")
    w("## 로그 목록")
    w("")
    w("| 로그 | 이름 | 경로(기본) | 필드 수 | 스키마 |")
    w("| --- | --- | --- | --- | --- |")
    for name, (schema, rows, title, desc, path) in schemas.items():
        w("| `%s` | %s | `%s` | %d | [`%s.schema.json`](../schema/logs/%s.schema.json) |" % (name, cell(title), path, len(rows), name, name))
    w("")
    for name, (schema, rows, title, desc, path) in schemas.items():
        w("## %s (`%s`)" % (title, name))
        w("")
        w(cell(desc))
        w("")
        w("| 필드 | 타입 | 필수 | 값 | 설명 |")
        w("| --- | --- | --- | --- | --- |")
        for fname, tname, req, s, d in rows:
            w("| `%s` | %s | %s | %s | %s |" % (fname, tname, "필수" if req else "", cell(values_text(s)), cell(d)))
        w("")
    w("## 열거값")
    w("")
    w("### 룰과 진단명 (`rule`, `diagnosis`)")
    w("")
    w("단독 탐지의 `diagnosis`는 룰마다 고정입니다. 상관 탐지(`Correlated_KillChain`)는 `NSM.Correlation.<첫 단계>.<가장 많이 진행된 단계>`입니다.")
    w("")
    w("| `rule` | `diagnosis` |")
    w("| --- | --- |")
    rd = sorted(zip(fields_enum(fields, "rule"), fields_enum(fields, "diagnosis")))
    for r, dg in rd:
        w("| `%s` | `%s` |" % (r, dg if r != "Correlated_KillChain" else "NSM.Correlation.<첫 단계>.<마지막 단계>"))
    w("")
    w("### 킬체인 단계 (`killchain_stages`, `killchain_stage`)")
    w("")
    w(", ".join("`%s`" % x for x in sorted(enums["killchain_stage"])))
    w("")
    w("### 자산 신호 종류 (`asset_signal.signal`)")
    w("")
    w(", ".join("`%s`" % x for x in sorted(enums["asset_signal"])) + ". 각 신호의 뜻은 [자산 식별 SPEC 2.1](asset-id/SPEC.md).")
    w("")
    return "\n".join(out)


def fields_enum(fields, name):
    for e in fields["enums"]:
        if e["name"] == name:
            return e["values"]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--fields")
    a = ap.parse_args()
    fields = json.load(open(a.fields)) if a.fields else zeek_fields()
    overlay = json.load(open(OVERLAY, encoding="utf-8"))
    schemas, enums, problems = build(fields, overlay)
    if problems:
        sys.exit("스키마 생성 실패:\n  " + "\n  ".join(problems))
    files = {os.path.join(SCHEMA_DIR, n + ".schema.json"): json.dumps(s, ensure_ascii=False, indent=2) + "\n"
             for n, (s, *_r) in schemas.items()}
    files[DOC] = render_doc(schemas, enums, fields) + "\n"
    stale = []
    for path, text in files.items():
        cur = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        if cur != text:
            stale.append(os.path.relpath(path, ROOT))
            if not a.check:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w", encoding="utf-8").write(text)
    known = set(files)
    for d, _s, fs in os.walk(SCHEMA_DIR):
        for f in fs:
            p = os.path.join(d, f)
            if p not in known:
                stale.append(os.path.relpath(p, ROOT) + " (코드에 없는 로그)")
                if not a.check:
                    os.remove(p)
    if a.check and stale:
        sys.exit("스키마가 코드와 다릅니다. python3 schema/build.py 로 다시 만들어 커밋하세요:\n  " + "\n  ".join(stale))
    print("%s: 로그 %d개%s" % ("확인" if a.check else "생성", len(schemas),
                             "" if not stale or a.check else ", 바뀐 파일 %d개" % len(stale)))


if __name__ == "__main__":
    main()
