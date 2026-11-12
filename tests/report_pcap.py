#!/usr/bin/env python3
"""tests/run_pcap.sh 결과(Zeek 로그 디렉터리)로 통합 리포트(report.html, 파일 하나)를 만든다.

  python3 tests/report_pcap.py <zeek 로그 디렉터리> -o report.html [--assets assets.json]
         [--asset-report 상대경로] [--pcap 이름] [--elapsed 초] [--tz 9]

탐지(탐지 요약·근거), 킬체인 상관, 예외, 자산(리졸버 assets.json 이 있으면 자산 단위, 없으면 신호 단위),
메타데이터 선별 전송, Manager 로 가는 전송량, 센서 상태를 한 페이지에 모은다. 탐지의 공격자·대상 IP 는
탐지 시각에 그 IP 를 쓰던 자산(assets.json 의 IP 점유 구간)으로 이름을 붙이고, 자산 표에는 관련 탐지 수를 센다.

리포트에는 주소·호스트명·계정 같은 원문이 들어 있다. 로컬에서 보는 용도이며 외부로 보내지 않는다.
외부 라이브러리를 쓰지 않는다(오프라인 VM 에서 그대로 열림).
"""
import argparse
import collections
import datetime
import html
import ipaddress
import json
import os
import sys

MGR = ("nsm_detection", "evidence", "nsm_exception", "asset_signal")


def rows(path):
    out = []
    if not path or not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.strip() and not line.startswith("#"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def size(path):
    return os.path.getsize(path) if path and os.path.exists(path) else 0


def nlines(path):
    return sum(1 for _ in open(path, encoding="utf-8", errors="replace")) if path and os.path.exists(path) else 0


def split_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [x for x in str(v).split(",") if x and x != "-"]


class AssetIndex:
    """assets.json 의 IP 점유 구간으로 (IP, 시각) -> 자산을 찾는다."""

    def __init__(self, assets):
        self.by_ip = collections.defaultdict(list)
        for a in assets:
            for b in a.get("ips", []):
                self.by_ip[b.get("ip")].append((b.get("first", 0), b.get("last", 0), a))

    def find(self, ip, ts=None):
        cand = self.by_ip.get(ip)
        if not cand:
            return None
        if ts is not None:
            for first, last, a in cand:
                if first <= ts <= last:
                    return a
            # 구간 밖이면 가장 가까운 구간의 자산(신호가 탐지 전후에만 있는 경우)
            return min(cand, key=lambda c: min(abs(ts - c[0]), abs(ts - c[1])))[2]
        return cand[-1][2]


def collect(z, assets_path, args):
    logs = {f[:-4]: os.path.join(z, f) for f in os.listdir(z) if f.endswith(".log")}
    mdir = os.path.join(z, "meta")
    meta = {f[:-4]: os.path.join(mdir, f) for f in os.listdir(mdir) if f.endswith(".log")} if os.path.isdir(mdir) else {}

    det = rows(logs.get("nsm_detection"))
    ev = rows(logs.get("evidence"))
    notices = rows(logs.get("notice"))
    exc = rows(logs.get("nsm_exception"))
    sig = rows(logs.get("asset_signal"))
    assets = json.load(open(assets_path, encoding="utf-8")) if assets_path and os.path.exists(assets_path) else None
    if isinstance(assets, dict):
        assets = assets.get("assets", [])
    idx = AssetIndex(assets or [])

    # 내부 대역: --nets(run_pcap.sh -n) 또는 사설 대역. 대상이 외부면 자산 식별 대상이 아니다(C2·유출의 대상은 외부 서버).
    nets = []
    for n in (args.nets or "").split(","):
        n = n.strip()
        if n:
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass

    def internal(ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return a.is_private or any(a in n for n in nets)

    # 리졸버 결과가 없을 때 IP 옆에 붙일 이름: 자산 신호의 호스트명 > 머신 계정 > FQDN > DNS 이름(판정 전 참고값)
    pri = {"hostname": 0, "machine_account": 1, "fqdn": 2, "dns_name": 3}
    sig_names = {}
    for x in sig:
        k = x.get("signal")
        if k in pri and x.get("value"):
            cur = sig_names.get(x.get("ip"))
            if cur is None or pri[k] < cur[0]:
                sig_names[x.get("ip")] = (pri[k], str(x["value"]))

    def label(ip, ts):
        out = {"ip": ip}
        if not internal(ip):
            out["ext"] = True
        a = idx.find(ip, ts) if assets else None
        if a:
            out.update({"asset": a.get("asset_id"), "name": a.get("display_name") or a.get("hostname") or ""})
        elif ip in sig_names:
            out["name"] = sig_names[ip][1]
            out["guess"] = True
        return out

    ev_by = collections.defaultdict(list)
    for e in ev:
        ev_by[e.get("evidence_id")].append({k: e.get(k) for k in ("ts", "note", "operation", "src", "dst", "account", "uid", "detail", "technique")})

    detections = []
    related = collections.Counter()
    for d in det:
        ts = d.get("ts")
        att = d.get("attacker")
        vics = split_list(d.get("victims"))
        eids = split_list(d.get("evidence_ids")) or ([d["detection_id"]] if d.get("detection_id") else [])
        evs = []
        for eid in eids:
            evs.extend(ev_by.get(eid, []))
        item = {
            "ts": ts, "id": d.get("detection_id"), "diagnosis": d.get("diagnosis"), "techniques": d.get("techniques"),
            "category": d.get("category"), "stages": d.get("killchain_stages"), "severity": d.get("severity"),
            "attacker": label(att, ts) if att else None, "victims": [label(v, ts) for v in vics],
            "evidence_count": d.get("evidence_count", 0), "disposition": d.get("disposition"),
            "exception_id": d.get("exception_id"), "evidence": sorted(evs, key=lambda e: e.get("ts") or 0)[:200],
        }
        detections.append(item)
        for who in [item["attacker"]] + item["victims"]:
            if who and who.get("asset"):
                related[who["asset"]] += 1

    # 자산: 리졸버 결과가 있으면 자산 단위, 없으면 IP 별 신호 요약
    asset_rows = []
    if assets is not None:
        for a in assets:
            asset_rows.append({
                "id": a.get("asset_id"), "name": a.get("display_name") or a.get("hostname") or "",
                "key": f"{a.get('id_type', '')}({a.get('confidence', '')})", "ips": [b.get("ip") for b in a.get("ips", [])],
                "macs": a.get("macs", []), "os": a.get("os", ""), "roles": a.get("roles", []),
                "users": a.get("users", [])[:5], "signals": a.get("signal_count", 0), "detections": related.get(a.get("asset_id"), 0),
            })
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))
    else:
        per = collections.defaultdict(lambda: {"signals": collections.Counter(), "names": set()})
        for s in sig:
            p = per[s.get("ip")]
            p["signals"][s.get("signal")] += 1
            if s.get("signal") in ("hostname", "machine_account", "fqdn"):
                p["names"].add(str(s.get("value")))
        det_ips = collections.Counter()
        for d in detections:
            for who in [d["attacker"]] + d["victims"]:
                if who:
                    det_ips[who["ip"]] += 1
        for ip, p in per.items():
            asset_rows.append({"id": "", "name": ", ".join(sorted(p["names"]))[:80], "key": "", "ips": [ip], "macs": [],
                               "os": "", "roles": [], "users": [], "signals": sum(p["signals"].values()),
                               "detections": det_ips.get(ip, 0)})
        asset_rows.sort(key=lambda r: (-r["detections"], -r["signals"]))

    # 전송량
    meta_rows = [{"name": k, "bytes": size(p), "rows": nlines(p)} for k, p in meta.items()]
    meta_rows.sort(key=lambda r: -r["bytes"])
    mgr = {k: size(logs.get(k)) for k in MGR}
    local = {k: size(p) for k, p in logs.items() if k not in MGR}
    ts_all = [r["ts"] for p in list(logs.values()) + list(meta.values()) for r in rows(p)
              if isinstance(r.get("ts"), (int, float)) and r["ts"] > 1e9]
    span = (max(ts_all) - min(ts_all)) if len(ts_all) >= 2 else 0

    # 센서 상태
    cl = rows(logs.get("capture_loss"))
    other_notes = collections.Counter(n.get("note") for n in notices if not str(n.get("note", "")).startswith("NSM::"))
    stderr = os.path.join(z, "stderr.txt")
    warn = [l.strip() for l in open(stderr, encoding="utf-8", errors="replace")
            if any(w in l.lower() for w in ("warning", "error", "fatal"))][:20] if os.path.exists(stderr) else []

    return {
        "pcap": args.pcap or "", "elapsed": args.elapsed, "tz": args.tz, "span": span,
        "start": min(ts_all) if ts_all else None, "end": max(ts_all) if ts_all else None,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "detections": detections,
        "exceptions": exc,
        "assets": asset_rows, "asset_mode": "resolver" if assets is not None else "signals",
        "asset_report": args.asset_report or "",
        "signal_counts": collections.Counter(s.get("signal") for s in sig).most_common(),
        "signal_rows": len(sig), "signal_ips": len({s.get("ip") for s in sig}),
        "meta": meta_rows, "mgr": mgr, "local": local,
        "sensor": {"capture_loss_max": max((c.get("percent_lost", 0) for c in cl), default=0),
                   "other_notices": other_notes.most_common(), "warnings": warn},
    }


PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NSM 통합 리포트</title>
<style>
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--mut:#5f6b7a;--line:#e3e7ed;--acc:#2f6fde;--warn:#b35c00;--bad:#c62828;--ok:#2e7d32;--chip:#eef2f8}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--card:#1c2027;--fg:#e6e9ee;--mut:#9aa4b2;--line:#2c323b;--acc:#7aa7ff;--warn:#f0a050;--bad:#ff7a7a;--ok:#7bd07f;--chip:#262c35}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans KR",sans-serif}
header{padding:20px 24px 8px}h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);font-size:13px}
nav{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 24px;display:flex;gap:6px;flex-wrap:wrap}
nav a{color:var(--fg);text-decoration:none;padding:4px 10px;border-radius:14px;background:var(--chip);font-size:13px}nav a:hover{background:var(--acc);color:#fff}
main{padding:12px 24px 40px;max-width:1400px}section{margin:18px 0}h2{font-size:16px;margin:0 0 10px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.card .v{font-size:22px;font-weight:600}.card .k{color:var(--mut);font-size:12px}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;color:var(--mut);font-weight:600;white-space:nowrap;user-select:none}th:hover{color:var(--fg)}
tr.row{cursor:pointer}tr.row:hover td{background:var(--chip)}tr.det td{background:var(--bg)}
.chip.ext{background:transparent;border:1px solid var(--line);color:var(--mut)}.chip.guess{font-style:italic}
.chip{display:inline-block;white-space:nowrap;padding:1px 7px;border-radius:10px;background:var(--chip);font-size:12px;margin:1px 2px 1px 0}
.sus{color:var(--bad);font-weight:600}.sup{color:var(--warn)}.mut{color:var(--mut)}.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--acc);border-radius:4px;min-width:2px}.filter{margin:0 0 8px;padding:6px 10px;width:100%;max-width:360px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
.note{color:var(--mut);font-size:12px;margin-top:6px}code{font-size:12px}
</style></head><body>
<header><h1>NSM 통합 리포트</h1><div class="sub" id="sub"></div></header>
<nav><a href="#sum">요약</a><a href="#det">탐지</a><a href="#chain">킬체인</a><a href="#asset">자산</a><a href="#xfer">전송량</a><a href="#exc">예외</a><a href="#sensor">센서 상태</a></nav>
<main>
<section id="sum"><h2>요약</h2><div class="cards" id="cards"></div></section>
<section id="det"><h2>탐지</h2><div class="box"><div id="detbars"></div></div>
 <div class="box" style="margin-top:10px"><input class="filter" id="detf" placeholder="필터: 진단·IP·자산 이름·기법"><div id="dett"></div>
 <div class="note">행을 누르면 근거(evidence)가 펼쳐집니다. 대상은 확산·랜섬웨어 등에서는 피해 host, C2·유출·비표준 포트에서는 연결한 외부 서버입니다(<span class="chip ext">외부</span> 표시, 자산 식별 대상 아님). IP 옆 이름은 자산 판정 결과가 있으면 탐지 시각에 그 IP를 쓰던 자산, 없으면 자산 신호의 호스트명(<i>기울임</i>, 판정 전 참고값)입니다.</div></div></section>
<section id="chain"><h2>킬체인 상관</h2><div class="box"><label class="note"><input type="checkbox" id="chainall"> 중간 단계 포함(체인이 길어질 때마다 나온 상관 탐지를 모두 보기)</label><div id="chaint"></div></div></section>
<section id="asset"><h2>자산</h2><div class="box"><input class="filter" id="asf" placeholder="필터: 이름·IP·OS·역할"><div id="ast"></div><div class="note" id="asnote"></div></div></section>
<section id="xfer"><h2>전송량</h2><div class="box" id="xft"></div></section>
<section id="exc"><h2>예외</h2><div class="box" id="exct"></div></section>
<section id="sensor"><h2>센서 상태</h2><div class="box" id="sent"></div></section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmtB=b=>b>=1e6?(b/1e6).toFixed(2)+' MB':b>=1e3?(b/1e3).toFixed(1)+' KB':b+' B';
const fmtT=t=>{if(!t)return'-';const d=new Date((t+D.tz*3600)*1000);return d.toISOString().replace('T',' ').slice(0,19)};
const who=w=>w?`${esc(w.ip)}${(w.name||w.asset)?` <span class="chip${w.guess?' guess':''}" title="${w.guess?'자산 신호의 이름(판정 전)':'자산 판정 결과'}">${esc(w.name||w.asset)}</span>`:''}${w.ext?' <span class="chip ext">외부</span>':''}`:'-';
const arrow=s=>esc(String(s??'').replace(/->/g,'→'));
document.getElementById('sub').textContent=`${D.pcap} · 캡처 ${fmtT(D.start)} ~ ${fmtT(D.end)} (UTC${D.tz>=0?'+':''}${D.tz}, 약 ${(D.span/60).toFixed(1)}분) · 처리 ${D.elapsed}초 · 생성 ${D.generated}`;
// 표: 열 정의 [제목, 값 함수, 정렬 키 함수, 클래스]
function table(el,cols,data,opts={}){
  let sk=null,sd=1,flt='';const host=document.getElementById(el);
  function draw(){let d=data.filter(r=>!flt||JSON.stringify(r).toLowerCase().includes(flt));
    if(sk!==null)d=[...d].sort((a,b)=>{const x=cols[sk][2](a),y=cols[sk][2](b);return (x>y?1:x<y?-1:0)*sd});
    let h='<table><thead><tr>'+cols.map((c,i)=>`<th data-i="${i}">${c[0]}${sk===i?(sd>0?' ▲':' ▼'):''}</th>`).join('')+'</tr></thead><tbody>';
    d.forEach((r,i)=>{h+=`<tr class="${opts.detail?'row':''}" data-i="${data.indexOf(r)}">`+cols.map(c=>`<td class="${c[3]||''}">${c[1](r)}</td>`).join('')+'</tr>';});
    if(!d.length)h+=`<tr><td colspan="${cols.length}" class="mut">없음</td></tr>`;
    host.innerHTML=h+'</tbody></table>';
    host.querySelectorAll('th').forEach(th=>th.onclick=()=>{const i=+th.dataset.i;sd=sk===i?-sd:1;sk=i;draw()});
    if(opts.detail)host.querySelectorAll('tr.row').forEach(tr=>tr.onclick=()=>{const n=tr.nextElementSibling;
      if(n&&n.classList.contains('det')){n.remove();return}const x=document.createElement('tr');x.className='det';
      x.innerHTML=`<td colspan="${cols.length}">${opts.detail(data[+tr.dataset.i])}</td>`;tr.after(x)});}
  if(opts.filter)document.getElementById(opts.filter).oninput=e=>{flt=e.target.value.toLowerCase();draw()};
  draw();}
// 요약 카드
const dets=D.detections,single=dets.filter(d=>d.category!=='Correlated'),chains=dets.filter(d=>d.category==='Correlated');
const mgrTotal=Object.values(D.mgr).reduce((a,b)=>a+b,0)+D.meta.reduce((a,b)=>a+b.bytes,0);
const perDay=D.span>=600?mgrTotal*86400/D.span:null;
const cards=[[single.length,'탐지(단일)'],[chains.filter(c=>!chains.some(o=>o!==c&&o.attacker&&c.attacker&&o.attacker.ip===c.attacker.ip&&String(o.stages).length>String(c.stages).length&&String(o.stages).startsWith(String(c.stages)))).length,'킬체인(최종)'],[new Set(dets.map(d=>d.attacker&&d.attacker.ip).filter(Boolean)).size,'공격자 IP'],
 [D.asset_mode==='resolver'?D.assets.length:D.signal_ips,D.asset_mode==='resolver'?'자산(판정)':'자산 신호 IP'],[D.assets.filter(a=>a.detections>0).length,'탐지 관련 자산'],
 [fmtB(mgrTotal),'Manager 전송'],[perDay?fmtB(perDay)+'/일':'-','하루 환산'],[(D.sensor.capture_loss_max||0).toFixed(2)+'%','최대 캡처 손실']];
document.getElementById('cards').innerHTML=cards.map(c=>`<div class="card"><div class="v">${esc(c[0])}</div><div class="k">${c[1]}</div></div>`).join('');
// 탐지 막대
const byDiag={};single.forEach(d=>byDiag[d.diagnosis]=(byDiag[d.diagnosis]||0)+1);const mx=Math.max(1,...Object.values(byDiag));
document.getElementById('detbars').innerHTML=Object.keys(byDiag).length?'<table>'+Object.entries(byDiag).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<tr><td style="width:40%">${esc(k)}</td><td class="num" style="width:60px">${v}</td><td><div class="bar" style="width:${100*v/mx}%"></div></td></tr>`).join('')+'</table>':'<span class="mut">탐지 없음</span>';
const evTable=d=>!d.evidence.length?'<span class="mut">근거 없음</span>':'<table>'+'<tr><th>시각</th><th>행위</th><th>출발→대상</th><th>계정</th><th>내용</th></tr>'+d.evidence.map(e=>`<tr><td>${fmtT(e.ts)}</td><td>${esc(e.operation)}</td><td>${esc(e.src)} → ${esc(e.dst)}</td><td>${esc(e.account)}</td><td>${esc(e.detail)}</td></tr>`).join('')+'</table>'+`<div class="note">탐지 ID <code>${esc(d.id)}</code>${d.exception_id?` · 예외 <code>${esc(d.exception_id)}</code>`:''}</div>`;
table('dett',[['시각',d=>fmtT(d.ts),d=>d.ts],['진단',d=>esc(d.diagnosis),d=>d.diagnosis],['기법',d=>esc(d.techniques),d=>d.techniques],
 ['단계',d=>arrow(d.stages),d=>d.stages],['공격자',d=>who(d.attacker),d=>d.attacker?d.attacker.ip:''],
 ['대상',d=>d.victims.map(who).join('<br>')||'-',d=>d.victims.length],['근거',d=>d.evidence_count,d=>d.evidence_count,'num'],
 ['처리',d=>d.disposition?`<span class="sup">${esc(d.disposition)}</span>`:'',d=>d.disposition||'']],single,{detail:evTable,filter:'detf'});
// 킬체인: 상관 탐지는 체인이 한 단계 길어질 때마다 새로 나온다. 기본은 공격자별로 다른 체인의 앞부분이 아닌 것(최종 체인)만.
const finalChains=chains.filter(c=>!chains.some(o=>o!==c&&o.attacker&&c.attacker&&o.attacker.ip===c.attacker.ip&&String(o.stages).length>String(c.stages).length&&String(o.stages).startsWith(String(c.stages))));
const chainCols=[['시각',d=>fmtT(d.ts),d=>d.ts],['단계',d=>`<span class="sus">${arrow(d.stages)}</span>`,d=>d.stages],['기법',d=>arrow(d.techniques),d=>d.techniques],
 ['공격자',d=>who(d.attacker),d=>d.attacker?d.attacker.ip:''],['대상',d=>d.victims.map(who).join('<br>')||'-',d=>d.victims.length],['근거',d=>d.evidence_count,d=>d.evidence_count,'num']];
const drawChains=()=>table('chaint',chainCols,document.getElementById('chainall').checked?chains:finalChains,{detail:evTable});
document.getElementById('chainall').onchange=drawChains;drawChains();
// 자산
const roleChips=a=>a.roles.map(r=>`<span class="chip">${esc(r)}</span>`).join('');
table('ast',[['관련 탐지',a=>a.detections?`<span class="sus">${a.detections}</span>`:'0',a=>a.detections,'num'],['이름',a=>esc(a.name)||`<span class="mut">${esc(a.id)||'-'}</span>`,a=>a.name||a.id],
 ['식별 키',a=>esc(a.key),a=>a.key],['IP',a=>a.ips.map(esc).join('<br>'),a=>a.ips.join()],['MAC',a=>a.macs.map(esc).join('<br>'),a=>a.macs.join()],
 ['OS',a=>esc(a.os),a=>a.os],['역할',roleChips,a=>a.roles.join()],['신호',a=>a.signals,a=>a.signals,'num']],D.assets,{filter:'asf'});
document.getElementById('asnote').innerHTML=D.asset_mode==='resolver'
 ?`자산 판정은 claudtest2 리졸버 결과입니다. 근거 신호 타임라인·식별 품질은 ${D.asset_report?`<a href="${esc(D.asset_report)}">자산 리포트</a>`:'자산 리포트'}를 보세요.`
 :`자산 판정 없이 IP별 신호만 보여 줍니다(run_pcap.sh -r &lt;claudtest2 경로&gt; 를 주면 자산 단위로 묶습니다). 신호 ${D.signal_rows}행: `+D.signal_counts.map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join('');
// 전송량
const mm=Math.max(1,...D.meta.map(m=>m.bytes));const mt=D.meta.reduce((a,b)=>a+b.bytes,0);
document.getElementById('xft').innerHTML=`<table><tr><th>구분</th><th class="num">바이트</th><th></th></tr>
 <tr><td><b>Manager 전송 합계</b></td><td class="num"><b>${fmtB(mgrTotal)}</b></td><td>${perDay?`하루 환산 약 ${fmtB(perDay)}/일 (단순 비례, 짧은 캡처는 과대평가)`:''}</td></tr>
 <tr><td>선별 전송(/log/zeek/meta)</td><td class="num">${fmtB(mt)}</td><td></td></tr>
 <tr><td>자산 신호(asset_signal)</td><td class="num">${fmtB(D.mgr.asset_signal)}</td><td></td></tr>
 <tr><td>탐지 로그(탐지·근거·예외)</td><td class="num">${fmtB(D.mgr.nsm_detection+D.mgr.evidence+D.mgr.nsm_exception)}</td><td></td></tr>
 <tr><td class="mut">센서 로컬 로그(notice·stats 등, 전송 안 함)</td><td class="num mut">${fmtB(Object.values(D.local).reduce((a,b)=>a+b,0))}</td><td></td></tr></table>
 <h2 style="margin-top:14px">선별 전송 로그별</h2><table><tr><th>로그</th><th class="num">바이트</th><th class="num">행</th><th></th></tr>`+
 D.meta.map(m=>`<tr><td>${esc(m.name)}</td><td class="num">${fmtB(m.bytes)}</td><td class="num">${m.rows.toLocaleString()}</td><td style="width:40%"><div class="bar" style="width:${100*m.bytes/mm}%"></div></td></tr>`).join('')+'</table>'+
 '<div class="note">전체 Zeek 로그 대비 비율과 처리 부하는 tests/measure_meta_export.sh 로 잽니다.</div>';
// 예외
const ek={};D.exceptions.forEach(e=>{const k=e.exception_id;ek[k]=ek[k]||{id:k,kinds:new Set(),hits:0,disp:e.disposition||'',scope:e.scope||'',msg:''};
 ek[k].kinds.add(e.kind);if(e.kind==='hits')ek[k].hits+=e.hits||0;if(e.scope)ek[k].scope=e.scope;if(e.disposition)ek[k].disp=e.disposition;if(e.msg&&e.kind!=='hits')ek[k].msg=e.msg});
table('exct',[['예외 ID',e=>`<code>${esc(e.id)}</code>`,e=>e.id],['상태',e=>[...e.kinds].filter(k=>k!=='hits').map(k=>`<span class="chip ${k==='rejected'||k==='error'?'sus':''}">${esc(k)}</span>`).join(''),e=>[...e.kinds].join()],
 ['처리',e=>esc(e.disp),e=>e.disp],['범위',e=>esc(e.scope),e=>e.scope],['적중(관측 수)',e=>e.hits.toLocaleString(),e=>e.hits,'num'],['비고',e=>esc(e.msg),e=>e.msg]],Object.values(ek));
// 센서
const S=D.sensor;document.getElementById('sent').innerHTML=`<table>
 <tr><td>최대 캡처 손실</td><td>${(S.capture_loss_max||0).toFixed(2)}% ${S.capture_loss_max>1?'<span class="sus">미러 손실 확인 필요</span>':''}</td></tr>
 <tr><td>탐지 외 notice</td><td>${S.other_notices.map(([k,v])=>`<span class="chip">${esc(k)} ${v}</span>`).join('')||'-'}</td></tr>
 <tr><td>Zeek 경고·오류</td><td>${S.warnings.length?S.warnings.map(w=>`<div class="sus"><code>${esc(w)}</code></div>`).join(''):'없음'}</td></tr></table>`;
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zeek_dir")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--assets", help="리졸버 assets.json(있으면 자산 단위)")
    ap.add_argument("--asset-report", help="리포트에서 링크할 자산 리포트 경로(report.html 기준 상대 경로)")
    ap.add_argument("--pcap", default="")
    ap.add_argument("--elapsed", type=int, default=0)
    ap.add_argument("--tz", type=float, default=9, help="표시 시간대 UTC 오프셋(시), 기본 9(KST)")
    ap.add_argument("--nets", default="", help="내부 대역(쉼표 구분, run_pcap.sh -n 과 같음). 사설 대역은 항상 내부로 본다")
    args = ap.parse_args()
    data = collect(args.zeek_dir, args.assets, args)
    blob = json.dumps(data, ensure_ascii=False, default=list).replace("</", "<\\/")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(PAGE.replace("__DATA__", blob))
    print(f"통합 리포트: {args.out} (탐지 {len(data['detections'])}건, 자산 {len(data['assets'])}개)")


if __name__ == "__main__":
    sys.exit(main())
