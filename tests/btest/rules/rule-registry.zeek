# @TEST-DOC: 룰 레지스트리(main.zeek rule_registry) — 모든 NSM notice 가 등록돼 있고(룰을 추가하면 한 줄), 진단명·ATT&CK·단계 형식이 맞다. 근거에 기법을 적지 않으면 레지스트리 값이 들어가고, 룰이 넣은 값은 그대로 둔다. 7단계 공격의 탐지·근거·notice 의 기법·단계·진단명이 레지스트리와 같다. 리포트(report_pcap DIAG_NOTE)도 같은 목록(schema/rules.json)을 쓴다
# @TEST-EXEC: zeek $PKG $SETUP %INPUT > out
# @TEST-EXEC: grep -qx 'registry ok' out
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t1 technique=T1046 killchain_stage=Recon
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t2 technique=T9999
# @TEST-EXEC: mkdir kc && cd kc && zeek -C -r $TRACES/killchain_story.pcap $PKG $SETUP && python3 ../check.py $SCHEMA/rules.json
# @TEST-EXEC: python3 -c "import json,sys;sys.path.insert(0,'$PKG/../tests');import report_pcap as r;j=json.load(open('$SCHEMA/rules.json'));assert len(r.DIAG_NOTE)==len(j)-1 and all(r.DIAG_NOTE[x['rule']]==x['diagnosis'].split('.')[-1] for x in j if x['rule']!='Correlated_KillChain')"

module NSM;

event zeek_init() &priority=-10
	{
	local bad: vector of string = vector();
	for ( name in enum_names(Notice::Type) )
		{
		if ( /^NSM::/ !in name )
			next;
		local v = lookup_ID(name);
		if ( ! ( v is Notice::Type ) || ( v as Notice::Type ) !in rule_registry )
			{
			bad += fmt("미등록 %s", name);
			next;
			}
		local ri = rule_registry[v as Notice::Type];
		if ( /^NSM\.[A-Za-z0-9]+(\.[A-Za-z0-9]+)?$/ !in ri$diagnosis )
			bad += fmt("진단명 %s %s", name, ri$diagnosis);
		if ( /^T[0-9]{4}(\.[0-9]{3})?(,T[0-9]{4}(\.[0-9]{3})?)*$/ !in ri$technique )
			bad += fmt("기법 %s %s", name, ri$technique);
		if ( name == "NSM::Correlated_KillChain" ? ri$stage != "" : ri$stage !in stage_tags )
			bad += fmt("단계 %s '%s'", name, ri$stage);
		}
	print |bad| == 0 ? "registry ok" : join_string_vec(bad, "\n");

	# 근거 기법: 적지 않으면 레지스트리 값, 룰이 넣으면 그 값
	write_evidence([$ts=network_time(), $evidence_id="t1", $note=Port_Scan, $src=10.0.0.1]);
	write_evidence([$ts=network_time(), $evidence_id="t2", $note=Port_Scan, $src=10.0.0.1, $technique="T9999"]);
	}

@TEST-START-FILE check.py
import json, sys
reg = {r["rule"]: r for r in json.load(open(sys.argv[1]))}
rows = lambda f: [json.loads(l) for l in open(f) if l.strip()]
n = 0
for e in rows("evidence.log"):
    if e["rule"] == "Correlated_KillChain":     # 상관 근거의 기법은 단계 흐름(T1046->T1190)
        continue
    r = reg[e["rule"]]
    assert e.get("technique") and set(e["technique"].split(",")) <= set(r["techniques"]), e
    assert e.get("killchain_stage") == r["stage"], e
    n += 1
for d in rows("nsm_detection.log"):
    if d["rule"] == "Correlated_KillChain":
        continue
    r = reg[d["rule"]]
    assert d["diagnosis"] == r["diagnosis"] and d["techniques"] == r["techniques"] and d["killchain_stages"] == [r["stage"]], d
    n += 1
for x in rows("notice.log"):
    rn = x["note"].split("::")[-1]
    if rn in reg and rn != "Correlated_KillChain":
        assert x["attack"] == ",".join(reg[rn]["techniques"]), x
        n += 1
assert n >= 30, n
@TEST-END-FILE
