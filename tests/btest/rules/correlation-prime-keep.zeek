# @TEST-DOC: 상관 — 반복되는 정찰이 이미 더 진행된 체인의 다음 단계 대기를 덮어쓰지 않는다. 10.0.0.5 가 포트 스캔 -> HTTP 비커닝(2단계 체인) 뒤 다른 대상에 포트 스캔을 다시 하고 SMB 확산을 하면 3단계 체인(정찰 -> C2 -> 확산)이 된다(전에는 새 스캔의 1단계 체인이 대기를 덮어써 정찰 -> 확산 2단계로 쪼개졌다)
# @TEST-EXEC: zeek $PKG $SETUP %INPUT
# @TEST-EXEC: python3 check.py

module NSM;

redef exit_only_after_terminate = T;
# 운영에서는 두 번째 스캔이 묶기 창(1분) 뒤에 다시 탐지된다. 테스트 시간을 줄이려고 창을 짧게 둔다
redef dedup_window = 100msec;
redef table_expire_interval = 100msec;

global step: event(i: count);

event step(i: count)
	{
	if ( i == 0 )
		NOTICE([$note=Port_Scan, $src=10.0.0.5, $dst=10.0.0.9, $msg="scan 1", $identifier="t-scan-1"]);
	else if ( i == 1 )
		NOTICE([$note=HTTP_Beaconing, $src=10.0.0.5, $dst=203.0.113.5, $msg="beacon", $identifier="t-beacon"]);
	else if ( i == 2 )
		NOTICE([$note=Port_Scan, $src=10.0.0.5, $dst=10.0.0.11, $msg="scan 2", $identifier="t-scan-2"]);
	else if ( i == 3 )
		NOTICE([$note=SMB_Admin_Share, $src=10.0.0.5, $msg="smb", $identifier="t-smb",
		        $lm_targets=set(10.0.0.20, 10.0.0.21, 10.0.0.22)]);
	else
		{
		terminate();
		return;
		}
	schedule 300msec { step(i + 1) };
	}

event zeek_init()
	{
	schedule 200msec { step(0) };
	}

@TEST-START-FILE check.py
import json
rows = [json.loads(l) for l in open("nsm_detection.log") if l.strip()]
corr = [r for r in rows if r.get("category") == "Correlated" and r.get("attacker") == "10.0.0.5"]
assert corr, rows
best = max(corr, key=lambda r: len(r.get("killchain_stages", [])))
assert best["killchain_stages"] == ["Recon", "Command and Control", "Lateral Movement"], best
@TEST-END-FILE
