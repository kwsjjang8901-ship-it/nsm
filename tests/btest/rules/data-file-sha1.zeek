# @TEST-DOC: 데이터 파일 지문(X1) — 예외·IOC·에이전트 정책 파일을 읽으면 각 로그에 kind=file 행(파일 경로, sha1sum 과 같은 SHA1)이 남고, 센서 상태 로그에도 같은 SHA1 이 실린다. 적재 결과 행(loaded·summary)의 시각은 실제 시각(트래픽 전에도 0 이 아님)이고 적중(hits)은 패킷 시각. 지문 계산용 파일 분석은 files.log 에 남지 않는다(원본 로그를 모두 켜도)
# @TEST-EXEC: zeek -C -r $TRACES/ioc.pcap $PKG $SETUP $FILES/keep-all-logs.zeek %INPUT NSM::ioc_file=ioc.tsv NSM::exception_file=exc.tsv AssetID::agent_policy_file=policy.tsv
# @TEST-EXEC: python3 check.py

redef AssetID::enable_agent_policy = T;

# @TEST-START-FILE check.py
import hashlib, json, os, time

def rows(p):
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []

sha = {f: hashlib.sha1(open(f, "rb").read()).hexdigest() for f in ("exc.tsv", "ioc.tsv", "policy.tsv")}
now = time.time()
for log, f in (("nsm_exception.log", "exc.tsv"), ("nsm_ioc.log", "ioc.tsv"), ("asset_agent_policy.log", "policy.tsv")):
    fr = [r for r in rows(log) if r["kind"] == "file"]
    assert len(fr) == 1 and fr[0]["file_sha1"] == sha[f] and fr[0]["msg"] == f, (log, fr, sha[f])
    assert abs(fr[0]["ts"] - now) < 600, (log, fr[0]["ts"])
# 적재 결과는 실제 시각, 적중은 패킷 시각(ioc.pcap 은 2026-11 합성 시각)
exc = rows("nsm_exception.log")
assert [r for r in exc if r["kind"] == "loaded"] and all(abs(r["ts"] - now) < 600 for r in exc if r["kind"] in ("loaded", "rejected", "file"))
assert all(r["ts"] > 0 for r in rows("nsm_ioc.log") + rows("asset_agent_policy.log"))
# 센서 상태 로그의 지문
st = rows("nsm_sensor.log")
assert st and st[-1].get("exc_sha1") == sha["exc.tsv"] and st[-1].get("ioc_sha1") == sha["ioc.tsv"] and st[-1].get("policy_sha1") == sha["policy.tsv"], st[-1]
# 지문 계산용 파일 분석은 files.log 에 없음
assert not [r for r in rows("files.log") if str(r.get("source", "")).startswith(("nsm-datafile", "assetid-agent-policy"))]
print("ok")
# @TEST-END-FILE

# @TEST-START-FILE ioc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	indicator	ioc_type	source	category	expires	desc
93.184.216.66	ip	test-feed	c2	-	C2 서버
evil-ioc.example	domain	test-feed	c2	-	C2 도메인
# @TEST-END-FILE

# @TEST-START-FILE exc.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	scope	src	dst	dst_port	service	domain	ja4	disposition	reason	owner	expires	ref
E-ioc-20	IOC_Match	10.0.42.20/32	-	-	-	-	-	drop	시험용 예외	admin	-	-
# @TEST-END-FILE

# @TEST-START-FILE policy.tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	id	product	server	ports	domain	user_agent	min_ports	device
ep-mgr	사내 백신 관리 서버	10.0.55.5	8443/tcp	-	-	-	epp-server
# @TEST-END-FILE
