# @TEST-DOC: 연결 참조(NSM::conn_ref) 풀기와 detail 값 올리기 단위 검사 — 근거 src 가 연결의 응답 쪽이면 포트 방향을 바꾼다, IPv6, 알 수 없는 프로토콜·참조가 아닌 uid 는 uid 만, Community ID 는 스펙 값(Zeek community_id_v1 과 Python 계산이 같은 값), 룰이 직접 넣은 필드가 우선, 이름의 포트·끝 점·대소문자 정리와 IP 이름 제외, 기록된 uid 에 참조가 남지 않음
# @TEST-EXEC: zeek $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-orig uid=Ca src_port=50000 dst_port=445 proto=tcp community_id=1:dkHwIWRbwJI8sKS6IQSrm0g0MEk=
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-resp uid=Ca src_port=445 dst_port=50000 proto=tcp community_id=1:dkHwIWRbwJI8sKS6IQSrm0g0MEk=
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-v6 uid=Cb src_port=5353 dst_port=53 proto=udp community_id=1:sEzqFsMvqwEs2PgSeOAwGpzkZJo=
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-badproto uid=Cc src_port=- proto=- community_id=-
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-plain uid=Cd src_port=- community_id=-
# @TEST-EXEC: python3 -c "import json;assert not [l for l in open('evidence.log') if '~' in json.loads(l).get('uid','')]"
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-dns dst_name=evil.example bytes=123 window_s=600.000000 proxy=10.0.0.5:3128
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-explicit dst_name=set.example
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-host dst_name=foo.example.com
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-iphost dst_name=-
# @TEST-EXEC: assert-rows evidence.log eq 1 evidence_id=t-sni dst_name=api.example.net

event zeek_init()
	{
	local tok = "Ca~10.0.0.1~50000~10.0.0.2~445~tcp";
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-orig", $note=NSM::SMB_Admin_Share, $src=10.0.0.1, $dst=10.0.0.2, $uid=tok]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-resp", $note=NSM::Name_Poisoning, $src=10.0.0.2, $dst=10.0.0.1, $uid=tok]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-v6", $note=NSM::DNS_Tunneling, $src=[2001:db8::1], $uid="Cb~2001:db8::1~5353~2001:db8::2~53~udp"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-badproto", $note=NSM::Port_Scan, $uid="Cc~10.0.0.1~1~10.0.0.2~2~xyz"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-plain", $note=NSM::Port_Scan, $uid="Cd"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-dns", $note=NSM::DNS_Tunneling,
	                     $detail="query=aGVsbG8.evil.example parent=evil.example window=10.0 mins sum_bytes=123 via_proxy=10.0.0.5:3128"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-explicit", $note=NSM::Encrypted_C2, $dst_name="set.example", $detail="sni=other.example"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-host", $note=NSM::HTTP_Beaconing, $detail="interval=30.0s host=Foo.Example.COM.:8443"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-iphost", $note=NSM::Encrypted_C2, $detail="sni=- host=93.184.215.170"]);
	NSM::write_evidence([$ts=network_time(), $evidence_id="t-sni", $note=NSM::AI_API_From_Server, $detail="service=openai sni=API.example.net host=other.example"]);
	}
