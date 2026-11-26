# @TEST-DOC: [23] DC 자동 학습 — Kerberos 로 응답한 서로 다른 내부 클라이언트가 3대(dcsync_learn_min_clients) 이상이어야 DC 로 배운다. 응답 한 번(공격 host 가 Kerberos 응답을 흉내)으로는 DC 가 되지 않아 그 host 의 DCSync 가 면제되지 않는다. 같은 클라이언트가 여러 번 받아도 1대로 센다
# @TEST-EXEC: zeek $PKG $SETUP %INPUT > out
# @TEST-EXEC: grep -qx 'dc 1=F 2=F 3=T' out
# @TEST-EXEC: grep -qx 'attacker same-client=F' out

module NSM;

event zeek_init() &priority=-10
	{
	local r: vector of string = vector();
	for ( i in vector(10.0.1.1, 10.0.1.2, 10.0.1.3) )
		{
		dcsync_learn_addr(10.0.0.10, vector(10.0.1.1, 10.0.1.2, 10.0.1.3)[i]);
		r += fmt("%d=%s", i + 1, dcsync_is_dc(10.0.0.10) ? "T" : "F");
		}
	print "dc " + join_string_vec(r, " ");
	for ( _j in vector(1, 2, 3, 4, 5) )
		dcsync_learn_addr(10.0.0.66, 10.0.1.9);     # 같은 클라이언트 한 대에 여러 번
	print fmt("attacker same-client=%s", dcsync_is_dc(10.0.0.66) ? "T" : "F");
	}
