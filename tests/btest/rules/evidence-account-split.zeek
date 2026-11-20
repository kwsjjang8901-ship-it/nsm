# @TEST-DOC: evidence.log 계정 분리(user_name·user_domain·user_domain_type) — NTLM 계정 corp\admin01 은 (admin01, corp, netbios), Kerberos 계정 opsadmin@corp.example 은 (opsadmin, corp.example, dns), 계정이 없는 근거는 세 칸 모두 없음. 분리 함수는 대문자·앞뒤 공백·도메인 없는 계정도 같은 규칙으로 나눈다
# @TEST-EXEC: zeek -C -r $TRACES/lateral_auth.pcap $PKG $SETUP %INPUT > split.out
# @TEST-EXEC: assert-rows evidence.log eq 3 account=corp\\admin01 user_name=admin01 user_domain=corp user_domain_type=netbios
# @TEST-EXEC: assert-rows evidence.log eq 3 account=opsadmin@corp.example user_name=opsadmin user_domain=corp.example user_domain_type=dns
# @TEST-EXEC: assert-rows evidence.log eq 3 account=- user_name=- user_domain=- user_domain_type=-
# @TEST-EXEC: assert-rows evidence.log eq 0 user_name=- account=corp\\admin01
# @TEST-EXEC: grep -qxF 'CORP\Kim.JH|kim.jh|corp|netbios' split.out
# @TEST-EXEC: grep -qxF ' User01@Corp.Example |user01|corp.example|dns' split.out
# @TEST-EXEC: grep -qxF 'administrator|administrator||' split.out
# @TEST-EXEC: grep -qxF 'pc01$@corp.example|pc01$|corp.example|dns' split.out

event zeek_init()
	{
	for ( _i, a in vector("CORP\\Kim.JH", " User01@Corp.Example ", "administrator", "pc01$@corp.example") )
		{
		local p = NSM::split_account(a);
		print fmt("%s|%s|%s|%s", a, p$user, p$domain, p$domain_type);
		}
	}
