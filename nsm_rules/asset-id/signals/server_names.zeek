##! 서버 이름 신호: 클라이언트가 서버에 접속할 때 쓴 이름.
##!   SMB 공유 경로(\\server\share), TLS SNI, HTTP Host -> 응답측 IP의 dns_name
##!   Kerberos 서비스 티켓(AP-REQ)의 서비스 이름(cifs/fs01.corp.local) -> 응답측 IP의 dns_name, 티켓 realm -> domain
##!
##! 서버 소프트웨어: HTTP 응답 Server 헤더 -> 응답측 IP의 software("http_server:..."), os_hint(IIS 버전 등)
##!
##! 별칭(CNAME, DFS, 가상 호스트)일 수 있으므로 식별 키가 아니라 표시용 이름이다.
##!
##! 프록시를 거친 요청(CONNECT, 절대 URL)의 Host/SNI는 외부 사이트 이름이므로 제외한다.
##! 그래도 이름이 몰리는 IP(프록시, 로드밸런서)는 max_server_names 개까지만 기록한다.

@load base/protocols/smb
@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/krb
@load ../main

module AssetID;

## 프록시 요청이 지나간 연결 uid.
global proxied_conns: set[string] &create_expire=1hr;

## IP별로 기록한 서버 이름 수.
global server_name_count: table[addr] of count &default=0 &create_expire=suppress_interval;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	if ( method == "CONNECT" || /^[a-zA-Z]+:\/\// in original_URI )
		add proxied_conns[c$uid];
	}

function server_name(ip: addr, name: string, source: string, uid: string)
	{
	if ( ! enable_server_names || uid in proxied_conns )
		return;

	if ( server_name_count[ip] >= max_server_names )
		return;

	local n = normalize_name(name);

	# IP 주소, 포트가 붙은 값, 빈 값은 이름이 아니다.
	n = split_string1(n, /:/)[0];
	if ( n == "" || is_valid_ip(n) || /^\[/ in n )
		return;

	if ( emit(ip, DNS_NAME, n, source, 50, uid) )
		++server_name_count[ip];
	}

## "\\\\server\\share" -> "server"
function unc_server(path: string): string
	{
	local p = sub(path, /^\\\\+/, "");
	return split_string1(p, /\\/)[0];
	}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
	{
	server_name(c$id$resp_h, unc_server(path), "smb", c$uid);
	}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
	{
	server_name(c$id$resp_h, unc_server(path), "smb", c$uid);
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
	{
	if ( is_client && |names| > 0 )
		server_name(c$id$resp_h, names[0], "tls", c$uid);
	}

## Server 헤더에서 OS 계열. IIS 버전은 Windows 버전과 짝이 정해져 있다(같은 버전의 클라이언트 Windows도 있지만
## 다른 PC에 웹 응답을 주는 쪽은 대부분 서버다).
function http_server_os(v: string): string
	{
	if ( /^Microsoft-IIS\// in v )
		{
		switch ( v[14:] ) {
		case "10.0": return "windows server 2016+";
		case "8.5": return "windows server 2012 r2";
		case "8.0": return "windows server 2012";
		case "7.5": return "windows server 2008 r2";
		case "7.0": return "windows server 2008";
		case "6.0": return "windows server 2003";
		default: return "windows";
		}
		}

	if ( /^Microsoft-HTTPAPI\// in v )
		return "windows";

	# Apache 등은 괄호 안에 배포판을 붙인다: "Apache/2.4.52 (Ubuntu)"
	local l = to_lower(v);
	for ( _, os in vector("ubuntu", "debian", "centos", "red hat", "rocky") )
		if ( strstr(l, "(" + os) > 0 )
			return "linux(" + sub(os, / /, "") + ")";
	if ( /\((win32|win64)\)/ in l )
		return "windows";

	return "";
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( is_orig && name == "HOST" )
		server_name(c$id$resp_h, value, "http", c$uid);

	# 프록시를 거친 요청의 응답 Server 헤더는 외부 사이트의 것이라 프록시 IP에 붙이지 않는다.
	if ( is_orig || name != "SERVER" || ! enable_http_server || c$uid in proxied_conns )
		return;

	local v = strip(value);
	if ( v == "" )
		return;

	local ip = c$id$resp_h;
	emit(ip, SOFTWARE, "http_server:" + v[:64], "http_server", 50, c$uid);
	emit(ip, OS_HINT, http_server_os(v), "http_server", 45, c$uid);
	}

## Kerberos 서비스 이름("cifs/fs01.corp.local", "MSSQLSvc/db01.corp.local:1433",
## "ldap/dc01.corp.local/corp.local")에서 호스트 부분. 서버 자신의 이름이 아니면 빈 문자열.
function spn_host(spn: string, realm: string): string
	{
	local parts = split_string(spn, /\//);
	if ( |parts| < 2 )
		return "";

	# 티켓 발급 서버(krbtgt), 암호 변경(kadmin)은 서버 이름이 아니다.
	local svc = to_lower(parts[0]);
	if ( svc == "krbtgt" || svc == "kadmin" )
		return "";

	# 도메인 이름 자체로 받은 티켓(DFS 도메인 루트 cifs/corp.local)은 특정 서버 이름이 아니다.
	local host = split_string1(normalize_name(parts[1]), /:/)[0];
	if ( host == realm )
		return "";

	return host;
	}

# 클라이언트가 서버(SMB, LDAP, MSSQL 등)에 보낸 서비스 티켓. 티켓 안 사용자 정보는 암호화돼 있어
# 서버 쪽 이름·도메인만 나온다. 라우팅 구간(DC가 안 보이는 사용자 -> 서버 구간)에서도 보인다.
event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{
	if ( ! enable_server_names || ! ticket?$service_name )
		return;

	local realm = ticket?$realm ? normalize_name(ticket$realm) : "";
	local host = spn_host(ticket$service_name, realm);
	if ( host == "" )
		return;

	local ip = c$id$resp_h;
	server_name(ip, host, "krb", c$uid);

	if ( realm != "" )
		emit(ip, DOMAIN, realm, "krb", 70, c$uid);
	}
