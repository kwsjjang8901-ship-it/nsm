##! 자산 식별 신호(asset signal) 수집 프레임워크.
##!
##! 센서는 "판정"하지 않고 관측 사실(신호)만 남긴다. 자산 판정(엔티티 리졸루션)은
##! MDS Manager가 한다(PoC에서는 tools/asset_resolver.py가 대신한다).
##!
##! 신호 1건 = 로그 1줄:  (ts, ip, signal, value, source, confidence)
##! 동일 (ip, signal, value, source)는 suppress_interval 동안 한 번만 기록한다.
##!
##! 다른 탐지 스크립트에서 신호를 추가하려면 AssetID::emit()을 호출한다.

@load ./config

module AssetID;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## 신호 종류. 문자열 상수로 두어 Manager/리졸버와 그대로 공유한다.
	## 식별 키 (Manager 판정 우선순위 순)
	const MACHINE_ACCOUNT = "machine_account";  ##< domain\host$
	const DHCP_CLIENT_ID = "dhcp_client_id";    ##< DHCP option 61
	const MAC = "mac";
	const HOSTNAME = "hostname";                ##< 단축 호스트명(소문자)
	## 보조 정보
	const FQDN = "fqdn";
	const DOMAIN = "domain";
	const DNS_NAME = "dns_name";                ##< 일반 DNS 응답 이름(별칭 가능, 식별 키 아님)
	const USER_ACCOUNT = "user_account";
	const OS_HINT = "os_hint";
	const SOFTWARE = "software";
	const DHCP_VENDOR_CLASS = "dhcp_vendor_class";
	const DHCP_FINGERPRINT = "dhcp_fingerprint"; ##< option 55 파라미터 목록
	const SERVICE = "service";                  ##< 이 IP가 제공하는 서비스(proto/port[/app])
	const DEVICE = "device";                    ##< 장비/제품 종류(vmware-esxi, cisco-asa, ahnlab-mds 등)
	const SECURITY_AGENT = "security_agent";    ##< 단말에 설치된 보안 제품 통신(ahnlab:V3ES90ASD/5.6.0.55 등)
	const SSH_HOST_KEY = "ssh_host_key";        ##< SSH 서버 호스트 키 지문
	const SMB_CLIENT_GUID = "smb_client_guid";  ##< SMB2 NEGOTIATE ClientGuid (검증 중인 후보 키)
	const FORM_FACTOR = "form_factor";          ##< 기기 형태 힌트(phone, tablet, mobile). 장비 유형 판정은 Manager
	const TCP_FP = "tcp_fp";                    ##< TCP SYN·SYN-ACK 특징(TTL·윈도·옵션). OS 계열 추정 재료(판정은 Manager)

	type Info: record {
		## 관측 시각
		ts:         time   &log;
		## 근거 연결 uid (있을 때)
		uid:        string &log &optional;
		## 신호가 가리키는 자산 IP
		ip:         addr   &log;
		## 관측 시점의 MAC (알 때)
		mac:        string &log &optional;
		## 신호 종류 (위 상수)
		signal:     string &log;
		## 신호 값 (정규화됨)
		value:      string &log;
		## 신호 출처 (dhcp, kerberos, ntlm, arp, conn, nbns, ...)
		source:     string &log;
		## 출처 기준 신뢰도 0-100
		confidence: count  &log;
		## 계정 신호(user_account·machine_account)의 value 를 나눈 값.
		##   domain\user 는 (user, domain), user@realm 은 (user, realm). 도메인이 없으면 user_name 만.
		##   user_domain_type: 도메인에 점이 있으면 dns, 없으면 netbios. evidence.log 와 같은 규칙이다.
		user_name:        string &log &optional;
		user_domain:      string &log &optional;
		user_domain_type: string &log &optional;
	};

	## 신호를 기록한다. 중복 억제와 자산 대역 필터를 거친다.
	global emit: function(ip: addr, signal: string, value: string, source: string,
	                      confidence: count, uid: string &default="",
	                      mac: string &default=""): bool;

	## ip가 자산 신호 수집 대상인지.
	global is_asset_addr: function(ip: addr): bool;

	## 호스트명/도메인/계정 정규화: 공백·NUL·끝의 '.' 제거, 소문자.
	global normalize_name: function(s: string): string;

	## MAC 정규화: 소문자, 00:00:00:00:00:00/브로드캐스트는 빈 문자열.
	global normalize_mac: function(s: string): string;

	global log_asset_signal: event(rec: Info);
}

global recent: set[addr, string, string, string] &create_expire=suppress_interval;

event zeek_init() &priority=5
	{
	Log::create_stream(AssetID::LOG, [$columns=Info, $ev=log_asset_signal,
	                                  $path="asset_signal", $policy=log_policy]);
	}

function is_asset_addr(ip: addr): bool
	{
	if ( ip == 0.0.0.0 || ip == 255.255.255.255 || ip == [::] )
		return F;

	if ( ip in 224.0.0.0/4 || ip in [ff00::]/8 )
		return F;

	if ( |asset_nets| > 0 )
		return ip in asset_nets;

	if ( |Site::local_nets| > 0 )
		return Site::is_local_addr(ip);

	return ip in Site::private_address_space;
	}

function normalize_name(s: string): string
	{
	local r = to_lower(strip(gsub(s, /\x00/, "")));

	while ( |r| > 0 && r[-1] == "." )
		r = r[:-1];

	return r;
	}

function normalize_mac(s: string): string
	{
	local m = to_lower(strip(s));

	if ( m == "" || m == "00:00:00:00:00:00" || m == "ff:ff:ff:ff:ff:ff" )
		return "";

	return m;
	}

# 계정 값을 사용자·도메인으로 나눠 rec 에 채운다(nsm_rules 의 NSM::split_account 와 같은 규칙).
#   자산 식별 패키지는 단독으로도 쓰이므로 따로 둔다.
function split_account(rec: Info)
	{
	local a = rec$value;
	local user = a;
	local domain = "";
	local p: string_vec;

	if ( /\\/ in a )
		{
		p = split_string1(a, /\\/);
		domain = p[0];
		user = p[1];
		}
	else if ( /@/ in a )
		{
		p = split_string1(a, /@/);
		user = p[0];
		domain = p[1];
		}

	if ( user == "" )
		return;

	rec$user_name = user;

	if ( domain != "" )
		{
		rec$user_domain = domain;
		rec$user_domain_type = /\./ in domain ? "dns" : "netbios";
		}
	}

function emit(ip: addr, signal: string, value: string, source: string,
              confidence: count, uid: string &default="",
              mac: string &default=""): bool
	{
	if ( value == "" || ! is_asset_addr(ip) )
		return F;

	if ( signal == HOSTNAME && value in ignore_hostnames )
		return F;

	if ( [ip, signal, value, source] in recent )
		return F;

	add recent[ip, signal, value, source];

	local rec = Info($ts=network_time(), $ip=ip, $signal=signal, $value=value,
	                 $source=source, $confidence=confidence);

	if ( uid != "" )
		rec$uid = uid;

	if ( mac != "" )
		rec$mac = mac;

	if ( signal == USER_ACCOUNT || signal == MACHINE_ACCOUNT )
		split_account(rec);

	Log::write(AssetID::LOG, rec);
	return T;
	}
