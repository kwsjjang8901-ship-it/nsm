##! 고객 정의 에이전트 정책: 고객이 원하는 제품(EDR, 백신 관리 서버, 패치·자산관리, NAC, DLP 등)의
##! 에이전트 통신을 정책 파일로 정의하고, 맞는 통신이 보인 단말에 security_agent "policy:<id>" 를 남긴다.
##!
##! 정책 파일(agent_policy_file, TSV, 비어 있으면 꺼짐):
##!   #fields id product server ports domain user_agent min_ports device
##!     id          정책 id (영문·숫자·._-). 신호 값은 "policy:<id>"
##!     product     화면에 보일 제품명(센서는 로그에만 씀)
##!     server      관리 서버 주소·대역, 쉼표로 여러 개 (예 10.1.2.30,10.1.3.0/24)
##!     ports       에이전트 포트, 쉼표로 여러 개 (예 8443/tcp,443). 프로토콜을 안 적으면 tcp
##!     domain      접속 도메인(하위 도메인 포함), 쉼표로 여러 개. TLS SNI, HTTP Host, 프록시 CONNECT 대상과 맞춤
##!     user_agent  HTTP User-Agent 에 들어 있어야 하는 문자열(대소문자 무시)
##!     min_ports   같은 서버의 서로 다른 포트를 몇 개 이상 봐야 하는지(연결 정책만, 기본 1, 서버 없이 포트만이면 2 이상)
##!     device      서버 IP 에 남길 device 값(선택, 서버 주소를 적은 정책만)
##!
##! 맞추는 방식(적은 조건은 모두 맞아야 함):
##!   연결 정책(domain·user_agent 없음): 연결 성립(SYN-ACK)이 server·ports 에 맞고,
##!     agent_policy_window 안에 같은 서버의 서로 다른 포트 min_ports 개 이상.
##!   앱 정책(domain 또는 user_agent 있음): TLS SNI 또는 HTTP 요청이 domain·user_agent 에 맞고,
##!     적었다면 연결의 응답측이 server·ports 에도 맞음. 프록시를 거치면 응답측이 프록시이므로
##!     도메인 정책에는 보통 server 를 적지 않는다.
##!
##! 신뢰도: 서버 주소가 맞음 90, 도메인·User-Agent 가 맞음 80, 서버 없이 포트 수로만 70.
##! 신호가 없는 단말이 미설치라는 뜻은 아니다(센서가 그 경로를 못 보거나, 관측 시간이 보고 주기보다 짧을 수 있음).
##! 미설치 후보 판정은 Manager 가 대상 범위·관측 구간과 함께 한다(SPEC 3.17).

@load base/frameworks/input
@load base/frameworks/files
@load base/files/hash
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load ../main

module AssetID;

export {
	redef enum Log::ID += { POLICY_LOG };

	type PolicyLogInfo: record {
		ts:        time   &log;
		## summary(읽은 결과), invalid(형식이 틀려 뺀 정책), error(파일 읽기 오류), file(파일 지문)
		kind:      string &log;
		policy_id: string &log &optional;
		## kind=file 은 파일 경로
		msg:       string &log;
		## kind=file: 읽은 정책 파일의 SHA1(다시 읽을 때마다 한 행). Manager 가 배포한 파일과 비교한다
		file_sha1: string &log &optional;
	};

	## 마지막으로 읽은 정책 파일의 SHA1(센서 상태 로그용)
	global agent_policy_sha1 = "";
}

type PolicyIdx: record {
	id: string;
};

type PolicyVal: record {
	product:    string &optional;
	server:     string &optional;
	ports:      string &optional;
	domain:     string &optional;
	user_agent: string &optional;
	min_ports:  count  &optional;
	device:     string &optional;
};

## 해석한 정책
type AgentPolicy: record {
	id:        string;
	servers:   set[subnet];
	ports:     set[port];
	domains:   set[string];
	ua:        string;        ##< 소문자, 빈 값이면 조건 없음
	min_ports: count;
	device:    string;
	app:       bool;          ##< domain 또는 user_agent 가 있음
};

const POLICY_STREAM = "assetid-agent-policy";

global policy_file_recs: table[string] of PolicyVal = table();
global agent_policies: table[string] of AgentPolicy = table();
global policy_waiting_initial = F;

## (단말, 서버, 정책) -> 연결이 성립한 포트
global policy_pair_ports: table[addr, addr, string] of set[port] &create_expire=agent_policy_window;
## 이미 기록한 (단말, 정책)
global policy_done: set[addr, string] &create_expire=agent_policy_window;

function policy_log(kind: string, id: string, msg: string)
	{
	# 적재 결과 행은 실제 시각(트래픽을 읽기 전에도 0 이 아님)
	local r = PolicyLogInfo($ts=current_time(), $kind=kind, $msg=msg);
	if ( id != "" )
		r$policy_id = id;
	Log::write(POLICY_LOG, r);
	}

function policy_items(s: string): vector of string
	{
	local out: vector of string = vector();
	for ( _, x in split_string(s, /,/) )
		{
		x = strip(x);
		if ( x != "" && x != "-" )
			out += x;
		}
	return out;
	}

## 정책 한 줄 해석. 틀리면 이유를 돌려준다(빈 문자열이면 정상).
function policy_parse(id: string, v: PolicyVal, p: AgentPolicy): string
	{
	if ( /^[A-Za-z0-9_.\-]+$/ != id )
		return "id 는 영문·숫자·._- 만 쓸 수 있음";

	if ( v?$server )
		for ( _, x in policy_items(v$server) )
			{
			if ( is_valid_ip(x) )
				add p$servers[to_subnet(x + (/:/ in x ? "/128" : "/32"))];
			else if ( /\// in x && is_valid_ip(split_string1(x, /\//)[0]) )
				add p$servers[to_subnet(x)];
			else
				return "server 값이 주소·대역이 아님: " + x;
			}

	if ( v?$ports )
		for ( _, x in policy_items(v$ports) )
			{
			local px = /\// in x ? to_lower(x) : x + "/tcp";
			if ( /^[0-9]+\/(tcp|udp)$/ != px || to_count(split_string1(px, /\//)[0]) > 65535 )
				return "ports 값이 포트가 아님: " + x;
			add p$ports[to_port(px)];
			}

	if ( v?$domain )
		for ( _, x in policy_items(v$domain) )
			{
			local d = sub(sub(to_lower(x), /^\*\./, ""), /\.$/, "");
			if ( /^[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?)+$/ != d )
				return "domain 값이 도메인이 아님: " + x;
			add p$domains[d];
			}

	if ( v?$user_agent && strip(v$user_agent) != "" && v$user_agent != "-" )
		p$ua = to_lower(strip(v$user_agent));

	if ( v?$device && v$device != "-" )
		p$device = to_lower(strip(v$device));

	p$app = |p$domains| > 0 || p$ua != "";

	if ( ! p$app && |p$servers| == 0 && |p$ports| == 0 )
		return "server, ports, domain, user_agent 중 하나는 있어야 함";

	# 서버 주소 없이 포트만으로는 다른 제품과 겹치기 쉽다(8291: MDS Agent 와 MikroTik Winbox).
	local min = v?$min_ports ? v$min_ports : 0;
	if ( ! p$app && |p$servers| == 0 )
		{
		if ( min == 0 )
			min = 2;
		if ( min < 2 )
			return "서버 주소 없이 포트만 적은 정책은 min_ports 가 2 이상이어야 함";
		if ( min > |p$ports| )
			return "min_ports 가 적은 포트 수보다 큼";
		}
	p$min_ports = min == 0 ? 1 : min;

	if ( p$device != "" && |p$servers| == 0 )
		return "device 는 server 를 적은 정책에만 쓸 수 있음";

	return "";
	}

function policy_sync()
	{
	local fresh: table[string] of AgentPolicy = table();
	local invalid = 0;

	for ( id, v in policy_file_recs )
		{
		local p = AgentPolicy($id=id, $servers=set(), $ports=set(), $domains=set(), $ua="",
		                      $min_ports=1, $device="", $app=F);
		local err = policy_parse(id, v, p);
		if ( err != "" )
			{
			++invalid;
			policy_log("invalid", id, err);
			next;
			}
		fresh[id] = p;
		}

	agent_policies = fresh;
	policy_log("summary", "", fmt("active=%d invalid=%d", |fresh|, invalid));
	}

function policy_release_wait()
	{
	if ( policy_waiting_initial )
		{
		policy_waiting_initial = F;
		continue_processing();
		}
	}

event policy_input_error(desc: Input::TableDescription, message: string, level: Reporter::Level)
	{
	policy_log("error", "", message);
	policy_release_wait();
	}

# 정책 파일 SHA1: 다 읽은 뒤 같은 파일을 파일 분석 프레임워크로 한 번 더 읽어 계산한다(sha1sum 과 같은 값).
#   nsm_rules 의 NSM::hash_data_file 과 같은 방식이다(자산 식별은 단독으로도 쓰이므로 따로 둔다).
global policy_hash_names: set[string] &create_expire=1hr;
global policy_hash_seq = 0;

function policy_hash_file()
	{
	++policy_hash_seq;
	local nm = fmt("assetid-agent-policy-%d", policy_hash_seq);
	add policy_hash_names[nm];
	Input::add_analysis([$source=agent_policy_file, $name=nm]);
	}

event file_new(f: fa_file)
	{
	if ( f?$source && f$source in policy_hash_names )
		Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( kind != "sha1" || ! f?$source || f$source !in policy_hash_names )
		return;
	agent_policy_sha1 = hash;
	Log::write(POLICY_LOG, PolicyLogInfo($ts=current_time(), $kind="file", $msg=agent_policy_file, $file_sha1=hash));
	}

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$source && rec$source in policy_hash_names )
		break;
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name != POLICY_STREAM )
		return;
	policy_sync();
	policy_release_wait();
	policy_hash_file();
	}

event zeek_init() &priority=5
	{
	Log::create_stream(POLICY_LOG, [$columns=PolicyLogInfo, $path="asset_agent_policy"]);
	}

event zeek_init() &priority=-10
	{
	if ( ! enable_agent_policy || agent_policy_file == "" )
		return;
	# pcap 을 읽을 때는 정책을 다 읽을 때까지 패킷 처리를 멈춘다(실시간 센서는 멈추지 않음).
	if ( reading_traces() )
		{
		policy_waiting_initial = T;
		suspend_processing();
		}
	Input::add_table([$source=agent_policy_file, $name=POLICY_STREAM, $idx=PolicyIdx, $val=PolicyVal,
	                  $destination=policy_file_recs, $mode=Input::REREAD, $error_ev=policy_input_error]);
	}

# ---------------------------------------------------------------- 맞추기

function policy_hit(p: AgentPolicy, c: connection, conf: count)
	{
	local cl = c$id$orig_h;
	if ( [cl, p$id] in policy_done )
		return;
	add policy_done[cl, p$id];

	emit(cl, SECURITY_AGENT, "policy:" + p$id, "agent_policy", conf, c$uid);
	if ( p$device != "" )
		emit(c$id$resp_h, DEVICE, p$device, "agent_policy", conf - 10, c$uid);
	}

## 응답측이 server·ports 조건에 맞는지(적지 않은 조건은 통과)
function policy_conn_ok(p: AgentPolicy, c: connection): bool
	{
	if ( |p$servers| > 0 && c$id$resp_h !in p$servers )
		return F;
	if ( |p$ports| > 0 && c$id$resp_p !in p$ports )
		return F;
	return T;
	}

function policy_domain_ok(p: AgentPolicy, host: string): bool
	{
	if ( |p$domains| == 0 )
		return T;
	if ( host == "" )
		return F;

	local h = sub(split_string1(to_lower(host), /:/)[0], /\.$/, "");
	for ( d in p$domains )
		if ( h == d || ( |h| > |d| && h[|h| - |d| - 1:] == "." + d ) )
			return T;
	return F;
	}

function policy_ua_ok(p: AgentPolicy, ua: string): bool
	{
	return p$ua == "" || strstr(to_lower(ua), p$ua) > 0;
	}

## 앱 정책: TLS SNI(ua 없음) 또는 HTTP 요청(host, ua)
function policy_app(c: connection, host: string, ua: string, is_http: bool)
	{
	if ( ! enable_agent_policy )
		return;

	for ( id, p in agent_policies )
		{
		if ( ! p$app || [c$id$orig_h, id] in policy_done )
			next;
		# User-Agent 조건은 평문 HTTP 요청에서만 확인할 수 있다.
		if ( p$ua != "" && ! is_http )
			next;
		if ( ! policy_conn_ok(p, c) || ! policy_domain_ok(p, host) || ! policy_ua_ok(p, ua) )
			next;
		policy_hit(p, c, |p$servers| > 0 ? 90 : 80);
		}
	}

event connection_established(c: connection)
	{
	if ( ! enable_agent_policy || |agent_policies| == 0 )
		return;

	local cl = c$id$orig_h;
	local sv = c$id$resp_h;

	for ( id, p in agent_policies )
		{
		if ( p$app || [cl, id] in policy_done || ! policy_conn_ok(p, c) )
			next;

		if ( p$min_ports > 1 )
			{
			if ( [cl, sv, id] !in policy_pair_ports )
				policy_pair_ports[cl, sv, id] = set();
			add policy_pair_ports[cl, sv, id][c$id$resp_p];
			if ( |policy_pair_ports[cl, sv, id]| < p$min_ports )
				next;
			delete policy_pair_ports[cl, sv, id];
			}

		policy_hit(p, c, |p$servers| > 0 ? 90 : 70);
		}
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
	{
	if ( is_client && |names| > 0 && |agent_policies| > 0 )
		policy_app(c, names[0], "", F);
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! is_orig || ! c?$http || |agent_policies| == 0 )
		return;
	policy_app(c, c$http?$host ? c$http$host : "", c$http?$user_agent ? c$http$user_agent : "", T);
	}
