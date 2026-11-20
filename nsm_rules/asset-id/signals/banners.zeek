##! 서비스 배너 신호: 지문 대조(Recog) 입력용 원문. 응답한 쪽(서버·장비) IP 에 software 로 남긴다.
##!
##!   HTTP 401 WWW-Authenticate (Basic·Digest realm만) -> "http_wwwauth:Basic realm=\"Router\""  (Recog http_wwwauth)
##!   SIP User-Agent·Server 헤더(보낸 쪽)            -> "sip_ua:…", "sip_server:…"            (sip_user_agents, sip_banners)
##!   FTP·SMTP 접속 인사(첫 220 응답 본문)            -> "ftp_banner:…", "smtp_banner:…"       (ftp_banners, smtp_banners)
##!   (POP3 접속 인사, MySQL 서버 버전은 banners_extra.zeek)
##!
##! 연결마다 처음 한 번만 본다. 여기 이벤트는 모두 Zeek 기본 스크립트가 이미 처리하는 것이라 추가 부하가 작다
##! (해당 프로토콜만 있는 최악 조건 측정에서 +2.8%, SPEC 3.20).
##! Negotiate·NTLM·Bearer 인증 값은 연결마다 바뀌는 토큰이라 남기지 않는다. 프록시 경유 응답은 외부 사이트 것이라 뺀다.
##! IMAP 은 Zeek 가 접속 인사를 이벤트로 주지 않아 대상이 아니다.

@load base/protocols/http
@load base/protocols/sip
@load base/protocols/ftp
@load base/protocols/smtp
@load ./server_names
@load ../main

module AssetID;

## 이미 본 (연결 uid, 종류)
global banner_done: set[string, string] &create_expire=1hr;

function banner_once(c: connection, kind: string): bool
	{
	if ( [c$uid, kind] in banner_done )
		return F;
	add banner_done[c$uid, kind];
	return T;
	}

## 제어 문자를 공백으로, 앞뒤 공백 제거, n 자로 자름. 비면 빈 문자열(emit 이 버림).
function banner_val(prefix: string, v: string, n: count): string
	{
	local x = strip(gsub(v, /[\x00-\x1f]+/, " "));
	return x == "" ? "" : prefix + x[:n];
	}

## WWW-Authenticate 에서 Basic 은 그대로, Digest 는 realm 만. 그 밖(Negotiate·NTLM·Bearer)은 빈 문자열.
function wwwauth_val(v: string): string
	{
	local x = strip(v);
	if ( /^[Bb][Aa][Ss][Ii][Cc]( |$)/ in x )
		return x;
	if ( /^[Dd][Ii][Gg][Ee][Ss][Tt] / in x && /[Rr][Ee][Aa][Ll][Mm]=\"[^\"]*\"/ in x )
		return "Digest " + find_all_ordered(x, /[Rr][Ee][Aa][Ll][Mm]=\"[^\"]*\"/)[0];
	return "";
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( is_orig || name != "WWW-AUTHENTICATE" || ! enable_http_wwwauth || c$uid in proxied_conns )
		return;
	local v = wwwauth_val(value);
	if ( v != "" && banner_once(c, "wwwauth") )
		emit(c$id$resp_h, SOFTWARE, banner_val("http_wwwauth:", v, 128), "http_wwwauth", 60, c$uid);
	}

# SIP 메시지를 보낸 쪽의 User-Agent(전화기·소프트폰)와 Server(PBX·게이트웨이)
event sip_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! enable_sip || ( name != "USER-AGENT" && name != "SERVER" ) )
		return;
	local who = is_orig ? c$id$orig_h : c$id$resp_h;
	local kind = name == "USER-AGENT" ? "sip_ua:" : "sip_server:";
	if ( banner_once(c, cat(kind, who)) )
		emit(who, SOFTWARE, banner_val(kind, value, 128), "sip", 60, c$uid);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	if ( enable_service_banners && code == 220 && banner_once(c, "ftp") )
		emit(c$id$resp_h, SOFTWARE, banner_val("ftp_banner:", msg, 160), "ftp", 60, c$uid);
	}

# 첫 220 만(STARTTLS 응답의 220 은 접속 인사가 아님)
event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
	{
	if ( enable_service_banners && ! is_orig && banner_once(c, "smtp") && code == 220 )
		emit(c$id$resp_h, SOFTWARE, banner_val("smtp_banner:", msg, 160), "smtp", 60, c$uid);
	}
