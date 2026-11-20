##! 서비스 배너 신호(추가): POP3 접속 인사, MySQL 서버 버전. 지문 대조(Recog pop_banners·mysql_banners) 입력.
##!
##!   POP3 접속 인사(첫 +OK 응답 본문)  -> software "pop3_banner:…"
##!   MySQL 핸드셰이크의 서버 버전      -> software "mysql:…"
##!
##! 이 두 이벤트는 Zeek 기본 스크립트가 처리하지 않아 이 파일을 로드하면 새로 생긴다(POP3 는 응답 줄마다, MySQL 은 연결마다).
##! 해당 프로토콜만 있는 최악 조건 측정에서 banners.zeek 대비 추가 +3.9%(SPEC 3.20). 부하를 완전히 없애려면
##! signals/__load__.zeek 에서 이 파일의 @load 를 뺀다(enable_service_banners=F 는 기록만 멈추고 이벤트는 그대로 생긴다).
##! POP3 는 클라이언트가 POP3 명령(USER·CAPA 등)을 보내야 Zeek 가 인식한다(DPD).

@load base/protocols/pop3
@load base/protocols/mysql
@load ./banners
@load ../main

module AssetID;

event pop3_reply(c: connection, is_orig: bool, cmd: string, msg: string)
	{
	if ( enable_service_banners && ! is_orig && banner_once(c, "pop3") && /OK/ in cmd )
		emit(c$id$resp_h, SOFTWARE, banner_val("pop3_banner:", msg, 160), "pop3", 60, c$uid);
	}

event mysql_server_version(c: connection, ver: string)
	{
	if ( enable_service_banners && banner_once(c, "mysql") )
		emit(c$id$resp_h, SOFTWARE, banner_val("mysql:", ver, 64), "mysql", 70, c$uid);
	}
