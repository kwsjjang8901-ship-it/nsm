# @TEST-DOC: [17] TGS 오류는 비밀번호 실패가 아니다 — 비활성 계정이 캐시된 TGT 로 서비스 티켓을 요청해 받는 KRB-ERROR 18(CLIENT_REVOKED)은 같은 연결에 AS-REQ 가 없어도 무차별 대입(.5, 25번)·스프레이(.6, 계정 12개)로 세지 않는다. 오류의 cname 으로 세는 대체 경로는 AS 교환(대상 krbtgt)의 오류에만 쓴다
# @TEST-EXEC: zeek -C -r $TRACES/krb_tgs_error.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows kerberos.log ge 37 request_type=TGS
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Bruteforce
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Kerberos_Spray

redef NSM::keep_log_streams += { KRB::LOG };
