##! TCP SYN 지문 신호: 연결을 여는 SYN(클라이언트)과 SYN-ACK(서버)의 특징을 남긴다.
##! OS 계열 추정 재료이며 판정은 Manager(리포트)가 한다(SPEC 3.18, 4.4).
##!
##!   값: "<syn|synack> ittl=<추정 초기 TTL> hops=<거리> win=<윈도> ws=<스케일|-> mss=<MSS|-> sack=<0|1> ts=<0|1> df=<0|1>"
##!   예: "syn ittl=128 hops=0 win=64240 ws=8 mss=1460 sack=1 ts=0 df=1"   (Windows 10/11 계열)
##!
##! IP·방향(syn/synack)마다 suppress_interval(1시간)에 한 번만 본다(첫 SYN 기준).
##! Zeek 가 주는 값에는 TCP 옵션 순서·세부 특이점이 없어 p0f 지문을 그대로 맞출 수는 없고 계열 수준까지다.
##! NAT·프록시 뒤 장비는 마지막 장비의 값이 보이고, 튜닝된 서버·가상 머신은 틀릴 수 있어 신뢰도를 낮게(30) 둔다.

@load ../main

module AssetID;

## 이미 본 (IP, SYN-ACK 여부)
global tcp_fp_done: set[addr, bool] &create_expire=suppress_interval;

## 관측 TTL 로 초기 TTL 추정(흔한 기본값 32·64·128·255 중 관측값 이상인 가장 작은 값)
function tcp_fp_ittl(ttl: count): count
	{
	if ( ttl <= 32 )
		return 32;
	if ( ttl <= 64 )
		return 64;
	if ( ttl <= 128 )
		return 128;
	return 255;
	}

event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	if ( ! enable_tcp_fp )
		return;

	local synack = ! pkt$is_orig;
	local ip = pkt$is_orig ? c$id$orig_h : c$id$resp_h;
	if ( [ip, synack] in tcp_fp_done )
		return;
	add tcp_fp_done[ip, synack];

	local ittl = tcp_fp_ittl(pkt$ttl);
	local v = fmt("%s ittl=%d hops=%d win=%d ws=%s mss=%s sack=%d ts=%d df=%d",
	              synack ? "synack" : "syn", ittl, ittl - pkt$ttl, pkt$win_size,
	              pkt$win_scale < 0 ? "-" : cat(pkt$win_scale),
	              pkt$MSS == 0 ? "-" : cat(pkt$MSS),
	              pkt$SACK_OK ? 1 : 0, pkt?$TSval ? 1 : 0, pkt$DF ? 1 : 0);
	emit(ip, TCP_FP, v, "tcp_fp", 30, c$uid);
	}
