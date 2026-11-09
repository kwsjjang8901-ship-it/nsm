# @TEST-DOC: 08 DNS 터널링·유출 — hex TXT 터널(.110) 터널링 탐지, base32 대량(.111) 유출 탐지(+터널링), CDN형(.112)·국내 co.kr 사이트(.113)·AV 평판 조회(.114) 미탐
# @TEST-EXEC: zeek -C -r $TRACES/dns_tunnel.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DNS_Tunneling src=10.0.0.110
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_DNS src=10.0.0.110
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Exfil_DNS src=10.0.0.111
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::DNS_Tunneling src=10.0.0.111
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.112
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.113
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::DNS_Tunneling src=10.0.0.114
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_DNS src=10.0.0.112
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_DNS src=10.0.0.113
# @TEST-EXEC: assert-rows notice.log eq 0 note=NSM::Exfil_DNS src=10.0.0.114
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.C2.DnsTunneling attacker=10.0.0.110
# @TEST-EXEC: assert-rows nsm_detection.log eq 1 diagnosis=NSM.Exfiltration.DnsTunnel attacker=10.0.0.111
# @TEST-EXEC: assert-rows evidence.log ge 1 note=NSM::DNS_Tunneling src=10.0.0.110
# @TEST-EXEC: assert-evidence-join NSM::DNS_Tunneling
# @TEST-EXEC: assert-evidence-join NSM::Exfil_DNS

# pcap 크기를 줄이기 위해 유출 임계만 낮춘다(기본 256KB/5분).
redef NSM::dnsexfil_bytes = 32 * 1024;
