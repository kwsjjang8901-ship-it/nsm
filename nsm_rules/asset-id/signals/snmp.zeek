##! SNMP 신호: 관리 서버(NMS)의 질의에 장비가 응답한 시스템 정보.
##!   sysDescr    (1.3.6.1.2.1.1.1.0) -> software "snmp_sysdescr:<값>"  (지문 대조: Recog snmp_sysdescr)
##!   sysObjectID (1.3.6.1.2.1.1.2.0) -> software "snmp_sysobjid:<OID>" (제조사 번호, Recog snmp_sysobjid)
##!   sysName     (1.3.6.1.2.1.1.5.0) -> hostname (70)
##!
##! 응답한 쪽(장비) IP 에 남긴다. 커뮤니티 문자열은 기록하지 않는다. SNMPv3 암호화 응답은 보이지 않는다.
##! NMS 의 수집 경로가 미러에 걸려야 보인다(네트워크 장비·프린터·UPS 등의 이름·모델 확보 경로).

@load base/protocols/snmp
@load ../main

module AssetID;

event snmp_response(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
	{
	if ( ! enable_snmp )
		return;

	local agent = is_orig ? c$id$orig_h : c$id$resp_h;

	for ( _, b in pdu$bindings )
		{
		local v = b$value;
		switch ( b$oid ) {
		case "1.3.6.1.2.1.1.1.0":
			if ( v?$octets )
				{
				# 줄바꿈·제어 문자는 공백으로(한 줄 로그)
				local d = strip(gsub(gsub(v$octets, /[\x00-\x1f]+/, " "), /  +/, " "));
				emit(agent, SOFTWARE, d == "" ? "" : "snmp_sysdescr:" + d[:200], "snmp", 70, c$uid);
				}
			break;
		case "1.3.6.1.2.1.1.2.0":
			if ( v?$oid )
				emit(agent, SOFTWARE, "snmp_sysobjid:" + v$oid, "snmp", 70, c$uid);
			break;
		case "1.3.6.1.2.1.1.5.0":
			if ( v?$octets )
				{
				local n = normalize_name(v$octets);
				if ( /\./ in n )
					emit(agent, FQDN, n, "snmp", 70, c$uid);
				emit(agent, HOSTNAME, split_string1(n, /\./)[0], "snmp", 70, c$uid);
				}
			break;
		}
		}
	}
