##! ============================================================================
##! [22] LLMNR / NBT-NS / mDNS 포이즈닝 (Responder 류) — T1557.001 (2026-11 신규)
##!
##! 탐지 원리
##!   - Windows 는 DNS 로 못 찾은 이름을 LLMNR(5355)·NBT-NS(137) 브로드캐스트/멀티캐스트로 묻는다.
##!     Responder·Inveigh 는 어떤 이름을 묻든 "그건 나다"라고 답해 피해 host 의 NTLM 인증을 가로챈다.
##!   - 정상 host 는 자기 이름에만 답한다. 한 응답자가 poisoning_interval 안에 긍정 응답한
##!     "고유 이름" 수가 poisoning_name_threshold 이상이면 탐지한다.
##!   - 이름 해석 응답만 센다: LLMNR·mDNS 의 A/AAAA 응답 레코드, NBNS 의 NB 질의에 대한 긍정 응답.
##!     mDNS 서비스 광고(PTR/SRV/TXT)는 한 장비가 여러 이름을 정상적으로 내므로 제외한다.
##!   - 응답자 = 그 응답 패킷의 출발 주소(연결 방향과 무관).
##!
##! 오탐 통제: WINS 서버 등 남의 이름에 답하는 것이 정상인 장비는 poisoning_allowlist 에 등록.
##!
##! 상관 계약: notice $src = 응답자(공격 host), $lm_targets = 응답을 받은 질의 host 집합.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/dns
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const poisoning_interval       = 10min &redef;  # 집계 윈도우
    const poisoning_name_threshold = 5     &redef;  # 응답자별 긍정 응답한 고유 이름 수

    ## 감시할 이름 해석 프로토콜 포트
    const poisoning_ports: table[port] of string = {
        [137/udp]  = "nbns",
        [5353/udp] = "mdns",
        [5355/udp] = "llmnr",
    } &redef;

    ## NBNS 에서 세는 질의 유형: A(1), NB(32), AAAA(28), ANY(255)
    const poisoning_qtypes: set[count] = { 1, 28, 32, 255 } &redef;

    ## 예외 응답자(WINS 서버 등).
    const poisoning_allowlist: set[subnet] = {} &redef;
}

event zeek_init()
    {
    # 고유 이름(str = "프로토콜|이름") / 근거 표본(str = "프로토콜|이름|질의 host")
    local r_names  = SumStats::Reducer($stream="nsm.poison", $apply=set(SumStats::UNIQUE));
    local r_sample = SumStats::Reducer($stream="nsm.poison.sample", $apply=set(SumStats::SAMPLE),
                                       $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-name-poisoning",
        $epoch     = poisoning_interval,
        $reducers  = set(r_names, r_sample),
        $threshold = poisoning_name_threshold + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["nsm.poison"]$unique + 0.0;
            },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local n   = result["nsm.poison"]$unique;
            local eid = cat(key$host, "|name-poisoning|", time_bucket(poisoning_interval));
            local victims: set[addr] = set();
            local protos: set[string] = set();

            # 근거를 NOTICE 보다 먼저 적재한다.
            if ( "nsm.poison.sample" in result && result["nsm.poison.sample"]?$samples )
                for ( i in result["nsm.poison.sample"]$samples )
                    {
                    local o = result["nsm.poison.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);
                    if ( |p| != 3 )
                        next;
                    add protos[p[0]];
                    local ev = EvidenceInfo($ts=network_time(),
                                            $evidence_id=eid,
                                            $note=Name_Poisoning,
                                            $technique="T1557.001",
                                            $src=key$host,
                                            $operation=fmt("%s_poisoned_response", p[0]),
                                            $detail=fmt("name=%s unique_names=%d window=%s",
                                                        p[1], n, poisoning_interval));
                    if ( p[2] != "-" )
                        {
                        ev$dst = to_addr(p[2]);
                        add victims[ev$dst];
                        }
                    if ( NSM::evidence_is_new(eid, o$str) )
                        NSM::write_evidence(ev);
                    }

            local plist = "";
            for ( pr in protos )
                plist = plist == "" ? pr : cat(plist, ",", pr);

            NOTICE([$note=Name_Poisoning,
                    $src=key$host,
                    $msg=fmt("Possible LLMNR/NBT-NS/mDNS poisoning: %s answered %d different names in %s (%s)",
                             key$host, n, poisoning_interval, plist),
                    $sub=fmt("unique_names=%d protocols=%s", n, plist),
                    $identifier=cat(key$host, "name-poisoning"),
                    $suppress_for=1hr,
                    $evidence_id=eid,
                    $lm_targets=victims]);
            }
    ]);
    }

## NBNS 응답에는 질문 섹션이 없고 NB 레코드는 Zeek 가 이벤트로 내지 않는다(DNS.cc ParseRR_NBS).
##   그래서 질의 이름을 (질의 host, 트랜잭션 ID)로 잠시 기억해 응답과 짝짓는다.
global nbns_pending: table[addr, count] of string &create_expire=30sec;

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |poisoning_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:poisoning_allowlist",
            [$scope=set("Name_Poisoning"), $src=poisoning_allowlist]);
    }

function poisoning_observe(proto: string, responder: addr, querier: addr, name: string)
    {
    # 예외(예외 파일 + 기존 poisoning_allowlist). 응답자가 notice src, 질의 host 가 dst 다
    if ( NSM::exception_drop_ctx(Name_Poisoning, [$src=responder, $dst=querier], T) )
        return;
    local n = to_lower(strip(name));
    if ( n == "" )
        return;
    # 멀티캐스트·브로드캐스트로 보낸 응답은 질의 host 를 알 수 없다
    local qhost = ( is_v4_addr(querier) && ( querier in 224.0.0.0/4 || querier == 255.255.255.255 ) )
                  ? "-" : cat(querier);
    SumStats::observe("nsm.poison.sample", [$host=responder], [$str=cat(proto, "|", n, "|", qhost)]);
    SumStats::observe("nsm.poison", [$host=responder], [$str=cat(proto, "|", n)]);
    }

## LLMNR·mDNS: 응답 레코드(A/AAAA)의 이름. mDNS 응답은 질문 섹션이 없으므로 레코드 이름을 쓴다.
function poisoning_answer(c: connection, msg: dns_msg, ans: dns_answer)
    {
    if ( c$id$resp_p != 5353/udp && c$id$resp_p != 5355/udp )
        return;
    if ( c$id$resp_p !in poisoning_ports || msg$rcode != 0 || ans$answer_type != DNS_ANS )
        return;
    local hdr = get_current_packet_header();
    if ( ! hdr?$ip )
        return;
    poisoning_observe(poisoning_ports[c$id$resp_p], hdr$ip$src, hdr$ip$dst, ans$query);
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    poisoning_answer(c, msg, ans);
    }

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    poisoning_answer(c, msg, ans);
    }

# NBNS 질의 기억
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( c$id$resp_p != 137/udp || 137/udp !in poisoning_ports || qtype !in poisoning_qtypes )
        return;
    local hdr = get_current_packet_header();
    if ( ! hdr?$ip )
        return;
    local decoded = decode_netbios_name(query);
    nbns_pending[hdr$ip$src, msg$id] = |decoded| > 0 ? decoded : query;
    }

# NBNS 긍정 응답
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( c$id$resp_p != 137/udp || ! msg$QR || msg$rcode != 0 || msg$num_answers == 0 )
        return;
    local hdr = get_current_packet_header();
    if ( ! hdr?$ip || [hdr$ip$dst, msg$id] !in nbns_pending )
        return;
    local name = nbns_pending[hdr$ip$dst, msg$id];
    poisoning_observe(poisoning_ports[137/udp], hdr$ip$src, hdr$ip$dst, name);
    }
