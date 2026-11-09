##! ============================================================================
##! [7] HTTP Beaconing (주기적 C2 콜백) - T1071.001
##!
##!   - (src,dst)별 HTTP 연결 발생 시각을 추적해 "일정 주기 반복"을 탐지.
##!     연속 간격이 base_interval ± jitter 안에 beacon_min_hits 회 이어지면 발화.
##!   - 연결당 1비트: connection_state_remove 에서 c?$http 인 연결만(암호화 C2 는 09).
##!   - SumStats 로는 주기 규칙성을 못 재므로 커스텀 상태머신 사용.
##!
##! 상관 계약: notice $src = 감염 host (C2 단계, SRC_TO_SRC 로 Lateral 에 연결).
##!
##! ⚠ 클러스터 주의: 이 상태는 워커 로컬이다. AF_PACKET fanout 이 5-튜플 해시면
##!   같은 (src,dst)의 연결이 포트마다 다른 워커로 흩어져 주기 카운트가 쪼개질 수 있다.
##!   -> 단일 워커로 테스트하거나 flow/IP 기반 fanout 을 확인할 것. (Phase2 개선 후보)
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_beaconing = T &redef;

    ## 정상 주기 트래픽(업데이트/시간 서버 등) 제외 대역.
    const beacon_allowlist: set[subnet] = {} &redef;

    ## 도메인(HTTP Host) 기반 예외 목록. 부분매칭(하위 도메인 포함).
    ##  예: "oneocsp.microsoft.com" 또는 상위 "microsoft.com" 을 넣으면
    ##      해당 도메인/하위도메인으로의 비커닝은 예외 처리된다.
    ##  IP 가 자주 바뀌는 OCSP/업데이트/텔레메트리 오탐 억제에 사용.
    const beacon_allowlist_domains: set[string] = {} &redef;
}

type BeaconState: record {
    last_seen:   time;
    base_ival:   interval &default=0secs;   # 기준 주기
    consecutive: count    &default=1;        # 기준 주기에 맞아떨어진 연속 횟수
    total:       count    &default=1;        # 관측 연결 총수
    fired:       bool     &default=F;
};

## key: (src, dst). 마지막 활동 후 beacon_expire 지나면 만료.
global beacons: table[addr, addr] of BeaconState &write_expire=beacon_expire;

event connection_state_remove(c: connection)
    {
    if ( ! detect_beaconing )
        return;
    if ( ! c?$http )                       # HTTP 연결만
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    if ( ! Site::is_local_addr(orig) || ! is_external(resp) )
        return;                            # 내부 -> 외부 C2 방향만
    if ( resp in beacon_allowlist )
        return;

    local now = c$start_time;

    if ( [orig, resp] !in beacons )
        {
        beacons[orig, resp] = [$last_seen=now];
        return;
        }

    local st = beacons[orig, resp];
    local delta = now - st$last_seen;
    st$last_seen = now;
    st$total += 1;

    if ( delta < beacon_min_interval )     # 너무 빠름(페이지 다중 객체 등): 스트릭 미반영
        {
        beacons[orig, resp] = st;
        return;
        }
    if ( delta > beacon_max_interval )     # 너무 느림: 스트릭 리셋
        {
        st$base_ival = 0secs;
        st$consecutive = 1;
        st$fired = F;                      # 주기 변경(예: 30s->60s) 후 재탐지 허용
        beacons[orig, resp] = st;
        return;
        }

    if ( st$base_ival == 0secs )           # 기준 주기 확립
        {
        st$base_ival = delta;
        st$consecutive = 2;
        }
    else
        {
        # 누락 허용: delta 가 기준주기의 정수배(k=1,2,3...) 근처면 "박자 유지"로 본다.
        # 캡처 손실로 중간 비콘이 빠져도(예: 5s 주기인데 10s 관측) 스트릭이 끊기지 않음.
        local ratio = delta / st$base_ival;
        local k = double_to_count(floor(ratio + 0.5));   # 가장 가까운 정수배
        local on_beat = F;
        if ( k >= 1 )
            {
            local expect = st$base_ival * k;
            local tol = st$base_ival * beacon_jitter * k;  # 배수만큼 허용오차도 비례
            if ( delta >= expect - tol && delta <= expect + tol )
                on_beat = T;
            }
        if ( on_beat )
            st$consecutive += 1;
        else
            {
            st$base_ival = delta;          # 박자 이탈 -> 새 주기로 리셋
            st$consecutive = 2;
            }
        }

    if ( st$consecutive >= beacon_min_hits && ! st$fired )
        {
        local hoststr = c$http?$host ? c$http$host : "-";

        # 도메인 예외(부분매칭): 신뢰 도메인으로의 비커닝은 발화하지 않음.
        #   상태(st$fired)를 세워 이후 재평가도 스킵 -> 반복 오탐 억제.
        if ( NSM::domain_matches(hoststr, beacon_allowlist_domains) )
            {
            st$fired = T;
            beacons[orig, resp] = st;
            return;
            }

        st$fired = T;
        local eid_base = cat(orig, "|beacon|", resp);
        local eid = cat(eid_base, "|", time_bucket(beacon_expire));
        local ival_s = interval_to_double(st$base_ival);

        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=HTTP_Beaconing,
            $technique="T1071.001",
            $src=orig,
            $dst=resp,
            $operation="http_beacon",
            $uid=c$uid,
            $detail=fmt("interval=%.1fs consecutive=%d total=%d host=%s",
                        ival_s, st$consecutive, st$total, hoststr)]);

        NOTICE([$note=HTTP_Beaconing,
                $src=orig,
                $msg=fmt("HTTP beaconing: %s -> %s ~%.1fs interval x%d hits",
                         orig, resp, ival_s, st$consecutive),
                $sub=fmt("interval=%.1fs hits=%d host=%s", ival_s, st$consecutive, hoststr),
                $identifier=eid_base,
                $suppress_for=beacon_expire,
                $evidence_id=eid]);
        }

    beacons[orig, resp] = st;
    }
