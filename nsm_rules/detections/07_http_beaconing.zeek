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
##! 클러스터 동작 (2026-11 개정)
##!   - 이전에는 주기 상태가 워커 로컬이라, 워커 분배가 5-튜플 해시면 같은 (src,dst)의
##!     연결이 출발 포트마다 다른 워커로 흩어져 각 워커가 보는 연결 수가 줄었다(미탐).
##!   - 이제 워커는 연결마다 관측값(BeaconObs)만 만들어, (src,dst) 키의 HRW 해시로 정해지는
##!     프록시 1대로 보낸다(Cluster::publish_hrw). 프록시가 없으면 매니저로 보낸다.
##!     같은 (src,dst)는 항상 같은 노드로 가므로 주기 상태가 한 곳에 모인다.
##!     standalone 에서는 로컬에서 바로 처리한다.
##!   - 관측 시각이 이전 관측보다 과거(도착 순서 역전, 장기 연결의 늦은 종료)면 무시한다.
##!     (이전에는 last_seen 이 과거로 되돌아가 주기 판정이 흐트러졌다)
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/conn
@load base/utils/site
@load base/frameworks/cluster
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./ai_common

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

    ## 캡처 손실 등으로 빠진 비콘을 연속 몇 개까지 허용할지.
    ##   delta 가 기준주기의 k 배(k <= beacon_max_missed + 1) 근처면 박자 유지로 본다.
    const beacon_max_missed = 2 &redef;

    ## HTTP 연결 1건의 비커닝 관측값(워커 -> 상태 보유 노드 전달용).
    type BeaconObs: record {
        orig: addr;
        resp: addr;
        ts:   time;                 # 연결 시작 시각
        host: string &default="-";  # HTTP Host
        uid:  string &default="";
    };

    ## 관측값을 상태 보유 노드(프록시 HRW / 매니저 / standalone 로컬)로 보낸다.
    global beacon_submit: function(obs: BeaconObs);

    ## 관측값 처리 이벤트(상태 보유 노드에서만 처리).
    global beacon_obs: event(obs: BeaconObs);
}

type BeaconState: record {
    last_seen:   time;
    base_ival:   interval &default=0secs;   # 기준 주기
    consecutive: count    &default=1;        # 기준 주기에 맞아떨어진 연속 횟수
    total:       count    &default=1;        # 관측 연결 총수
    fired:       bool     &default=F;
};

## key: (src, dst). 마지막 활동 후 beacon_expire 지나면 만료.
## (클러스터에서는 관측값을 받는 프록시/매니저에만 상태가 쌓인다)
global beacons: table[addr, addr] of BeaconState &write_expire=beacon_expire;

function beacon_submit(obs: BeaconObs)
    {
@if ( Cluster::is_enabled() )
    # 같은 (src,dst) 는 항상 같은 프록시로. 프록시가 없으면(풀 비어 있음) 매니저로.
    if ( ! Cluster::publish_hrw(Cluster::proxy_pool, cat(obs$orig, "-", obs$resp), beacon_obs, obs) )
        Cluster::publish(Cluster::manager_topic, beacon_obs, obs);
@else
    event beacon_obs(obs);
@endif
    }

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |beacon_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:beacon_allowlist",
            [$scope=set("HTTP_Beaconing"), $dst=beacon_allowlist]);
    if ( |beacon_allowlist_domains| > 0 )
        NSM::exception_add_legacy("legacy:beacon_allowlist_domains",
            [$scope=set("HTTP_Beaconing"), $domain=beacon_allowlist_domains]);
    }

# 워커(또는 standalone): HTTP 연결이 끝나면 관측값을 만들어 보낸다.
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
    # 예외(예외 파일 + 기존 beacon_allowlist·beacon_allowlist_domains). 워커에서 연결마다 판정해
    #   예외 연결은 상태 보유 노드로 보내지 않는다. 연결이 끝난 시점이라 HTTP Host(domain 축)를 쓸 수 있다.
    if ( NSM::exception_drop_agg(HTTP_Beaconing, c) )
        return;

    local obs = BeaconObs($orig=orig, $resp=resp, $ts=c$start_time, $uid=c$uid);
    if ( c$http?$host )
        obs$host = c$http$host;
    beacon_submit(obs);
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY || Cluster::local_node_type() == Cluster::MANAGER )
# 상태 보유 노드: 주기 상태머신
event beacon_obs(obs: BeaconObs)
    {
    local orig = obs$orig;
    local resp = obs$resp;
    local now = obs$ts;

    if ( [orig, resp] !in beacons )
        {
        beacons[orig, resp] = [$last_seen=now];
        return;
        }

    if ( now < beacons[orig, resp]$last_seen )   # 과거 시각(순서 역전) -> 무시
        return;

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
        # 누락 허용: delta 가 기준주기의 정수배(k=1..beacon_max_missed+1) 근처면 "박자 유지".
        # 캡처 손실로 중간 비콘이 빠져도(예: 5s 주기인데 10s 관측) 스트릭이 끊기지 않음.
        #
        # 허용오차는 k 와 무관하게 기준주기 x jitter 로 고정한다.
        #   (이전: 기준주기 x jitter x k. jitter 0.25 면 k>=2 부터 허용 구간이 배수 간격의
        #    절반 이상이 되어, 기준주기의 1.5배 이상인 "모든" 간격이 박자 맞음으로 판정됐다.
        #    -> 같은 외부 IP 로 불규칙 HTTP 연결이 13회 이상이면 비커닝 오탐. 회귀 테스트로 확인)
        local ratio = delta / st$base_ival;
        local k = double_to_count(floor(ratio + 0.5));   # 가장 가까운 정수배
        local on_beat = F;
        if ( k >= 1 && k <= beacon_max_missed + 1 )
            {
            local expect = st$base_ival * k;
            local tol = st$base_ival * beacon_jitter;
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
        local hoststr = obs$host;

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
            $uid=obs$uid,
            $detail=fmt("interval=%.1fs consecutive=%d total=%d host=%s%s",
                        ival_s, st$consecutive, st$total, hoststr,
                        ai_service_match(split_string1(hoststr, /:/)[0]) != "" ? " ai_service=T" : "")]);

        NOTICE([$note=HTTP_Beaconing,
                $src=orig,
                $msg=fmt("HTTP beaconing: %s -> %s ~%.1fs interval x%d hits",
                         orig, resp, ival_s, st$consecutive),
                $sub=fmt("interval=%.1fs hits=%d host=%s%s", ival_s, st$consecutive, hoststr,
                         ai_service_match(split_string1(hoststr, /:/)[0]) != "" ? " ai_service=T" : ""),
                $identifier=eid_base,
                $suppress_for=beacon_expire,
                $evidence_id=eid]);
        }

    beacons[orig, resp] = st;
    }
@endif
