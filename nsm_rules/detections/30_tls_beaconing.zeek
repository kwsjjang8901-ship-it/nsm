##! ============================================================================
##! [30] TLS(HTTPS) 비커닝 — T1071.001 (2026-11 신규)
##!
##! TLS_Beaconing
##!   - 07 HTTP 비커닝과 같은 주기 상태머신을 TLS 연결에 적용한다. 요즘 C2(Cobalt Strike·Sliver 등)는
##!     대부분 HTTPS 라 07(평문 HTTP)과 09(인증서·지문 점수)로는 주기 통신이 보이지 않는다.
##!   - 내용은 못 보므로 연결 크기를 함께 본다: 지시가 없는 C2 콜백은 매번 거의 같은 바이트를 주고받는다.
##!     같은 (출발지, 목적지)로 07 과 같은 주기(beacon_min_interval~max, 오차 beacon_jitter, 누락 허용)가
##!     beacon_min_hits(12)회 이어지고, 그 연결들의 양방향 바이트가 기준 연결의 ±tls_beacon_size_tolerance
##!     (또는 tls_beacon_size_slack 바이트) 안이면 탐지한다. 크기가 벗어나면 연속 수를 다시 센다.
##!   - 짧은 연결만 센다(tls_beacon_max_duration). 메신저·푸시처럼 오래 붙어 있는 연결은 24 장기 연결이 본다.
##!
##! 클러스터: 07 과 같이 (출발지, 목적지) HRW 로 프록시(없으면 매니저) 한 곳에 상태를 모은다.
##! 상관 계약: notice $src = 감염 host, $dst = C2 서버(C2 단계).
##! ============================================================================

@load base/frameworks/notice
@load base/protocols/ssl
@load base/protocols/conn
@load base/utils/site
@load base/frameworks/cluster
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_tls_beaconing = T &redef;
    ## 박자에 맞은 연결의 양방향 바이트가 기준 연결과 이 비율 안이어야 같은 콜백으로 본다
    const tls_beacon_size_tolerance = 0.25 &redef;
    ## 작은 연결의 크기 오차 하한(바이트). 패딩·세션 재개 차이
    const tls_beacon_size_slack = 512 &redef;
    ## 이보다 오래 이어진 연결은 비커닝 관측에서 뺀다
    const tls_beacon_max_duration = 2min &redef;

    type TlsBeaconObs: record {
        orig:  addr;
        resp:  addr;
        ts:    time;
        bytes: count;
        sni:   string &default="-";
        uid:   string &default="";
    };

    global tls_beacon_obs: event(obs: TlsBeaconObs);
}

type TlsBeaconState: record {
    last_seen:   time;
    base_ival:   interval &default=0secs;
    ref_bytes:   count    &default=0;
    consecutive: count    &default=1;
    total:       count    &default=1;
    fired:       bool     &default=F;
};

global tls_beacons: table[addr, addr] of TlsBeaconState &write_expire=beacon_expire;

function tls_beacon_size_ok(ref: count, b: count): bool
    {
    local diff = ref > b ? ref - b : b - ref;
    local tol = double_to_count(ref * tls_beacon_size_tolerance);
    return diff <= ( tol > tls_beacon_size_slack ? tol : tls_beacon_size_slack );
    }

# 워커(또는 standalone): TLS 연결이 끝나면 관측값을 만들어 상태 보유 노드로 보낸다.
event connection_state_remove(c: connection)
    {
    if ( ! detect_tls_beaconing || ! c?$ssl )
        return;
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    if ( ! Site::is_local_addr(orig) || ! is_external(resp) )
        return;
    if ( c?$duration && c$duration > tls_beacon_max_duration )
        return;
    # 예외: 연결이 끝난 시점이라 SNI(domain 축)도 쓸 수 있다.
    if ( NSM::exception_drop_agg(TLS_Beaconing, c) )
        return;
    local obs = TlsBeaconObs($orig=orig, $resp=resp, $ts=c$start_time, $uid=c$uid,
                             $bytes=c$orig$size + c$resp$size);
    if ( c$ssl?$server_name )
        obs$sni = c$ssl$server_name;
@if ( Cluster::is_enabled() )
    if ( ! Cluster::publish_hrw(Cluster::proxy_pool, cat(orig, "-", resp), tls_beacon_obs, obs) )
        Cluster::publish(Cluster::manager_topic, tls_beacon_obs, obs);
@else
    event tls_beacon_obs(obs);
@endif
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY || Cluster::local_node_type() == Cluster::MANAGER )
event tls_beacon_obs(obs: TlsBeaconObs)
    {
    local orig = obs$orig;
    local resp = obs$resp;
    local now = obs$ts;

    if ( [orig, resp] !in tls_beacons )
        {
        tls_beacons[orig, resp] = [$last_seen=now, $ref_bytes=obs$bytes];
        return;
        }
    local st = tls_beacons[orig, resp];
    if ( now < st$last_seen )
        return;
    local delta = now - st$last_seen;
    st$last_seen = now;
    st$total += 1;

    if ( delta < beacon_min_interval )      # 페이지 로딩 등 연속 연결: 연속 수에 반영하지 않음
        {
        tls_beacons[orig, resp] = st;
        return;
        }
    if ( delta > beacon_max_interval )
        {
        st$base_ival = 0secs;
        st$consecutive = 1;
        st$ref_bytes = obs$bytes;
        st$fired = F;
        tls_beacons[orig, resp] = st;
        return;
        }

    local on_beat = F;
    if ( st$base_ival == 0secs )
        {
        if ( tls_beacon_size_ok(st$ref_bytes, obs$bytes) )
            {
            st$base_ival = delta;
            st$consecutive = 2;
            }
        else
            st$ref_bytes = obs$bytes;
        }
    else
        {
        # 07 과 같은 박자 판정(정수배 누락 허용, 허용오차는 기준주기 x jitter 고정)
        local k = double_to_count(floor(delta / st$base_ival + 0.5));
        if ( k >= 1 && k <= beacon_max_missed + 1 )
            {
            local tol = st$base_ival * beacon_jitter;
            if ( delta >= st$base_ival * k - tol && delta <= st$base_ival * k + tol )
                on_beat = T;
            }
        if ( on_beat && tls_beacon_size_ok(st$ref_bytes, obs$bytes) )
            st$consecutive += 1;
        else
            {
            st$base_ival = delta;           # 박자 또는 크기 이탈 -> 새 기준
            st$ref_bytes = obs$bytes;
            st$consecutive = 2;
            }
        }

    if ( st$consecutive >= beacon_min_hits && ! st$fired )
        {
        st$fired = T;
        local eid_base = cat(orig, "|tls-beacon|", resp);
        local eid = cat(eid_base, "|", time_bucket(beacon_expire));
        local ival_s = interval_to_double(st$base_ival);
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=TLS_Beaconing,
            $technique="T1071.001",
            $src=orig,
            $dst=resp,
            $operation="tls_beacon",
            $uid=obs$uid,
            $detail=fmt("interval=%.1fs consecutive=%d total=%d bytes~%d sni=%s",
                        ival_s, st$consecutive, st$total, st$ref_bytes, obs$sni)]);
        NOTICE([$note=TLS_Beaconing,
                $src=orig,
                $dst=resp,
                $msg=fmt("TLS beaconing: %s -> %s ~%.1fs interval x%d, ~%d bytes each", orig, resp,
                         ival_s, st$consecutive, st$ref_bytes),
                $sub=fmt("interval=%.1fs hits=%d bytes~%d sni=%s", ival_s, st$consecutive, st$ref_bytes, obs$sni),
                $identifier=eid_base,
                $suppress_for=beacon_expire,
                $evidence_id=eid]);
        }
    tls_beacons[orig, resp] = st;
    }
@endif
