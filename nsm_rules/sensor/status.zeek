##! 센서 상태 로그(nsm_sensor.log): 노드별로 1분마다 한 행(로그 형식 검토 S1·N6·D2).
##!
##! Manager 의 장비 현황(마지막 응답, 패킷·트래픽, 패킷 누락, 엔진·스키마 버전, 적용 중인 예외·IOC 파일)에 쓴다.
##! 지금까지는 이 값들이 Zeek 기본 로그(stats.log 5분, capture_loss.log 15분)에 흩어져 있었고 버전은 없었다.
##! CPU·메모리·디스크, 수집 에이전트의 전송 지연은 센서 밖에서 재는 값이라 수집 에이전트가 채운다.

@load base/frameworks/logging
@load ../rules/filter_log
@load ../detections/data_file   # 예외·IOC 파일 SHA1
@load ../asset-id               # 에이전트 정책 파일 SHA1
@load ./version

module NSM;

export {
    redef enum Log::ID += { SENSOR_LOG };

    ## 기록 주기
    const sensor_status_interval = 1min &redef;

    type SensorStatus: record {
        ts:             time   &log;
        node:           string &log;              ##< 노드(standalone 은 zeek)
        schema_version: string &log;              ##< 로그 스키마 버전(schema/logs 내용 해시)
        pkg_version:    string &log;              ##< nsm_rules 패키지 버전
        zeek_version:   string &log;
        interval_s:     double &log;              ##< 이 행이 덮는 시간(초). 보통 60. 패킷이 끊긴 동안은 길어지고, 종료 행은 짧을 수 있음
        pkts:           count  &log;              ##< 이 구간에 받은 패킷
        bytes:          count  &log;              ##< 이 구간에 받은 바이트
        pkts_dropped:   count  &log;              ##< 이 구간에 캡처 장치(NIC·커널)가 놓친 패킷
        drop_pct:       double &log;              ##< 놓친 패킷 비율(%) = pkts_dropped / (pkts + pkts_dropped)
        gap_pct:        double &log &optional;    ##< TCP 누락 비율(%): ACK 된 데이터 중 못 본 구간(미러 품질). TCP ACK 가 없으면 없음
        capture_lag_s:  double &log;              ##< 벽시계 - 패킷 시각(초). 처리가 밀리면 커짐. pcap 재생에서는 의미 없음
        uptime_s:       double &log;              ##< 시작 후 시간(초, 벽시계)
        exc_sha1:       string &log &optional;    ##< 이 노드가 마지막으로 읽은 예외 파일 SHA1(파일을 읽는 노드만)
        ioc_sha1:       string &log &optional;    ##< IOC 파일 SHA1
        policy_sha1:    string &log &optional;    ##< 에이전트 정책 파일 SHA1
    };
}

redef NSM::keep_log_streams += { NSM::SENSOR_LOG };
redef NSM::log_paths += { [NSM::SENSOR_LOG] = "/log/zeek/nsm_sensor" };

global ss_start_wall: time;
global ss_last: time;
global ss_net: NetStats;
global ss_gap: GapStats;
global ss_started = F;

global sensor_status_tick: event();

function pct(part: count, whole: count): double
    {
    return whole == 0 ? 0.0 : 100.0 * part / whole;
    }

global ss_done = F;

function sensor_status_write()
    {
    local now = network_time();
    if ( now <= ss_last )
        return;     # 덮는 시간이 없는 행은 쓰지 않는다
    local ns = get_net_stats();
    local gs = get_gap_stats();
    local pk = ns$pkts_recvd - ss_net$pkts_recvd;
    local dr = ns$pkts_dropped - ss_net$pkts_dropped;
    local r = SensorStatus($ts=now, $node=peer_description, $schema_version=schema_version,
                           $pkg_version=pkg_version, $zeek_version=zeek_version(),
                           $interval_s=interval_to_double(now - ss_last),
                           $pkts=pk, $bytes=ns$bytes_recvd - ss_net$bytes_recvd,
                           $pkts_dropped=dr, $drop_pct=pct(dr, pk + dr),
                           $capture_lag_s=interval_to_double(current_time() - now),
                           $uptime_s=interval_to_double(current_time() - ss_start_wall));
    local acks = gs$ack_events - ss_gap$ack_events;
    if ( acks > 0 )
        r$gap_pct = pct(gs$gap_events - ss_gap$gap_events, acks);
    if ( "exception" in data_file_sha1 )
        r$exc_sha1 = data_file_sha1["exception"];
    if ( "ioc" in data_file_sha1 )
        r$ioc_sha1 = data_file_sha1["ioc"];
    if ( AssetID::agent_policy_sha1 != "" )
        r$policy_sha1 = AssetID::agent_policy_sha1;
    Log::write(NSM::SENSOR_LOG, r);
    ss_last = now;
    ss_net = ns;
    ss_gap = gs;
    }

event sensor_status_tick()
    {
    if ( ss_done )
        return;
    sensor_status_write();
    schedule sensor_status_interval { sensor_status_tick() };
    }

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::SENSOR_LOG, [$columns=SensorStatus, $path="nsm_sensor"]);
    ss_start_wall = current_time();
    # 통계 기준점은 패킷을 받기 전(누적값 0). 첫 패킷 시점에 잡으면 그 패킷이 빠진다.
    ss_net = get_net_stats();
    ss_gap = get_gap_stats();
    }

function sensor_status_start(t: time)
    {
    if ( ss_started )
        return;
    ss_started = T;
    ss_last = t;
    schedule sensor_status_interval { sensor_status_tick() };
    }

# 패킷을 받는 노드(standalone·워커, pcap 재생): 첫 패킷 시각에 맞춰 시작한다.
event network_time_init()
    {
    sensor_status_start(network_time());
    }

# 패킷 입력이 없는 노드(매니저·로거·프록시): 시각은 벽시계로 흐르므로 바로 시작한다.
#   Zeek 8.x 는 이런 노드에 network_time_init 을 주지 않는다.
event zeek_init() &priority=-5
    {
    if ( ! reading_traces() && ! reading_live_traffic() )
        sensor_status_start(current_time());
    }

# 종료 때 마지막 구간을 한 행 더 쓴다(1분보다 짧을 수 있음).
event zeek_done()
    {
    if ( ss_started )
        sensor_status_write();
    ss_done = T;
    }
