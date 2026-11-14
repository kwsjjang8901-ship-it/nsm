##! ============================================================================
##! [13-agg] Exfiltration - 호스트 단위 바이트 집계형 (S3 multipart 대응)  ※ 14번
##!
##!   - 10번(단일 연결 대용량)과 별개로, src 호스트가 1분 창에서 외부로 보낸
##!     orig TCP 페이로드 바이트를 SumStats 로 합산해 임계 초과를 본다.
##!   - 10번과의 충돌을 피하기 위해 독립 notice 타입(Exfil_Volume_Aggregate)을 쓴다.
##!     ※ 추후 삭제 가능성 있음 -> 증적도 자기완결적 1행만 남겨 제거가 깔끔하게.
##!
##! 집계 방식 (2026-11 개정, 검토 H3)
##!   - 이전: tcp_packet 이벤트(패킷마다 발생)에서 페이로드 길이를 매번 observe.
##!     Zeek 문서도 실시간 사용을 피하라고 하는 이벤트라 고대역에서 CPU 부하가 컸다.
##!   - 이제: 내부->외부 TCP 연결이 성립하면 ConnThreshold 로 "originator 가
##!     exfil_volume_step 바이트를 더 보낼 때마다" 깨어나, 그 시점의 페이로드 크기
##!     (c$orig$size) 증가분만 observe 한다. 연결 종료 시 남은 증가분을 반영한다.
##!       * 이벤트 빈도: 패킷마다 -> step(기본 1MB)마다
##!       * ConnThreshold 는 IP 헤더 포함 바이트로 깨어나지만, 집계는 페이로드 기준이다.
##!         (다운로드 시 내부 PC 가 보내는 ACK 헤더가 "외부 전송량"으로 잡히지 않는다)
##!       * 연결 진행 중에도 step 마다 반영되므로 장기 연결도 종료 전에 탐지된다.
##!   - 차이: 캡처 손실로 빠진 구간도 시퀀스 번호 기준으로 포함된다(실제 전송량에 더 가깝다).
##!     탐지 시점은 최대 step 만큼 늦어질 수 있다.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/utils/site
@load base/protocols/conn/thresholds
@load ./main
@load ./evidence_log
@load ./exceptions

module NSM;

export {
    const detect_exfil_volume_aggregate = T &redef;

    # 1분 집계
    const exfil_epoch = 1min &redef;

    # threshold 단계 (5MB)
    const exfil_thresholds: vector of double = vector(5.0 * 1024 * 1024) &redef;

    ## 연결당 집계 갱신 간격(바이트). originator 가 이만큼 더 보낼 때마다 반영한다.
    ##   작을수록 탐지가 빠르고 이벤트가 늘어난다. 임계(exfil_thresholds)보다 충분히 작게.
    const exfil_volume_step = 1024 * 1024 &redef;
}

## 추적 중인 연결(uid)별로 이미 반영한 페이로드 바이트.
global vol_reported: table[string] of count &read_expire=1hr;

event zeek_init()
{
    local r = SumStats::Reducer(
        $stream="nsm.exfil",
        $apply=set(SumStats::SUM)
    );

    SumStats::create([
        $name             = "nsm-detect-exfil",
        $epoch            = exfil_epoch,
        $reducers         = set(r),

        # SMB와 동일 방식 (호환성 100%)
        $threshold_series = exfil_thresholds,

        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
        {
            return result["nsm.exfil"]$sum;
        },

        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            local total = result["nsm.exfil"]$sum;

            # 집계형(임시) -> src 단위 합성 증적 key. 개별 연결 row 는 남기지 않고
            # (tcp_packet 단위라 폭증) 호스트 단위 요약 1행만 적재한다.
            local eid = cat(key$host, "|exfil-vol-agg|", time_bucket(exfil_epoch));

            NSM::write_evidence([
                $ts=network_time(),
                $evidence_id=eid,
                $note=Exfil_Volume_Aggregate,
                $technique="T1041",
                $src=key$host,
                $operation="tcp_volume_aggregate",
                $detail=fmt("sum_bytes=%.0f window=%s", total, exfil_epoch)]);

            NOTICE([
                $note=Exfil_Volume_Aggregate,
                $src=key$host,
                $msg=fmt("Exfil (volume aggregate): %s sent %.2f MB in %s",
                         key$host,
                         total/(1024.0*1024.0),
                         exfil_epoch),
                $identifier=cat(key$host, "vol-agg"),
                $suppress_for=suppress_vol_agg,
                $evidence_id=eid
            ]);
        }
    ]);
}

# =====================================================
# 연결 단위 + ConnThreshold (S3 multipart 대응)
# =====================================================

## 연결의 orig 페이로드 증가분을 SumStats 에 반영한다.
function vol_report(c: connection)
    {
    if ( c$uid !in vol_reported )
        return;
    local cur = c$orig$size;
    local prev = vol_reported[c$uid];
    if ( cur <= prev )
        return;
    # 예외(예외 파일): 허용한 백업·동기화 목적지 등. 맞으면 이 연결은 더 세지 않는다
    if ( NSM::exception_drop_agg(Exfil_Volume_Aggregate, c) )
        {
        delete vol_reported[c$uid];
        return;
        }
    SumStats::observe("nsm.exfil", [$host=c$id$orig_h], [$num=cur - prev]);
    vol_reported[c$uid] = cur;
    }

event connection_established(c: connection)
    {
    if ( ! detect_exfil_volume_aggregate )
        return;
    if ( ! Site::is_local_addr(c$id$orig_h) || Site::is_local_addr(c$id$resp_h) )
        return;
    vol_reported[c$uid] = 0;
    ConnThreshold::set_bytes_threshold(c, exfil_volume_step, T);
    }

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
    {
    if ( ! is_orig || c$uid !in vol_reported )
        return;
    vol_report(c);
    ConnThreshold::set_bytes_threshold(c, threshold + exfil_volume_step, T);
    }

event connection_state_remove(c: connection)
    {
    if ( c$uid !in vol_reported )
        return;
    vol_report(c);
    delete vol_reported[c$uid];
    }
