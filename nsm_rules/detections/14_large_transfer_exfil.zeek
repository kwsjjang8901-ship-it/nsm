##! ============================================================================
##! [13-agg] Exfiltration - 호스트 단위 바이트 집계형 (S3 multipart 대응)  ※ 14번
##!
##!   - 10번(단일 연결 100MB)과 별개로, src 호스트가 1분 창에서 외부로 보낸
##!     orig 페이로드 바이트를 SumStats 로 합산해 임계(기본 5MB) 초과를 본다.
##!   - 10번과의 충돌을 피하기 위해 독립 notice 타입(Exfil_Volume_Aggregate)을 쓴다.
##!     ※ 추후 삭제 가능성 있음 -> 증적도 자기완결적 1행만 남겨 제거가 깔끔하게.
##!
##! 주의(검토 의견)
##!   - tcp_packet 기반 observe 는 패킷당 호출이라 고대역에서 비용이 크다.
##!     운영 적용 시 connection_state_remove 기반(연결 단위)으로의 전환을 권장.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    const detect_exfil_volume_aggregate = T &redef;

    # 1분 집계
    const exfil_epoch = 1min &redef;

    # threshold 단계 (5MB)
    const exfil_thresholds: vector of double = vector(5.0 * 1024 * 1024) &redef;
}

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
# packet 기반 (S3 multipart 대응)
# =====================================================

event tcp_packet(c: connection,
                 is_orig: bool,
                 flags: string,
                 seq: count,
                 ack: count,
                 len: count,
                 payload: string)
{
    if ( !detect_exfil_volume_aggregate )
        return;

    if ( is_orig && len > 0 )
    {
        if ( Site::is_local_addr(c$id$orig_h) &&
             !Site::is_local_addr(c$id$resp_h) )
        {
            SumStats::observe("nsm.exfil",
                [$host=c$id$orig_h],
                [$num=len]);
        }
    }
}
