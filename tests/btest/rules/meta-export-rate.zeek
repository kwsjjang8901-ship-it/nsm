# @TEST-DOC: 메타데이터 선별 전송 — 분당 상한(쓰는 시각 기준)을 넘는 행은 버리고 통계에 남긴다
#   한 분 안에 경계 연결 32개가 기록된다(.62 외부 연결 30개 + 연결 종료 타이머가 늦게 돈 .61 경계 연결 2개). 상한 10.
#   (통계 행은 meta_stats_interval 마다 끊기므로 보낸 10건은 두 행에 나뉠 수 있다)
# @TEST-EXEC: zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows meta_conn.log eq 10
# @TEST-EXEC: assert-rows meta_export_stats.log eq 1 stream=conn dropped_rate=22
#
# 다른 스트림과 탐지 경로는 상한의 영향을 받지 않는다
# @TEST-EXEC: assert-rows meta_kerberos.log eq 3
# @TEST-EXEC: assert-rows conn.log eq 30 id.orig_h=10.0.0.62

redef NSM::meta_export_streams += {
    [Conn::LOG] = [$name="conn", $scope=NSM::META_BOUNDARY, $rate_limit=10],
};
