# @TEST-DOC: Community ID(Suricata 연동 설계 3.3절) — conn 과 연결 단위 선별 전송 로그(kerberos·ntlm·smb_mapping·smb_files·dce_rpc·rdp·ssh·ssl·http)의 community_id 가 스펙(seed, base64)대로 conn 5-tuple 에서 계산한 값과 같고 근거와도 같다. community_id_seed 를 바꾸면 conn·선별 로그·근거가 함께 바뀐다. 상태·요약 로그에는 없다
# @TEST-EXEC: zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP
# @TEST-EXEC: assert-meta-community-id 10 0 kerberos,ntlm,smb_mapping,smb_files,dce_rpc,rdp,ssh
# @TEST-EXEC: ! grep -q community_id meta/flow_summary.log meta/stats.log meta/capture_loss.log meta/meta_export_stats.log
# @TEST-EXEC: mkdir web && cd web && zeek -C -r $TRACES/meta_summary.pcap $PKG $SETUP && assert-meta-community-id 2 0 ssl,http
# @TEST-EXEC: mkdir seed && cd seed && zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP NSM::community_id_seed=7 && assert-meta-community-id 10 7 kerberos,ntlm,smb_mapping,smb_files,dce_rpc,rdp,ssh
