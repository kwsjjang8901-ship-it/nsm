# @TEST-DOC: 메타데이터 선별 전송(T1) — 대상 스트림별 출력, 필드 축소, 스트림별 조건(SMB 동작·RPC 인터페이스), 중복 억제, 범위(conn), 원본 출력 제거, 통계
# @TEST-EXEC: zeek -C -r $TRACES/meta_export.pcap $PKG $SETUP %INPUT
#
# Kerberos: AS 2(사전인증 요구 오류 + 성공) + TGS 1
# @TEST-EXEC: assert-rows meta_kerberos.log eq 3 id.orig_h=10.0.0.60
# @TEST-EXEC: assert-rows meta_kerberos.log eq 1 request_type=TGS service=MSSQLSvc/db01.corp.example:1433 cipher=rc4-hmac
# @TEST-EXEC: assert-fields meta_kerberos.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p request_type client service success error_msg cipher
#
# NTLM: 성공 1·실패 1
# @TEST-EXEC: assert-rows meta_ntlm.log eq 1 username=user01 domainname=CORP success=T
# @TEST-EXEC: assert-rows meta_ntlm.log eq 1 username=user02
# @TEST-EXEC: assert-fields meta_ntlm.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p username domainname hostname success
#
# SMB 공유: 같은 (출발지, 경로) 두 번 연결 -> 중복 억제로 1행
# @TEST-EXEC: assert-rows meta_smb_mapping.log eq 1 id.orig_h=10.0.0.60
#
# SMB 파일: 이름 변경만 남고 열기만 한 파일은 빠짐
# @TEST-EXEC: assert-rows meta_smb_files.log eq 1 action=SMB::FILE_RENAME 'prev_name=docs\a.txt' 'name=docs\b.txt'
# @TEST-EXEC: assert-rows meta_smb_files.log eq 1
#
# RPC: drsuapi 1 + IRemoteSCMActivator 같은 호출 2번 -> 1행, IObjectExporter(목록 밖) 제외
# @TEST-EXEC: assert-rows meta_dce_rpc.log eq 1 endpoint=drsuapi operation=DRSGetNCChanges
# @TEST-EXEC: assert-rows meta_dce_rpc.log eq 1 endpoint=IRemoteSCMActivator operation=RemoteCreateInstance
# @TEST-EXEC: assert-rows meta_dce_rpc.log eq 2
#
# RDP·SSH
# @TEST-EXEC: assert-rows meta_rdp.log eq 1 cookie=administrator
# @TEST-EXEC: assert-rows meta_ssh.log eq 1 id.orig_h=10.0.0.60 id.resp_p=22
#
# conn(테스트에서 추가, 경계 또는 내부 관리 포트): 외부 443·내부 445 는 남고 내부 8080 은 빠짐, 외부 -> 내부도 경계
# @TEST-EXEC: assert-rows meta_conn.log eq 1 id.orig_h=10.0.0.61 id.resp_p=443
# @TEST-EXEC: assert-rows meta_conn.log eq 1 id.orig_h=10.0.0.61 id.resp_p=445
# @TEST-EXEC: assert-rows meta_conn.log eq 0 id.orig_h=10.0.0.61 id.resp_p=8080
# @TEST-EXEC: assert-rows meta_conn.log eq 1 id.orig_h=93.184.215.121 id.resp_p=22
# @TEST-EXEC: assert-fields meta_conn.log ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state
#
# 원본: keep_log_streams 에 없는 대상 스트림은 원본을 쓰지 않는다. conn 은 SETUP 이 유지 목록에 넣어 원본도 남는다.
# @TEST-EXEC: test ! -f kerberos.log && test ! -f ntlm.log && test ! -f smb_files.log && test ! -f dce_rpc.log
# @TEST-EXEC: test -f conn.log
#
# 통계: 스트림별 탈락 사유
# @TEST-EXEC: assert-rows meta_export_stats.log ge 1 stream=smb_mapping dropped_dedup=1
# @TEST-EXEC: assert-rows meta_export_stats.log ge 1 stream=smb_files dropped_filter=2
# @TEST-EXEC: assert-rows meta_export_stats.log ge 1 stream=dce_rpc dropped_filter=1 dropped_dedup=1
# @TEST-EXEC: assert-rows meta_export_stats.log ge 1 stream=conn dropped_scope=2
#
# 탐지 경로는 영향 없음
# @TEST-EXEC: test -f notice.log && test -f nsm_detection.log

redef NSM::meta_export_streams += {
    [Conn::LOG] = [$name="conn", $scope=NSM::META_BOUNDARY_OR_ADMIN,
                   $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                               "proto", "service", "conn_state")],
};
