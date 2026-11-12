# @TEST-DOC: 자산 식별 머지 — nsm_rules 전체로 실행해도 asset_signal.log 가 로그 필터에 꺼지지 않고 남는다. SMB2 GUID 시그니처는 notice·signatures.log 를 만들지 않는다
#
# 합성 데모 pcap: 운영 필터(filter_log)를 거쳐도 자산 신호가 남는다
# @TEST-EXEC: zeek -C -r $TRACES/asset-id/demo.pcap $PKG $SETUP
# @TEST-EXEC: assert-rows asset_signal.log ge 10
# @TEST-EXEC: assert-rows asset_signal.log ge 1 signal=machine_account
# @TEST-EXEC: assert-rows asset_signal.log ge 1 signal=hostname
#
# SMB2 NEGOTIATE: 클라이언트 GUID 신호는 남고, 시그니처 프레임워크의 notice(패킷 바이트 포함)는 없다
# @TEST-EXEC: mkdir smb && cd smb && zeek -C -r $TRACES/asset-id/zeek/smb3.pcap $PKG $SETUP ../all-nets.zeek
# @TEST-EXEC: assert-rows smb/asset_signal.log ge 1 signal=smb_client_guid
# @TEST-EXEC: assert-rows smb/notice.log eq 0 note=Signatures::Sensitive_Signature
# @TEST-EXEC: test ! -e smb/signatures.log

# @TEST-START-FILE all-nets.zeek
redef AssetID::asset_nets = { 0.0.0.0/0 };
# @TEST-END-FILE
