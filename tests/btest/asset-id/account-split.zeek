# @TEST-DOC: 계정 신호(user_account·machine_account)의 user_name·user_domain·user_domain_type — Kerberos realm\name 은 dns, NTLM domain\user 는 netbios, 도메인 없는 계정(시작 시 직접 넣은 administrator)은 user_name 만. 다른 신호는 세 칸이 비어 있다
# @TEST-EXEC: zeek -C -r $TRACES/asset-id/zeek/kinit.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value user_name user_domain user_domain_type < asset_signal.log | awk -F'\t' '$2 ~ /account/' > krb.out
# @TEST-EXEC: zeek-cut signal user_name < asset_signal.log | awk -F'\t' '$1 !~ /account/ && $2 != "-"' > other.out
# @TEST-EXEC: rm -f asset_signal.log && zeek -C -r $TRACES/asset-id/zeek/raw_ntlm_in_smb.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value user_name user_domain user_domain_type < asset_signal.log | awk -F'\t' '$2 ~ /account/' > ntlm.out
# @TEST-EXEC: btest-diff krb.out
# @TEST-EXEC: btest-diff ntlm.out
# @TEST-EXEC: test ! -s other.out

redef AssetID::asset_nets = { 192.168.0.0/16 };

event zeek_init()
	{
	AssetID::emit(192.168.0.9, AssetID::USER_ACCOUNT, "administrator", "test", 50);
	}
