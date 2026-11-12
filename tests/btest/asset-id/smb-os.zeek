# @TEST-DOC: SMB1 native OS
# @TEST-EXEC: zeek -C -r $TRACES/asset-id/zeek/smb_gssapi.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
