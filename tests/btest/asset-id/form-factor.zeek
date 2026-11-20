# @TEST-DOC: 기기 형태 힌트 — User-Agent 로 iPhone·안드로이드 폰 브라우저(Mobile) -> phone, iPad·안드로이드 태블릿 브라우저 -> tablet, 안드로이드 앱(Dalvik) -> mobile. Apple 연결 확인(CaptiveNetworkSupport) -> os_hint apple. Windows 브라우저는 형태 없음
# @TEST-EXEC: zeek -C -r $TRACES/asset_device_class.pcap $ASSETID %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -E '	(form_factor|os_hint)	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
