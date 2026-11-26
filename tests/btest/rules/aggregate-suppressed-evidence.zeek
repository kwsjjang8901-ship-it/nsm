# @TEST-DOC: 집계형 룰은 notice 가 억제되는 반복이면 근거도 남기지 않는다(FR-C5). 22 이름 포이즈닝: 첫 창에서 이름 5개로 탐지(억제 1시간), 다음 창에서 다른 이름 5개로 다시 임계를 넘으면 notice 는 억제되고 근거도 쓰지 않는다(전에는 탐지가 없는 근거가 남았다)
# @TEST-EXEC: zeek $PKG $SETUP %INPUT
# @TEST-EXEC: assert-rows notice.log eq 1 note=NSM::Name_Poisoning src=10.0.0.66
# @TEST-EXEC: assert-rows evidence.log eq 5 note=NSM::Name_Poisoning
# @TEST-EXEC: ! grep -q 'second' evidence.log

module NSM;

redef exit_only_after_terminate = T;
redef poisoning_interval = 2secs;

global batch: event(tag: string);
global stop: event();

event batch(tag: string)
	{
	for ( i in set(1, 2, 3, 4, 5) )
		poisoning_observe("llmnr", 10.0.0.66, 10.0.0.5, fmt("%s-host%d", tag, i));
	}

event stop()
	{
	terminate();
	}

event zeek_init()
	{
	schedule 500msec { batch("first") };
	schedule 3sec { batch("second") };
	schedule 6sec { stop() };
	}
