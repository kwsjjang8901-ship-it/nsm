# @TEST-DOC: [검토 C3] 운영 기본 필터 — 유지 목록(notice/detection/evidence/reporter 등)만 남고 conn 등 원본 로그는 꺼진다
# @TEST-EXEC: zeek -C -r $TRACES/port_scan.pcap $PKG %INPUT
# @TEST-EXEC: test -f notice.log && test -f nsm_detection.log && test -f evidence.log && test -f loaded_scripts.log
# @TEST-EXEC: test ! -f conn.log && test ! -f weird.log

# SETUP 은 쓰지 않고 운영 기본 keep_log_streams 를 그대로 검사한다. 경로만 현재 디렉터리로.
redef NSM::log_paths = {};
redef NSM::create_log_dirs = F;
redef Log::default_rotation_interval = 0secs;
