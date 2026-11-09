##! 테스트 공통 설정 — 모든 테스트가 `zeek ... $PKG $SETUP %INPUT` 순서로 로드한다.
##!   - 로그를 테스트 작업 디렉터리에 TSV 로 남긴다(zeek-cut / assert-rows 로 검사).
##!   - 운영 필터(filter_log)는 그대로 동작시키되, 검증에 필요한 원본 로그만 추가로 켠다.

# 운영 경로(/log/zeek, /hdd_tmp/...) 대신 현재 디렉터리에 기록
redef NSM::log_paths = {};
redef NSM::create_log_dirs = F;

# json-logs 대신 TSV (assert-rows 가 #fields 헤더를 사용)
redef LogAscii::use_json = F;

# 디버깅·교차 확인용 원본 로그
redef NSM::keep_log_streams += { Conn::LOG, SSL::LOG, HTTP::LOG, DNS::LOG, Weird::LOG };
