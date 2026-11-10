##! 테스트 공통 설정 — 모든 테스트가 `zeek ... $PKG $SETUP %INPUT` 순서로 로드한다.
##!   - 로그를 테스트 작업 디렉터리에 운영과 같은 JSON 으로 남긴다(log-cut / assert-rows 로 검사).
##!   - 운영 필터(filter_log)는 그대로 동작시키되, 검증에 필요한 원본 로그만 추가로 켠다.

# 운영 경로(/log/zeek, /hdd_tmp/...) 대신 현재 디렉터리에 기록
redef NSM::log_paths = {};
redef NSM::create_log_dirs = T;
# 메타데이터 선별 전송은 운영과 같이 하위 디렉터리(meta/)에 쓴다. 디렉터리는 선별 전송 모듈이 만든다
#   (log_paths 가 비어 있으므로 filter_log 는 만들 디렉터리가 없다).
redef NSM::meta_path_prefix = "meta/";

# 운영 필터의 4시간 로그 회전을 끈다. pcap 재생 시 회전은 네트워크 시각 기준이라
# notice.log 가 notice.<날짜>.log 로 회전돼 버린다.
redef Log::default_rotation_interval = 0secs;

# 운영과 같은 JSON 로그(패키지가 policy/tuning/json-logs 를 로드한다). 명시해 둔다.
#   테스트 도구(tools/assert-rows, log-cut)는 JSON·TSV 를 모두 읽는다.
redef LogAscii::use_json = T;

# 디버깅·교차 확인용 원본 로그
redef NSM::keep_log_streams += { Conn::LOG, SSL::LOG, HTTP::LOG, DNS::LOG, Weird::LOG };
