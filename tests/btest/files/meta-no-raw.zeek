# 운영 기본값처럼 원본 conn·dns 로그를 남기지 않는다(테스트 공통 설정 setup.zeek 은 교차 확인용으로 남긴다).
redef NSM::keep_log_streams -= { Conn::LOG, DNS::LOG };
