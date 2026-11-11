# 원본 conn.log 만 유지 목록(keep_log_streams)으로 남기고 원본 dns.log 는 남기지 않는다(T2 는 끔).
redef NSM::keep_log_streams -= { DNS::LOG };
