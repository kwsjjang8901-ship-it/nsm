# T2: 선별 전송 대상 스트림의 원본을 로컬 경로(raw_ 접두어)에도 남긴다.
redef NSM::meta_keep_raw_local = T;
redef NSM::meta_raw_path_prefix = "raw_";
