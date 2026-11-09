# packages/ — 선택 패키지 수납 디렉터리 (벤더링 방식)

zkg 없이 룰셋과 함께 반입·배포하기 위한 구조.
인터넷 가능 환경에서 아래대로 받아서 각 디렉터리에 넣은 뒤 전체를 재압축하면 됨.

## 1) JA4 (주력) -> rules/ja4/
    git clone https://github.com/FoxIO-LLC/ja4
    cp -r ja4/zeek/* rules/ja4/
  - !! 라이선스: JA4(TLS 클라이언트)만 BSD 3-Clause. JA4S/JA4H 등 JA4+ 는
    FoxIO License(비상용)이므로 rules/ja4/config.zeek 에서 JA4(TLS) 외
    메서드를 반드시 비활성화할 것. (OSS 등록 시 범위: "JA4 TLS client, BSD")
  - 설치 후 ssl.log 실측으로 ja4 필드명 확인 -> nsm-config.zeek 의
    get_ja4 훅 redef 주석 해제

## 2) JA3 (레거시, 선택) -> rules/ja3/
    git clone https://github.com/salesforce/ja3
    cp -r ja3/zeek/* rules/ja3/
  - BSD 3-Clause. 기존 JA3 인텔 자산 병행용. 생략 가능(권장 구성은 ja4 단독).
  - Zeek 7+ 는 내장 fingerprint 로 대체 가능할 수 있으니 먼저 ssl.log 확인.

## 3) 활성화
  루트 __load__.zeek 의 주석 처리된 @load 를 해제:
    # @load ./rules/ja4
    # @load ./rules/ja3
  (패키지를 넣지 않은 상태에서 주석만 해제하면 로드 에러 — 순서 주의)

## 4) 검증
    zeek -a __load__.zeek                      # 문법
    zeek -r sample-tls.pcap __load__.zeek      # ssl.log 에 ja4/ja3 필드 확인
