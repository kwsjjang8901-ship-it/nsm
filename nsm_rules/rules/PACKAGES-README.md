# packages/ — 선택 패키지 수납 디렉터리 (벤더링 방식)

> **현재 형상 (2026-11):** 제품 형상은 **JA3(rules/ja3) 단독** 사용.
> JA4는 FoxIO License 1.1의 상업적 사용 제한 때문에 제품 형상에서 사용하지 않고
> 평가/테스트 형상에서만 쓴다 (`detections/nsm_config_fixed.zeek` [09] 참고).
> JA3는 루트 `__load__.zeek` 최상단에서 이미 로드되며, JA4 로드 줄은 두지 않는다.
> 아래 1)~3)의 JA4 절차는 평가 형상 구성 시에만 적용한다.

zkg 없이 룰셋과 함께 반입·배포하기 위한 구조.
인터넷 가능 환경에서 아래대로 받아서 각 디렉터리에 넣은 뒤 전체를 재압축하면 됨.

## 1) JA4 (평가 형상 전용) -> rules/ja4/
    git clone https://github.com/FoxIO-LLC/ja4
    cp -r ja4/zeek/* rules/ja4/
  - !! 라이선스: JA4(TLS 클라이언트)만 BSD 3-Clause. JA4S/JA4H 등 JA4+ 는
    FoxIO License(비상용)이므로 rules/ja4/config.zeek 에서 JA4(TLS) 외
    메서드를 반드시 비활성화할 것. (OSS 등록 시 범위: "JA4 TLS client, BSD")
  - 설치 후 ssl.log 실측으로 ja4 필드명 확인 -> detections/nsm_config_fixed.zeek 의
    get_ja4 훅 redef 주석 해제

## 2) JA3 (제품 형상 사용 중) -> rules/ja3/
    git clone https://github.com/salesforce/ja3
    cp -r ja3/zeek/* rules/ja3/
  - BSD 3-Clause. 기존 JA3 인텔 자산 병행용. 제품 형상의 지문 탐지는 JA3 로 운영.
  - Zeek 7+ 는 내장 fingerprint 로 대체 가능할 수 있으니 먼저 ssl.log 확인.

## 3) 활성화
  JA3 는 루트 __load__.zeek 에서 이미 로드됨(@load ./rules/ja3).
  JA4 평가 시에만 루트 __load__.zeek 최상단에 추가:
    @load ./rules/ja4
  (패키지를 넣지 않은 상태에서 주석만 해제하면 로드 에러 — 순서 주의)

## 4) 검증
    zeek -a ./nsm_rules                        # 문법 (저장소 루트에서)
    zeek -C -r sample-tls.pcap ./nsm_rules     # ssl.log 에 ja3(ja4) 필드 확인
