# 작업 규칙

Zeek 기반 NSM 탐지 룰 패키지(`nsm_rules/`). 요구사항·설정의 원본 문서는 `docs/SRS.md`(탐지)와 `docs/SRS_METADATA_EXPORT.md`(메타데이터 선별 전송, `nsm_rules/metadata/`). 해당 기능을 바꾸는 PR에서 함께 고친다.

## 기본

- 대상 Zeek 9.x, CI는 9.0.1과 8.0.9. 문법 검사·시작 시 경고가 하나라도 나오면 CI가 실패한다.
  이벤트·훅 핸들러 위 주석은 `#`로 쓴다(`##`는 선언 문서용이라 Zeek 8.x가 "Discarded extraneous Zeekygen comment" 경고를 낸다).
- `nsm_rules/nsm_config_custom.zeek`는 저장소에서 비워 둔다(고객별로 배포 때 작성). 운영 기본값은 `nsm_config_fixed.zeek`.
- 테스트: `tests/run_tests.sh` (btest, 결과는 `tests/btest/output/`, JSON 로그).
- 합성 pcap은 `tests/gen_pcaps.py`로 만든다. 새 생성기는 파일 끝에 덧붙여 기존 pcap이 바이트 단위로 그대로이게 한다(CI가 재현성을 검사).
  `tests/pcaps/asset-id/`는 자산 식별 PoC에서 가져온 고정 파일이라 재현성 검사 대상이 아니다(생성기는 `tests/asset-id/`에 출처 기록용으로만 둠).
- 자산 식별(`nsm_rules/asset-id/`)을 바꾸면 `docs/asset-id/SPEC.md`와 SRS 5.5절을 함께 고친다. 단독 테스트는 `tests/btest/asset-id/`(기대 출력 `Baseline/`, 바꿀 때는 `btest -U`로 갱신하고 차이를 PR에 적는다).
- 작업은 브랜치와 PR로 하고, 머지는 사용자가 한다.

## PR 본문

탐지 룰을 추가하거나 동작을 바꾸는 PR은 `.github/pull_request_template.md` 양식을 쓰고, notice마다 ``## 탐지 (`Notice_Name`, Txxxx)`` 절을 둔다. 각 절에 들어갈 내용:

1. 한 문단 설명: 공격이 어떻게 동작하는지, 정상과 무엇이 다른지, 탐지 조건(굵게, 숫자 포함).
2. 표 "프로토콜·데이터 | 값을 얻는 방법 (Zeek 버전 소스 확인)": 쓰는 이벤트·필드, Zeek가 주지 않는 값을 어떻게 보완했는지.
3. 목록: 주체(notice `src`·`dst`), 집계·억제, 제외·오탐 통제(룰에 남긴 탐지 정의, 예외 엔진에서 쓰는 축), 근거·`lm_targets`·킬체인 묶음. 새 룰은 입구에서 `NSM::exception_drop`(건별) 또는 `exception_drop_agg`(집계형)를 부르고 새 `*_allowlist`는 만들지 않는다.
4. 파라미터 표(이름·기본값·의미).

그 뒤에 테스트 표(호스트·트래픽·기대), 공통 등록 체크리스트, 운영 영향을 적는다. 같은 내용을 `docs/SRS.md` 4장·7장에도 반영한다.

### Markdown 주의

- 굵게 닫는 `**` 바로 앞이 따옴표·괄호 같은 문장부호이고 바로 뒤에 한글이 붙으면 GitHub에서 굵게가 풀린다.
  `**어떤 이름이든 "나다"**라고`는 깨지고, `**어떤 이름이든 나다라고**` 또는 `**어떤 이름이든 "나다"** 라고`처럼 쓴다.
- 본문에 `$`가 두 번 나오면 수식으로 렌더링될 수 있다. `$src`, `ADMIN$` 같은 값은 코드 스팬(백틱)에 넣는다.
- `~`가 한 줄에 두 번 나오면 취소선이 될 수 있다. 범위는 `17~24`처럼 쓰되 한 줄에 둘 이상이면 `\~`로 쓴다.
