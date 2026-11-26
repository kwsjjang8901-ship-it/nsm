# 정식 저장소 이관 검토

문서 버전: 0.1 (2026-11-26) · 대상: nsm 저장소(main `c150bbb`, PR #165까지), surica 저장소(main `0a34783`)

이 문서는 nsm·surica 저장소의 산출물을 정식 콘텐츠 저장소(이하 **새 저장소**)로 옮기는 계획을 검토한 결과다.
새 저장소의 범위와 구조는 그 저장소 README(초안, "팀 합의 후 갱신")를 기준으로 했다.

## 0. 새 저장소 README 요약 (검토 기준)

| 포함 | 포함하지 않음 |
|---|---|
| 자체 작성 Suricata 룰, classification, threshold 설정 | Zeek/Suricata 엔진 소스·바이너리 (`nsm-sensor-build`에서 Artifactory 기준으로 관리) |
| 탐지용 Zeek 스크립트 (zkg 패키지 구조) | Zeek C++ 플러그인과 딸린 스크립트 (`nsm-sensor`) |
| 서비스 룰과 스키마 (위치 미확정) | 엔진 설정 템플릿 suricata.yaml, local.zeek (`nsm-sensor`) |
| 룰·스크립트 회귀 테스트와 정제된 테스트 pcap | 서드파티 룰(ET Open 등) 원본. 버전을 고정해 Artifactory에서 가져옴 |

디렉터리: `suricata/rules/`, `zeek/<package>/`(zkg.meta, `scripts/__load__.zeek`), `service-rules/schema/`, `tests/`, `scripts/`, `docs/`.

주요 규칙:

- Suricata 룰은 주제별 파일로 나누고, 자체 SID 대역은 따로 할당해 `docs/`에 기록한다.
- 모든 룰에 sid·rev·msg·classtype·metadata를 쓰고, 룰을 고치면 rev를 올린다.
- Zeek 스크립트는 zkg 패키지 구조를 따르고 Zeek 버전 호환을 zkg.meta에 적는다.
- 로그 필드를 바꾸면 하위 호환 여부를 PR에 적는다.
- 서드파티 콘텐츠는 복사해 커밋하지 않는다. `nsm-sensor-build`의 `deps/versions.yaml`로 버전을 고정한다.

## 1. 결론

방향은 맞다. 다만 그대로 옮기면 새 저장소 규칙에 어긋나는 것이 **세 가지**(2장) 있고, 옮기기 전에 정해야 할 것이 **여덟 가지**(4장) 있다.
그중 설정 파일 위치(4.1), 엔진 설정 경계(4.2), 스키마 위치(4.4), 버전 원천(4.5)은 파일 배치를 바꾸므로 이동 전에 정한다.

## 2. 그대로 옮기면 규칙에 어긋나는 것

| 항목 | 지금 위치 | 문제 | 처리안 |
|---|---|---|---|
| JA3 (salesforce, BSD 3-Clause) | nsm `nsm_rules/rules/ja3/` | 서드파티 Zeek 패키지를 복사해 둔 것이다 | 아래 설명 참고 |
| ET Open 룰 사본 10개 | surica `tests/rules/et_sample/rules/` | 서드파티 룰을 복사해 둔 것이다 | 새 저장소로 옮기지 않는다. 테스트에 꼭 필요하면 Artifactory 고정 버전에서 받아 쓰고, 아니면 자체 테스트 룰(SID 9900000 이상)로 바꾼다. 이력을 옮길 때는 이 경로를 이력에서도 뺀다 |
| suricata-update 룰 출처 | surica `suricata/update/update.yaml`의 `sources: et/open` | 인터넷에서 바로 받는다 | 출처를 Artifactory 주소로 바꾼다. 버전 고정은 `nsm-sensor-build`에서 한다 |

**JA3 처리안.** 원본(github.com/salesforce/ja3 `zeek/`)과 비교하면 우리 사본은 `ja3.zeek` 맨 앞의 `@load base/misc/version.zeek` 한 줄만 다르다.
이 줄을 우리 패키지의 `__load__.zeek`에서 ja3보다 먼저 로드하면 원본을 고치지 않고 쓸 수 있다.
원본은 zkg 패키지(`zkg.meta`의 `script_dir = zeek`)이므로 `nsm-sensor-build` `deps/versions.yaml`에 고정하고, 우리 `zkg.meta`의 `depends`에 적는다.
`nsm_rules/rules/PACKAGES-README.md`(JA3·JA4 반입 절차)도 이 방식으로 고친다.

## 3. 파일 대응안

```
<새 저장소>/
├── zeek/nsm/                      ← 패키지 이름은 정해야 함
│   ├── zkg.meta                   (새로 작성: script_dir = scripts, depends = ja3, Zeek 버전 조건)
│   ├── scripts/                   ← nsm_rules/ 전체(__load__, detections, asset-id, metadata, sensor, rules/filter_log)
│   └── schema/                    ← nsm schema/ (로그 스키마, rules.json, build.py, validate.py, overlay.json)
├── suricata/
│   ├── rules/local.rules          ← surica suricata/rules/
│   ├── threshold.config           ← surica suricata/
│   └── update/                    ← surica disable/enable/modify.conf, update.yaml(출처만 바꿈)
├── tests/
│   ├── zeek/                      ← nsm tests/btest, tests/pcaps(68개, 6.1MB), gen_pcaps.py, asset-id/
│   └── suricata/                  ← nsm tests/suricata, surica tests/rules/test.rules
├── scripts/                       ← run_tests.sh, run_pcap.sh, measure_perf.py, measure_meta_export.sh
└── docs/                          ← 룰 작성·운영 문서(아래 표)
```

자산 식별(`asset-id/`)은 단독으로도 로드되지만(nsm 쪽 이름은 주석에만 나옴), 배포 단위가 하나이므로 지금은 한 패키지로 둔다.
따로 배포할 일이 생기면 그때 `zeek/nsm-asset-id/`로 나눈다. 메타데이터(`metadata/`)는 `NSM::` 설정을 쓰므로 탐지 패키지와 떼지 않는다.

새 저장소로 옮기지 않는 것:

| 대상 | 갈 곳 |
|---|---|
| surica `config/sensor.example.yaml`, `tools/render_config.py`, `sensor_config.py`, `eve_envelope.py` | `nsm-sensor` (엔진 설정 템플릿·전송) |
| nsm `ui/` 목업, `docs/examples/*.html`, PoC 결과·검토 문서(`*_POC_RESULT.md`, `*_REVIEW.md`) | 지금 저장소를 읽기 전용으로 보관 |
| `tests/report_pcap.py`, `report_mockup.py`, `asset_enrich.py`, `detection_enrich.py`, surica `tools/alert_join.py`, `run_poc.sh` | PoC 리포트 도구. 보관하되, 회귀 테스트(`test_detection_enrich.py`, btest)에 계속 쓰는 것만 `scripts/`로 옮김 |

문서:

| 문서 | 처리안 |
|---|---|
| `SRS.md`, `SRS_METADATA_EXPORT.md`, `LOG_SCHEMA.md`, `SENSOR_CONTROL_SPEC.md`, `DETECTION_GUIDE.md`, `asset-id/SPEC.md`, `SENSOR_SIZING_GUIDE.md` | 룰·스키마와 함께 바뀌는 문서라 새 저장소 `docs/`로 옮긴다. 제품 문서를 따로 관리하는 곳이 있으면 그쪽으로 옮긴다 |
| `docs/examples/exceptions*.tsv` | 예외 파일 예시라 `docs/`로 옮긴다 |
| 설계·검토·PoC 결과 문서 | 보관 저장소에 남긴다 |
| SID 대역 문서 | 새로 작성(4.7) |

## 4. 옮기기 전에 정할 것

### 4.1 설정 파일 위치 (가장 중요)

- 고객별 `nsm_config_custom.zeek`와 Manager가 만드는 `nsm_config_policy.zeek`가 지금은 패키지 안(`detections/`)에 있다.
- 패키지를 배포물로 다루면 업그레이드할 때 이 파일이 덮어써지고, 설치 경로에 파일을 써야 하는 문제가 생긴다.
- 권장안: 패키지에는 `nsm_config_fixed.zeek`만 두고, custom·policy는 `nsm-sensor`의 local.zeek이 패키지 다음에 로드한다.
- 확인할 점: 지금 `__load__.zeek`는 policy 다음에 `intel_ja3`, `rules/filter_log`, `json-logs`를 로드한다. 로드 순서(fixed → custom → policy)와 기본값이 적용되는 시점이 그대로인지 확인한다.
- `SENSOR_CONTROL_SPEC.md`와 `CLAUDE.md`의 로드 순서 설명을 함께 고친다. 동작이 바뀌는 일이므로 이동 PR과 나눈다.

### 4.2 엔진 설정과의 경계

- README는 local.zeek를 `nsm-sensor` 몫으로 둔다.
- 패키지 안에도 엔진 설정 성격의 것이 있다: `rules/filter_log.zeek`, `policy/tuning/json-logs`·`policy/protocols/conn/mac-logging` 로드, 로그 경로 기본값(`/log/zeek`, `/hdd_tmp/log/zeek`).
- 탐지와 스키마 검사(CI)가 JSON 로그를 전제하므로 기본값은 패키지에 남기고, `nsm-sensor`가 `redef`로 바꾸는 방식을 권한다.
- `filter_log`를 어느 쪽에 둘지는 정해야 한다.

### 4.3 zkg 설치 방식

- zkg는 git 저장소 최상위의 `zkg.meta`를 읽는 것으로 알고 있다. 그래서 `zeek/<package>/` 같은 하위 디렉터리를 `zkg install <URL>`로 바로 설치하지 못할 가능성이 크다(확인 필요).
- 지금 배포는 zkg 없이 디렉터리를 복사하는 방식이라 당장 문제는 없다.
- README의 "zkg 패키지 구조"가 zkg 설치까지 뜻하면 `nsm-sensor-build`에 패키지 디렉터리만 떼어 만드는 단계를 둔다.

### 4.4 스키마 위치

- 로그 스키마(`schema/logs/`)와 룰 목록(`schema/rules.json`)은 Zeek 코드에서 생성되고 Manager와의 계약이다. 그래서 패키지 옆(`zeek/nsm/schema/`)에 두기를 권한다.
- README의 `service-rules/schema/`가 같은 것을 가리키는지 확인한다. "서비스 룰"의 정의가 아직 없다.

### 4.5 버전 원천

- 지금 버전 값이 네 곳에 있다: 저장소 `VERSION`(새로 생김), `NSM::pkg_version`(`sensor/version.zeek`, 0.1.0), `zkg.meta` version(새로 생김), `NSM::schema_version`(build.py가 만듦).
- 권장안: `VERSION`을 원천으로 두고, 빌드가 `zkg.meta`와 `pkg_version`에 넣고, CI가 일치하는지 검사한다. 스키마 버전은 지금처럼 따로 둔다.

### 4.6 CI

- 지금은 GitHub Actions(`.github/workflows/zeek-check.yml`)이다.
  - Zeek 9.0.1과 8.0.9에서 문법 검사·시작 시 경고 0
  - btest
  - 로그 스키마 검사
  - pcap 재현성(`scapy==2.6.1`)
- 사내 CI로 옮기면 Docker Hub의 `zeek/zeek` 이미지와 pip 패키지를 Artifactory 미러에서 받아야 한다.
- Suricata 쪽에는 `suricata -T` 룰 검사를 새로 둔다.

### 4.7 SID 대역

- README에는 "대역 확정 후 기재"로 비어 있다.
- surica에서 쓰던 값은 사내 룰 9000000–9099999, 테스트 룰 9900000 이상이다.
- ET Open(2000000번대)과 겹치지 않아 후보로 그대로 쓸 수 있다. 팀에서 확정해 `docs/`에 적는다.
- classification은 아직 자체 파일이 없고 Suricata 기본 파일을 쓴다.

### 4.8 이력

- nsm은 공개 저장소이고 커밋이 363개이다. surica는 5개다.
- `git filter-repo`로 경로를 바꿔 이력을 같이 옮기면 룰별 변경 맥락이 남는다. PR 본문에 적은 탐지 근거도 커밋 링크로 찾을 수 있다. 대신 ET 사본 경로는 이력에서 뺀다.
- 스냅샷만 옮긴다면 원본 저장소를 보관하고 새 저장소 README에 링크를 남긴다.

## 5. 경로가 바뀌면 같이 고칠 곳

| 대상 | 내용 |
|---|---|
| 테스트·도구 | `tests/btest/btest.cfg`(`PKG`, `ASSETID`), CI 워크플로, `schema/build.py`(`ROOT`, `sensor/schema_version.zeek` 경로), `run_pcap.sh`, `measure_perf.py`, `gen_pcaps.py` 출력 경로 |
| 문서 | 38개 파일에 `nsm_rules` 참조가 121곳 있다. GitHub 링크 13곳(nsm·surica·claudtest2)과 `CLAUDE.md`도 고친다 |
| 다른 저장소 | `nsm-sensor` local.zeek의 로드 경로, Manager가 정책 파일을 배포하는 경로(4.1과 함께) |

## 6. 진행 순서

| 단계 | 내용 | 확인 |
|---|---|---|
| 1 | 4장의 4.1·4.2·4.4·4.5 결정 | - |
| 2 | 이동만 하는 PR. 내용은 고치지 않고 경로 참조만 고친다 | btest가 지금과 같다(9.0.1 158/158, 8.0.9 152 통과·6 건너뜀). 합성 pcap 66개 출력이 이동 전과 같다. pcap 재현성 검사를 통과한다 |
| 3 | 서드파티 정리: JA3 의존성 전환, ET 사본 제외, 룰 출처를 Artifactory로 | 문법 검사·btest 동일, ssl.log `ja3` 필드 동일 |
| 4 | 설정 파일 경계 변경(4.1·4.2). 동작 변경이라 별도 PR | 로드 순서 btest, `SENSOR_CONTROL_SPEC` 갱신 |
| 5 | nsm·surica를 읽기 전용으로 보관하고 README에 새 위치를 적음 | - |
