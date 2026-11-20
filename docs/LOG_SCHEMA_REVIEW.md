# 센서 로그 형식 검토 (Manager 개발 관점)

- 검토일: 2026-11-20 · 기준: main `0fed325`(PR #120까지)
- 대상: 센서가 Manager로 보내는 로그 `nsm_detection.log`, `evidence.log`, `nsm_exception.log`, `asset_signal.log`, `meta/*.log`(선별 전송), `meta_export_stats.log`. 센서에만 남는 `notice.log`·`stats.log`·`capture_loss.log`는 참고로만 봤습니다.
- 방법: 스키마 정의(`detection_log.zeek`, `evidence_log.zeek`, `correlation_killchain.zeek`, `exceptions.zeek`, `asset-id/main.zeek`, `metadata/main.zeek`)와 합성 pcap 실행 결과(`killchain_story`, `proxy_c2`)의 실제 행, 그리고 리포트(`tests/report_pcap.py`, `tests/report_mockup.py`)가 로그를 읽는 방식을 대조했습니다.
- 관련: [탐지 SRS 6장](SRS.md), [선별 전송 SRS](SRS_METADATA_EXPORT.md), [자산 식별 SPEC 2장](asset-id/SPEC.md), [통합 리포트 스펙](REPORT_SPEC.md)

---

## 요약

**기본 형식은 Manager가 바로 쓸 수 있습니다.** JSON 한 줄 한 행, 목록 필드는 JSON 배열, 시각은 epoch 초(ClickHouse `DateTime64`로 바로 적재), 탐지와 근거는 `evidence_ids`로 조인되고, 같은 공격의 반복은 `incident_id`·`occurrence`로 묶입니다.

다만 **Manager를 만들기 전에 고치는 것이 싼 항목**이 있습니다. 필드를 더하는 것은 하위 호환이라 지금 넣어도 기존 소비자(리포트, OCSF 변환기)가 깨지지 않습니다. 반대로 Manager가 테이블을 만든 뒤에는 이름·의미를 바꾸기 어렵습니다.

| 우선 | # | 항목 | 지금 | 제안 |
| --- | --- | --- | --- | --- |
| P1 | D1 | 등급을 숫자로도 | `severity` 문자열(`Information`·`Suspicious`) | `severity_id` 정수 추가(OCSF 척도). 문자열은 유지 |
| P1 | D2 | 센서 식별·스키마 버전 | 행에 센서 식별자 없음(`node`는 클러스터 노드 이름) | 수집 에이전트가 `sensor_id`를 붙이고, 센서는 상태 로그에 버전을 남김 |
| P1 | D3 | 상관 탐지 갱신 | 체인이 길어질 때마다 같은 `detection_id`로 새 행. 갱신 번호 없음, 갈래가 다른 체인도 같은 id | `revision` 추가, 갈래별 id 또는 마지막 행이 전체를 담게 |
| P1 | D4 | 룰 식별 키 | 탐지 로그에 notice 이름이 없음. 상관 진단명은 첫·마지막 단계에 따라 바뀜 | `rule` 필드(예: `TLS_Beaconing`, 상관은 `Correlated_KillChain`) 추가 |
| P1 | E1 | 근거의 핵심 값 | `detail` 자유 문자열(`host=… via_proxy=… port=…`). 리포트가 정규식으로 뽑음 | 자주 쓰는 값을 필드로: `dst_name`, `dst_port`, `proxy`, `bytes`, `window_s` |
| P2 | D5 | 피해 host 개수 | `victims`는 상한(`chain_max_victims`)까지만, 잘렸는지 모름 | `victim_count` 추가 |
| P2 | X1 | 예외 적재 시각 | `kind=loaded`·`rejected` 행의 `ts`가 0(시작 전 `network_time`) | 실제 시각(`current_time()`)과 파일 지문(`file_sha1`) |
| P2 | M1 | 선별 전송 필드 이름 | 행 단위 로그는 `id.orig_h`(점), 요약 로그는 `orig_h` | 센서에서 `orig_h`·`orig_p`·`resp_h`·`resp_p`로 통일(`field_name_map`) |
| P2 | S1 | 센서 상태 로그 | 없음(장비 현황 화면이 쓸 값이 Zeek 기본 로그에 흩어져 있고 센서에만 남음) | `nsm_sensor.log` 1분 주기(버전·패킷·누락·로그 지연) |
| P2 | E2 | 상관 근거의 하위 id | `parent_id` 쉼표 문자열 | 배열 |
| P3 | E3 | 시간 값의 단위 | `detail` 안 `window=10.0 mins`, `interval=30.0s` | E1의 `window_s`처럼 초 단위 숫자 |
| P3 | G1 | 열거값·스키마 문서 | 값 목록이 코드·SRS에 흩어짐 | 열거값 표 한 곳 + JSON Schema(CI에서 실제 행 검증) |

---

## 1. 그대로 두는 것

| 항목 | 이유 |
| --- | --- |
| JSON 한 줄 한 행, `ts` epoch 초(소수) | ClickHouse·수집기 모두 바로 읽음. ISO 문자열보다 작고 시간대 문제가 없음 |
| 목록 필드는 JSON 배열(#96) | `techniques`, `killchain_stages`, `victims`, `evidence_ids`, 예외 `scope`, 요약 `service` |
| 탐지 ↔ 근거: `evidence_ids` ↔ `evidence_id` | 탐지 1건 = 탐지 요약 1행 계약을 btest가 검사 |
| 사건 묶기: `incident_id`(첫 탐지 id)·`occurrence` | Manager는 `occurrence > 1`을 새 알림 없이 갱신으로 처리 |
| `first_seen`·`last_seen` | 집계형 룰은 `ts`가 창이 끝난 시각이라 실제 구간은 이 둘로 봄 |
| 자산 신호: `signal`·`value` 정규화, `confidence` 0\~100, `source` | 판정(리졸버·Manager)이 출처별 신뢰도로 결합. 중복 억제 규칙이 명확(SPEC 2장) |
| 선별 전송 요약의 `node`, `ts`·`ts_end` | 클러스터에서 노드별 요약을 합칠 때 씀 |

---

## 2. 항목별 검토

### D1. 등급을 숫자로도 (`severity_id`)

**지금:** `severity`는 문자열입니다. 단독 탐지는 `Information`, 상관 탐지는 `Suspicious`입니다(`detection_log.zeek`, `correlation_killchain.zeek`).

**문제:** Manager는 등급으로 정렬하고("높은 것부터"), 임계로 거르고("이 등급 이상만 알림"), 색을 정합니다. 문자열이면 Manager 코드에 순서 표가 따로 있어야 하고, 등급이 늘 때 소비자가 모두 바뀝니다. OCSF 변환기도 문자열을 `severity_id`로 다시 매핑합니다.

**제안:** 문자열은 **바꾸지 않고**, 정수 `severity_id`를 더합니다. 척도는 OCSF와 같게 둡니다(변환기가 그대로 씀).

| `severity_id` | OCSF 이름 | NSM에서 |
| --- | --- | --- |
| 1 | Informational | 단독 탐지(`Information`) |
| 2 | Low | (예약) |
| 3 | Medium | 상관 탐지(`Suspicious`) |
| 4 | High | (예약: 예를 들어 유출·피해 단계까지 이어진 상관 탐지) |
| 5 | Critical | (예약) |

- 문자열을 없애지 않는 이유: 사람이 로그를 읽을 때와 `grep`, 기존 리포트·변환기가 문자열을 씁니다. 숫자는 정렬·비교용, 문자열은 표시용으로 둘 다 둡니다.
- **센서 등급과 Manager 우선순위는 따로 둡니다.** 목업의 룰별 위험도(Critical·High 등)는 고객이 Manager에서 바꾸는 정책 값입니다. 이 값을 센서 로그에 넣으면 바꿀 때마다 센서를 다시 배포해야 합니다. 센서는 "무엇을 봤는가"(단독·상관, 체인 길이)만 등급으로 내고, Manager가 룰 표로 우선순위를 붙입니다.
- 비용: 정수 필드 하나(행당 약 16바이트).

### D2. 센서 식별·스키마 버전

**지금:** 탐지·근거·자산 신호 행에는 어느 센서가 썼는지가 없습니다. 선별 전송·예외 로그의 `node`는 클러스터 노드 이름(standalone이면 `zeek`)이라 센서 식별자가 아닙니다. 스키마 버전도 없습니다. 이전 보고서들도 다음 단계로 적어 둔 항목입니다(POC_RESULT "MDS Manager 연동").

**문제:** 센서가 여러 대면 `detection_id`가 겹칠 수 있고(D5), 필드가 바뀐 버전이 섞여 들어오면 Manager가 구분하지 못합니다.

**제안:**
- `sensor_id`는 **수집 에이전트가 모든 행에 붙입니다.** 에이전트는 센서 등록 때 받은 id를 알고 있고, 센서 코드는 그대로 둘 수 있습니다. 센서 행마다 넣으면 로그 크기가 늘고, 설정이 틀린 센서가 남의 id를 쓸 위험이 있습니다.
- 스키마 버전은 행마다 넣지 않고 **센서 상태 로그(S1)에 한 번** 남깁니다(`schema_version`, 패키지·룰·Zeek 버전). Manager는 센서별 최신 상태 행으로 해석 규칙을 고릅니다.
- 정할 것: 에이전트가 붙일 필드 이름(`sensor_id`)과 위치(행 최상위)를 에이전트 담당과 맞춥니다.

### D3. 상관 탐지의 갱신

**지금:** 상관 탐지는 체인이 한 단계 길어질 때마다 새 행을 냅니다. `detection_id`(`kc-<시작 epoch>-<번호>`)는 같고, `incident_id`·`occurrence`는 비어 있습니다. `killchain_story` 실행에서 한 체인이 8행이었습니다(2→2→3→4→5→6→6→6단계). 마지막 세 행은 유출 갈래 두 개와 피해 갈래 하나로, 내용이 다른데 같은 id입니다.

**문제:** Manager는 같은 id를 "갱신"으로 덮어써야 하는데 순서를 `ts`로만 알 수 있습니다. 갈래가 다른 행이 같은 id로 오면 마지막 행(피해 갈래)이 앞 갈래(유출)를 덮어써 유출 단계가 사라집니다.

**제안 (둘 중 하나, 앞쪽 권장):**
1. 체인 상태가 갈래를 합친 전체를 담게 하고(단계·기법·피해 host 합집합), `revision`(1부터 증가)을 붙입니다. Manager는 `(detection_id, revision)` 최대 행만 씁니다.
2. 갈래마다 다른 `detection_id`를 쓰고 `incident_id`로 묶습니다.

어느 쪽이든 `revision`(또는 `occurrence`)을 상관 행에도 채워 단독 탐지와 같은 규칙으로 처리하게 합니다.

### D4. 룰 식별 키 (`rule`)

**지금:** 탐지 로그에는 `diagnosis`(`NSM.C2.TlsBeaconing`)만 있고 notice 이름(`TLS_Beaconing`)은 근거 로그의 `note`(`NSM::TLS_Beaconing`)에만 있습니다. 상관 진단명은 `NSM.Correlation.<첫 단계>.<마지막 단계>`라 같은 체인도 갱신마다 바뀝니다. 목업형 리포트는 근거의 `note`를 먼저 보고, 없으면 `detection_log.zeek`의 표를 읽어 거꾸로 찾습니다.

**문제:** Manager의 룰 정책(위험도·사용 여부·예외 scope)은 notice 이름 기준인데, 탐지 행에서 바로 얻을 수 없습니다.

**제안:** 탐지 로그에 `rule`(notice 이름, `NSM::` 접두사 없이)을 더합니다. 상관은 `Correlated_KillChain`입니다. `diagnosis`는 표시용으로 그대로 둡니다. 예외 파일의 `scope`와 같은 값이라 Manager가 "이 탐지에 맞는 예외"를 바로 찾을 수 있습니다.

### D5. `detection_id`와 피해 host 개수

- `detection_id`는 단독 탐지가 `출발지|룰|대상|시간 구간`(예: `172.16.0.66|port-scan|10.0.10.81|5980608`), 상관 탐지가 `kc-<epoch>-<번호>`입니다. 같은 입력이면 같은 id라서 재전송·중복 적재에 강합니다. 다만 센서가 여러 대면 겹칠 수 있으므로 Manager의 키는 `(sensor_id, detection_id)`로 둡니다(D2가 되면 센서 쪽 변경 없음). 상관 id의 번호는 프로세스 안 순번이라, 같은 초에 재시작하면 겹칠 수 있습니다. 노드 이름이나 난수 몇 자를 붙이는 것을 권합니다.
- `victims`는 `chain_max_victims`개까지만 담고 잘렸는지 알려 주지 않습니다. 확산 탐지에서 "몇 대에 퍼졌나"가 중요하므로 `victim_count`(전체 수)를 더합니다.

### E1. 근거의 핵심 값을 필드로

**지금:** `evidence.log`의 `detail`은 룰마다 다른 `key=value` 문자열입니다(근거를 쓰는 곳 42곳). 리포트는 프록시 경유 표시와 같은 인프라 판단에 `host=`, `sni=`, `via_proxy=`, `port=`를 정규식으로 뽑습니다(`report_pcap.py`의 `_HOSTKEY`·`_VIA_PROXY`, `report_mockup.py`).

**문제:** Manager도 같은 정규식을 가져야 합니다. 룰이 문구를 바꾸면 조용히 깨지고, 값으로 검색·집계(예: "이 도메인으로 간 근거")할 때 문자열 검색이 됩니다.

**제안:** 여러 룰에 공통인 값만 선택 필드로 올리고, 나머지는 `detail`에 둡니다.

| 필드 | 타입 | 내용 | 쓰는 룰(예) |
| --- | --- | --- | --- |
| `dst_name` | string | 목적지 이름(SNI > 프록시 CONNECT 대상 > HTTP Host > DNS 질의) | C2·유출·AI·IOC·DNS 계열 |
| `dst_port` | port | 실제 목적지 포트(프록시 경유면 CONNECT 대상 포트) | 비표준 포트, 유출, 스캔 |
| `proxy` | string | 거친 프록시 `주소:포트` | 프록시 인식 룰(07·09·10·12·14·24·30·33) |
| `bytes` | count | 이 근거의 전송량(바이트) | 유출·AI 업로드 |
| `window_s` | double | 집계 창(초) | 집계형 룰 전부 |

- 지금 `detail`은 그대로 둡니다(사람이 읽는 요약, 하위 호환).
- 작업: `proxy_detail()`·`conn_dest_name()` 같은 공통 함수가 이미 있어, 근거를 쓰는 곳에서 필드 몇 개를 같이 채우면 됩니다. 리포트는 필드가 있으면 필드를, 없으면 정규식을 씁니다.

### E2·E3. 근거의 그 밖의 형식

- `parent_id`(상관 행이 묶는 하위 근거 id)는 쉼표로 이은 문자열입니다. 다른 목록 필드처럼 배열로 바꿉니다. 지금 이 필드를 읽는 소비자는 없습니다.
- `note`는 `NSM::Port_Scan`처럼 Zeek 열거형 이름입니다. D4의 `rule`과 같은 값을 쓰도록 접두사 없는 형태로 맞추면 조인이 단순해집니다(바꾸면 리포트도 함께 수정).
- 시간 값이 `detail` 안에 `10.0 mins`, `30.0s`처럼 Zeek 표기로 들어갑니다. 필드로 올리는 값(E1의 `window_s`)은 초 단위 숫자로 씁니다.

### X1. 예외 로그

- 시작할 때 쓰는 `kind=loaded`·`rejected` 행의 `ts`가 0입니다(트래픽을 읽기 전 `network_time()`). Manager는 "언제 이 예외 파일이 적용됐나"를 알 수 없습니다. 이 행은 실제 시각(`current_time()`)으로 씁니다.
- 어떤 예외 파일이 적용됐는지 확인할 수 있게, 파일을 읽을 때 한 번 `file_sha1`(또는 Manager가 붙인 버전 id)을 남깁니다. Manager가 배포한 버전과 센서가 읽은 버전을 비교하는 데 씁니다.
- 예외 조건(주소·도메인)은 로그에 없습니다. 원본이 Manager에 있으므로 그대로 둡니다.

### M1. 선별 전송 로그의 필드 이름

- 행 단위 로그(`kerberos`, `ntlm`, `smb_*`, `dce_rpc`, `http`, `ssl` 등)는 Zeek 원래 이름 `id.orig_h`·`id.resp_p`를 쓰고, 요약 로그(`flow_summary`, `dns_summary`, `http_ua_summary`)는 `orig_h`·`resp_h`를 씁니다. 통합 보고서는 "적재 때 점이 들어간 이름을 바꾼다"고 적어 두었습니다.
- 수집기·Manager·리포트가 각자 바꾸지 않도록, **센서에서 `Log::Filter`의 `field_name_map`으로 `orig_h`·`orig_p`·`resp_h`·`resp_p`로 통일**하는 것을 권합니다. 선별 전송 로그만 해당하고, 원본 로그(T2 보관)는 Zeek 이름 그대로 둡니다.
- 리포트(`report_pcap.py`)는 이미 두 이름을 모두 읽습니다.

### S1. 센서 상태 로그

목업의 장비 현황(마지막 응답, 패킷·트래픽, 패킷 누락, 기록 전송 지연, 엔진 버전)에 필요한 값이 지금은 Zeek 기본 로그(`stats.log`, `capture_loss.log`)에 흩어져 있고 센서에만 남습니다. 1분마다 한 행씩 쓰는 `nsm_sensor.log`를 제안합니다.

| 필드 | 내용 |
| --- | --- |
| `ts`, `node` | 시각, 노드 |
| `schema_version` | 로그 형식 버전(D2) |
| `pkg_version`, `zeek_version`, `rules_version` | 패키지·Zeek·룰(엔진 업데이트 화면의 버전) |
| `pkts`, `bytes`, `pkts_dropped`, `loss_pct` | 1분 동안 받은 패킷·바이트, 놓친 패킷·비율 |
| `exc_version` | 적용 중인 예외 파일 지문(X1) |
| `uptime_s` | 시작 후 시간 |

CPU·메모리·디스크와 전송 지연은 센서 밖에서 재는 값이라 수집 에이전트가 채우는 것이 자연스럽습니다.

### G1. 열거값과 스키마 문서

- 값 목록이 코드와 SRS에 흩어져 있습니다: `category`(`Single`·`Correlated`), `severity`, `disposition`(`suppressed`), 예외 `kind`(`loaded`·`rejected`·`expired`·`hits`·`error`), 자산 `signal`·`source`, 진단명.
- 로그별 JSON Schema를 저장소에 두고, CI의 btest가 실제 출력 행을 검증하게 하면 필드가 바뀔 때 바로 드러납니다. Manager 담당은 이 파일을 기준으로 테이블을 만듭니다.

---

## 3. "위험도를 숫자로 바꾸는 게 낫지 않나"에 대한 답

**바꾸지 말고 더합니다(D1).** `severity_id`를 정수로 추가하고 OCSF 척도(1 Informational … 5 Critical)를 씁니다. 정렬·임계·색은 숫자로 하고, 문자열은 사람이 읽는 값으로 남깁니다. 지금은 단독 1, 상관 3이고, 상관 체인이 유출·피해까지 이어지면 4로 올리는 식의 세분은 나중에 센서만 바꾸면 됩니다. 룰별 우선순위(Critical·High 등)는 Manager가 정책으로 붙이는 값이라 센서 로그에 넣지 않습니다.

---

## 4. 작업 순서와 호환성

| 순서 | 작업 | 호환성 |
| --- | --- | --- |
| 1 | D1·D4·D5(`victim_count`)·X1: 탐지·예외 로그에 필드 추가 | 추가만, 기존 소비자 영향 없음 |
| 2 | D3: 상관 갱신 규칙(`revision`, 갈래 합치기) | 행 수가 줄 수 있음(리포트의 "중간 단계 포함" 보기 확인) |
| 3 | E1·E2: 근거 공통 필드, `parent_id` 배열 | 추가 + 형식 변경 1개(소비자 없음). 리포트는 필드 우선으로 |
| 4 | M1: 선별 전송 행 로그 필드 이름 통일 | 이름 변경. 리포트는 이미 두 이름을 읽음. OCSF 변환기 확인 필요 |
| 5 | S1·G1: 센서 상태 로그, JSON Schema와 CI 검증 | 새 로그 |
| - | D2: `sensor_id`는 수집 에이전트에서 | 센서 변경 없음 |

각 단계는 SRS 6장(출력 요구사항)과 선별 전송 SRS를 함께 고칩니다.

---

## 5. 결정 필요

| # | 질문 | 제안 |
| --- | --- | --- |
| Q1 | `sensor_id`를 누가 붙이나 | 수집 에이전트(행 최상위 `sensor_id`) |
| Q2 | 상관 갱신 방식 | 갈래를 합친 전체 + `revision` |
| Q3 | `severity_id` 척도 | OCSF(1\~5), 단독 1·상관 3 |
| Q4 | 선별 전송 필드 이름을 센서에서 바꿀지 | 바꿈(`orig_h` 계열) |
