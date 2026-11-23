# 센서 로그 형식 검토 (Manager 개발 관점)

- 검토일: 2026-11-20 · 기준: main `0fed325`(PR #120까지)
- 최종 갱신: 2026-11-23 · main `1c07616`(PR #129까지). 아래 표의 "지금" 칸은 검토 당시 상태이고, 현재 상태는 "상태" 칸입니다. 현재 형식의 기준은 [LOG_SCHEMA.md](LOG_SCHEMA.md)(JSON Schema `schema/logs/`)입니다.
- 대상: 센서가 Manager로 보내는 로그 `nsm_detection.log`, `evidence.log`, `nsm_exception.log`, `asset_signal.log`, `meta/*.log`(선별 전송), `meta_export_stats.log`. 센서에만 남는 `notice.log`·`stats.log`·`capture_loss.log`는 참고로만 봤습니다.
- 방법: 스키마 정의(`detection_log.zeek`, `evidence_log.zeek`, `correlation_killchain.zeek`, `exceptions.zeek`, `asset-id/main.zeek`, `metadata/main.zeek`)와 합성 pcap 실행 결과(`killchain_story`, `proxy_c2`)의 실제 행, 그리고 리포트(`tests/report_pcap.py`, `tests/report_mockup.py`)가 로그를 읽는 방식을 대조했습니다.
- 갱신: 2026-11-20 통합 상관(MDS·MTA·NSM) 관점 추가(6장). 우선순위가 바뀐 항목과 새 항목은 6장 표가 기준입니다.
- 진행: 2026-11-20 작업 순서 1·2단계(D1·D4·D5·N1·N2·N3·N4), 3단계(D3·N7), 4단계(E1·E2·E3·N5, `community_id` 포함), G1(스키마), X1(파일 지문·적재 시각)·S1(센서 상태 로그, N6 지연, D2의 스키마 버전)·M1(선별 전송 필드 이름) 반영. 센서 쪽 작업 순서 1\~5단계 완료, D2 `sensor_id`(수집 에이전트)만 남음. 6.4 표의 상태 칸과 [SRS 6.2·6.3](SRS.md)이 기준입니다.
- 관련: [탐지 SRS 6장](SRS.md), [선별 전송 SRS](SRS_METADATA_EXPORT.md), [자산 식별 SPEC 2장](asset-id/SPEC.md), [통합 리포트 스펙](REPORT_SPEC.md)

---

## 요약

**기본 형식은 Manager가 바로 쓸 수 있습니다.** JSON 한 줄 한 행, 목록 필드는 JSON 배열, 시각은 epoch 초(ClickHouse `DateTime64`로 바로 적재), 탐지와 근거는 `evidence_ids`로 조인되고, 같은 공격의 반복은 `incident_id`·`occurrence`로 묶입니다.

다만 **Manager를 만들기 전에 고치는 것이 싼 항목**이 있습니다. 필드를 더하는 것은 하위 호환이라 지금 넣어도 기존 소비자(리포트, OCSF 변환기)가 깨지지 않습니다. 반대로 Manager가 테이블을 만든 뒤에는 이름·의미를 바꾸기 어렵습니다.

| 우선 | # | 항목 | 지금(검토 당시) | 제안 | 상태 |
| --- | --- | --- | --- | --- | --- |
| P1 | D1 | 등급을 숫자로도 | `severity` 문자열(`Information`·`Suspicious`) | `severity_id` 정수 추가(OCSF 척도). 문자열은 유지 | 반영(#124) |
| P1 | D2 | 센서 식별·스키마 버전 | 행에 센서 식별자 없음(`node`는 클러스터 노드 이름) | 수집 에이전트가 `sensor_id`를 붙이고, 센서는 상태 로그에 버전을 남김 | 스키마 버전 반영(#128), `sensor_id`는 수집 에이전트와 합의 남음 |
| P1 | D3 | 상관 탐지 갱신 | 체인이 길어질 때마다 같은 `detection_id`로 새 행. 갱신 번호 없음, 갈래가 다른 체인도 같은 id | `revision` 추가, 갈래별 id 또는 마지막 행이 전체를 담게 | 반영(#125) |
| P1 | D4 | 룰 식별 키 | 탐지 로그에 notice 이름이 없음. 상관 진단명은 첫·마지막 단계에 따라 바뀜 | `rule` 필드(예: `TLS_Beaconing`, 상관은 `Correlated_KillChain`) 추가 | 반영(#124) |
| P1 | E1 | 근거의 핵심 값 | `detail` 자유 문자열(`host=… via_proxy=… port=…`). 리포트가 정규식으로 뽑음 | 자주 쓰는 값을 필드로: `dst_name`, `dst_port`, `proxy`, `bytes`, `window_s` | 반영(#126) |
| P2 | D5 | 피해 host 개수 | `victims`는 상한(`chain_max_victims`)까지만, 잘렸는지 모름 | `victim_count` 추가 | 반영(#124) |
| P2 | X1 | 예외 적재 시각 | `kind=loaded`·`rejected` 행의 `ts`가 0(시작 전 `network_time`) | 실제 시각(`current_time()`)과 파일 지문(`file_sha1`) | 반영(#128) |
| P2 | M1 | 선별 전송 필드 이름 | 행 단위 로그는 `id.orig_h`(점), 요약 로그는 `orig_h` | 센서에서 `orig_h`·`orig_p`·`resp_h`·`resp_p`로 통일(`field_name_map`) | 반영(#129) |
| P2 | S1 | 센서 상태 로그 | 없음(장비 현황 화면이 쓸 값이 Zeek 기본 로그에 흩어져 있고 센서에만 남음) | `nsm_sensor.log` 1분 주기(버전·패킷·누락·로그 지연) | 반영(#128) |
| P2 | E2 | 상관 근거의 하위 id | `parent_id` 쉼표 문자열 | 배열 | 반영(#126) |
| P3 | E3 | 시간 값의 단위 | `detail` 안 `window=10.0 mins`, `interval=30.0s` | E1의 `window_s`처럼 초 단위 숫자 | 반영(#126) |
| P3 | G1 | 열거값·스키마 문서 | 값 목록이 코드·SRS에 흩어짐 | 열거값 표 한 곳 + JSON Schema(CI에서 실제 행 검증) | 반영(#127) |

**현재(2026-11-23):** D2의 `sensor_id`(수집 에이전트가 붙임)를 뺀 모든 항목이 센서에 반영됐습니다. 각 항목에서 정한 내용은 6.4절 아래에 단계별로 적었습니다.

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

---

## 6. 통합 상관 관점에서 다시 본 결과 (2026-11-20 추가)

[통합 상관·공격 스토리 설계안](INTEGRATED_CORRELATION_DESIGN.md)은 Manager가 MDS·MTA·NSM 탐지를 공통 이벤트 모델로 바꾸고, 같은 사용자·PC·파일·외부 대상으로 묶습니다. 이 관점에서 다시 보면 **1\~5장의 방향은 그대로**이고, 바뀌는 것은 두 가지입니다.

1. 근거(evidence)에만 있던 값 일부가 **탐지 요약(nsm_detection) 단위**로 필요해집니다. 통합 상관의 입력은 탐지 이벤트이고, 근거 행을 일일이 읽지 않습니다.
2. 제품 사이를 잇는 키(계정, 프록시 여부, 연결 식별자)의 **표기를 맞추는 일**이 새로 생깁니다.

### 6.1 그대로인 것

| 항목 | 이유 |
| --- | --- |
| JSON·epoch·배열(1장) | 공통 이벤트 모델로 바꾸는 쪽(Manager)에서 그대로 읽음 |
| 센서는 Zeek JSON 그대로, OCSF 변환은 Manager | 제품마다 원래 형식이 달라 변환은 어차피 Manager가 함. 센서가 OCSF를 직접 내면 필드가 늘고 근거 원문이 줄어듦 |
| `sensor_id`는 수집 에이전트가 붙임(D2) | 공통 모델의 `event_uid = 제품:센서:id`도 에이전트 값으로 충분 |
| 선별 전송 필드 이름 통일(M1), 예외 로그(X1) | 우선순위 그대로 |

### 6.2 우선순위가 올라가는 것

| # | 항목 | 이유(통합 상관에서) | 바뀐 우선 |
| --- | --- | --- | --- |
| D2 | `sensor_id` | 상관 룰 C-04(다른 센서 구간으로 이어진 확산)가 `sensor_id`로 구분. 이벤트 고유 id의 일부 | P1 그대로, **가장 먼저** |
| D3 | 상관 갱신 `revision`, 갈래 합치기 | Manager가 NSM 상관 결과를 통합 사건에 넣을 때 "이 행이 앞 행을 대신하는가"를 알아야 함 | P1 그대로, 통합 사건 묶기의 전제 |
| D5 | `detection_id` 재시작 충돌 | 공통 모델의 `event_uid`가 겹치면 다른 제품 이벤트와 잘못 이어짐 | P2 → **P1** |
| S1 | 센서 상태 로그 | 늦은 이벤트 판단에 센서 지연(`wall_time - network_time`)이 필요. 버전으로 해석 규칙 선택 | P2 그대로, 지연 값 추가(6.3 N6) |

### 6.3 새로 필요한 것

| # | 항목 | 지금(검토 당시) | 제안 | 우선 | 상태 |
| --- | --- | --- | --- | --- | --- |
| N1 | **탐지 단위 계정** | 계정은 근거 행의 `account`에만 있음 | `nsm_detection`에 `accounts`(배열, 최대 5) 추가. 근거·인증 맥락에서 모음. 사용자로 묶는 상관(메일 수신자 → 사용자)에 씀 | P1 | 반영(#124) |
| N2 | **계정 표기 통일** | 같은 사람이 세 가지로 나옴: Kerberos 자산 신호 `realm\이름`, NTLM `도메인\이름`(NetBIOS), 근거 `이름@realm`(UPN) | 원문은 두고 `user_name`(소문자 이름)·`user_domain`(원래 표기)·`user_domain_type`(`netbios`·`dns`)으로 나눠 씀. NetBIOS ↔ DNS 도메인 대응은 Manager가 디렉터리로(센서는 관측한 도메인 쌍을 자산 신호 `domain`으로 이미 남김) | P1 | 반영(#124) |
| N3 | **탐지 단위 목적지 이름** | 근거 `detail`의 `host=`·`sni=`(E1에서 근거 필드로 제안) | E1에 더해 `nsm_detection`에도 `dst_names`(배열). 피싱 URL 메일 → 같은 도메인 접속(C-02)처럼 도메인으로 묶는 상관에 씀 | P1 | 반영(#124) |
| N4 | **중계 장비 표시** | 프록시 경유 탐지의 `victims`에 프록시 IP가 들어가고, 프록시라는 표시는 근거 `detail`의 `via_proxy=`에만 있음 | `nsm_detection`에 `relays`(배열: 프록시 `주소:포트`). Manager는 `victims`에서 이 주소를 엔티티로 쓰지 않음(모든 PC가 한 스토리로 묶이는 것을 막음). 센서가 배운 프록시는 자산 신호 `device=proxy`로도 남김 | P1 | 반영(#124) |
| N5 | **연결 단위 조인 키** | 근거에는 Zeek `uid`뿐(센서 안에서만 의미). **MDS는 Community ID가 없음**(2026-11-20 확인) | MDS와 NSM을 연결 단위로 이을 때는 `(출발 IP, 목적지 IP, 목적지 포트, 시각 ±N초)`로 맞춤. 이를 위해 근거에 `src_port`·`dst_port`를 필드로 둠(E1의 `dst_port`와 같은 값). 근거에 `community_id`도 넣음(Q6 변경): Suricata 경보, 그리고 앞으로 Community ID를 갖게 될 다른 제품과의 연결 조인 키 | P2 | 반영(#126) |
| N6 | **센서 지연** | 없음 | S1 상태 로그에 `capture_lag_s`(벽시계 - 패킷 시각). Manager가 "아직 안 온 이벤트"를 기다릴 시간을 정함 | P2 | 반영(#128) |
| N7 | **상관 행의 구성 탐지 id** | 상관 행의 `evidence_ids`가 구성 단독 탐지의 id와 같다는 것이 코드상 규칙일 뿐 문서·필드에 없음 | `member_detection_ids` 필드 추가(또는 SRS에 규칙 명시). 통합 사건이 "이 NSM 상관은 이 단독 탐지들을 포함"을 알게 함 | P2 | 반영(#125) |
| N8 | **ATT&CK 전술 id** | 단계는 `killchain_stages` 이름(`Command and Control`) | `tactics`(예: `TA0011`) 추가. 제품마다 단계 이름이 달라도 전술 id로 맞춤 | P3 | 미정 |
| N9 | **파일 해시(평문 전송)** | 선별 전송에 HTTP·SMB로 받은 파일의 해시가 없음 | 평문 HTTP·SMB로 받은 실행·문서 파일만 `files_summary`(SHA-256, 받은 PC, 출처)로. HTTPS가 대부분이라 효과가 제한적이므로 MDS 연동 범위를 보고 결정 | P3 | 미정 |

### 6.4 바뀐 작업 순서

| 순서 | 작업 | 상태 |
| --- | --- | --- |
| 1 | D1(`severity_id`)·D4(`rule`)·D5(id 충돌·`victim_count`)·N1(`accounts`)·N3(`dst_names`)·N4(`relays`): 탐지 요약에 필드 추가(하위 호환) | 완료(아래 참고) |
| 2 | N2: 계정 표기 나누기(근거·자산 신호) | 완료(아래 참고) |
| 3 | D3: 상관 갱신 규칙(`revision`, 갈래 합치기) + N7 | 완료(아래 참고) |
| 4 | E1·E2: 근거 공통 필드(`dst_port` 포함, N5 `src_port`) | 완료(아래 참고) |
| 5 | M1·S1(+N6)·G1, X1 | 완료([LOG_SCHEMA.md](LOG_SCHEMA.md), [SRS 6.4·6.5](SRS.md), [메타데이터 SRS 5.1](SRS_METADATA_EXPORT.md)) |
| - | D2 `sensor_id`: 수집 에이전트(센서 변경 없음). 통합 상관 개발 전에 에이전트와 합의 | |

1·2단계에서 정한 것:

- `severity_id`: 단독 1, 상관 3. `rule`: notice 이름에서 `NSM::`을 뺀 값, 상관은 `Correlated_KillChain`.
- 상관 `detection_id`: `kc-<시작 epoch>-<프로세스 값 6자리 16진수>-<번호>`. 프로세스 값은 시작할 때 난수로 정하므로, 같은 pcap을 다시 돌려도 상관 id는 달라집니다(단독 탐지 id는 그대로).
- `victim_count`: 확산 룰은 `lm_targets` 수, 그 밖의 단독 탐지는 1, 상관은 체인이 지난 피해 host 수(`victims`와 같은 기준).
- `accounts`·`dst_names`·`relays`: 근거에서 모아 정렬한 뒤 최대 5개(`evidence_summary_max`). 이름은 `detail`의 `host=`·`sni=`·`name=`, DNS는 상위 도메인(`parent=`, 없으면 `query=`)이고 IP 주소는 뺍니다. E1(근거 필드화) 전이라 센서 안에서 `detail`을 읽어 만듭니다. 클러스터에서는 단계마다 요약을 상관 이벤트에 실어 보내 상관 행에도 들어갑니다.
- N2: `evidence.log`와 `asset_signal.log`(계정 신호)에 `user_name`·`user_domain`·`user_domain_type`. 원문 `account`·`value`는 그대로입니다. 근거 `account`가 여러 개(쉼표)면 첫 계정을 나눕니다.

3단계에서 정한 것(D3 제안 1, [SRS 5.1.2](SRS.md)):

- 상관 행은 매번 갈래를 합친 체인 전체를 담고 `revision`(1부터)을 붙입니다. Manager는 `detection_id`별 `revision`이 가장 큰 행만 쓰면 됩니다. 단독 탐지와 같은 사건 규칙으로도 처리되도록 `incident_id` = `detection_id`, `occurrence` = `revision`을 채웁니다.
- N7: `member_detection_ids`(구성 단독 탐지 id, 처음 본 순서). `evidence_ids`에서 체인 자신의 근거 id를 뺀 것과 같습니다.
- 합친 값: 기법은 구성 탐지마다 하나(처음 탐지된 시각 순), 단계명은 중복 없이, 피해 host는 출발지 자신을 빼고 모든 갈래의 합집합. 진단명의 뒤 단계는 가장 많이 진행된 단계입니다.
- notice와 체인 근거(`operation=killchain`)는 갈래마다 한 건 그대로입니다(notice 1건 = 탐지 1건).
- 통합 리포트도 같은 체인은 `revision`이 가장 큰 행 하나만 씁니다(`revision`이 없는 옛 로그는 행마다).

4단계에서 정한 것([SRS 6.3](SRS.md)):

- 근거 공통 필드: `rule`, `src_port`·`dst_port`·`proto`·`community_id`(근거 연결), `dst_name`·`proxy`·`bytes`·`window_s`(`detail`에서 센서가 올림). `parent_id`는 배열(E2). `note`는 그대로 두고 `rule`을 더했습니다(E2의 접두사 문제).
- 연결 필드는 룰이 `uid` 자리에 연결 참조(`NSM::conn_ref(c)`)를 넘기면 `write_evidence()`가 채웁니다. SumStats 표본에도 같은 참조를 넣어, 클러스터에서 워커가 본 연결도 매니저가 쓰는 근거에 포트·`community_id`가 들어갑니다. 룰 50곳 중 연결이 있는 곳은 모두 바꿨습니다.
- 처음 제안과 다른 점: `dst_port`는 프록시 경유여도 실제 연결(프록시) 포트입니다. `community_id`와 같은 연결을 가리키게 하려는 것이고, 실제 목적지는 `dst_name`·`proxy`로 압니다(비표준 포트 룰의 대상 포트는 `detail`의 `port=`).
- 값 검증: btest가 근거의 `community_id`를 conn.log의 5-tuple에서 스펙대로 따로 계산한 값과 대조합니다(Zeek 계산과 Python 계산이 같음).
- 리포트(`report_pcap.py`·`report_mockup.py`)는 필드가 있으면 필드를, 없으면(옛 로그) 예전처럼 `detail`을 읽습니다.

X1·S1에서 정한 것([SRS 6.4·6.5](SRS.md)):

- 파일 지문은 예외 파일뿐 아니라 IOC 파일·에이전트 정책 파일에도 남깁니다(각 로그의 `kind=file`, `file_sha1`). 센서가 파일 내용 그대로의 SHA1을 계산하므로 `sha1sum`과 같습니다. Manager가 파일에 버전 id를 적는 방식은 쓰지 않았습니다(SHA1만으로 비교 가능).
- 적재 결과 행(예외 `loaded`·`rejected`·`expired`·`error`·`file`, IOC·정책 로그 전부)은 실제 시각, 예외 적중(`hits`)만 패킷 시각입니다.
- 센서 상태 로그 `nsm_sensor.log`: 노드별 1분마다. 처음 제안의 `loss_pct`는 둘로 나눴습니다. 캡처 장치가 놓친 비율(`drop_pct`)과 TCP 누락 비율(`gap_pct`, 미러 품질)입니다. 지연은 `capture_lag_s`(N6)입니다.
- `schema_version`은 사람이 올리는 번호가 아니라 `schema/logs` 내용의 해시(앞 12자리)입니다. `schema/build.py`가 `nsm_rules/sensor/schema_version.zeek`를 만들어 스키마가 바뀌면 반드시 바뀝니다(D2의 버전 부분).
- `rules_version`은 따로 두지 않고 `pkg_version`(`0.1.0`부터, 릴리스 때 올림) 하나로 했습니다.
- `meta/stats`·`meta/capture_loss` 선별 전송은 그대로 둡니다. Manager가 `nsm_sensor`로 옮긴 뒤 끌지 정합니다.

M1에서 정한 것:

- 선별 전송 행 로그(`kerberos`, `ntlm`, `smb_*`, `dce_rpc`, `rdp`, `ssh`, `ssl`, `http`, 설정으로 켠 `conn`)의 `id.orig_h`·`id.orig_p`·`id.resp_h`·`id.resp_p`를 `orig_h`·`orig_p`·`resp_h`·`resp_p`로 보냅니다(`NSM::meta_field_name_map`, `Log::Filter`의 `field_name_map`). 요약 로그와 같은 이름입니다.
- 설정의 `fields`는 Zeek 이름 그대로 적습니다(필드 선택은 원래 이름, 이름 바꾸기는 출력 때). 센서에 남기는 원본(T2)과 탐지 로그는 바꾸지 않습니다.
- 근거(`evidence`)의 `src`·`dst`와는 뜻이 다릅니다. 근거는 공격 방향, 선별 전송은 연결 방향입니다.

### 6.5 결정 필요 (추가)

| # | 질문 | 제안 |
| --- | --- | --- |
| Q5 | 계정을 센서에서 나눠 쓸지(N2), Manager에서 원문을 파싱할지 | 센서에서 나눔. 표기 규칙은 프로토콜을 아는 쪽이 정확함 |
| Q6 | `community_id`를 넣을지(N5) | **결정(2026-11-20 변경): 넣음.** 센서가 근거 연결의 5-tuple로 계산해 `evidence.log`에 남긴다(seed 0). MDS에는 아직 없으므로 MDS ↔ NSM은 당분간 주소·포트·시각으로 맞추고, MDS 이벤트에 출발 포트가 있으면 Manager가 같은 방식으로 계산해 붙일 수 있다(NAT·프록시 뒤 연결은 값이 달라 맞지 않음) |

