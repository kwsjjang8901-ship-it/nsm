# 통합 상관·공격 스토리 설계안 (MDS·MTA·NSM)

작성: 2026-11-20 · 상태: 설계안(결정 대기, 11장) · 화면 목업: [`ui/mockup/integrated_story_mockup.html`](../ui/mockup/integrated_story_mockup.html) · 관련: [센서 로그 형식 검토](LOG_SCHEMA_REVIEW.md), [Suricata 연동 설계안](SURICATA_INTEGRATION_DESIGN.md), [통합 리포트 스펙](REPORT_SPEC.md), [MDS Manager 목업](../ui/mockup/mdsm_nsm_mockup.html)

## 0. 요약

MDS Manager가 MDS(샌드박스)·MTA(메일)·NSM(네트워크) 탐지를 한곳에 모아 두 가지를 합니다.

1. **통합 공격 스토리:** 같은 대상(PC·사용자·파일·외부 도메인)에 걸린 세 제품의 탐지를 한 스토리로 묶어, "악성 메일 → 첨부 실행 → C2 통신 → 내부 확산"을 한 화면에서 보여 줍니다. 새 탐지 로직이 없어도 됩니다.
2. **통합 상관 탐지:** 여러 제품·여러 센서를 잇는 시나리오를 **Sigma 상관 룰** 형식으로 정의하고, 맞으면 새 탐지(`Correlated_Cross`)를 냅니다.

핵심 판단은 다음과 같습니다.

| 질문 | 결론 |
| --- | --- |
| 무엇이 가장 어려운가 | 룰 형식이 아니라 **제품마다 다른 "대상"을 같은 엔티티로 잇는 일**(메일 주소 ↔ 계정 ↔ PC ↔ IP, 시각 기준). Manager가 이벤트마다 정규화된 엔티티를 먼저 붙이고, 룰은 그 값으로만 묶습니다(4장) |
| Sigma를 쓸 것인가 | 쓴다. 단, **Sigma는 룰 형식**이고 실행은 Manager 엔진이 합니다. Sigma 상관(v2 correlation)의 `temporal_ordered`·`temporal`·`event_count`·`value_count`를 지원하고, 여러 번 건너뛰는 추적과 늦게 오는 이벤트는 엔진 확장으로 처리합니다(5장) |
| NSM 센서 상관은 어떻게 | **그대로 둡니다.** 센서는 네트워크 킬체인 상관을 계속하고, Manager는 그 결과(`Correlated_KillChain`)를 이벤트 하나로 받아 더 큰 흐름에 넣습니다(5.5절) |
| 무엇부터 | 공통 이벤트 모델·엔티티 키 → 통합 스토리(탐지 없이) → 기본 제공 통합 상관 시나리오 → 고객 정의 Sigma 룰(10장) |

---

## 1. 목적과 범위

| 범위 안 | 범위 밖 |
| --- | --- |
| 세 제품의 **탐지 이벤트**(판정·경보)를 Manager로 모아 정규화 | 원본 메일 로그, 원본 네트워크 메타데이터 전부를 상관 입력으로 쓰기(조회·소급검색은 별도) |
| 엔티티 연결(사용자·PC·메일함·파일·도메인·IP), 신뢰도 | 사용자 행위 분석(UEBA)·기준선 학습 |
| 통합 공격 스토리, 통합 상관 탐지(Sigma 상관 룰), 기본 제공 시나리오 | 자동 차단·격리(조치는 기존 대응 탭의 승인 흐름) |
| 예외·등급·알림·사건 묶기를 NSM과 같은 규칙으로 | 다른 SIEM용 Sigma 변환(Splunk·Elastic 질의 생성) |

**기대 효과**

- 끊긴 흐름 잇기: 지금 목업의 탐지 현황에는 MDS·MTA 이벤트가 있지만 공격 스토리는 NSM 탐지만으로 만듭니다. 메일로 들어온 공격의 첫 단계가 스토리에 없습니다.
- 센서 사이 상관: NSM 킬체인 상관은 센서(클러스터) 안에서만 봅니다. 지사 센서에서 감염된 PC가 본사 서버로 확산하는 흐름은 Manager에서만 이어집니다.
- 근거 보강: 네트워크만으로는 "추정"인 C2 의심이, MDS 동적 분석의 악성 판정과 같은 파일·같은 PC로 이어지면 확정에 가까워집니다.

---

## 2. 입력: 제품별 탐지 이벤트

입력은 각 제품의 **탐지(판정) 이벤트만** 받습니다. 하루 수천\~수만 건 규모라 Manager가 메모리에서 스트리밍으로 판정할 수 있습니다.

| 제품 | 이벤트 | 대상을 나타내는 값 | 비고 |
| --- | --- | --- | --- |
| MTA | 악성 첨부, 피싱 URL, 스팸, 발신 위조(SPF·DKIM 실패) 판정 | 수신자 메일 주소, 발신자·발신 도메인, 첨부 파일 해시·이름, 본문 URL, 메일 ID, 조치(격리·차단·태그) | 메일 한 통에 수신자 여러 명 |
| MDS | 파일 정적·동적 분석 판정, 에이전트 실행 차단 | 파일 해시(SHA-256), 파일 이름, 유입 경로(메일·웹·SMB), 판정 등급, 단말(에이전트가 있으면 호스트명·IP), 분석 ID | **판정이 유입보다 늦게 올 수 있음**(동적 분석 수 분\~수 시간) |
| NSM | 단독 탐지 48종, 킬체인 상관 | IP(출발·대상), 목적지 이름(SNI·Host·프록시 CONNECT 대상), 계정(NTLM·Kerberos), 자산 식별(호스트명·머신 계정·로그온 사용자) | `nsm_detection.log` + `evidence.log`, 로그 형식은 [LOG_SCHEMA_REVIEW](LOG_SCHEMA_REVIEW.md) |

**확인 필요(제품 담당):** MDS·MTA 이벤트의 실제 필드 이름과 전송 방식(Syslog·API·DB 조회), 메일 수신자 주소와 AD 계정의 대응 관계, MDS 판정 등급 체계. 이 문서는 위 표의 값이 있다고 가정합니다.

---

## 3. 공통 이벤트 모델

세 제품의 이벤트를 하나의 모델로 바꿉니다. 필드 체계는 OCSF 계열(이미 있는 OCSF 변환기와 맞춤)로 두고, 상관에 쓰는 값은 아래 필드로 평탄화합니다.

| 필드 | 타입 | 내용 | MTA | MDS | NSM |
| --- | --- | --- | --- | --- | --- |
| `event_uid` | string | `<제품>:<센서·장비 id>:<원래 id>` | 메일 판정 id | 분석 id | `sensor_id` + `detection_id` |
| `product` | enum | `MTA`·`MDS`·`NSM` | ✓ | ✓ | ✓ |
| `time`, `time_end` | epoch | 발생 시각(유입·실행·탐지), 구간 끝 | 수신 시각 | 유입·실행 시각(판정 시각 아님) | `first_seen`·`last_seen` |
| `observed_at` | epoch | Manager가 받은 시각(늦게 온 이벤트 판단) | ✓ | ✓ | ✓ |
| `rule` | string | 탐지 종류 키 | 판정 종류 | 판정 종류 | `rule`(notice 이름) |
| `stage` | enum | 킬체인 단계(정찰·초기 침투·…·피해) | 초기 침투 | 초기 침투·실행 | `killchain_stages` |
| `technique` | 목록 | ATT&CK | T1566.001 등 | 판정 매핑 | `techniques` |
| `severity_id` | int | OCSF 척도 1\~5 | 판정 등급 매핑 | 판정 등급 매핑 | `severity_id` |
| `src_ip`, `dst_ip` | addr | 연결 양끝 | 발신 서버 | 다운로드 서버 | 출발·대상 |
| `dst_name`, `url` | string | 외부 도메인·URL | 본문 URL | 다운로드 URL | 근거의 `dst_name` |
| `file_sha256`, `file_name` | string | 파일 | 첨부 | 분석 파일 | (HTTP로 받은 파일이면 해시) |
| `mailbox`, `sender` | string | 수신 메일 주소, 발신자 | ✓ | 유입이 메일이면 | - |
| `user` | string | 정규화한 계정(`도메인\계정`, 소문자) | 수신자 → 계정(4장) | 에이전트 사용자 | 근거 계정 |
| `host` | string | **정규화한 PC 엔티티 id**(4장) | 수신자 → 계정 → PC | 에이전트 호스트 | IP → 자산(시각 기준) |
| `entity_conf` | int | `host`·`user` 연결 신뢰도 0\~100 | 연결 경로에 따라 | 에이전트면 높음 | 자산 판정 신뢰도 |
| `raw_ref` | string | 원본 이벤트 위치(화면 링크) | ✓ | ✓ | ✓ |

- **시각:** MDS는 판정 시각이 아니라 파일이 들어오거나 실행된 시각을 `time`으로 씁니다. 판정 시각은 `observed_at`·원본에 남깁니다. 그래야 "메일 → 실행 → C2" 순서가 맞습니다.
- 이 필드는 센서 로그 형식 검토의 P1 항목(`sensor_id`, `rule`, `severity_id`, 근거의 `dst_name`)을 전제로 합니다.

---

## 4. 엔티티 연결

### 4.1 엔티티와 다리

| 엔티티 | 키 | 다른 엔티티로 가는 다리 | 신뢰도 |
| --- | --- | --- | --- |
| 메일함 | 수신 메일 주소(소문자) | → 사용자: 디렉터리(AD `mail`·`proxyAddresses`)·Manager 사용자 대장 | 높음(90) |
| 사용자 | `도메인\계정` | → PC: NSM 자산 식별의 로그온 사용자(`user_account`, Kerberos·NTLM), MDS 에이전트의 로그인 사용자 | 에이전트 90, NSM 로그온 70(공용 PC면 낮춤) |
| PC | 자산 id(머신 계정 > DHCP > MAC > 호스트명) | → IP: 자산 판정의 IP 점유 구간(시각 기준) | 자산 판정 신뢰도 그대로 |
| IP | 주소 + 시각 | → PC: 위 점유 구간 역조회 | NAT·프록시·VPN 뒤면 낮음 |
| 파일 | SHA-256 | 제품 사이 그대로 일치 | 높음(95) |
| 외부 대상 | 등록 도메인·URL·외부 IP | 제품 사이 그대로 일치(도메인은 등록 도메인으로도) | 도메인 90, IP 70(공유 호스팅·CDN) |

연결은 이벤트를 받을 때 한 번 계산해 `host`·`user`·`entity_conf`로 붙이고, 연결 경로(`via: mailbox→user→host`)를 남겨 화면에서 보여 줍니다.

### 4.2 잘못 묶는 경우와 막는 법

| 경우 | 위험 | 대책 |
| --- | --- | --- |
| 프록시·NAT | 프록시 IP로 묶으면 모든 PC가 한 스토리 | NSM이 프록시를 중계 장비로 표시(`via_proxy`). 프록시 IP는 엔티티로 쓰지 않고, 실제 출발 PC·목적지 이름으로 묶음 |
| DHCP 재할당 | 같은 IP의 다른 PC | IP는 항상 시각과 함께 PC로 바꿈. 점유 구간 밖이면 신뢰도 낮춤 |
| 공용 PC·VDI·터미널 서버 | 한 PC에 사용자 여럿 | 같은 시간대 로그온 사용자가 둘 이상이면 사용자 → PC 신뢰도 낮춤 |
| 단체 메일 | 수신자 수백 명 | 수신자 N명(기본 20) 초과 메일은 메일 자체를 엔티티로 두고, 실제로 첨부를 연(MDS 실행·NSM 통신) 사용자만 스토리에 넣음 |
| 흔한 외부 대상 | CDN·클라우드 도메인으로 무관한 PC가 묶임 | NSM 리포트의 "흔한 목적지" 규칙과 같게, 내부 host N대 이상이 붙는 대상은 연결 키에서 뺌 |

신뢰도 50 미만 연결로 묶인 단계는 스토리에서 "추정"(점선)으로 보여 주고, 통합 상관의 `group-by`에는 쓰지 않습니다(설정으로 조정).

---

## 5. 통합 상관 엔진

### 5.1 처리 흐름

```
제품별 수집 -> 정규화(3장) -> 엔티티 연결(4장) -> 이벤트 버스
   -> 기본 룰(Sigma detection, 이벤트 1건 조건) 판정 -> 맞은 이벤트에 룰 id 표시
   -> 상관 룰(Sigma correlation) 상태 갱신(group-by 엔티티별 창)
   -> 맞으면 Correlated_Cross 탐지 + 근거(묶인 event_uid) -> 예외 -> 사건 묶기 -> 알림·스토리
```

### 5.2 Sigma 사용 범위

| Sigma 기능 | 지원 | 비고 |
| --- | --- | --- |
| detection(selection·condition·modifier) | 지원 | 공통 이벤트 모델 필드 이름으로 씀. `logsource`는 `product: mta·mds·nsm`, `category`로 구분 |
| correlation `temporal_ordered` | 지원 | 같은 `group-by` 값에서 순서대로 |
| correlation `temporal` | 지원 | 순서 무관 |
| correlation `event_count`, `value_count` | 지원 | 예: 한 사용자에게 피싱 메일 N통, 한 파일이 N대 PC에서 실행 |
| `aliases` | 지원 | 룰마다 다른 필드를 하나의 그룹 키로(예: MTA `user` ↔ NSM `host`의 사용자) |
| 상관 룰을 다시 상관 | 지원 | 상관 결과를 기본 이벤트처럼 씀 |

### 5.3 엔진 확장 (Sigma에 없는 것)

| 확장 | 이유 | 표기 |
| --- | --- | --- |
| **피벗**(대상 → 다음 출발지) | "감염 PC가 다른 PC로 확산 → 그 PC가 C2" 같은 여러 번 건너뛰는 흐름. NSM 센서 킬체인 상관의 `SRC_TO_SRC`·`DST_TO_SRC`와 같은 개념 | 상관 룰에 `x-nsm-pivot: dst_to_src` |
| **늦게 온 이벤트 다시 평가** | MDS 동적 분석 판정이 몇 시간 뒤에 옴 | 창이 끝난 뒤에도 `x-nsm-late: 6h` 동안 늦게 온 이벤트(`time`이 창 안, `observed_at`이 늦음)로 다시 판정 |
| **최소 신뢰도** | 추정 연결로 묶지 않음 | `x-nsm-min-entity-conf: 50` |
| **결과 등급** | 상관 결과의 `severity_id` | `x-nsm-severity-id: 4` |

확장 키는 `x-` 접두사로 두어 표준 Sigma 도구가 무시해도 룰을 읽을 수 있게 합니다.

### 5.4 상태와 성능

- 상태는 `(룰, group-by 값)`마다 창 안의 이벤트 id 목록입니다. 입력이 탐지 이벤트뿐이라 1,000명 규모에서 수천\~수만 개 상태로 충분합니다.
- 새 룰과 룰 수정은 저장된 이벤트(ClickHouse)를 다시 흘려 **사전 검증**합니다: 지난 N일 동안 맞았을 건수, 예시 3건. 목업의 "사전 검증" 화면.
- 이벤트 순서가 뒤바뀌어도(제품마다 지연이 다름) `time` 기준으로 판정하고, 창이 닫히는 시점은 `max(time) - 허용 지연`으로 정합니다.

### 5.5 NSM 센서 상관과의 관계

| 상관 | 어디서 | 입력 | 결과 |
| --- | --- | --- | --- |
| 네트워크 킬체인(지금) | NSM 센서(클러스터 매니저) | NSM 단독 탐지 | `Correlated_KillChain` |
| 통합 상관(새로) | MDS Manager | 세 제품 탐지 + NSM 상관 결과 + 다른 센서 | `Correlated_Cross` |

- 센서 상관을 Sigma로 옮기지 않습니다. 센서 상관은 네트워크 세부 정보(근거·uid)를 갖고 있고 센서 안에서 빨리 판정합니다.
- 통합 상관 결과가 센서 상관 결과를 포함하면(같은 host, 겹치는 단계) **같은 사건으로 묶어** 알림을 한 번만 보냅니다. 사건 id는 먼저 난 탐지의 것을 씁니다.

---

## 6. 상관 룰 예시

### 6.1 기본 룰 (이벤트 1건 조건)

```yaml
title: MTA 악성 첨부 메일
id: mta_malicious_attachment
logsource: {product: mta, category: mail_verdict}
detection:
  sel:
    verdict: malicious
    file_sha256|exists: true
  condition: sel
level: medium
```

```yaml
title: MDS 악성 판정(실행 또는 유입)
id: mds_malicious_verdict
logsource: {product: mds, category: file_verdict}
detection:
  sel: {verdict: [malicious, suspicious]}
  condition: sel
level: high
```

```yaml
title: NSM C2 계열 탐지
id: nsm_c2
logsource: {product: nsm, category: detection}
detection:
  sel:
    rule: [HTTP_Beaconing, TLS_Beaconing, Encrypted_C2, DNS_Tunneling, IOC_Match, Unknown_Protocol]
  condition: sel
level: medium
```

### 6.2 상관 룰

**C-01 악성 첨부 메일 → 같은 파일 실행 → 같은 PC의 C2 통신**

```yaml
title: 악성 첨부 메일 뒤 같은 PC의 C2 통신
id: x_mail_exec_c2
correlation:
  type: temporal_ordered
  rules: [mta_malicious_attachment, mds_malicious_verdict, nsm_c2]
  group-by: [host]
  timespan: 24h
x-nsm-late: 6h
x-nsm-min-entity-conf: 50
x-nsm-severity-id: 4
tags: [attack.initial_access, attack.t1566.001, attack.command_and_control]
```

MTA 이벤트의 `host`는 수신자 → 사용자 → PC로, MDS는 에이전트 호스트로, NSM은 출발 IP → PC로 정해집니다(4장). 파일 해시가 같으면 더 강한 근거로 표시합니다(`x-nsm-also-match: file_sha256`, 선택).

**C-02 피싱 URL 메일 → 같은 사용자 PC가 그 도메인에 접속**

```yaml
title: 피싱 URL 메일 뒤 같은 도메인 접속
id: x_phish_url_visit
correlation:
  type: temporal_ordered
  rules: [mta_phishing_url, nsm_web_access_to_mail_domain]
  group-by: [host, dst_name]
  timespan: 4h
```

`nsm_web_access_to_mail_domain`은 탐지가 아니라 NSM 선별 전송 로그(`ssl`·`http`·`dns_summary`)를 조회하는 **보조 조회 룰**입니다. 메일의 URL 도메인이 들어오면 Manager가 그 시간대 해당 PC의 접속 기록을 찾아 이벤트를 만듭니다(통합 리포트의 추정 근거와 같은 방식).

**C-03 같은 악성 파일이 여러 PC에서 실행(확산)**

```yaml
title: 같은 악성 파일이 여러 PC에서 실행
id: x_file_spread
correlation:
  type: value_count
  rules: [mds_malicious_verdict]
  group-by: [file_sha256]
  timespan: 24h
  condition: {field: host, gte: 3}
```

**C-04 지사 센서 감염 PC → 본사 서버 확산**

```yaml
title: 다른 센서 구간으로 이어진 확산
id: x_cross_sensor_lateral
correlation:
  type: temporal_ordered
  rules: [nsm_c2, nsm_lateral]
  group-by: [host]
  timespan: 12h
x-nsm-pivot: dst_to_src
x-nsm-require-distinct: sensor_id
```

---

## 7. 통합 공격 스토리

### 7.1 묶는 규칙

1. **씨앗:** 통합 상관 결과, NSM 상관 결과, 또는 등급 3 이상 탐지.
2. **넓히기:** 씨앗의 엔티티(host·user·mailbox·file·외부 대상)를 공유하는 다른 제품 이벤트를 앞뒤 창(기본 24시간, 메일은 앞으로 72시간) 안에서 붙입니다. 신뢰도 50 미만 연결은 "추정"으로 붙입니다.
3. **피벗:** 확산 단계의 대상 PC는 새 출발점이 되어 다시 넓힙니다(NSM 리포트의 스토리 규칙과 같음).
4. **합치기:** 두 스토리가 같은 엔티티(같은 PC, 같은 파일, 같은 C2 도메인)를 공유하면 합칩니다. 흔한 외부 대상은 합치는 키에서 뺍니다(4.2절).

### 7.2 화면 변경 (목업)

| 화면 | 지금(NSM 목업) | 통합 |
| --- | --- | --- |
| 스토리 목록 | NSM 탐지 수, 관련 PC 수 | 제품별 탐지 수(MTA·MDS·NSM 배지), 메일·파일·사용자 수, 통합 상관 여부 |
| 진행 단계 | NSM 단계 | 단계마다 제품 색으로 표시(메일 → 실행 → C2) |
| 확산 경로 그래프 | 노드가 IP뿐 | 노드 종류: 메일(발신자)·메일함·사용자·PC·파일·외부 대상. 연결선에 "어떻게 이었나"(파일 해시 일치, 로그온 사용자, IP 점유) |
| 내러티브 | NSM 탐지 문장 | 세 제품 이벤트를 시간순. 각 줄에 제품 배지와 원본 링크 |
| 엔티티 연결 | 없음 | "왜 이 메일과 이 PC가 같은 사람인가": 연결 경로와 신뢰도 |
| 관리 | NSM 룰 정책 | **통합 상관 룰**: 기본 제공·고객 정의, Sigma 보기·편집, 사전 검증, 예외 |

---

## 8. 예외·등급·사건·알림

- **예외:** NSM 예외 엔진과 같은 형식(`scope` = 통합 상관 룰 id, 축 = host·user·mailbox·file·dst_name, `drop`·`suppress`, 사유·만료 필수). 기본 룰 단계의 예외(예: 보안팀 테스트 메일함)는 상관 입력에서 뺍니다.
- **등급:** 통합 상관 결과는 룰의 `x-nsm-severity-id`(기본 4 High). 공통 척도는 OCSF `severity_id`(센서 로그 형식 검토 D1).
- **사건 묶기:** 같은 `(룰, group-by 값)`이 열려 있는 동안 다시 맞으면 `occurrence`를 올리고 새 알림을 내지 않습니다(NSM `incident_id` 규칙과 같음).
- **알림:** 통합 상관 결과와 스토리가 새로 생기거나 단계가 늘 때만. 제품별 단독 이벤트는 기존 알림 정책을 따릅니다.

---

## 9. 저장

| 데이터 | 저장소 | 보관 |
| --- | --- | --- |
| 정규화 이벤트(3장) | ClickHouse `xevent` | 탐지 로그와 같게(1년) |
| 엔티티 연결 결과·연결 경로 | PostgreSQL(현재 상태) + ClickHouse(이력) | 자산 이력과 같게 |
| 상관 상태 | Manager 메모리(재시작 때 최근 창을 ClickHouse에서 다시 채움) | 창 길이 |
| 통합 상관 결과·스토리 | PostgreSQL(사건 상태) + ClickHouse(근거) | 사건과 같게 |
| 룰(YAML)·버전·사전 검증 결과 | PostgreSQL | 영구, 버전별 |

---

## 10. 단계 계획

| 단계 | 내용 | 전제 | 끝났다고 보는 기준 |
| --- | --- | --- | --- |
| 0 | 공통 이벤트 모델·엔티티 키 확정, MDS·MTA 이벤트 필드 확인 | 센서 로그 형식 P1(`sensor_id`·`rule`·`severity_id`·`dst_name`) | 세 제품 샘플 이벤트가 3장 모델로 변환됨 |
| 1 | 엔티티 연결(메일함·사용자·PC·IP·파일·도메인) | 디렉터리 연동 또는 사용자 대장, 자산 판정 | 실험실 시나리오에서 메일 수신자 → PC 연결 정확도 확인 |
| 2 | **통합 공격 스토리**(탐지 로직 없이 묶기만) | 1 | 시나리오 3종이 한 스토리로 보임 |
| 3 | 상관 엔진 + 기본 제공 시나리오 5\~10개(C-01\~C-04 등) | 2 | 시나리오별 탐지, 정상 업무 데이터 2주 오탐 측정 |
| 4 | 고객 정의 Sigma 룰(편집기, 사전 검증, 버전, 예외) | 3 | 고객이 룰 추가 → 사전 검증 → 배포 |

**검증 데이터:** 지금 PoC 데이터(CIC-IDS2017, 고객 pcap)에는 메일·샌드박스 로그가 없습니다. 실험실에서 시나리오(악성 첨부 메일 수신 → 실행 → C2 → 확산, 피싱 URL 클릭, 같은 파일 여러 PC 실행)를 재현해 MTA·MDS·NSM 로그를 같은 시간대로 모으는 일부터 계획합니다.

---

## 11. 결정 필요

| # | 질문 | 제안 |
| --- | --- | --- |
| Q1 | MDS·MTA 이벤트를 어떻게 받나(Syslog·API·DB) | 제품 담당과 확인. 3장 모델로 바꾸는 수집기는 Manager 안에 |
| Q2 | 메일 주소 ↔ 계정 다리 | 디렉터리(AD) 연동 우선, 없으면 Manager 사용자 대장 |
| Q3 | Sigma 엔진을 직접 만들지, 기존 라이브러리(pySigma 등)를 쓸지 | 룰 파싱은 기존 라이브러리, 판정 엔진은 Manager 스트리밍 엔진(공통 이벤트 모델에 맞춰) |
| Q4 | 엔진 확장 키(`x-nsm-*`) 범위 | 피벗·늦은 이벤트·최소 신뢰도·등급 4개로 시작 |
| Q5 | 통합 상관 결과의 기본 등급 | `severity_id` 4(High) |
| Q6 | 고객 정의 룰을 언제 여나 | 기본 제공 시나리오로 오탐을 잰 뒤(10장 4단계) |
