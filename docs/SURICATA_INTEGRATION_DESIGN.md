# Suricata 연동 설계 (Manager 직접 전송)

작성: 2026-11-19 · 개정: 2026-11-24(방식 B로 결정) · 상태: 방식 확정, 기본값은 측정 뒤 확정(9장) · 관련: Suricata 엔진 구성 설계 [surica `docs/DESIGN.md` 0.2](https://github.com/kwsjjang8901-ship-it/surica/blob/main/docs/DESIGN.md), [통합 상관 설계안](INTEGRATED_CORRELATION_DESIGN.md), [탐지 SRS](SRS.md), [소급검색 설계안](RETRO_SEARCH_DESIGN.md)

## 0. 이 문서의 범위

Suricata 엔진을 센서에 붙이는 부분은 surica 저장소에서 설계하고 PoC까지 끝냈습니다(2026-11-10, surica DESIGN 0.2). 이 문서는 그 위에서 **Suricata 경보를 MDS Manager의 탐지 흐름(예외·사건 묶기·공격 스토리·상관)에 합치는 방법**을 정합니다.

| 구분 | 어디서 정함 | 이 문서에서 |
| --- | --- | --- |
| 엔진 켜기·끄기, `sensor.yaml`, `suricata.yaml` 생성, AF_PACKET 공존, 장애 격리, 룰 업데이트(`suricata-update`), stats 전송 | surica DESIGN 2\~4장, 3.3절 | 그대로 따름. 바꿀 점만 8장에 적음 |
| 경보 전송(`suricata_alert` 스트림), 경보와 자산 결합(IP 점유 구간) | surica DESIGN 5.2·6장 | 그대로 따름 |
| **경보를 Manager 공통 이벤트로 바꾸기(단계·위험도·연결 찾기·예외·사건 묶기)** | 없음 | 3\~4장 |
| **행위 탐지(Zeek)와 잇기: 통합 상관·공격 스토리** | [통합 상관 설계안](INTEGRATED_CORRELATION_DESIGN.md) | 5장(Suricata 시나리오) |
| **Zeek 탐지와 겹치는 경보 정리, ET 룰 범위** | surica DESIGN 6.2절·12장 | 6장 |

**결정(2026-11-24):**

| 항목 | 결정 |
| --- | --- |
| 연동 방식 | **B. Manager 직접 전송.** Suricata 경보는 Zeek를 거치지 않고 Manager로 갑니다. Manager가 통합 상관의 공통 이벤트 모델로 바꿉니다(2장) |
| 일정 | Manager 통합 상관 엔진(통합 상관 설계 10장)과 **동시에** 진행합니다. Suricata 경보는 그 엔진의 입력 하나입니다(7장) |
| 시그니처와 행위 탐지 잇기 | 센서 킬체인 상관에 넣지 않고 **통합 상관(기본 제공 시나리오)과 통합 공격 스토리**로 잇습니다(5장) |
| Community ID | **센서에 넣음.** conn과 연결 단위 선별 전송 로그에 `community_id`를 붙입니다(3.3) |

이미 정한 것:
- IP·도메인·URL IOC 일치는 Suricata를 넣어도 Zeek(`IOC_Match`, 탐지 35)에 둡니다(RETRO_SEARCH_DESIGN 0장).
- Suricata는 시그니처 경보만 맡습니다. 프로토콜 로그(http·dns·tls·flow)는 끕니다(surica DESIGN 원칙 1).
- Suricata는 센서마다 꺼져 있을 수 있습니다(출시 기본값 off). 꺼져 있으면 지금 동작과 같아야 합니다.

처음 판(2026-11-19\~23)은 방식 A(센서에서 Zeek가 경보를 받아 notice로 냄)를 권했습니다. 그 설계(경보 파일 읽기, pcap 시각 정렬, 단계별 notice, 예외 파일 `sid` 열)는 이 문서의 git 이력에 남아 있습니다.

## 1. 탐지 흐름

```
[센서] 패킷 ─┬─ Zeek ─ 룰(01~35) ─ 예외 엔진 ─ NOTICE ─ evidence.log / nsm_detection.log
             │                                      └─ 센서 킬체인 상관 ─ Correlated_KillChain
             │       └─ 선별 전송(meta/*, 연결 로그에 community_id)
             └─ Suricata ─ eve(alert) ─ suricata_alert 스트림
                        ─ eve(stats) ─ 센서 상태
                                   │
[Manager] 수집 ─ 자산 결합 ─ 공통 이벤트(Zeek 탐지 + Suricata 경보 + MDS·MTA)
         ─ Suricata 정규화(단계·위험도·연결 찾기·예외, 3~4장)
         ─ 사건 묶기 ─ 같은 연결 묶어 보이기(6.2) ─ 통합 상관·통합 스토리(5장) ─ 알림·화면
```

Zeek와 Suricata는 같은 패킷을 따로 봅니다. 서로 통신하지도, 파일을 주고받지도 않습니다. 둘을 잇는 값은 **Community ID**(연결 단위)와 **IP·시각**(호스트 단위)이고, 잇는 일은 Manager가 합니다.

## 2. 연동 방식 비교

| 방식 | 내용 | 장점 | 단점 |
| --- | --- | --- | --- |
| A. 센서에서 Zeek가 경보를 받아 notice로 냄 (처음 제안) | Zeek(매니저 노드)가 Suricata 경보 파일을 읽어 NSM notice로 바꿔 냄 | 센서의 예외 엔진·근거·사건 묶기·킬체인을 그대로 씀. 예외 파일 하나 | Zeek가 EVE 형식을 알아야 함. 경보 폭주가 Zeek notice·상관으로 들어옴. pcap 모드 시각 정렬 필요. 단계·위험도 매핑을 바꾸려면 센서 배포 |
| **B. Manager 직접 전송 (결정)** | `suricata_alert` 스트림을 Manager로 보내고 Manager가 공통 이벤트로 바꿈 | 엔진이 완전히 따로 돎. Zeek 경로에 영향 없음. 매핑을 Manager에서 바로 바꿈. Zeek를 끈 센서에서도 동작 | 예외·사건 묶기·상관을 Manager에서 해야 함. 센서 킬체인에 시그니처가 안 들어감 |
| C. 따로 둠 | Suricata 경보는 별도 목록으로만 보임 | 가장 단순 | 공격 스토리·상관에 안 들어감 |

**B로 정한 이유:**
- Manager는 통합 상관 때문에 공통 이벤트 모델, 예외, 사건 묶기, 통합 스토리, Sigma 상관을 어차피 만듭니다(통합 상관 설계 3·5·7·8장). Suricata 경보는 그 엔진에 입력 하나를 더하는 일입니다. A의 가장 큰 장점이던 "다시 만들지 않음"이 사라집니다.
- surica의 장애 격리 원칙이 더 강해집니다. Zeek는 Suricata 파일도 읽지 않습니다.
- 단계·위험도·ATT&CK 매핑을 Manager 화면에서 바로 바꾸고, 지난 경보에 다시 적용할 수 있습니다.

**B의 대가와 대응:**

| 대가 | 대응 |
| --- | --- |
| 센서 킬체인(`Correlated_KillChain`)에 시그니처 단계가 안 들어감 | 통합 상관 기본 시나리오(5.2)와 통합 공격 스토리로 잇습니다 |
| 예외 적용 위치가 둘(행위 탐지 = 센서 예외 파일, 시그니처 = Manager) | 화면은 "NSM 예외" 하나로 두고 행마다 적용 위치를 보입니다. 한 예외에 둘을 섞지 않습니다(4.4) |
| 경보에는 도메인·서비스가 없음(Suricata 프로토콜 로그를 끔) | Community ID로 선별 전송 연결 로그를 찾아 붙입니다(3.3) |
| 프록시 경유 판단(Zeek `conn_via_proxy`, #117)을 Manager가 해야 함 | 찾은 http 로그가 `CONNECT`면 Zeek 룰과 같게 바꿉니다(3.5) |
| 센서 억제가 없어 전송량이 늘 수 있음 | 룰 범위(6.1) + Suricata `threshold.config`로 센서에서 줄이고, 나머지는 Manager 사건 묶기. S5에서 경보량 측정 |
| PoC 리포트가 센서 로그만 읽음 | 리포트 스크립트가 eve 경보도 읽어 같은 규칙으로 바꿉니다(7장 S6) |

## 3. 전송과 정규화

### 3.1 센서 쪽

| 항목 | 설계 |
| --- | --- |
| eve 출력 | 경보(alert)와 stats를 나눔. 경보는 `suricata_alert` 스트림으로 Manager에 보냄(**기본 켬**, surica DESIGN 0.2의 전송 경로 그대로) |
| 경보 필드 | `timestamp`, `flow_id`, `src_ip`·`src_port`·`dest_ip`·`dest_port`·`proto`, `direction`, `community_id`, `app_proto`, `alert.{signature_id, rev, signature, category, severity, metadata, source, target}`. payload·packet·http 본문은 받지 않음(surica DESIGN 8장) |
| 룰 범위 | 6.1절 기본값을 `disable.conf`로 |
| 반복 억제 | `threshold.config`: (SID, 출발지, 목적지) 기준 limit. 기본값은 surica 값으로 시작해 S5에서 확정 |
| Community ID seed | Suricata `community-id-seed` = Zeek `community_id_seed`(기본 0). 렌더러가 같은 값을 넣음 |
| 센서 식별 | 수집 에이전트가 붙이는 `sensor_id`(NSM 로그와 같음, LOG_SCHEMA_REVIEW D2) |
| Zeek | 경보를 읽지 않음. Suricata가 꺼지거나 멈춰도 Zeek 경로는 그대로 |

### 3.2 Manager 처리 순서

```
경보 한 줄(suricata_alert)
 -> 센서·자산 결합(IP 점유 구간, surica DESIGN 5.2)
 -> 단계 결정(4.2) -> 이벤트 종류(3.4)
 -> 연결 찾기: community_id로 선별 전송 연결 로그(3.3), 늦게 오면 기다림
 -> 출발지·대상(3.5), 프록시 경유 판단
 -> 예외(4.4) -> 위험도(4.3)
 -> 공통 이벤트(통합 상관 3장)로 저장
 -> 사건 묶기(3.4) -> 같은 연결 묶어 보이기(6.2) -> 통합 상관·통합 스토리(5장) -> 알림
```

선별 전송 연결 로그는 연결이 끝나거나 요청이 끝날 때 쓰이므로 경보보다 늦게 올 수 있습니다. Manager는 경보를 최대 `suri_join_wait`(기본 2분, S5에서 확정)까지 보류하고 연결 로그를 기다립니다. 그때까지 없으면 주소·포트만으로 판정합니다. 기다리는 동안에도 경보는 저장하고, 알림만 판정 뒤에 냅니다.

### 3.3 Community ID와 연결 찾기

conn.log는 Manager로 가지 않고 `flow_summary`(묶음)로만 갑니다(SRS_METADATA_EXPORT FR-M8). 그래서 Community ID를 conn에만 넣으면 Manager에서 쓸 수 없습니다. 아래처럼 넣습니다.

| 위치 | 내용 |
| --- | --- |
| conn | nsm_rules에서 Zeek `policy/protocols/conn/community-id-logging`을 로드. conn 레코드에 `community_id`. 원본 conn.log를 남기는 센서(T2)에 기록됨 |
| **연결 단위 선별 전송 로그** | `meta/ssl`·`http`·`ssh`·`rdp`·`smb_files`·`smb_mapping`·`kerberos`·`ntlm`·`dce_rpc`에 `community_id`를 붙임. Manager가 경보와 맞추는 키 |
| 근거(`evidence.log`) | 이미 있음(#126). Zeek 탐지와 경보를 같은 연결로 묶는 키(6.2) |

행당 48바이트(gzip 뒤 약 19바이트)가 늡니다. 저장소 합성 pcap 64개 합계로 선별 로그가 7.4%(gzip 뒤 15%) 커졌고, 운영 비율은 S5에서 확인합니다(SRS_METADATA_EXPORT 5.1절).

맞추는 규칙:
- 같은 `community_id`, 경보 시각이 연결 시간 안에 있으면 같은 연결입니다. 연결 로그의 `uid`, 서비스, 목적지 이름(ssl `server_name`, http `host`), `CONNECT` 여부를 경보에 붙입니다.
- 같은 연결의 http 행이 여러 개면 경보 시각에 가장 가까운 행을 씁니다. 목적지 이름은 그 연결의 이름을 모두 모읍니다.
- 연결 로그가 없으면(선별 대상 프로토콜이 아님, 경계 밖) 주소·포트만 씁니다.

### 3.4 이벤트 종류: 단계별 8개

Manager 공통 이벤트의 `rule` 값입니다. 행위 탐지와 같은 방식으로 예외 범위(`scope`), 사건 묶기 키, 스토리 시작점 규칙을 씁니다.

| `rule` | 단계 | 스토리 시작점 |
| --- | --- | --- |
| `Suricata_Recon` | 정찰 | 됨 |
| `Suricata_Initial_Access` | 초기 침투 | 됨 |
| `Suricata_C2` | 외부 연락(C2) | 됨 |
| `Suricata_Credential` | 계정 탈취 | 됨 |
| `Suricata_Lateral` | 내부 확산 | 됨 |
| `Suricata_Exfil` | 정보 유출 | 됨 |
| `Suricata_Impact` | 피해 | 됨 |
| `Suricata_Other` | 단계 없음(정책 위반, 알 수 없음) | 안 됨. 이미 시작된 스토리의 host가 낸 경우에만 들어감 |

공통 이벤트의 값: `product` = `NSM`, `engine` = `Suricata`, 진단명 `NSM.Signature.<단계>`, 탐지 이름은 시그니처 이름입니다.

**사건 묶기 키:** (`rule`, 출발지, 대상)입니다. SID는 키에 없습니다. 같은 공격자가 같은 대상에 익스플로잇 경보 여러 종류를 내면 알림이 한 번만 올라가게 의도한 것입니다. 시그니처별 내역은 이벤트에 남습니다. 묶는 간격은 NSM과 같습니다(15분).

### 3.5 출발지·대상

Zeek 룰과 같은 뜻으로 맞춥니다. 공격 단계에서는 공격자가 출발지이고, C2·유출 단계에서는 내부(감염) host가 출발지입니다.

| 경보 | 출발지 | 대상 |
| --- | --- | --- |
| 룰에 `target` 키워드가 있어 경보에 `alert.source`·`alert.target`이 있음 | `alert.source.ip` | `alert.target.ip` |
| C2·유출 단계 | 내부 쪽 IP | 외부 쪽 IP |
| 그 밖 | 연결을 시작한 쪽(`direction`이 `to_client`면 경보의 src·dest를 바꿈) | 반대쪽 |

명시적 프록시(예: PC → 프록시 3128/tcp)를 거친 연결은 3.3절에서 찾은 http 로그가 `CONNECT`인지로 판단하고, Zeek 룰(#117)과 같게 바꿉니다.
- 출발지는 PC, 대상은 프록시 주소입니다.
- 목적지 이름(`dst_name`)은 CONNECT 대상이고, `proxy`는 `주소:포트`입니다. 화면·리포트는 프록시를 피해 장비가 아니라 중계 장비로 봅니다.
- 예외의 도메인 축은 CONNECT 대상 이름으로 판정합니다. 고객이 도메인으로 건 예외가 경보에도 맞습니다.

## 4. 단계·위험도·예외 (Manager)

### 4.1 이벤트 필드

공통 이벤트(통합 상관 설계 3장)에 아래 값을 더합니다. 목업 탐지 상세의 "기술 상세"에 예시가 있습니다.

| 필드 | 내용 |
| --- | --- |
| `engine` | `Suricata`(행위 탐지는 `Zeek`) |
| `sig_id`, `sig_rev`, `signature` | 시그니처 SID·rev·이름 |
| `sig_category`, `sig_classtype` | ET 카테고리(룰 파일), classtype |
| `sig_severity` | Suricata priority(1\~4) |
| `stage_by` | 단계를 정한 근거: `sid_map`, `mitre`, `classtype` |
| `technique` | 룰 메타데이터 `mitre_technique_id`(없으면 빈 목록) |
| `community_id`, `flow_id`, `app_proto` | 경보 값 그대로 |
| `uid`, `dst_name`, `proxy` | 3.3·3.5절에서 찾은 값(없을 수 있음) |
| `role_up` | 목적지 역할로 위험도를 올렸는지(4.3) |

### 4.2 단계 정하기

| 순서 | 근거 | 예 |
| --- | --- | --- |
| 1 | SID별 지정(룰 정책 화면 "시그니처 룰", Manager 설정) | 특정 SID를 강제로 내부 확산으로 |
| 2 | 룰 메타데이터 `mitre_tactic_id`(ET Open 최근 룰 다수에 있음) | TA0011 → C2, TA0001 → 초기 침투, TA0008 → 확산 |
| 3 | 분류(classtype) | `trojan-activity`·`command-and-control` → C2, `web-application-attack`·`attempted-admin`·`attempted-user` → 초기 침투, `attempted-recon`·`network-scan` → 정찰, `credential-theft` → 계정 탈취, `policy-violation`·`misc-activity` → 단계 없음 |
| 4 | 그 밖 | `Suricata_Other` |

Manager가 정하므로 바꾸면 새 경보부터 바로 적용되고, 필요하면 지난 경보에 다시 적용합니다. 공격 단계는 스토리용 제품 분류라 ATT&CK 전술과 다를 수 있습니다(목업 "ATT&CK 커버리지").

### 4.3 위험도

근거의 `sig_severity`(Suricata priority)를 화면 위험도로 바꿉니다.

| Suricata priority | 화면 위험도 |
| --- | --- |
| 1 | High |
| 2 | Medium |
| 3, 4 | Low |

- Critical은 Suricata priority만으로는 주지 않습니다. 목적지가 DC·DB 서버(Manager 자산 판정)면 한 단계 올리고 `role_up`을 남깁니다(surica DESIGN 6.3).
- Low 경보는 탐지 목록에는 나오지만 공격 스토리의 시작점이 되지 않습니다.
- 변환표와 역할로 올리기는 룰 정책 화면에서 바꿉니다(Manager 즉시 적용).

### 4.4 예외와 룰 끄기

| 하고 싶은 것 | 어디서 | 방법 |
| --- | --- | --- |
| 이 시그니처를 아예 안 씀 | Suricata | 룰 정책 화면 → `suricata-update` disable → `reload-rules`(재시작 없음, surica DESIGN 3.2) |
| 특정 host·서버에서만 이 시그니처 예외 | **Manager 예외** | "NSM 예외" 화면에서 등록. 축: 출발지·목적지·포트·서비스·도메인·**시그니처(SID)**. drop·suppress·만료·사유·적중 수는 행위 탐지 예외와 같은 규칙 |
| 경보 폭주 억제 | Suricata + Manager | `threshold.config`(3.1) + Manager 사건 묶기(3.4) |

- **화면은 하나, 적용은 두 곳:** 적용할 탐지가 시그니처 탐지(`Suricata_*`)이거나 SID 조건이 있는 예외는 Manager가 적용하고 저장하면 바로 반영됩니다. 행위 탐지 예외는 지금처럼 센서 예외 파일로 배포합니다. 한 예외에 둘을 함께 고르지 못하게 합니다.
- **센서 예외 파일 형식은 바꾸지 않습니다.** `sid` 열을 더하지 않고, 시그니처 예외는 파일에 넣지 않습니다. 파일 가져오기에서 시그니처 탐지 범위가 있으면 오류로 알립니다.
- `drop`은 공통 이벤트로 저장은 하되 화면·알림·상관에서 빼고(적중 수는 셈), `suppress`는 화면에 보이되 알림을 내지 않습니다.
- 도메인·서비스 축은 3.3절에서 연결 로그를 찾은 경보에만 맞습니다.

## 5. 통합 상관과 공격 스토리

### 5.1 어디서 잇나

| 상관 | 어디서 | 시그니처 |
| --- | --- | --- |
| 네트워크 킬체인(지금) | NSM 센서 | **안 들어감**. 행위 탐지만 |
| 통합 공격 스토리 | Manager(통합 상관 설계 7장) | 들어감. 스토리 묶기 입력(시작점 규칙은 3.4) |
| 통합 상관 탐지(`Correlated_Cross`) | Manager(통합 상관 설계 5장) | 들어감. 5.2절 기본 제공 시나리오 |
| 같은 연결 묶어 보이기 | Manager(6.2) | 들어감 |

### 5.2 기본 제공 시나리오 (시그니처 ↔ 행위 탐지)

통합 상관 설계 10장 3단계의 기본 제공 시나리오에 넣습니다. 형식은 Sigma 상관 룰(`temporal_ordered` + 엔진 확장 `x-nsm-pivot`)이고, 결과는 `Correlated_Cross`입니다.

| id | 시나리오 | 묶는 조건 | 창 |
| --- | --- | --- | --- |
| S-01 | 시그니처 초기 침투 → 같은 서버의 외부 연락 | `Suricata_Initial_Access`의 대상 = 이후 C2 행위 탐지(`HTTP_Beaconing`·`TLS_Beaconing`·`Encrypted_C2`·`DNS_Tunneling`·`Long_Connection`) 또는 `Suricata_C2`의 출발지(`dst_to_src`) | 2시간 |
| S-02 | 행위 초기 침투 → 같은 서버의 시그니처 외부 연락 | `SQL_Injection`·`Webshell_Access`·`AI_Service_Exploit`의 대상 = 이후 `Suricata_C2`의 출발지 | 2시간 |
| S-03 | 시그니처 내부 확산 → 대상의 후속 행위 | `Suricata_Lateral`의 대상 = 이후 C2·유출·`SMB_Ransomware`의 출발지 | 2시간 |
| S-04 | 시그니처 초기 침투 → 그 서버에서 시작한 내부 탐색·확산 | `Suricata_Initial_Access`의 대상 = 이후 `AD_Enumeration`·`Host_Scan`·확산 행위 탐지의 출발지 | 2시간 |

- 창 길이와 묶음은 센서 킬체인의 같은 전이(`chain_group_rules`)에 맞췄습니다.
- 센서 `Correlated_KillChain`과 같은 host·겹치는 단계면 같은 사건으로 묶어 알림을 한 번만 냅니다(통합 상관 설계 5.5).
- 등급은 룰의 `x-nsm-severity-id`(기본 4 High), 시나리오 안에 Critical 탐지가 있으면 5입니다.

## 6. Zeek 탐지와 겹치는 경보 정리

두 단계로 정리합니다.

### 6.1 룰 범위로 겹침을 없앰 (기본값)

ET Open 카테고리별 기본값 제안입니다. **CIC-IDS2017 5일에 ET Open을 돌려 카테고리별 경보 수와 Zeek 탐지와의 겹침을 측정한 뒤 확정**합니다(7장 S5).

| ET 카테고리 | 기본 | 이유 |
| --- | --- | --- |
| exploit, exploit_kit, web_server, web_specific_apps, web_client, attack_response, shellcode, malware, mobile_malware, worm, coinminer, phishing, current_events | 켬 | 알려진 공격 서명. Zeek 행위 룰에 없는 정보 |
| sql, smb, netbios, rpc, scada | 켬(scada는 고객망에 OT가 있을 때만) | 프로토콜 익스플로잇 |
| ciarmy, compromised, drop, dshield, tor(IP 평판 목록) | **끔** | IOC 피드는 `IOC_Match`로 일원화(IOC를 두 곳에 넣지 않음) |
| scan | 도구 지문 룰만 켬, 횟수 기반 룰은 끔 | 횟수 기반은 Zeek `Port_Scan`·`Host_Scan`·`SSH_Bruteforce`·`FTP_Bruteforce`와 겹침. Nmap 스크립트 엔진 같은 도구 지문은 Zeek에 없음 |
| dns | 끔 | Zeek `DNS_Tunneling`·`DGA_Domain`과 겹침. 악성 도메인 조회 룰은 malware·current_events에 있음 |
| policy, info, hunting, inappropriate, games, chat, p2p, user_agents, icmp, icmp_info | 끔 | 정책·정보성 경보가 대부분. AI 서비스(33)·비표준 포트(24)·자체 서명 인증서(09)와 겹치는 룰 포함 |
| ja3 | 끔 | TLS 지문은 범위에서 뺌(2026-11 결정) |
| adware_pup, dos | 끔(고객 요청 시 켬) | MDS가 PUP를 이미 봄. DoS는 미러 구간에서 의미가 작음 |

surica 설계의 예시 `disable: [re:heartbleed]`(DESIGN 3.1절)는 Zeek `TLS_Heartbleed`(27)와 겹쳐 끈 것으로, 이 원칙과 같습니다.

### 6.2 같은 연결에 둘 다 나온 경우 (Manager 표시)

룰 범위를 줄여도 웹 공격처럼 겹치는 곳이 남습니다(Zeek `SQL_Injection`·`Cross_Site_Scripting`·`Webshell_Access`와 ET web_server·web_specific_apps). 경보의 `community_id`와 Zeek 근거의 `community_id`로 같은 연결을 찾습니다.

| 조건 | 처리 |
| --- | --- |
| 같은 `community_id`, 같은 단계, 10분 안 | 화면에서 **한 탐지**로 보이고 근거에 "Zeek + Suricata"가 함께 나옴. 알림은 먼저 온 쪽으로 한 번 |
| 같은 `community_id`, 다른 단계 | 둘 다 보임(예: Suricata 익스플로잇 경보 + Zeek 웹쉘). 스토리에서 같은 연결로 이어짐 |

두 탐지는 오는 순서가 정해져 있지 않습니다(Zeek 집계형 룰은 창이 끝나야 냄). 먼저 온 쪽이 알림을 내고, 뒤에 온 쪽은 같은 탐지에 붙습니다.

## 7. 단계별 계획

| 단계 | 범위 | 저장소 | 규모(추정) |
| --- | --- | --- | --- |
| S1. Community ID | conn `community-id-logging` 로드, 연결 단위 선별 전송 로그에 `community_id`(3.3), 스키마(`schema/`, LOG_SCHEMA), SRS_METADATA_EXPORT, btest, 선별 전송 증가분 측정 | nsm | 완료(2026-11-24) |
| S2. 렌더러 | eve 경보·stats 분리, `suricata_alert` 스트림 기본 켬, 6.1절 기본값을 `disable.conf`로, `threshold.config` 기본값, Community ID seed 맞춤, AssetID 위치 갱신(8장) | surica | 3\~5일 |
| S3. Manager 정규화 | 3.2절 처리(단계·위험도·연결 찾기·프록시·예외·사건 묶기), 공통 이벤트 저장, 화면(목업) | Manager | 통합 상관 0\~2단계와 함께 |
| S4. 통합 상관 시나리오 | 5.2절 S-01\~S-04 | Manager | 통합 상관 3단계와 함께 |
| S5. 측정 | CIC-IDS2017 5일에 ET Open: 카테고리별 경보 수, 오탐, Zeek 탐지와 겹침, 센서 부하, `threshold` 뒤 전송량. 결과로 6.1절 기본값과 `suri_join_wait` 확정 | nsm·surica | 1주 |
| S6. PoC 리포트 | `report_pcap.py`가 eve 경보도 읽어 같은 규칙(단계·위험도·연결 찾기)으로 목업형 리포트에 넣음 | nsm | 3일 |

S5를 먼저 시작하면 룰 범위와 경보량을 일찍 알 수 있습니다. S1은 센서에 반영했습니다(`nsm_rules/metadata/community_id.zeek`, btest `rules/meta-community-id`).

화면은 [목업](../ui/mockup/mdsm_nsm_mockup.html)에 그려 두었습니다. 화면 목록은 [`ui/README.md`](../ui/README.md)의 "Suricata 연동 화면"에 있습니다.

## 8. surica DESIGN 0.2에서 바꿀 점

| 항목 | 0.2 | 바꿀 내용 |
| --- | --- | --- |
| 자산 식별 위치 | `claudtest2` 저장소의 Zeek 패키지 | 센서 패키지는 nsm `nsm_rules/asset-id/`로 옮김(2026-11-12). 리졸버만 claudtest2 |
| 경보 전송 | `suricata_alert` 스트림으로 Manager에 보내 결합 | **그대로**. 결합 뒤 공통 이벤트로 바꾸는 단계(3.2)를 더함 |
| eve 출력 | eve-log 하나(alert + stats) | 경보와 stats를 나눔(가는 곳이 다름) |
| 사건 묶기 | Manager가 `community_id`로 notice·경보를 한 사건으로 | Manager 사건 묶기(3.4) + 같은 연결 묶어 보이기(6.2). Zeek 쪽은 근거와 연결 단위 선별 전송 로그에 `community_id`가 있음(3.3) |
| Community ID seed | 언급 없음 | Zeek `community_id_seed`와 같게(3.1) |
| IOC 평판 룰 | 언급 없음 | 끔(6.1). IOC는 `IOC_Match` |

## 9. 결정 기록과 남은 것

| 항목 | 결정 | 날짜 |
| --- | --- | --- |
| 연동 방식 | B. Manager 직접 전송 | 2026-11-24 |
| 일정 | 통합 상관 엔진과 동시에 | 2026-11-24 |
| 시그니처 ↔ 행위 탐지 | 통합 상관(5.2)·통합 스토리. 센서 킬체인에는 넣지 않음 | 2026-11-24 |
| Community ID | conn과 연결 단위 선별 전송 로그에 넣음(3.3) | 2026-11-24 |
| 예외 | Manager가 적용, 화면은 NSM 예외 하나, 센서 예외 파일 형식은 그대로(4.4) | 2026-11-24 |
| 위험도 변환 | 4.3절 표. Critical은 자산 역할로만 | 2026-11-24 |
| Low 경보 | 스토리 시작점만 아님, 목록에는 보임 | 2026-11-24 |

남은 것:

| 항목 | 정하는 때 |
| --- | --- |
| ET 카테고리 기본값(6.1) | S5 측정 뒤 |
| `threshold.config` 기본값, `suri_join_wait` | S5 측정 뒤 |
| Manager의 원본 경보 보관 기간 | Manager 저장 설계(통합 상관 설계 9장)와 함께 |
