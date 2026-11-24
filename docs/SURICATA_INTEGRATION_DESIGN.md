# Suricata 연동 설계안 (탐지 흐름 합치기)

작성: 2026-11-19 · 상태: 설계안(결정 대기, 9장) · 관련: Suricata 엔진 구성 설계 [surica `docs/DESIGN.md` 0.2](https://github.com/kwsjjang8901-ship-it/surica/blob/main/docs/DESIGN.md), [탐지 SRS](SRS.md), [소급검색 설계안](RETRO_SEARCH_DESIGN.md)

## 0. 이 문서의 범위

Suricata 엔진을 센서에 붙이는 부분은 surica 저장소에서 설계하고 PoC까지 끝냈습니다(2026-11-10, surica DESIGN 0.2). 이 문서는 그 위에서 **Suricata 경보를 지금의 NSM 탐지 흐름에 합치는 방법**을 정합니다.

| 구분 | 어디서 정함 | 이 문서에서 |
| --- | --- | --- |
| 엔진 켜기·끄기, `sensor.yaml`, `suricata.yaml` 생성, AF_PACKET 공존, 장애 격리, 룰 업데이트(`suricata-update`), stats 전송 | surica DESIGN 2\~4장, 3.3절 | 그대로 따름. 바꿀 점만 8장에 적음 |
| 경보와 자산 결합(IP 점유 구간), Community ID | surica DESIGN 5.2·6장 | 그대로 따름 |
| **경보를 탐지(notice)·예외·근거·사건 묶기·킬체인·공격 스토리에 합치기** | 없음 | 2\~5장 |
| **Zeek 탐지와 겹치는 경보 정리** | surica DESIGN 6.2절 한 줄 | 6장 |
| **ET 룰 범위와 위험도** | surica DESIGN 12장(ET Open + 사내 룰) | 6.1절, 4.3절 |

이미 정한 것:
- IP·도메인·URL IOC 일치는 Suricata를 넣어도 Zeek(`IOC_Match`, 탐지 35)에 둡니다(RETRO_SEARCH_DESIGN 0장).
- Suricata는 시그니처 경보만 맡습니다. 프로토콜 로그(http·dns·tls·flow)는 끕니다(surica DESIGN 원칙 1).
- Suricata는 센서마다 꺼져 있을 수 있습니다(출시 기본값 off). 꺼져 있으면 지금 동작과 같아야 합니다.

## 1. 지금 탐지 흐름

```
Zeek 이벤트 -> 룰(01~35) -> exception_drop(예외 엔진) -> NOTICE
   -> evidence.log(근거) / nsm_detection.log(탐지 요약, 사건 묶기) / notice.log
   -> corr_notice -> 킬체인 상관(correlation_killchain, 매니저 한 곳) -> Correlated_KillChain
   -> 선별 전송 -> Manager: 자산 결합, 공격 스토리, 알림, 화면
```

Suricata 경보가 이 흐름 밖에 있으면 아래 기능을 Suricata 쪽에 따로 만들어야 합니다.
- 예외: 예외 파일, drop·suppress, 만료, 적중 수
- 근거 행과 `evidence_id` 조인
- 같은 사건 묶기(`incident_id`, `occurrence`)
- 킬체인 상관(예: 웹 익스플로잇 경보 다음에 같은 서버의 C2 탐지)
- 공격 스토리의 단계

## 2. 연동 방식 비교

| 방식 | 내용 | 장점 | 단점 |
| --- | --- | --- | --- |
| **A. 센서에서 Zeek가 경보를 받아 notice로 냄 (권장)** | Zeek(매니저 노드)가 Suricata 경보 파일을 읽어 NSM notice로 바꿔 냄. 이후는 기존 흐름 그대로 | 예외 엔진·근거·사건 묶기·킬체인·스토리·선별 전송을 다시 만들지 않음. 예외 파일·화면이 하나. 연결 uid를 센서에서 바로 붙임 | Zeek가 Suricata 출력 형식(EVE)을 알아야 함. 경보 폭주가 Zeek notice로 들어오므로 룰 범위·억제가 필요 |
| B. Manager가 EVE를 탐지 요약 형식으로 바꿈 | surica PoC처럼 `suricata_alert` 스트림을 Manager로 보내고 Manager가 변환 | 센서 변경이 적음. 엔진이 완전히 따로 돎 | 예외·사건 묶기·킬체인을 Manager에 다시 만들어야 함. 예외를 두 곳(Zeek 예외 파일, Manager)에서 관리. 센서 킬체인에 Suricata 단계가 못 들어감 |
| C. 따로 둠 | Suricata 경보는 별도 목록으로만 보임 | 가장 단순 | 공격 스토리·킬체인에 안 들어감. 목업 NSM 대시보드(위험도별 탐지에 Suricata 탐지를 함께 셈)와 맞지 않음 |

**A를 권합니다.** IOC 일치를 Zeek에 둔 이유와 같습니다. 이미 만든 처리 흐름을 그대로 쓰고, 예외를 한 곳에서 관리합니다. Suricata가 꺼져 있으면 경보 파일이 없어 지금과 똑같이 동작합니다.

surica의 장애 격리 원칙은 그대로 지킵니다. Zeek는 Suricata 프로세스와 통신하지 않고 파일만 읽습니다. Suricata가 멈추거나 파일이 없어도 Zeek 경로는 영향이 없습니다.

## 3. 센서 수용 설계 (방식 A)

### 3.1 입력

| 항목 | 설계 |
| --- | --- |
| 파일 | Suricata가 경보만 쓰는 EVE 파일(`eve-alert.json`, 한 줄에 경보 하나). surica 렌더러가 eve-log 출력을 경보 전용 하나와 stats 전용 하나로 나눠 만듦(8장) |
| 설정 | `NSM::suricata_alert_file`(기본 빈 값 = 꺼짐). surica 렌더러가 `suricata.enabled`일 때만 값을 넣음. IOC 파일(`ioc_file`)과 같은 방식 |
| 읽기 | Input 프레임워크 원문 리더(`Input::READER_RAW`), 실시간은 `MODE::STREAM`(파일 끝을 계속 읽음). 줄마다 `from_json()`으로 필요한 필드만 레코드로 바꿈(모르는 키는 무시) |
| 노드 | standalone 또는 매니저 한 곳만 읽음(IOC 파일과 같음). Suricata는 같은 센서 호스트에서 돌고 파일도 그 호스트에 있음 |
| 파일 교체 | Suricata 로그 회전(rename 후 새 파일)은 `MODE::STREAM`이 따라가지 못하므로, 회전 대신 Suricata `SIGHUP` 재열기 + 크기 제한으로 운영. 2단계에서 실측 |

Zeek 8.0.9·9.0.1 모두 `from_json`, `community_id_v1`, `lookup_connection`을 지원합니다(2026-11-19 확인).

### 3.2 pcap 모드 (PoC·리포트)

pcap을 읽을 때는 Suricata를 먼저 돌려 경보 파일을 만든 뒤 Zeek를 돌립니다. Zeek는 시작할 때 파일을 모두 읽고(그동안 `suspend_processing`), 경보를 시각순으로 둔 뒤 **pcap 시각이 경보 시각에 닿을 때** 하나씩 냅니다. 이렇게 해야 경보가 같은 시각의 Zeek 탐지와 같은 순서로 킬체인·사건 묶기에 들어갑니다. surica PoC에서 확인한 "pcap 모드 Suricata는 경보를 시각순으로 쓰지 않는다"(surica DESIGN 10장)는 정렬로 해결됩니다.

실시간 모드에서는 읽는 즉시 냅니다. Suricata 경보가 Zeek보다 수 초 늦게 들어올 수 있지만, 상관 시간 창(30분\~2시간)과 사건 묶기 간격(15분)에 비하면 작습니다.

### 3.3 연결 찾기

| 순서 | 방법 | 결과 |
| --- | --- | --- |
| 1 | 경보의 5-tuple로 `lookup_connection()` | 아직 열린 연결이면 Zeek `uid`와 연결 레코드. 예외 판정의 서비스·도메인 축에도 씀 |
| 2 | 연결이 이미 닫혔으면 | 연결 레코드 없이 주소·포트만으로 예외 판정. 근거에는 Community ID만 남기고 Manager가 conn.log와 맞춤 |

Community ID는 경보에 들어 있는 값(`community_id`)을 그대로 씁니다. Zeek `community_id_v1()`로 같은 값을 계산할 수 있어 검증에 씁니다. conn.log에 Community ID를 넣는 것(`policy/protocols/conn/community-id-logging` 로드)은 surica DESIGN 12장에서 제안한 대로입니다. 선별 전송 필드 목록에도 넣어야 합니다(9장).

> 2026-11-23 현황: NSM 근거(`evidence.log`)에는 이미 연결의 `community_id`(seed 0)와 `src_port`·`dst_port`·`proto`가 들어갑니다(#126, [LOG_SCHEMA.md](LOG_SCHEMA.md)). Suricata 경보 근거도 같은 필드 이름(`community_id`)에 경보의 값을 넣으면 Manager가 NSM 탐지와 경보를 같은 키로 묶을 수 있습니다. conn.log에 Community ID를 넣는 결정(9장)은 Manager가 경보 ↔ 원본 연결을 찾을 때만 필요합니다.

### 3.4 notice 종류: 단계별 8개

경보마다 공격 단계가 다르므로 notice 하나로 두지 않고 **단계별로 나눕니다**. 그러면 예외 범위(`scope`), 킬체인 묶음(`corr_*_notes`), 사건 묶기 키(notice 종류 + 공격자 + 피해 host)를 지금 코드 그대로 씁니다.

| notice | 단계 | 킬체인 묶음 |
| --- | --- | --- |
| `Suricata_Recon` | 정찰 | `corr_recon_notes` |
| `Suricata_Initial_Access` | 초기 침투 | `corr_initial_notes` |
| `Suricata_C2` | 외부 연락(C2) | `corr_c2_notes` |
| `Suricata_Credential` | 계정 탈취 | `corr_cred_notes` |
| `Suricata_Lateral` | 내부 확산 | `corr_lateral_notes` |
| `Suricata_Exfil` | 정보 유출 | `corr_exfil_notes` |
| `Suricata_Impact` | 피해 | `corr_impact_notes` |
| `Suricata_Other` | 단계 없음(정책 위반, 알 수 없음) | 넣지 않음. 공격 스토리 시작점이 되지 않음 |

도메인 장악 묶음(`corr_domain_notes`: DCSync, Zerologon)에는 넣지 않습니다. ATT&CK 전술로는 계정 탈취와 구분할 수 없어, 그런 경보는 `Suricata_Credential`로 들어갑니다.

단계를 정하는 순서는 4.2절에 있습니다. 진단명은 `NSM.Signature.<단계>`(예: `NSM.Signature.InitialAccess`)입니다. 탐지 이름은 notice `msg`에 `Suricata: <signature>`로 남깁니다.

한 사건에는 같은 단계의 서로 다른 시그니처가 함께 묶입니다(사건 키에 SID가 없음). 같은 공격자가 같은 대상에 익스플로잇 경보 여러 종류를 낼 때 알림이 한 번만 올라가도록 의도한 것입니다. 시그니처별 내역은 탐지 행과 근거에 남습니다.

### 3.5 출발지·대상 (상관 계약)

Zeek 룰과 같은 뜻으로 맞춥니다. 공격 단계에서는 공격자가 `src`이고, C2·유출 단계에서는 내부(감염) host가 `src`입니다.

| 경보 | `src` | `dst` |
| --- | --- | --- |
| 룰에 `target` 키워드가 있어 경보에 `alert.source`·`alert.target`이 있음 | `alert.source.ip` | `alert.target.ip` |
| C2·유출 단계 | 내부 쪽 IP | 외부 쪽 IP |
| 그 밖 | 연결을 시작한 쪽(`direction`이 `to_client`이면 경보의 src·dest를 바꿈) | 반대쪽 |

명시적 프록시(예: PC → 프록시 3128/tcp)를 거친 연결의 경보는 PC와 프록시가 모두 내부 주소라 "외부 쪽"이 없습니다. 3.3절에서 찾은 Zeek 연결이 프록시 경유(`conn_via_proxy`)면 Zeek 룰(#117)과 같게 처리합니다.

- `src` = PC, `dst` = 프록시 주소. 근거에 실제 목적지 `host=`(CONNECT 대상)와 `via_proxy=주소:포트`를 붙여, Manager·리포트가 프록시를 피해 장비가 아니라 중계 장비로 보게 합니다.
- 예외 판정 컨텍스트는 `ctx_of_conn`을 그대로 써서 `dst`를 비우고 실제 목적지 이름·포트를 넣습니다. 고객이 도메인으로 건 예외가 경보에도 맞습니다.
- 억제 키의 목적지는 CONNECT 대상 이름입니다. 대상을 모르면 프록시 주소를 씁니다.

### 3.6 처리 순서

```
경보 한 줄
 -> SID 기본 필터: 룰 범위 밖이면 버림(6.1절, suricata-update로 이미 끈 룰은 경보 자체가 없음)
 -> 단계 결정(4.2) -> notice 종류
 -> 연결 찾기(3.3)
 -> exception_drop_ctx(notice, ctx{src, dst, dst_port, services, domain, sid})   # 4.4
 -> 억제: (notice, SID, src, dst)를 suppress_suricata(기본 1시간)
 -> 근거: sid, rev, signature, category, severity, community_id, app_proto, suricata_ts, uid
 -> NOTICE(src, dst, msg, sub="sid=…", evidence_id) -> 이후 기존 흐름
```

## 4. 위험도·단계·예외

### 4.1 근거 필드

`evidence.log`의 근거 행(`detail`)에 남기는 값입니다. URL·헤더·페이로드는 surica DESIGN 8장대로 받지 않으므로 근거에도 없습니다.

```
sid=2024217 rev=3 signature="ET EXPLOIT …" category="Attempted Administrator Privilege Gain" severity=1
community_id=1:LQU9… app_proto=smb suricata_ts=2026-11-19T09:12:03.123Z stage_by=mitre
```

`stage_by`는 단계를 어떻게 정했는지입니다(`mitre`, `classtype`, `sid_map`). 단계가 틀렸을 때 고칠 곳을 알려 줍니다.

### 4.2 단계 정하기

| 순서 | 근거 | 예 |
| --- | --- | --- |
| 1 | 사내 SID 표(`suricata_stage_map`, redef 가능) | 특정 SID를 강제로 Impact로 |
| 2 | 룰 메타데이터 `mitre_tactic_id` (ET Open 최근 룰 다수에 있음) | TA0011 → C2, TA0001 → 초기 침투, TA0008 → 확산 |
| 3 | 분류(classtype) | `trojan-activity`·`command-and-control` → C2, `web-application-attack`·`attempted-admin`·`attempted-user` → 초기 침투, `attempted-recon`·`network-scan` → 정찰, `credential-theft` → 계정 탈취, `policy-violation`·`misc-activity` → 단계 없음 |
| 4 | 그 밖 | `Suricata_Other` |

기법 ID(ATT&CK)는 룰 메타데이터 `mitre_technique_id`를 쓰고, 없으면 비웁니다. 탐지 요약의 `techniques`와 화면의 ATT&CK 매핑에 그대로 들어갑니다.

### 4.3 위험도

화면 스펙 초안대로 **Suricata가 정한 위험도를 그대로** 씁니다. 근거의 `severity`(Suricata priority)를 Manager가 화면 위험도로 바꿉니다. 센서 `nsm_detection.log`의 `severity`는 다른 단일 탐지처럼 `Information`입니다(SRS 10장 한계와 같음).

| Suricata `severity` | 화면 위험도 |
| --- | --- |
| 1 | High |
| 2 | Medium |
| 3, 4 | Low |

Critical은 Suricata 경보만으로는 주지 않습니다. 자산 역할로 올리는 것(목적지가 DC·DB면 한 단계 위)은 surica DESIGN 6.3절의 3단계 작업입니다. Low 경보는 탐지 목록에는 나오지만 공격 스토리의 시작점이 되지 않습니다.

### 4.4 예외와 룰 끄기

세 가지를 나눠 씁니다.

| 하고 싶은 것 | 어디서 | 방법 |
| --- | --- | --- |
| 이 시그니처를 아예 안 씀 | Suricata | 룰 정책 화면 → `suricata-update` disable → `reload-rules`(재시작 없음, surica DESIGN 3.2) |
| 특정 host·서버에서만 이 시그니처 예외 | **NSM 예외 파일** | 예외 엔진에 `sid` 축을 더함(아래). drop·suppress·만료·적중 수가 Zeek 탐지와 같게 동작 |
| 경보 폭주 억제 | Suricata | `threshold.config`(surica 기본값). 센서 억제(`suppress_suricata`)가 한 번 더 막음 |

예외 엔진의 `sid` 축은 두 가지 방법이 있습니다.

| 방법 | 내용 | 비고 |
| --- | --- | --- |
| **예외 파일에 `sid` 열 추가 (권장)** | `#fields id scope src dst dst_port service domain ja4 sid disposition …`. 값은 SID 목록, `-`면 모든 SID | Manager 예외 화면·파일 생성기를 함께 고침. 기존 파일은 `sid` 열이 없어 읽기 실패하므로, 열이 없는 옛 형식도 읽게 하거나 배포 때 한꺼번에 바꿈 |
| `scope`에 SID를 붙임 | `Suricata_Initial_Access:2024217` | 파일 형식은 그대로지만 scope 해석이 복잡해지고 묶음 범위(`group:`)와 섞임 |

## 5. 킬체인과 공격 스토리

- **킬체인 상관(센서):** 3.4절의 단계별 notice를 해당 묶음에 넣으면 묶음 전이(`chain_group_rules`) 23개가 그대로 적용됩니다. 예: 외부 IP의 `Suricata_Initial_Access`(웹 익스플로잇) → 같은 서버가 낸 `TLS_Beaconing`(C2)은 "초기 침투 → C2, `DST_TO_SRC`, 2시간"으로 이어집니다. `stage_attack` 표에는 단계별 기본 기법이 없으므로 근거의 `mitre_technique_id`를 씁니다.
- **공격 스토리(Manager):** 스토리는 `nsm_detection.log`를 묶어 만드므로 별도 작업이 없습니다. 목록 기준(체인 있음, 단계 2개 이상, Critical 포함)도 그대로입니다. 스토리 단계 표시에 출처(Zeek·Suricata)를 붙입니다.
- **스토리 시작점:** `Suricata_Other`와 Low 경보는 시작점이 되지 않습니다. 이미 시작된 스토리의 host가 낸 경우에는 스토리에 들어갑니다.

## 6. Zeek 탐지와 겹치는 경보 정리

두 단계로 정리합니다.

### 6.1 룰 범위로 겹침을 없앰 (기본값)

ET Open 카테고리별 기본값 제안입니다. **CIC-IDS2017 5일에 ET Open을 돌려 카테고리별 경보 수와 Zeek 탐지와의 겹침을 측정한 뒤 확정**합니다(7장 S4).

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

룰 범위를 줄여도 웹 공격처럼 겹치는 곳이 남습니다(Zeek `SQL_Injection`·`Cross_Site_Scripting`·`Webshell_Access`와 ET web_server·web_specific_apps).

| 조건 | 처리 |
| --- | --- |
| 같은 `uid`, 같은 단계, 10분 안 | 화면에서 **한 탐지**로 보이고 근거에 "Zeek + Suricata"가 함께 나옴. 알림은 먼저 온 쪽으로 한 번 |
| 같은 `uid`, 다른 단계 | 둘 다 보임(예: Suricata 익스플로잇 경보 + Zeek 웹쉘). 스토리에서 같은 연결로 이어짐 |
| `uid`가 없음(Suricata 경보가 닫힌 연결) | Community ID로 conn.log를 찾아 같은 규칙 적용 |

센서에서 합치지 않는 이유: 경보와 Zeek 탐지가 오는 순서가 정해져 있지 않습니다(Zeek 집계형 룰은 창이 끝나야 냄). 센서는 두 탐지를 모두 내고 `uid`를 붙이는 데까지만 합니다.

## 7. 단계별 계획

| 단계 | 범위 | 저장소 | 규모(추정) |
| --- | --- | --- | --- |
| S1. 센서 수용 | 경보 파일 읽기, 단계별 notice 8개 공통 등록, 상관 계약, 연결 찾기, 억제, pcap 모드 정렬, 예외 `sid` 축 | nsm | 2주 |
| S1 테스트 | Suricata 8.0.6으로 만든 고정 경보 파일(합성 pcap에서 생성, 저장소에 넣어 CI에 Suricata가 필요 없게)로 btest. 꺼짐 회귀(파일 없음 = 지금과 같은 출력), 클러스터(매니저만 읽음) | nsm | S1에 포함 |
| S2. 렌더러 수정 | 경보 전용 EVE 출력, `NSM::suricata_alert_file` 설정, 원본 `suricata_alert` 스트림 기본 끔(9장), AssetID 위치 갱신(8장), 6.1절 기본값을 `disable.conf`로 | surica | 3\~5일 |
| S3. Manager·화면 | 탐지 출처 표시, 위험도 변환(4.3), 같은 연결 묶어 보이기(6.2), 룰 정책 화면 "시그니처 룰" 탭, 예외 화면 `sid` | Manager | Manager 팀 |
| S4. 측정 | CIC-IDS2017 5일에 ET Open: 카테고리별 경보 수, 오탐, Zeek 탐지와 겹침, 센서 부하. 결과로 6.1절 기본값 확정 | nsm·surica | 1주 |

S4를 S1과 함께 먼저 시작하면 룰 범위와 경보량을 일찍 알 수 있습니다. 경보량이 크면 S1의 억제 기본값을 그에 맞춰 정합니다.

S3 화면은 연동이 끝났을 때를 기준으로 [목업](../ui/mockup/mdsm_nsm_mockup.html)에 먼저 그려 두었습니다(9장 제안대로라고 가정: 근거 필드 `sig_*`·`stage_by`, 예외 파일 `sid` 칸, Low는 시작점만 아님). 화면 목록은 [`ui/README.md`](../ui/README.md)의 "Suricata 연동 화면"에 있습니다.

## 8. surica DESIGN 0.2에서 바꿀 점

| 항목 | 0.2 | 바꿀 내용 |
| --- | --- | --- |
| 자산 식별 위치 | `claudtest2` 저장소의 Zeek 패키지 | 센서 패키지는 nsm `nsm_rules/asset-id/`로 옮김(2026-11-12). 리졸버만 claudtest2 |
| 경보 전송 | `suricata_alert` 스트림으로 Manager에 보내 결합 | NSM notice로 바뀌어 기존 탐지 스트림으로 감. 원본 스트림은 조사용으로 남기되 기본 끔 |
| eve 출력 | eve-log 하나(alert + stats) | 경보 전용 파일(Zeek가 읽음)과 stats 파일로 나눔 |
| 사건 묶기 | Manager가 `community_id`로 notice·경보를 한 사건으로 | 센서 사건 묶기(3.4) + Manager 같은 연결 묶어 보이기(6.2) |
| IOC 평판 룰 | 언급 없음 | 끔(6.1). IOC는 `IOC_Match` |

## 9. 결정이 필요한 것

| 항목 | 선택지 | 제안 |
| --- | --- | --- |
| 연동 방식 | A 센서 수용 / B Manager 변환 / C 따로 | **A** (2장) |
| 예외의 `sid` 축 | 예외 파일 열 추가 / scope에 붙임 | **열 추가**, Manager 예외 화면과 함께 (4.4) |
| 원본 `suricata_alert` 스트림 | 켬 / 끔 | **끔**(근거에 필요한 값이 다 들어감). 조사용으로 고객별 켬 |
| 위험도 변환 | 4.3절 표 | 표대로. Critical은 자산 역할로만 |
| ET 카테고리 기본값 | 6.1절 표 | S4 측정 뒤 확정 |
| conn.log Community ID | nsm_rules에서 로드 / Manager 계산 | **nsm_rules에서 로드**(surica 제안과 같음). 선별 전송 필드 목록과 SRS_METADATA_EXPORT를 함께 고침 |
| Low 경보 | 스토리 시작점 아님 / 목록에서도 숨김 | **시작점만 아님**, 목록에는 보임 |
