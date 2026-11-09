# NSM 탐지룰 SRS (소프트웨어 요구사항 명세)

최종 수정: 2026-11-09 · 원본: 이 파일(`docs/SRS.md`). 룰·설정을 바꾸는 PR에서 함께 고칩니다.

nsm_rules는 미러 트래픽을 Zeek로 분석해 킬체인 7단계(정찰 → 초기 침투 → 자격증명 접근 → 확산 → C2 → 유출 → 영향)의 위협 29종을 탐지 룰 23개로 탐지하고, 탐지마다 근거와 요약 로그를 남기는 Zeek 패키지입니다. 이 문서는 2026-11-09 main(6c1484c, PR #1\~#22 반영) 기준으로 시스템이 무엇을 해야 하는지와 어떻게 설정하는지를 정리합니다.

## 1. 개요

이 시스템의 목적은 네트워크 미러 트래픽만으로 공격 단계별 위협을 찾아내고, 담당자가 바로 확인할 수 있는 근거를 남기는 것입니다. 단말 에이전트 없이 동작합니다.

### 1.1 범위

| 구분 | 포함 | 제외 |
| --- | --- | --- |
| 탐지 | 탐지 룰 23개(파일 01\~24, 11번은 08번에 통합), 탐지 유형 29종 | 페이로드 복호화(TLS·SMB3 암호화 내용) |
| 공통 기능 | 근거 기록, 탐지 요약, ATT&CK 매핑, 알람 억제, 킬체인 상관, 로그 필터 | 경보 전송(메일·SIEM 연동)은 외부 시스템 몫 |
| 운영 | 단일 프로세스, 클러스터(manager·proxy·worker) | 센서 하드웨어·미러 구성 |
| 검증 | btest 34개, 합성 pcap 21개 + Zeek 공개 trace 1개, CI(Zeek 9.0.1·8.0.9) | 실제 고객망 성능 측정 |

### 1.2 대상 독자

- **보안 관제 담당자**: 어떤 탐지가 무슨 뜻인지(4·6장)
- **배포·운영 담당자**: 무엇을 설정해야 하는지(3·7장, 부록 A)
- **룰 개발자**: 요구사항과 검증 기준(5·8·9장)

### 1.3 용어

| 용어 | 뜻 |
| --- | --- |
| Zeek | 네트워크 트래픽을 프로토콜별 이벤트와 로그로 바꿔 주는 오픈소스 분석기 |
| 룰 | `nsm_rules/detections/NN_*.zeek` 파일 하나. 한 위협 주제를 탐지 |
| notice | 탐지 1건. `notice.log`에 남고 `NSM::Port_Scan`처럼 탐지 유형 이름을 가짐 |
| 근거(evidence) | 탐지를 뒷받침하는 관측 1건(누가·어디서·무엇을). `evidence.log` |
| 탐지 요약(detection) | notice 1건을 관제용으로 정리한 행. `nsm_detection.log` |
| 킬체인 상관 | 같은 공격자의 여러 탐지를 단계 순서로 이어 붙인 탐지(`Correlated_KillChain`) |
| 내부망 | `Site::local_nets`에 등록한 대역. 모든 방향 판정(내부→외부 등)의 기준 |
| 예외 목록(allowlist) | 탐지에서 빼는 출발지·목적지·도메인 목록 |
| 집계 창(epoch/interval) | 개수를 세는 시간 단위. 창이 끝나거나 임계를 넘으면 판정 |
| SumStats | Zeek의 분산 집계 프레임워크. 클러스터에서 워커 값을 매니저가 합침 |
| fan-out | 한 출발지가 여러 목적지로 퍼지는 형태(확산 탐지의 기본 모양) |

## 2. 시스템 구성

Zeek가 미러 트래픽을 프로토콜 이벤트로 바꾸면, nsm_rules 패키지의 탐지 룰이 설정값을 기준으로 판정하고 로그 3종을 남깁니다.

```mermaid
flowchart LR
    T["미러 트래픽"] --> Z["Zeek 9.x<br/>프로토콜 분석기"]
    Z -->|"이벤트"| R["탐지 룰 01~24"]
    CFG["설정<br/>nsm_config_fixed / custom"] --> R
    R --> N["notice.log<br/>탐지 원문"]
    R --> EV["evidence.log<br/>근거 행"]
    R --> K["킬체인 상관<br/>중복 묶기"]
    K --> N
    N --> D["nsm_detection.log<br/>관제용 요약"]
    D -.-> O["OCSF 변환기<br/>(5단계)"]
    A["자산 식별<br/>(5단계)"] -.-> CFG
    style R stroke:#2563eb,stroke-width:3px
    classDef todo stroke-dasharray: 5 5
    class O,A todo
```

파란 테두리가 판정의 중심인 탐지 룰이고, 점선 상자는 아직 연결되지 않은 다음 단계입니다.

| 구성 요소 | 파일 | 역할 |
| --- | --- | --- |
| 로더 | `nsm_rules/__load__.zeek` | 모든 구성 요소를 정해진 순서로 로드(7.1절) |
| 공통 정의 | `detections/main.zeek` | 탐지 유형(notice) 목록, 공통 파라미터·함수, 킬체인 단계명 |
| 탐지 룰 | `detections/01~24_*.zeek`, `web_common.zeek` | 위협별 탐지(4장) |
| 근거·요약 | `evidence_log.zeek`, `detection_log.zeek`, `attack_mapping.zeek` | 근거 기록, 탐지 요약, ATT&CK 매핑 |
| 상관·묶기 | `correlation_killchain.zeek`, `notice_aggregation.zeek` | 킬체인 상관, 중복 묶기 |
| 설정 | `nsm_config_fixed.zeek`, `nsm_config_custom.zeek`, `intel_ja3.zeek` | 운영 기본값, 고객별 값, JA3 목록(7장) |
| 로그 필터 | `rules/filter_log.zeek` | 남길 로그·경로·회전 |
| 외부 패키지 | `rules/ja3/` | Salesforce JA3 지문 계산(BSD) |
| 테스트 | `tests/` | btest·합성 pcap·생성기(9장) |

## 3. 운영 환경과 제약

Zeek 9.0.1을 기준으로 하고 8.0.9에서도 같은 결과를 내야 하며, 내부망(`Site::local_nets`)이 정확히 설정돼 있어야 대부분의 룰이 동작합니다.

| 항목 | 요구사항 | 비고 |
| --- | --- | --- |
| Zeek 버전 | 9.0.1(기준), 8.0.9(호환) | CI가 두 버전 모두 검사. 자산 식별 PoC와 같은 9.x 기준 |
| 설치 | `@load /경로/nsm_rules` 한 줄(`local.zeek`) | 패키지가 룰·상관·설정·로그 필터를 정해진 순서로 로드 |
| 배포 형태 | 단일 프로세스 또는 클러스터(manager + proxy + worker) | 클러스터 백엔드: Zeek 9 ZeroMQ, Zeek 8 Broker 모두 동작 |
| 내부망 정의 | `Site::local_nets`에 고객 내부 대역을 등록(**필수**) | 비어 있으면 내부·외부 판정이 모두 틀어짐. `172.0.0.0/8`이 아니라 `172.16.0.0/12` |
| 센서 위치 | 룰마다 필요한 구간이 다름(아래 표) | 보이지 않는 구간의 룰은 조용히 동작하지 않음 |
| 로그 형식 | 운영: JSON(`policy/tuning/json-logs`), 테스트: TSV | 로그 경로는 `filter_log.zeek`에서 지정 |
| 암호화 트래픽 | 내용 복호화 없음 | TLS·SMB3 암호화·Kerberos 티켓 내용은 보지 않고 메타데이터만 사용 |

### 3.1 룰별로 센서가 봐야 하는 구간

| 구간 | 필요한 룰 |
| --- | --- |
| 인터넷 경계(내부 ↔ 외부) | 07 비커닝, 09 암호화 C2, 10·12·14 유출, 19 외부향 SMB, 24 비표준 포트·장기 연결 |
| 클라이언트 ↔ DNS 서버 | 08 DNS 터널링·유출, 13 DGA |
| 클라이언트 ↔ 도메인 컨트롤러(88, 135, 동적 RPC) | 17 Kerberos 스프레이, 18 Kerberoasting, 23 DCSync |
| 클라이언트 ↔ 파일 서버(445) | 05 NTLM 스프레이, 06 관리 공유, 21 랜섬웨어 |
| 내부 호스트 간(동서 구간) | 01·02 스캔, 15 RDP, 16 SSH, 20 WinRM·DCOM 확산 |
| 내부 웹서버 인입 | 03 SQLi, 04 웹쉘 |
| 같은 L2 세그먼트(브로드캐스트·멀티캐스트) | 22 LLMNR/NBT-NS/mDNS 포이즈닝 |

## 4. 탐지 기능 요구사항

탐지 룰 23개가 탐지 유형 29종을 내며, 모두 `__load__.zeek`에서 활성화돼 있습니다(비활성 룰 0개). 아래 ‘판정 조건’의 숫자는 `nsm_config_fixed.zeek`까지 적용된 현재 운영 기본값입니다.

### 4.1 룰 목록 (킬체인 순서)

| 단계 | 룰 파일 | 탐지 유형(notice) | ATT&CK | 판정 조건 (기본값) | 주요 오탐 통제 |
| --- | --- | --- | --- | --- | --- |
| 정찰 | 01_port_scan | Port_Scan | T1046 | 내부 출발지가 한 목적지에 5분 안 고유 포트 25개 이상(응답 없거나 거부된 시도만) | 예외 출발지, 제외 포트 |
| 정찰 | 02_host_scan | Host_Scan | T1018 | 내부 출발지가 같은 포트로 5분 안 고유 호스트 25개 이상 | 80·443·53 포트 기본 제외 |
| 초기 침투 | 03_sqli | SQL_Injection | T1190 | 내부 웹서버로 들어오는 URI·POST/PUT 본문에 SQL 구문 구조(UNION SELECT, ' or 1=1, sleep( 등) | URL 2회 디코딩 후 검사, 검색어에 흔한 `#`·`select..from` 단독은 무시 |
| 초기 침투 | 04_webshell | Webshell_Access | T1505.003 | 웹쉘 파일명+스크립트 확장자, 명령 파라미터 값이 실제 명령(`cmd=whoami`), China Chopper류 본문 | 파라미터 이름만으로는 탐지하지 않음 |
| 자격증명 접근 | 05_ntlm_spray | NTLM_Spray | T1110.003 | 한 출발지에서 10분 안 **인증 실패** 고유 계정 10개 이상(SMB 상태코드·SPNEGO reject) | 성공은 세지 않음, 대소문자 정규화 |
| 자격증명 접근 | 17_kerberos_spray | Kerberos_Spray | T1110.003 | 10분 안 AS 사전인증 실패(코드 24·6·18·23) 고유 계정 10개 이상 | 정상 로그온 첫 단계(코드 25) 제외 |
| 자격증명 접근 | 17_kerberos_spray | Kerberos_Bruteforce | T1110.001 | 한 출발지가 같은 계정으로 10분 안 비밀번호 실패(코드 24·18) 20회 이상 | 예외 출발지 |
| 자격증명 접근 | 18_kerberoasting | Kerberoasting | T1558.003 | 10분 안 RC4·DES 서비스 티켓을 받은 고유 SPN 5개 이상 | krbtgt·kadmin 제외 |
| 자격증명 접근 | 18_kerberoasting | ASREP_Roasting | T1558.004 | 사전인증 없는 AS 요청에 RC4·DES로 암호화된 AS-REP(계정마다 1건) | AES 응답은 제외(스마트카드 오탐 방지) |
| 자격증명 접근 | 19_outbound_smb | NTLM_Credential_Leak | T1187 | 내부 호스트가 외부 서버에 NTLM 인증을 보냄(1건) | 익명 인증 제외, 허용 목적지 |
| 자격증명 접근 | 22_name_poisoning | Name_Poisoning | T1557.001 | 한 응답자가 10분 안 LLMNR·NBT-NS·mDNS로 고유 이름 5개 이상에 긍정 응답 | mDNS 서비스 광고(PTR 등) 제외, WINS 예외 |
| 자격증명 접근 | 23_dcsync | DCSync | T1003.006 | DC가 아닌 호스트의 DRSUAPI DRSGetNCChanges 요청(1건) | DC 목록+자동 학습, Azure AD Connect 예외 |
| 확산 | 06_smb_admin_share | SMB_Admin_Share | T1021.002 | 1분 안 관리 공유(`ADMIN$`·`C$` 등)에 접근한 고유 피해 호스트 2대 이상 | `IPC$`·`PRINT$` 제외, 관리 서버 예외 |
| 확산 | 15_rdp_lateral | RDP_Lateral | T1021.001 | 1분 안 내부 RDP 고유 목적지 3대 이상 | 점프 서버 예외 |
| 확산 | 16_ssh_lateral | SSH_Lateral | T1021.004 | 1분 안 SSH 인증 성공 고유 목적지 3대 이상 | 즉시 끊긴 연결 제외 |
| 확산 | 20_winrm_dcom_lateral | WinRM_Lateral | T1021.006 | 5분 안 WinRM(5985·5986) 연결 고유 내부 목적지 3대 이상 | 관리 서버 예외(필수 등록) |
| 확산 | 20_winrm_dcom_lateral | DCOM_Lateral | T1021.003 | 5분 안 원격 COM 객체 생성(RemoteCreateInstance) 고유 목적지 3대 이상 | 같은 인터페이스의 다른 호출 제외 |
| C2 | 07_http_beaconing | HTTP_Beaconing | T1071.001 | 같은 목적지로 3초\~1시간 주기의 HTTP 콜백 12회(오차 25%, 누락 2회 허용) | 도메인·출발지 예외 |
| C2 | 08_dns_tunneling | DNS_Tunneling | T1071.004 | (출발지, 등록 도메인)별 5분 안 고유 서브도메인 50개 이상 + 수상한 질의 비율 0.5 이상 | 내부 리졸버 제외, AV·DNSBL 도메인 기본 예외 |
| C2 | 09_encrypted_c2 | Encrypted_C2 | T1573.002 | TLS 점수 3 이상(자체서명 2, SNI 없음 1, SNI 불일치 1, JA3·JA4 차단목록 3, JA4-a 1) | SNI·출발지 예외 |
| C2 | 13_dga | DGA_Domain | T1568.002 | 10분 안 NXDOMAIN 50개 이상 + NXDOMAIN 비율 0.8 이상 + 무작위형 라벨 비율 0.5 이상 | 역방향 조회 제외 |
| C2 | 24_nonstd_port | Nonstandard_Port | T1571 | 외부향 연결의 프로토콜(HTTP·TLS·SSH)이 표준 포트가 아님(1건) | 표준 포트 표, 허용 포트·목적지 |
| C2 | 24_nonstd_port | Long_Connection | T1572 | 외부향 TCP 연결이 6시간 이상 지속(연결 중 실시간) | VPN·메신저 목적지 예외 |
| 유출 | 08_dns_tunneling | Exfil_DNS | T1048.003 | (출발지, 등록 도메인)별 5분 안 서브도메인 누적 256KB 이상 + 수상한 질의 비율 0.5 이상 | DNS_Tunneling과 같음 |
| 유출 | 10_large_transfer_exfil | Exfil_Large_Transfer | T1041 | 외부향 단일 연결 업로드 50MB 이상 | 1시간 억제 |
| 유출 | 12_web_upload_exfil | Exfil_Web_Upload | T1567.002 | 클라우드 저장소(지정 호스트 패턴)로 50MB 이상 업로드 | 출발지 예외 |
| 유출 | 14_large_transfer_exfil | Exfil_Volume_Aggregate | T1041 | 한 호스트의 외부향 업로드 합계가 1분 안 50MB 이상(1MB 단위 실시간 집계) | 5분 억제 |
| 유출 | 19_outbound_smb | Outbound_SMB | T1048 | 내부 → 외부 445·139 TCP 연결 성립(1건) | 경계에서 막힌 시도는 제외 |
| 영향 | 21_smb_ransomware | SMB_Ransomware | T1486 | 1분 안 확장자가 바뀐 이름 변경 30개 이상, 또는 랜섬 노트 생성 폴더 5개 이상 | Office 임시 파일 제외, 백업 서버 예외 |

킬체인 상관 탐지 `Correlated_KillChain`은 위 탐지들을 이어 붙여 만드는 별도 유형입니다(5장).

### 4.2 탐지 방식

| 방식 | 룰 | 동작 |
| --- | --- | --- |
| 단건 | 03, 04, 10, 12, 19, 23, 24 | 조건에 맞는 연결 하나가 보이면 바로 탐지. 같은 대상은 일정 시간 억제 |
| 임계 집계 | 05, 08, 09, 13, 14, 17, 18, 21, 22 | 창 안에서 개수·바이트를 세다가 임계를 넘는 순간 탐지(창당 1건) |
| 창 종료 판정 | 01, 02, 06, 15, 16, 20 | 창이 끝날 때 한 번 판정. 최대 창 길이만큼 늦게 나오지만 창당 1건으로 깔끔 |
| 상태 추적 | 07 | 목적지별 주기를 추적(클러스터에서는 한 노드에 모음) |

## 5. 공통 기능 요구사항

모든 룰은 탐지 1건마다 “근거 → notice → 탐지 요약” 순서로 기록하고, 공통 모듈이 ATT&CK 매핑·억제·상관·로그 필터를 맡습니다.

| ID | 요구사항 | 담당 파일 |
| --- | --- | --- |
| FR-C1 | 탐지마다 근거(누가·어디서·무엇을·어떻게)를 `evidence.log`에 1행 이상 남긴다. 집계형은 판정 시점의 표본(최대 20개)을 남긴다 | `evidence_log.zeek` |
| FR-C2 | notice와 근거는 같은 `evidence_id`로 연결되고, notice보다 근거를 먼저 기록해 근거 건수가 정확해야 한다 | 각 룰 |
| FR-C3 | notice 1건당 탐지 요약 1행을 `nsm_detection.log`에 남긴다(진단명, 기법, 킬체인 단계, 공격자, 피해 호스트, 근거 건수) | `detection_log.zeek` |
| FR-C4 | 모든 notice에 ATT&CK 기법 ID를 붙인다(`attack` 필드) | `attack_mapping.zeek` |
| FR-C5 | 같은 대상에 대한 반복 탐지는 룰별 억제 시간 동안 1건만 낸다(`identifier` + `suppress_for`) | 각 룰, `main.zeek` |
| FR-C6 | 같은 공격자의 탐지가 정해진 순서·시간 안에 이어지면 `Correlated_KillChain`을 낸다(클러스터에서는 매니저가 판정) | `correlation_killchain.zeek` |
| FR-C7 | 운영에 필요한 로그만 남기고 나머지 Zeek 기본 로그는 끈다. 로그별 출력 경로를 지정하고 디렉터리를 만든다 | `rules/filter_log.zeek` |
| FR-C8 | (선택) 짧은 시간 안 같은 notice를 하나로 묶어 중복 건수를 표시한다. 기본은 꺼짐 | `notice_aggregation.zeek` |
| FR-C9 | 내부·외부 판정, 등록 도메인 추출(`co.kr` 등 2단계 접미사 포함), 시간 버킷 같은 공용 함수를 한 곳에서 제공한다 | `main.zeek` |

### 5.1 킬체인 상관 규칙

상관은 “앞 단계 탐지 → 다음 단계 탐지” 전이 규칙으로 동작합니다. 규칙은 탐지와 탐지를 하나씩 잇는 개별 전이 23개(chain_rules, 아래 표)와 단계 묶음 전이 15개(chain_group_rules, 5.1.1)로 나뉩니다. 판정 결과는 `nsm_detection.log`에 `category=Correlated`, `severity=Suspicious`로 남고, 단일 탐지는 `Single` / `Information`입니다.

| 전이 | 연결 방식 | 시간 창 |
| --- | --- | --- |
| 정찰(01·02) → C2(07·09·13) | 같은 출발지 | 1시간 |
| DGA(13) → C2(07·09) | 같은 출발지 | 1시간 |
| C2(07·09·13) → 확산(06·15·16) | 같은 출발지 | 30분 |
| 확산(06·15·16) → 유출(10·14) | 확산의 피해 호스트가 유출의 출발지 | 10분 |

#### 5.1.1 단계 묶음 전이 (4단계 탐지 연결)

4단계에서 추가한 탐지(17\~24번)와 05번의 NTLM 인증 유출은 **단계 묶음 전이**로 킬체인에 이어집니다. 탐지를 공격 단계별 묶음으로 나누고, "이 묶음의 어느 탐지 다음에 저 묶음의 어느 탐지가 나오면" 전이로 봅니다. Zeek가 시작할 때 묶음 전이를 개별 전이로 펼쳐 위의 23개와 합치며, 같은 전이가 양쪽에 있으면 더 긴 시간 창을 씁니다.

| 묶음 | 설정 이름 | 포함 탐지 |
| --- | --- | --- |
| 정찰 | `corr_recon_notes` | Port_Scan, Host_Scan |
| C2 | `corr_c2_notes` | HTTP_Beaconing, Encrypted_C2, DGA_Domain, DNS_Tunneling, Nonstandard_Port, Long_Connection |
| 자격증명 | `corr_cred_notes` | NTLM_Spray, Kerberos_Spray, Kerberos_Bruteforce, Kerberoasting, ASREP_Roasting, Name_Poisoning |
| 도메인 장악 | `corr_domain_notes` | DCSync |
| 확산 | `corr_lateral_notes` | SMB_Admin_Share, RDP_Lateral, SSH_Lateral, WinRM_Lateral, DCOM_Lateral |
| 유출 | `corr_exfil_notes` | Exfil_Large_Transfer, Exfil_Volume_Aggregate, Exfil_DNS, Exfil_Web_Upload, Outbound_SMB |
| 영향 | `corr_impact_notes` | SMB_Ransomware |

| 앞 단계 | 다음 단계 | 연결 방식 | 시간 창 |
| --- | --- | --- | --- |
| 정찰 | C2, 자격증명 | 같은 출발지 | 1시간 |
| C2 | 자격증명, 도메인 장악 | 같은 출발지 | 1시간 |
| C2 | 확산 | 같은 출발지 | 30분 |
| 자격증명 | 도메인 장악, 확산 | 같은 출발지 | 1시간 |
| 도메인 장악 | 확산 | 같은 출발지 | 1시간 |
| 확산 | 유출 | 확산 대상 host가 다음 탐지의 출발지 | 10분 |
| 확산 | 영향 | 확산 대상 host가 출발지, 또는 같은 출발지 | 30분 |
| 확산 | 자격증명, 도메인 장악 | 확산 대상 host가 출발지 | 1시간 |
| 유출 | 영향 | 같은 출발지 | 1시간 |
| NTLM 인증 유출 | C2 | 같은 출발지 | 1시간 |

- 체인의 기법 ID 표시는 상관 전용 표(`stage_attack`)에 없으면 탐지 공통 표(`attack_map`)를 씁니다. 그래서 8단계 체인도 `T1046->T1568.002->T1071.001->T1558.003->T1003.006->T1021.006->T1041->T1486`처럼 끝까지 기법 ID로 나옵니다.
- 묶음에 탐지를 넣거나 빼려면 해당 `corr_*_notes`를 redef 하고 `chain_group_rules`도 함께 다시 정의해야 합니다(묶음 내용은 규칙을 정의할 때 복사되기 때문).
- 회귀 테스트 `tests/btest/rules/correlation-ext-chain.zeek`가 정찰 → C2(DGA·비커닝) → Kerberoasting → DCSync → WinRM 확산 → 유출 → 랜섬웨어의 8단계 체인과, 단독 Kerberoasting·단독 랜섬웨어가 상관으로 이어지지 않는 경우를 검증합니다.

### 5.2 로그 필터 기본값

| 남기는 로그 | 기본 경로(확장자 제외) |
| --- | --- |
| nsm_detection | `/log/zeek/nsm_detection` |
| evidence | `/log/zeek/evidence` |
| notice | `/hdd_tmp/log/zeek/notice` |
| capture_loss | `/hdd_tmp/log/zeek/capture_loss` |
| loadedscripts | `/hdd_tmp/log/zeek/loadedscripts` |
| stats | `/hdd_tmp/log/zeek/stats` |
| reporter | `/hdd_tmp/log/zeek/reporter` |

conn·dns·http 등 이 목록에 없는 로그는 기본으로 꺼집니다. 켜는 방법은 7.5절에 있습니다.

## 6. 출력(로그) 요구사항

탐지 결과는 로그 세 개로 나가며, `evidence_id`로 서로 조인합니다: `notice.log`(탐지 원문) → `nsm_detection.log`(관제용 요약) → `evidence.log`(근거 행들).

### 6.1 notice.log — Zeek 기본 필드에 추가하는 필드

| 필드 | 뜻 | 예 |
| --- | --- | --- |
| `note` | 탐지 유형 | `NSM::Kerberoasting` |
| `src` / `dst` | 공격 출발지 / 대상(룰마다 ‘상관 계약’으로 의미 고정) | `10.0.0.156` / `10.0.0.10` |
| `msg` / `sub` | 사람이 읽는 설명 / 핵심 수치 | `unique_services=5` |
| `evidence_id` | evidence.log와 조인하는 키 | `10.0.0.156\|kerberoast\|...` |
| `attack` | ATT&CK 기법 ID | `T1558.003` |
| `lm_targets` | 확산·포이즈닝·랜섬웨어의 피해 호스트 집합 | `10.0.20.11,10.0.20.12` |
| `dup_count` | (중복 묶기 사용 시) 묶인 건수 | `3` |

### 6.2 nsm_detection.log — 탐지 요약

| 필드 | 뜻 |
| --- | --- |
| `ts` | 탐지 시각 |
| `detection_id` | 탐지 고유 ID |
| `diagnosis` | 진단명(예: `NSM.CredentialAccess.DcSync`, `NSM.Impact.SmbRansomware`) |
| `techniques` | ATT&CK 기법 ID |
| `category` | `Single`(단일) 또는 `Correlated`(킬체인 상관) |
| `killchain_stages` | 킬체인 단계명(상관은 `정찰->C2->확산`처럼 이어 붙임) |
| `severity` | 단일 `Information`, 상관 `Suspicious` |
| `first_seen` / `last_seen` | 관측 시작·끝 |
| `attacker` / `attacker_subnet` | 공격 호스트와 그 대역 |
| `victims` | 피해 호스트(최대 8개, 쉼표 구분) |
| `evidence_count` / `evidence_ids` | 근거 행 수와 근거 키 |

### 6.3 evidence.log — 근거

| 필드 | 뜻(5W1H) |
| --- | --- |
| `ts` | 언제 |
| `evidence_id` | 어느 탐지의 근거인지(notice와 공유) |
| `note` / `killchain_stage` / `technique` | 무엇을(탐지 유형·단계·기법) |
| `account` | 누가(계정, 알 때만. 예: `user01@corp.example`) |
| `src` / `dst` | 어디서 → 어디로 |
| `operation` | 어떻게(예: `kerberos_as_failure`, `drsuapi_DRSGetNCChanges`) |
| `uid` / `fuid` | conn.log·files.log 조인 키 |
| `parent_id` | 상관 탐지가 묶는 하위 근거 |
| `detail` | 부가 정보(실패 코드, 파일명, 바이트 등) |

근거 건수 카운터는 2시간(`evidence_count_expire`) 뒤 만료됩니다. 운영에서는 세 로그 모두 JSON으로 나갑니다.

## 7. 설정 요구사항

룰 코드는 고치지 않고, 모든 임계값·토글·예외 목록을 설정 파일의 `redef` 한 줄로 바꿉니다. 배포 전에 **내부망(`Site::local_nets`)과 DC 목록은 반드시** 적어야 합니다.

### 7.1 설정 파일과 로드 순서

| 파일 | 용도 | 저장소에서의 상태 |
| --- | --- | --- |
| `nsm_config_fixed.zeek` | 제품 공통 운영 기본값(모든 고객 동일) | 관리됨. 룰 기본값을 덮어쓰는 값 + 주석 처리된 예시 |
| `nsm_config_custom.zeek` | **고객 환경별 값**(내부망, DC, 예외 목록, 로그 경로) | **빈 파일로 유지**. 배포 시 고객별로 별도 작성(부록 A) |
| `intel_ja3.zeek` | JA3 차단 목록 데이터 | 관리됨 |

`__load__.zeek`가 아래 순서로 로드하므로, 나중에 로드되는 파일의 값이 이깁니다.

1. `rules/ja3`(JA3 패키지) → `main` → `evidence_log`
2. 탐지 룰 23개(킬체인 순서)
3. `detection_log` → `attack_mapping` → `notice_aggregation` → `correlation_killchain`
4. `nsm_config_fixed` → **`nsm_config_custom`** → `intel_ja3`
5. `policy/protocols/conn/mac-logging`, `policy/tuning/json-logs`
6. `rules/filter_log`(로그 필터·경로)

따라서 **값의 우선순위는 custom > fixed > 룰 파일 기본값**입니다. 설정 파일은 `redef`만 담고 `@load`는 두지 않으며, 단독으로 실행하면 선언이 없어 오류가 납니다.

### 7.2 설정 문법 빠른 안내

| 하고 싶은 일 | 형식 | 예 |
| --- | --- | --- |
| 값 바꾸기 | `redef 이름 = 값;` | `redef NSM::krb_spray_user_threshold = 15;` |
| 목록에 추가 | `redef 이름 += { ... };` | `redef NSM::lm_mgmt_allowlist += { 10.20.30.0/24 };` |
| 대역(subnet) | `a.b.c.d/n` | `10.20.40.0/28` (한 대는 `/32`) |
| 주소(addr) | `a.b.c.d` | `{ 10.0.0.10, 10.0.0.11 }` |
| 포트 | `번호/프로토콜` | `8081/tcp` |
| 도메인 목록 | 큰따옴표 문자열 | `{ "update.example.com" }` (하위 도메인 포함) |
| 시간 | 숫자+단위 | `30sec`, `5min`, `6hr` |
| 바이트 | 곱셈식 | `50*1024*1024` (= 50MB) |
| 단계 임계(vector) | `vector(...)` | `vector(3.0, 5.0)` — **첫 값만 판정에 쓰임** |
| 켜기·끄기 | `T` / `F` | `redef NSM::detect_dga = F;` |

주의: 문법이 하나라도 틀리면 Zeek가 기동하지 않습니다. 배포 전 `zeek -a /경로/nsm_rules`로 문법을 검사하세요(7.7절).

### 7.3 배포 전 필수·권장 설정

| 중요도 | 설정 | 안 하면 생기는 일 |
| --- | --- | --- |
| 필수 | `Site::local_nets` — 고객 내부 대역 전체 | 내부·외부 판정이 틀려 대부분의 룰이 미탐 또는 오탐 |
| 필수 | `NSM::dcsync_domain_controllers` — DC 주소 | 클러스터에서 DC 간 복제가 DCSync로 오탐될 수 있음 |
| 필수 | `NSM::lm_mgmt_allowlist` — SCCM·모니터링·Ansible·점프 서버 | 원격 WMI·WinRM 관리가 전부 확산으로 탐지 |
| 권장 | `NSM::dns_tunnel_resolvers` — 내부 DNS 서버 | 리졸버가 DNS 터널링 출발지로 잡힘 |
| 권장 | `NSM::web_attack_allowlist` — 취약점 스캐너·모의해킹 장비 | 정기 점검이 SQLi·웹쉘로 탐지 |
| 권장 | `NSM::ntlm_spray_allowlist`, `NSM::krb_spray_allowlist` — 인증 프록시·VDI·계정 점검 도구 | 여러 사용자의 실패가 한 IP로 모여 스프레이로 탐지 |
| 권장 | `NSM::ransomware_allowlist` — 백업·동기화·DLP 서버 | 대량 이름 변경이 랜섬웨어로 탐지 |
| 권장 | `NSM::dcsync_allowlist` — Azure AD Connect | 디렉터리 동기화가 DCSync로 탐지 |
| 권장 | `NSM::poisoning_allowlist` — WINS 서버 | NBNS 응답이 포이즈닝으로 탐지 |
| 권장 | `NSM::smb_lm_allowlist`, `rdp_lm_allowlist`, `ssh_lm_allowlist` — 관리 서버·점프 서버 | 정상 관리 접속이 확산으로 탐지 |
| 환경에 따라 | 허용 외부 서비스: `outbound_smb_allowed_dsts`, `nonstd_port_allowed_*`, `long_conn_allowed_*`, `beacon_allowlist_domains` | 업무상 허용한 통신이 정책 위반·C2로 탐지 |
| 환경에 따라 | 로그 경로 `NSM::log_paths`, 디렉터리 생성 `NSM::create_log_dirs` | 기본 경로(`/log/zeek`, `/hdd_tmp/log/zeek`)가 없는 서버에서 로그 실패 |

### 7.4 기존 룰(01\~16) 파라미터

모든 이름 앞에는 `NSM::`을 붙입니다. ‘기본값’은 `nsm_config_fixed.zeek`까지 적용된 현재 값이고, 룰 파일 기본값과 다르면 괄호에 룰 기본값을 적었습니다. `detect_*` 토글은 모두 기본 `T`(켜짐)입니다.

#### 공통 (main.zeek)

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `lm_num_samples` | 20 | 집계형 탐지가 근거로 남기는 최대 표본 수 | 근거를 더 남기려면 올리되 메모리 증가 |
| `chain_max_victims` | 8 | 탐지 요약의 피해 호스트 표시 개수 | 표시용 |
| `multi_label_suffixes` | `co.kr`, `or.kr`, `go.kr` 등 | 등록 도메인을 구할 때 2단계로 보는 접미사 | 국가 도메인 추가 시 `+=` |

#### 01 포트 스캔 · 02 호스트 스캔

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `scan_interval` | 5min | 01·02 공용 집계 창 | 느린 스캔까지 잡으려면 늘림 |
| `port_scan_threshold` | 25 | (출발지, 목적지)별 고유 포트 수 | 오탐이 많으면 올림 |
| `port_scan_local_only` | T | 내부 출발지만 봄 | 외부 스캔도 보려면 F |
| `port_scan_count_established` | F | F면 미응답·거부된 시도만 셈 | T면 민감해지지만 오탐 증가 |
| `port_scan_allowlist` | 비어 있음 | 예외 출발지(취약점 스캐너) | custom에 기록 |
| `port_scan_exclude_ports` | 비어 있음 | 세지 않을 포트 |  |
| `host_scan_threshold` | 25 | (출발지, 포트)별 고유 호스트 수 |  |
| `host_scan_local_only` | T | 내부 출발지만 |  |
| `host_scan_count_established` | F | 01과 같음 |  |
| `host_scan_allowlist` | 비어 있음 | 예외 출발지(자산 관리·모니터링 서버) | custom에 기록 |
| `host_scan_exclude_ports` | 80/tcp, 443/tcp, 53/tcp, 53/udp | 웹·DNS처럼 자연스럽게 여러 호스트로 가는 포트 제외 |  |

#### 03 SQL Injection · 04 웹쉘 (web_common.zeek)

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `web_attack_local_servers_only` | T | 내부 웹서버로 들어오는 요청만 검사 | 외부 사이트 요청까지 보면 오탐 급증 |
| `web_attack_allowlist` | 비어 있음 | 예외 출발지(취약점 스캐너·모의해킹) | custom에 기록 |
| `web_attack_body_max` | 4096 | 연결당 본문 검사 바이트 | 업로드가 많은 환경에서는 줄여 부하 감소 |
| `sqli_patterns` | SQL 구문 시그니처 12종 | 정규화(URL 2회 디코딩·소문자) 된 입력에 적용 | 추가 시 `= ... \| /새패턴/`으로 전체 재정의 |
| `webshell_uri_patterns` / `webshell_body_patterns` | 웹쉘 파일명·명령·China Chopper 서명 | 위와 같음 | 위와 같음 |

#### 05 NTLM 스프레이

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `ntlm_interval` | 10min | 집계 창 |  |
| `ntlm_user_threshold` | 10 | 출발지별 인증 실패 고유 계정 수 | 계정 잠금 정책보다 낮게 |
| `ntlm_spray_local_servers_only` | T | 내부 서버 대상 인증만 |  |
| `ntlm_spray_allowlist` | 비어 있음 | 예외 출발지(인증 프록시·VDI) | custom에 기록 |
| `ntlm_failure_statuses` | NTSTATUS 12종(LOGON_FAILURE, WRONG_PASSWORD, ACCOUNT_LOCKED_OUT 등) | 실패로 보는 SMB 상태 코드 |  |

#### 06 SMB 관리 공유 · 15 RDP · 16 SSH 확산

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `smb_lm_epoch` / `rdp_lm_epoch` / `ssh_lm_epoch` | 1min | 집계 창 |  |
| `smb_lm_thresholds` | vector(2.0, 3.0) (룰 3.0) | 첫 값 = 고유 피해 호스트 임계 | psexec 1대도 잡으려면 1.0 |
| `rdp_lm_thresholds` / `ssh_lm_thresholds` | vector(3.0, 5.0, 10.0) | 첫 값 = 고유 목적지 임계 |  |
| `smb_lm_allowlist` / `rdp_lm_allowlist` / `ssh_lm_allowlist` | 비어 있음 | 예외 출발지(SCCM·백업·점프 서버) | custom에 기록 |
| `exclude_ipc_share` | T | `IPC$` 는 세지 않음 |  |
| `smb_lm_exclude_shares` | `PRINT$` | 세지 않을 숨김 공유 |  |
| `ssh_lm_min_orig_bytes` / `ssh_lm_min_duration` | 1000 / 0.05sec | SSH 판정 최소 바이트·지속 시간(즉시 끊긴 연결 제외) |  |
| `ssh_lm_use_auth_event` / `ssh_lm_conn_fallback` | T / T | 인증 성공 이벤트 사용 / 없을 때 연결 기반 판정 |  |

#### 07 HTTP 비커닝

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `beacon_min_interval` / `beacon_max_interval` | 3sec / 3600sec | 비커닝으로 보는 주기 범위 |  |
| `beacon_jitter` | 0.25 | 주기 허용 오차(25%) |  |
| `beacon_min_hits` | 12 | 같은 주기 연속 콜백 횟수 | 패킷 손실 환경에서는 낮춤 검토 |
| `beacon_max_missed` | 2 | 허용하는 누락 콜백 수 |  |
| `beacon_expire` | 30min | 상태 만료 |  |
| `beacon_allowlist` / `beacon_allowlist_domains` | 비어 있음 | 예외 출발지 / 도메인(업데이트·텔레메트리) | custom에 기록 |

#### 08 DNS 터널링·유출

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `dnstun_interval` | 5min | 집계 창(터널링·유출 공용) |  |
| `dnstun_unique_sub` | 50 | \[터널링\] 고유 서브도메인 수 |  |
| `dnsexfil_bytes` | 256\*1024 | \[유출\] 서브도메인 누적 바이트 |  |
| `dnstun_suspicious_ratio` | 0.5 | 수상한 질의 비율(이상일 때만 판정) |  |
| `dnstun_label_len` / `dnstun_min_label_len` | 40 / 20 | 이 길이 이상 라벨 = 수상 / 무작위성 점수로 판정하는 최소 길이 |  |
| `dnstun_local_only` | T | 내부 출발지만 |  |
| `dns_tunnel_resolvers` | 비어 있음 | 내부 재귀 리졸버(출발지에서 제외) | **custom에 기록 권장** |
| `dns_tunnel_allowlist_domains` | sophosxl.net, e5.sk, spamhaus.org 등 8개 | AV 평판·DNSBL 조회 도메인 | `+=`로 추가 |

#### 09 암호화 C2

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `enc_c2_score_threshold` | 3 | 탐지 점수 |  |
| `enc_c2_w_selfsigned` / `_nosni` / `_mismatch` | 2 / 1 / 1 | 자체서명 / SNI 없음 / SNI·인증서 불일치 가중치 | TLS 1.3은 인증서가 암호화돼 자체서명 신호가 없음 |
| `enc_c2_w_ja3` / `_ja4` / `_ja4_a` | 3 / 3 / 1 | JA3·JA4 차단목록 일치 / JA4 a부분 워치리스트 |  |
| `ja3_blocklist` / `ja4_blocklist` / `ja4_a_watchlist` | intel_ja3 데이터 / 비어 있음 | 지문 목록 | 위협 인텔로 갱신 |
| `enc_c2_allowlist` / `enc_c2_allowlist_sni` | 비어 있음 | 예외 출발지 / SNI |  |
| `suppress_enc_c2` | 1hr | 억제 시간 |  |

#### 10 단일 연결 유출 · 12 클라우드 업로드 · 14 볼륨 집계

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `exfil_bytes_threshold` | 50*1024*1024 (룰 100MB) | \[10\] 단일 연결 업로드 바이트 | 백업 환경에서는 올림 |
| `webupload_bytes` | 50*1024*1024 | \[12\] 클라우드 업로드 바이트 |  |
| `cloud_hosts` | Google Drive·Dropbox·S3 등 패턴 | \[12\] 클라우드 저장소 호스트 |  |
| `web_upload_allowlist` | 비어 있음 | \[12\] 예외 출발지 |  |
| `exfil_epoch` | 1min | \[14\] 집계 창 |  |
| `exfil_thresholds` | vector(50.0*1024*1024) (룰 5MB) | \[14\] 호스트당 합계 임계 |  |
| `exfil_volume_step` | 1024\*1024 | \[14\] 실시간 집계 단위(1MB) |  |
| `suppress_large_exfil` / `suppress_web_upload` / `suppress_vol_agg` | 1hr / 1hr / 5min | 억제 시간 |  |

#### 13 DGA

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `dga_interval` | 10min | 집계 창 |  |
| `dga_nxdomain_threshold` | 50 | 창 안 NXDOMAIN 수 |  |
| `dga_ratio_threshold` | 0.8 | NXDOMAIN / 전체 응답 비율 |  |
| `dga_like_ratio` | 0.5 | NXDOMAIN 중 무작위형 라벨 비율 |  |
| `dga_min_label_len` / `dga_label_min_score` | 6 / 2 | 무작위형 판정 최소 길이 / 최소 점수 |  |
| `dga_vowel_ratio_max` / `dga_consonant_run_min` / `dga_entropy_norm_min` | 0.25 / 4 / 0.90 | 무작위형 점수 기준(모음 비율·연속 자음·엔트로피) |  |
| `dga_exclude_reverse_dns` | T | 역방향 조회 제외 |  |
| `dga_allowlist_domains` | 비어 있음 | 예외 도메인 |  |

더 이상 쓰이지 않는 파라미터(`dnstun_entropy`, `dnsexfil_interval`, `dga_entropy`, `dga_evidence_min_entropy`)는 기존 배포 설정과의 호환을 위해 남겨 두었고, 쓰면 경고만 나옵니다.

### 7.5 신규 룰(17\~24)과 공통 모듈 파라미터

신규 룰은 `nsm_config_fixed.zeek`에서 덮어쓴 값이 없으므로 룰 파일 기본값이 그대로 운영 값입니다. fixed 파일의 \[17\]\~\[24\] 섹션에 주석 처리된 예시가 있습니다.

#### 17 Kerberos 스프레이·무차별 대입

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `krb_spray_interval` | 10min | 집계 창(스프레이·무차별 대입 공용) |  |
| `krb_spray_user_threshold` | 10 | 출발지별 실패 고유 계정 수 |  |
| `krb_bruteforce_threshold` | 20 | (출발지, 계정)별 비밀번호 실패 횟수 | 계정 잠금 정책(예: 5회)보다 높으면 잠금 후에야 탐지되므로 낮춤 검토 |
| `krb_spray_local_kdc_only` | T | 내부 KDC 대상만 |  |
| `krb_spray_allowlist` | 비어 있음 | 예외 출발지(계정 점검 도구·인증 게이트웨이) | custom에 기록 |
| `krb_failure_codes` | 6, 18, 23, 24 | 스프레이로 세는 KRB-ERROR 코드 | 25(사전인증 요구)는 넣지 말 것 |
| `krb_bruteforce_codes` | 18, 24 | 무차별 대입으로 세는 코드 |  |

#### 18 Kerberoasting · AS-REP Roasting

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `krb_roast_interval` | 10min | 집계 창 |  |
| `krb_roast_service_threshold` | 5 | 출발지별 약한 암호 서비스 티켓의 고유 SPN 수 | AES 강제 환경이면 2\~3으로 낮춰도 오탐이 적음 |
| `krb_roast_local_kdc_only` | T | 내부 KDC 응답만 |  |
| `krb_roast_allowlist` | 비어 있음 | 예외 출발지(레거시 RC4 서비스를 대량 쓰는 서버) |  |
| `krb_weak_ciphers` | 1, 3(DES), 23, 24(RC4) | 약한 암호로 보는 Kerberos 암호 번호 |  |
| `krb_roast_excluded_services` | `/^(krbtgt\|kadmin)\//` | 집계에서 빼는 SPN |  |
| `asrep_require_weak_cipher` | T | T면 RC4·DES AS-REP만 탐지 | F면 사전인증 없는 AS-REP 전부(스마트카드 로그온 오탐 가능) |

#### 19 외부향 SMB · 외부 NTLM 인증

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `outbound_smb_ports` | 445/tcp, 139/tcp | SMB 서비스 포트 |  |
| `outbound_smb_allowlist` | 비어 있음 | 예외 출발지 |  |
| `outbound_smb_allowed_dsts` | 비어 있음 | 허용한 외부 SMB 서버(협력사 파일 서버) | custom에 기록 |

#### 20 WinRM · DCOM 확산

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `lm_mgmt_epoch` | 5min | 집계 창 |  |
| `winrm_lm_threshold` / `dcom_lm_threshold` | 3 / 3 | 고유 내부 목적지 수 | 1로 낮추면 단일 원격 실행도 탐지(오탐 증가) |
| `winrm_ports` | 5985/tcp, 5986/tcp | WinRM 포트 |  |
| `lm_mgmt_allowlist` | 비어 있음 | 관리 서버(SCCM·모니터링·Ansible·점프) | **custom에 필수 기록** |

#### 21 랜섬웨어성 SMB

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `ransomware_interval` | 1min | 집계 창 |  |
| `ransomware_rename_threshold` | 30 | 확장자가 바뀐 이름 변경의 고유 파일 수 |  |
| `ransomware_note_threshold` | 5 | 랜섬 노트를 만든 고유 폴더 수 |  |
| `ransomware_note_names` | readme·decrypt·restore 등 조합 패턴 | 랜섬 노트 파일명(소문자, 확장자 txt·html·hta·rtf) | 새 랜섬웨어 노트 이름 추가 시 재정의 |
| `ransomware_allowlist` | 비어 있음 | 예외 출발지(백업·동기화·DLP·아카이빙) | custom에 기록 |

#### 22 LLMNR/NBT-NS/mDNS 포이즈닝

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `poisoning_interval` | 10min | 집계 창 |  |
| `poisoning_name_threshold` | 5 | 응답자별 긍정 응답한 고유 이름 수 |  |
| `poisoning_ports` | 137/udp=nbns, 5353/udp=mdns, 5355/udp=llmnr | 감시 포트 |  |
| `poisoning_qtypes` | 1, 28, 32, 255 | NBNS에서 세는 질의 유형(A·AAAA·NB·ANY) |  |
| `poisoning_allowlist` | 비어 있음 | 예외 응답자(WINS 서버) |  |

#### 23 DCSync

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `dcsync_domain_controllers` | 비어 있음 | DC 주소 목록 | **custom에 필수 기록**(클러스터에서는 자동 학습이 워커별로 따로 이뤄짐) |
| `dcsync_learn_dcs` | T | Kerberos 응답(AS-REP·TGS-REP)을 보낸 내부 호스트를 DC로 학습 | DC 목록을 정확히 적었으면 F도 가능 |
| `dcsync_allowlist` | 비어 있음 | 복제 권한을 정상 사용하는 서버(Azure AD Connect) | custom에 기록 |

#### 24 비표준 포트 · 장기 연결

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `nonstd_port_standard` | http: 80·8080·8000·8008·8888·3128 / ssl: 443·8443·993·995·465·587·636·853·989·990·5061·3389·25·143·110 / ssh: 22 | 프로토콜별 표준 포트 | 포트 추가는 아래 허용 포트 사용 권장 |
| `nonstd_port_allowed_ports` | 비어 있음 | 사내에서 허용한 외부 포트 | `+= { 8081/tcp }` |
| `nonstd_port_allowed_dsts` / `nonstd_port_allowlist` | 비어 있음 | 허용 외부 서비스 / 예외 출발지 |  |
| `long_conn_duration` | 6hr | 장기 연결 기준 시간 | 오탐이 많으면 12hr 등으로 늘림 |
| `long_conn_allowed_dsts` / `_ports` / `long_conn_allowlist` | 비어 있음 | VPN·메신저·클라우드 동기화 예외 | 초기 운영 시 튜닝 필요 |

#### 공통 모듈 (근거·상관·중복 묶기)

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `evidence_count_expire` | 2hr | 탐지별 근거 건수 카운터 만료 |  |
| `chain_max_expire` | 2hr | 킬체인 상관 상태 최대 보관 시간 |  |
| `chain_rules` | 개별 전이 23개(5.1절) | 어느 탐지에서 어느 탐지로 이어지는지 | `+=`로 규칙 추가 가능 |
| `chain_group_rules / corr_*_notes` | 묶음 전이 15개, 묶음 7개(5.1.1) | 어느 단계 묶음에서 어느 단계 묶음으로 이어지는지, 각 묶음에 속한 탐지 | 묶음을 바꾸면 chain_group_rules도 다시 정의 |
| `dedup_notes` | 비어 있음(꺼짐) | 중복 묶기를 적용할 탐지 유형 |  |
| `dedup_window` | 1min | 중복 묶기 창 |  |
| `dedup_emit_first` / `dedup_override_suppression` | T / F | 첫 건은 바로 내보냄 / 룰 억제를 무시하고 묶기만 사용 |  |

### 7.6 로그 설정

| 파라미터 | 기본값 | 의미 | 조정 가이드 |
| --- | --- | --- | --- |
| `NSM::keep_log_streams` | nsm_detection, evidence, notice, capture_loss, loadedscripts, stats, reporter | 남길 로그. 나머지는 기동 시 꺼짐 | conn·dns 등을 남기려면 `+=`로 추가 |
| `NSM::log_paths` | 5.2절 표 | 로그별 출력 경로(확장자 제외) | 추가한 로그는 경로도 함께 지정 |
| `NSM::create_log_dirs` | T | 기동 시 로그 디렉터리를 상위부터 생성 | 배포 스크립트가 만들면 F |
| `Log::default_rotation_interval` | 4hr | 로그 회전 주기 |  |
| 로그 형식 | JSON | `policy/tuning/json-logs`로 설정 | TSV가 필요하면 `redef LogAscii::use_json = F;` |

conn.log과 dns.log를 추가로 남기는 예:

```zeek
redef NSM::keep_log_streams += { Conn::LOG, DNS::LOG };
redef NSM::log_paths += {
    [Conn::LOG] = "/hdd_tmp/log/zeek/conn",
    [DNS::LOG]  = "/hdd_tmp/log/zeek/dns",
};
```

자산 식별 PoC를 함께 올리면 그 로그도 꺼지므로 `redef NSM::keep_log_streams += { AssetID::LOG };`가 필요합니다.

### 7.7 설정 변경·검증 절차

1. **파일 선택**: 고객별 값은 `nsm_config_custom.zeek`, 제품 공통 기본값은 `nsm_config_fixed.zeek`(저장소 PR로 변경).
2. **문법 검사**: `zeek -a /경로/nsm_rules` — 오류가 하나도 없어야 함.
3. **기동 검사**: `zeek /경로/nsm_rules` 를 입력 없이 실행해 집계·로그 디렉터리 생성까지 확인.
4. **회귀 테스트**(fixed를 바꾼 경우): `tests/run_tests.sh` — 임계를 바꾸면 기대값이 달라질 수 있으므로 테스트도 함께 수정.
5. **배포**: 클러스터는 `zeekctl deploy`로 모든 노드에 같은 설정을 반영.
6. **확인**: `loadedscripts.log`에 custom 파일이 로드됐는지, `reporter.log`에 경고가 없는지 본다.

## 8. 비기능 요구사항

성능·클러스터·호환성·신뢰성은 아래 기준을 따르며, 각 항목은 코드와 테스트에 반영돼 있습니다.

| ID | 분류 | 요구사항 | 현재 구현 |
| --- | --- | --- | --- |
| NFR-1 | 성능 | 대용량 데이터를 정규식에 통째로 넣지 않는다 | 웹 본문은 연결당 4KB까지만 검사 |
| NFR-2 | 성능 | 연결마다 남기는 상태는 연결이 끝나면 함께 사라져야 한다 | 연결 레코드 필드(예: NTLM·Kerberos 대기 계정) 사용, 전역 표는 만료 시간 설정 |
| NFR-3 | 성능 | 장기 연결·대용량 전송은 연결이 끝나기 전에 탐지한다 | ConnThreshold(바이트·기간 임계) 사용(14·24) |
| NFR-4 | 클러스터 | 집계형 탐지는 워커가 나눠 본 트래픽을 합쳐 판정한다 | SumStats(매니저가 합침) |
| NFR-5 | 클러스터 | 킬체인 상관은 다른 워커에서 나온 탐지도 이어 붙인다 | 매니저가 판정, btest cluster 테스트로 검증 |
| NFR-6 | 클러스터 | 07 비커닝은 (출발지, 목적지) 상태를 한 노드에 모은다 | proxy가 있으면 proxy, 없으면 manager로 모음 |
| NFR-7 | 호환성 | Zeek 9.0.1과 8.0.9에서 같은 결과 | CI 매트릭스로 두 버전 모두 검사 |
| NFR-8 | 호환성 | 예전 배포 설정에서 쓰던 파라미터는 지우지 않는다 | 더 이상 쓰지 않는 값은 `&deprecated`로 남겨 경고만 출력 |
| NFR-9 | 신뢰성 | 로그 디렉터리 생성은 기동 순서와 경쟁하지 않는다 | 동기식 `mkdir` 사용, CI에서 기동 10회 반복 검사 |
| NFR-10 | 신뢰성 | 예외 목록은 기본으로 비어 있고 환경별 설정으로만 채운다 | 모든 `*_allowlist` 기본 `{}` |
| NFR-11 | 추적성 | 모든 notice는 evidence.log에서 근거를 찾을 수 있어야 한다 | 룰마다 `assert-evidence-join` 테스트 |
| NFR-12 | 보안 | 패킷 내용을 로그에 원문 그대로 남기지 않는다 | 근거는 최대 256바이트 발췌·요약값만 |

## 9. 검증 요구사항

모든 룰은 “탐지돼야 하는 호스트”와 “비슷하지만 탐지되면 안 되는 호스트”를 한 pcap에 함께 넣은 btest로 검증하며, PR마다 CI가 Zeek 9.0.1·8.0.9에서 모두 통과해야 머지합니다.

| 항목 | 내용 |
| --- | --- |
| btest | 34개 — 룰·계약 테스트 31개(`tests/btest/rules`), 클러스터 테스트 3개(`tests/btest/cluster`, 매니저+워커 2\[+proxy\]) |
| 합성 pcap | 21개(`tests/pcaps`), `tests/gen_pcaps.py`가 고정 시드로 만들어 항상 같은 바이트 |
| 공개 trace | `tests/pcaps/zeek/ssh_auth_internal.pcap` — Zeek 테스트 trace에서 발췌(실제 SSH 인증 성공) |
| 검사 도구 | `assert-rows`(로그 행 수 조건 검사), `assert-evidence-join`(notice의 근거가 evidence.log에 있는지) |
| 실행 | `tests/run_tests.sh`(로컬 zeek 없으면 Docker `zeek/zeek:9.0.1`), `ZEEK_IMAGE=zeek/zeek:8.0.9 tests/run_tests.sh` |

실행 결과는 테스트마다 `tests/btest/output/<테스트 이름>/`에 운영과 같은 JSON 로그로 남습니다(통과한 테스트 포함, 클러스터는 `manager/`·`worker-1/` 등 노드별 하위 폴더). 검사 도구(`assert-rows`, `assert-evidence-join`, zeek-cut 대용 `log-cut`)는 JSON·TSV를 모두 읽고, CI는 어떤 레코드에도 없는 필드를 검사한 경우(필드명 오타 의심) 경고를 모아 보여줍니다.

### 9.1 CI 검사 항목 (`.github/workflows/zeek-check.yml`)

1. 패키지 문법 검사(`zeek -a ./nsm_rules`)
2. 비활성 룰 포함 문법 검사(`__load__.zeek`의 `#@load` 행을 자동으로 찾아 함께 로드)
3. 기동 검사 10회 반복(로그 디렉터리 생성 경쟁 조건 확인)
4. btest 전체
5. pcap 재현성: 생성기를 다시 돌려 커밋된 pcap과 바이트 단위로 같은지 비교

### 9.2 룰 테스트가 갖춰야 할 것

- 탐지 호스트 1개 이상과 오탐 후보(예외 목록, 임계 미달, 다른 용도의 비슷한 트래픽) 호스트를 함께 넣는다.
- notice·evidence·nsm_detection 세 로그의 행 수를 모두 검사하고, `assert-evidence-join`을 넣는다.
- 프로토콜을 직접 만든 pcap은 Zeek 프로토콜 로그(kerberos·ntlm·dce_rpc·smb_files 등)까지 검사해 Zeek가 제대로 해석했는지 확인한다.
- 합성 메시지는 가능하면 독립 파서(scapy)로 파싱·재인코딩을 확인한다(Kerberos·DCE-RPC·SMB2·NBNS·SSH).
- 기존 pcap은 바뀌지 않아야 한다. 생성기에 새 헬퍼·인자를 추가할 때는 기본값을 기존 동작과 같게 둔다.

## 10. 알려진 한계와 향후 과제

다음 단계(5단계)는 자산 식별 PoC 머지와 OCSF 변환기 연동이며, 아래 한계 중 상관 규칙 확장과 DC·파일 서버 자동 예외가 그 작업과 이어집니다.

| 한계 | 영향 | 대응·계획 |
| --- | --- | --- |
| 단일 탐지의 심각도가 모두 `Information` | DCSync·랜섬웨어도 스캔과 같은 등급 | 룰 레지스트리(룰 ID·ATT&CK·단계·심각도)를 두고 한 곳에서 관리 |
| ATT&CK 매핑이 세 곳(룰의 근거, `attack_map`, `stage_attack`)에 따로 있음 | 수정 누락 위험 | 위 레지스트리로 통합 |
| 암호화된 내용(SMB3 암호화, TLS 1.3 인증서) | 05·06·21은 SMB3 암호화 세션을 못 봄, 09의 자체서명 신호가 TLS 1.3에서 없음 | 하기 어려운 한계. JA4·SNI 신호 비중을 키움 |
| HTTP(WebDAV)로 오가는 NTLM | 05·19가 잡지 못함(Zeek가 HTTP 안 NTLM을 해석하지 않음) | HTTP Authorization 헤더 기반 보완 룰 검토 |
| 클러스터에서 워커별로 따로 판단하는 룰 | 22 NBNS는 질의·응답이 다른 워커로 가면 놓침, 23의 DC 학습이 워커별로 따로 이뤄짐 | 23은 DC 목록 설정으로 해결. 필요하면 클러스터 공유 상태로 보강 |
| 확산 룰(06·15·16·20)은 여러 대로 퍼지는 경우만 탐지 | 한 대로의 원격 실행은 미탐 | 임계를 1로 낮추되 관리 서버 예외를 충실히 등록 |
| 21은 이름 변경·랜섬 노트만 봄 | 덮어쓰기나 대량 삭제(T1485)형 랜섬웨어는 미탐 가능 | 대량 삭제·쓰기 신호 추가 |
| 등록 도메인 추출이 작은 접미사 목록 기반 | 08·13에서 드문 접미사가 한 도메인으로 묶일 수 있음 | `multi_label_suffixes` 보강 또는 Public Suffix List 도입 |
| 12의 `cloud_hosts`가 `*.amazonaws.com` 등 넓음 | 백업·CI 트래픽 오탐 가능 | 패턴 세분화 |
| 실제 고객망 성능·오탐률 미측정 | 임계값이 환경에 따라 맞지 않을 수 있음 | 시범 운영으로 주간 notice 건수를 보고 7장 값 튜닝 |
| 자산 식별 PoC 미머지 | 서버 역할(DC·파일 서버·DNS 서버)을 예외에 자동 반영 못함 | 5단계: `nsm_rules/asset-id/`로 머지, 로그 필터에 `AssetID::LOG` 추가 |
| OCSF 변환기가 신규 탐지 15종·Impact 단계를 모름 | SIEM으로 넘길 때 분류 누락 | 5단계: claudtest 저장소 매핑 추가 |

## 부록 A. 배포 설정 파일 예시 (nsm_config_custom.zeek)

아래는 고객 한 곳에 배포할 때 쓰는 예시입니다. 주소·대역은 모두 가상 값이므로 고객 환경에 맞게 바꾸고, 쓰지 않는 항목은 지우거나 주석으로 둡니다. 저장소의 이 파일은 빈 채로 두고 배포본에만 작성합니다.

```zeek
##! nsm_config_custom.zeek — 고객: <고객명>, 작성일: <YYYY-MM-DD>
##! redef 만 쓴다. @load 는 쓰지 않는다.

# ---------------------------------------------------------------- [필수] 내부망
redef Site::local_nets += {
    10.0.0.0/8,
    172.16.0.0/12,      # 172.0.0.0/8 아님
    192.168.0.0/16,
};

# ---------------------------------------------------------------- [필수] 도메인 컨트롤러 (23 DCSync)
redef NSM::dcsync_domain_controllers += { 10.0.0.10, 10.0.0.11 };
redef NSM::dcsync_allowlist          += { 10.0.0.30/32 };   # Azure AD Connect

# ---------------------------------------------------------------- [필수] 관리 서버 (06/15/16/20 확산)
redef NSM::lm_mgmt_allowlist  += { 10.20.30.0/24 };   # SCCM·모니터링·Ansible·점프
redef NSM::smb_lm_allowlist   += { 10.20.30.0/24 };
redef NSM::rdp_lm_allowlist   += { 10.20.30.10/32 };  # 점프 서버
redef NSM::ssh_lm_allowlist   += { 10.20.30.11/32 };

# ---------------------------------------------------------------- DNS (08 터널링·유출, 13 DGA)
redef NSM::dns_tunnel_resolvers += { 10.0.0.53, 10.0.0.54 };   # 내부 DNS 서버
redef NSM::dns_tunnel_allowlist_domains += { "corp-telemetry.example" };

# ---------------------------------------------------------------- 웹 공격 (03/04)
redef NSM::web_attack_allowlist += { 10.20.99.10/32 };   # 취약점 스캐너·모의해킹

# ---------------------------------------------------------------- 자격증명 (05/17/18/22)
redef NSM::ntlm_spray_allowlist += { 10.20.40.0/28 };   # 인증 프록시·VDI 게이트웨이
redef NSM::krb_spray_allowlist  += { 10.20.40.0/28 };
redef NSM::krb_roast_allowlist  += { 10.20.50.10/32 };  # 레거시 RC4 서비스를 대량 쓰는 서버
redef NSM::poisoning_allowlist  += { 10.0.0.60/32 };    # WINS 서버

# ---------------------------------------------------------------- 랜섬웨어 (21)
redef NSM::ransomware_allowlist += { 10.20.70.0/28 };   # 백업·동기화·DLP 서버

# ---------------------------------------------------------------- 외부 통신 허용 (07/19/24)
redef NSM::beacon_allowlist_domains  += { "update.vendor.example" };
redef NSM::outbound_smb_allowed_dsts += { 203.0.113.20/32 };   # 협력사 파일 서버
redef NSM::nonstd_port_allowed_ports += { 8081/tcp };
redef NSM::long_conn_allowed_dsts    += { 203.0.113.10/32 };   # VPN 게이트웨이

# ---------------------------------------------------------------- 로그 (필요할 때만)
# redef NSM::create_log_dirs = F;                        # 배포 스크립트가 디렉터리를 만들 때
# redef NSM::keep_log_streams += { Conn::LOG };
# redef NSM::log_paths += { [Conn::LOG] = "/hdd_tmp/log/zeek/conn" };

# ---------------------------------------------------------------- 임계 튜닝 (시범 운영 후)
# redef NSM::krb_bruteforce_threshold = 10;
# redef NSM::long_conn_duration       = 12hr;
```

배포 전에 `zeek -a /경로/nsm_rules`로 문법을 확인하고(7.7절), 배포 후 `loadedscripts.log`에 이 파일이 보이는지 확인합니다.
