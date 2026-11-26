# nsm_rules 검토 결과

- 검토일: 2026-11-16 (1차 검토 2026-11-09)
- 대상: `nsm_rules/` main(#88 머지 후). 탐지 룰 파일 33개(01\~34, 11번은 08번에 통합), 탐지 유형 47종 + 킬체인 상관 1종, 공통 모듈(근거·탐지 요약·상관·예외 엔진·인증 맥락), 메타데이터 선별 전송, 자산 식별
- 목적: (1) 1차 검토 지적 사항의 처리 확인, (2) 현재 룰의 검증 상태와 남은 위험 점검, (3) 다음 확대 후보 갱신
- 1차 검토 원문(룰 16개 기준 상세 분석, Critical·High 근거)은 git 이력의 이 파일(커밋 `9247c5c` 시점)에 있습니다.
- 이 문서는 2026-11-16 시점의 검토입니다. 이후 변경(PR #129까지)은 9장에 모았습니다.

## 0. 검토 방법

| 구분 | 내용 |
|---|---|
| 정적 분석 | 룰·공통 모듈·설정 파일 정독, SRS 4장(룰 목록)·10장(한계)과 대조 |
| 회귀 테스트 | btest 113개(룰·계약·예외·선별 전송 77개, 클러스터·자산 식별 36개). Zeek 9.0.1 전부 통과, 8.0.9는 9.x 분석기가 필요한 5개를 빼고 통과 |
| 합성 pcap | 54개. 룰마다 탐지돼야 하는 host와 비슷하지만 탐지되면 안 되는 host를 한 pcap에 넣음 |
| 실측 | CIC-IDS2017 5일(월\~금, 각 약 8시간)을 운영 설정으로 실행한 통합 리포트(2026-11-16) |
| 미수행 | 고객망 장기 운영, AD·AI 룰의 실제 공격 pcap 실행(후보만 확인, 6장) |

---

## 1. 요약

**1차 검토 지적은 모두 처리했습니다.** Critical 3건(C1\~C3)과 High 6건(H1\~H6)을 고쳤고, 우선 구현 후보 P1 9개(N1\~N9)를 모두 룰로 만들었습니다. 룰은 16개(활성 11)에서 33개(모두 활성)가 됐고 킬체인 7단계 모두에 탐지가 있습니다. 남은 것은 심각도 등급과 ATT&CK 매핑 단일화입니다(2장).

**지금 가장 큰 공백 다섯 가지**

| # | 공백 | 근거 | 제안 |
|---|---|---|---|
| R1 | DoS·DDoS 탐지 룰이 없음 | CIC 수요일 DoS 4종, 금요일 DDoS(LOIC) 미탐 | 신규 룰(6장 P1) |
| R2 | 단일 탐지의 심각도가 모두 `Information` | DCSync·랜섬웨어도 스캔과 같은 등급 | 룰 레지스트리(심각도·ATT&CK·단계) |
| R3 | AD·AI 룰은 합성 pcap으로만 확인 | CIC는 2017년 데이터라 해당 공격이 없음 | 공개 AD pcap 로컬 실행, AI는 실험실 캡처(6장) |
| R4 | 비콘 계열 오탐 | CIC 오탐 19건 중 15건이 HTTP·TLS 비콘 | 예외 등록 지원, 비콘 위험 등급 |
| R5 | 한 대 대상 확산·단발 정찰 미탐 | 06·15·16·20은 여러 대, 34 AD 정보 수집은 10대 이상 | 31로 일부 보완. 관리 서버 예외를 갖춘 뒤 임계 1 검토 |

---

## 2. 1차 검토 지적 사항 처리 결과

| # | 1차 지적 | 처리 |
|---|---|---|
| C1 | `notice_aggregation`이 모든 notice의 억제창을 0으로 덮음 | 룰 억제창 존중(`dedup_override_suppression` 기본 F) |
| C2 | `detection_log`가 중복·요약 notice까지 기록 | notice.log 1건 = 탐지 1건. 이후 사건 묶기(같은 공격의 반복을 `occurrences`로) 추가 |
| C3 | `filter_log`가 원본 스트림을 전부 끔 | 켜둘 목록 설정화(`keep_log_streams`), reporter 유지, 메타데이터 선별 전송으로 원본 대체, `keep_all_log_streams` 옵션(#76) |
| H1 | 03 SQLi 정규식 문법 오류 | 재작성 후 활성화 |
| H2 | 클러스터 상관이 노드별로 쪼개짐 | 모든 노드가 notice 요약을 매니저로 보내고 상관은 매니저 한 곳에서 |
| H3 | 14가 `tcp_packet`으로 집계 | `ConnThreshold` 1MB 단위 증가분 집계 |
| H4 | 13 DGA 엔트로피 임계 도달 불가 | 등록 라벨 무작위성 점수 기반 비율로 교체 |
| H5 | `parent_domain()`이 `co.kr` 등을 한 도메인으로 묶음 | `multi_label_suffixes` |
| H6 | 07 비콘 누락 허용 오차 오탐 | 허용 오차 고정 + 연속 누락 상한 2 |
| 구조 | 로더 2개, 비활성 경로, 하이픈 파일명, JA4 문서 모순 | 로더 일원화, 문서 정합 |
| 정합성 | 룰 번호 체계, 임계값 주석 불일치, `172.0.0.0/8` 예시 | 정리. 설정값은 SRS 7장이 기준 |
| 심각도 | 단일 탐지가 모두 `Information` | **미처리**(R2) |
| ATT&CK | 매핑이 룰 근거·`attack_map`·`stage_attack` 세 곳 | **해결(2026-11-26)**: 룰 레지스트리 `rule_registry` 한 곳(SRS 5.8절) |
| 테스트 | 테스트 없음 | btest 107개, 합성 pcap 생성기, CI(Zeek 9.0.1·8.0.9, 경고 1건도 실패) |
| P1 N1\~N9 | Kerberos 스프레이·Roasting, 외부향 SMB, 랜섬웨어, TLS 비콘, 이름 포이즈닝, DCSync, WinRM·DCOM, 비표준 포트 | 17·18·19·21·30·22·23·20·24로 구현 |
| P2 N16 | SSH·RDP 무차별 대입 | SSH·FTP는 26으로 구현. RDP는 미구현 |
| 자산 식별 | 머지 시 로그 필터 충돌, Zeek 버전 | 머지 완료(`nsm_rules/asset-id/`), Zeek 9.x 기준 통일 |

---

## 3. 룰 현황

‘검증’의 “합성”은 btest 합성 pcap, “CIC”는 CIC-IDS2017 5일 실측입니다. 판정 조건과 기본값은 SRS 4.1절을 따릅니다.

| 파일 | 탐지 유형 | 단계 | 검증 | 남은 이슈 |
|---|---|---|---|---|
| 01_port_scan | Port_Scan | 정찰 | 합성, CIC 목·금 탐지 | 5분 25포트 미만의 느린 탐색은 미탐(CIC 금 13시 5포트 사전 탐색) |
| 02_host_scan | Host_Scan | 정찰 | 합성 | 80·443·53 포트는 기본 제외, ICMP 스윕 없음 |
| 03_sqli | SQL_Injection | 초기 침투 | 합성, CIC 목 탐지 | HTTPS 웹서버는 못 봄 |
| 04_webshell | Webshell_Access | 초기 침투 | 합성 | HTTPS 웹서버는 못 봄, 실측 없음 |
| 05_ntlm_spray | NTLM_Spray | 자격증명 | 합성 | HTTP(WebDAV) NTLM·SMB3 암호화 세션 미관측 |
| 06_smb_admin_share | SMB_Admin_Share | 확산 | 합성 | 2대 이상 fan-out만 |
| 07_http_beaconing | HTTP_Beaconing | C2 | 합성, CIC 금 Ares 5대 탐지 | CIC 오탐 9건(뉴스·광고 자동 새로고침, 동영상 피드) |
| 08_dns_tunneling | DNS_Tunneling, Exfil_DNS | C2·유출 | 합성 | 실측 없음, 드문 접미사 묶임 |
| 09_encrypted_c2 | Encrypted_C2 | C2 | 합성, CIC 오탐 1건(자체서명·SNI 없음) | TLS 1.3에서 인증서 신호 소실, JA3 인텔 노후 |
| 10_large_transfer_exfil | Exfil_Large_Transfer | 유출 | 합성 | 백업·동기화 서버 예외 필요 |
| 12_web_upload_exfil | Exfil_Web_Upload | 유출 | 합성 | `cloud_hosts` 패턴이 넓음 |
| 13_dga | DGA_Domain | C2 | 합성 | 7자 이하 라벨은 판별력 낮음 |
| 14_large_transfer_exfil | Exfil_Volume_Aggregate | 유출 | 합성 | - |
| 15_rdp_lateral | RDP_Lateral | 확산 | 합성 | 3대 이상만 |
| 16_ssh_lateral | SSH_Lateral | 확산 | 합성 | 3대 이상만 |
| 17_kerberos_spray | Kerberos_Spray, Kerberos_Bruteforce | 자격증명 | 합성 | 실측 없음 |
| 18_kerberoasting | Kerberoasting, ASREP_Roasting | 자격증명 | 합성 | AES 티켓만 요청하는 Kerberoasting은 미탐 |
| 19_outbound_smb | Outbound_SMB, NTLM_Credential_Leak | 유출·자격증명 | 합성 | HTTP 안 NTLM 미해석 |
| 20_winrm_dcom_lateral | WinRM_Lateral, DCOM_Lateral | 확산 | 합성 | 관리 서버 예외 필수 |
| 21_smb_ransomware | SMB_Ransomware | 영향 | 합성 | 덮어쓰기·대량 삭제형 미탐, SMB3 암호화 |
| 22_name_poisoning | Name_Poisoning | 자격증명 | 합성 | 클러스터에서 NBNS 질의·응답이 다른 워커로 가면 놓침 |
| 23_dcsync | DCSync | 자격증명 | 합성 | (클러스터 DC 학습 공유로 해결, SRS 5.7절) |
| 24_nonstd_port | Nonstandard_Port, Long_Connection | C2 | 합성, CIC 오탐 3건 | 8081 TLS·443 평문 HTTP 같은 웹 서비스가 걸림 |
| 25_unknown_protocol | Unknown_Protocol | C2 | 합성, CIC 목 침투 C2(444/tcp) 탐지 | - |
| 26_service_bruteforce | SSH_Bruteforce, FTP_Bruteforce | 자격증명 | 합성, CIC 화 탐지 | RDP 무차별 대입 없음 |
| 27_heartbleed | TLS_Heartbleed | 초기 침투 | 합성, CIC 수 탐지 | - |
| 28_xss | Cross_Site_Scripting | 초기 침투 | 합성, CIC 목 탐지 | HTTPS 미관측 |
| 29_http_bruteforce | HTTP_Bruteforce | 자격증명 | 합성, CIC 목 탐지 | HTTPS 미관측 |
| 30_tls_beaconing | TLS_Beaconing | C2 | 합성, CIC 오탐 6건 | 주기 패턴이 30분 이상 이어져야 탐지 |
| 31_remote_exec | Remote_Service_Creation, Remote_Task_Creation, Remote_WMI_Execution | 확산 | 합성 | 관리 서버 예외 필수 |
| 32_machine_account | Machine_Account_Misuse | 자격증명 | 합성 | NAT·장애 조치 클러스터 예외 필요 |
| 33_ai_threats | AI_Service_Exploit, AI_API_From_Server, AI_Service_Upload | 초기 침투·C2·유출 | 합성(CIC 0건) | HTTPS AI 서버 미관측, 업무 AI 사용 정책 결정 필요 |
| 34_ad_attacks | AD_Enumeration, Coerced_Authentication, Remote_Registry_Dump, Zerologon_Attempt | 정찰·자격증명 | 합성 | 10대 미만 조회는 미탐, 암호화 RPC로 보낸 호출은 미관측 |

---

## 4. CIC-IDS2017 5일 실측

탐지 30건(킬체인 상관 포함), 오탐 19건입니다. 예외는 CIC용 17개를 적재했습니다.

| 요일 | 공격 시나리오 | 탐지 | 오탐 |
|---|---|---|---|
| 월 | 없음(정상) | - | 10(HTTP 비콘 4, TLS 비콘 4, 비표준 포트 2) |
| 화 | FTP·SSH 무차별 대입 | FTP_Bruteforce, SSH_Bruteforce(각 13회 묶음) | 6(HTTP 비콘 3, TLS 비콘 2, 비표준 포트 1) |
| 수 | DoS 4종(slowloris, Slowhttptest, Hulk, GoldenEye), Heartbleed | Heartbleed. **DoS는 룰이 없어 미탐** | 1(Encrypted_C2) |
| 목 | 웹 무차별 대입·XSS·SQLi, 침투 후 내부 스캔 | 웹 공격 3종, 침투 host의 포트 스캔·외부 C2(444/tcp), 킬체인 정찰 → C2 | 0 |
| 금 | Ares 봇넷, 포트 스캔, DDoS(LOIC) | 봇넷 5대(HTTP 비콘), 포트 스캔. **DDoS는 미탐** | 2(HTTP 비콘 2) |

- 오탐 19건은 모두 C2 계열입니다. 비콘 15건은 뉴스·광고 사이트의 자동 새로고침과 동영상 피드였고, 비표준 포트 3건은 8081 포트 TLS와 443 포트 평문 HTTP 웹 서비스였습니다.
- 금요일 DDoS는 웹 서버 한 대에 한 출발지가 포트 80으로 시간당 8만 건 넘게 연결했지만 탐지가 없었습니다. 수요일 DoS 4종도 같은 공백입니다(R1).
- 금요일 포트 스캔은 13시대에 같은 출발지가 포트 5개만 두드린 사전 탐색이 먼저 있었고, 이것은 임계(25포트) 미만이라 탐지되지 않았습니다.

---

## 5. 남은 위험·공백

| # | 항목 | 영향 | 제안 |
|---|---|---|---|
| R1 | DoS·DDoS 룰 없음 | 서비스 거부 공격 전체 미탐 | 6장 P1 |
| R2 | 심각도·ATT&CK 매핑 관리 | 등급 구분 불가, 매핑 수정 누락 위험 | ATT&CK·단계·진단명은 **룰 레지스트리로 해결(2026-11-26, SRS 5.8절)**. 심각도는 Manager 위험도로 표시(센서 제어 스펙) |
| R3 | AD·AI 룰 실측 없음 | 임계·필드 가정이 실제 도구와 다를 수 있음 | 6장의 공개 pcap을 로컬에서 실행해 파일별 결과표 작성 |
| R4 | 비콘 오탐 | CIC 오탐 19건 중 15건 | 예외 등록 지원(반복 오탐 묶음 제시), 비콘 위험 등급(목적지 평판·흔한 목적지 여부) |
| R5 | 한 대 대상 확산·단발 정찰 | 조용한 공격자 미탐 | 31이 원격 실행을 1건으로 보완. 관리 서버 예외를 갖춘 뒤 06·15·16·20 임계 1 검토 |
| R6 | 클러스터 워커별 상태 | 22·23·33 서버 학습이 워커마다 다름 | **해결(2026-11-26)**: 학습 값 공유와 NBNS 짝짓기(SRS 5.7절) |
| R7 | 암호화 구간 | SMB3 암호화, TLS 1.3 인증서, DoH, 암호화 RPC는 못 봄 | 하기 어려운 한계. JA4·SNI·흐름 신호 비중을 키움 |
| R8 | HTTP 안 NTLM | 05·19 미탐 | HTTP Authorization 헤더 기반 보완 검토 |
| R9 | 기존 `*_allowlist` 호환 설정 | 사유·만료가 없고 재시작 필요 | 예외 파일로 이관 후 다음 메이저에서 제거 검토 |

---

## 6. 확대 후보 (갱신)

### P1

| 룰 | ATT&CK | 데이터 | 방식 |
|---|---|---|---|
| DoS·DDoS | T1498, T1499 | conn, http | 내부 서버 대상 한 출발지(또는 다수)의 짧은 창 연결·요청 폭주, 응답 없는 연결(half-open) 비율, 오래 열린 미완료 HTTP 요청(slow HTTP) |
| DCShadow | T1207 | dce_rpc(drsuapi) | DC가 아닌 host의 DRSAddEntry·DRSReplicaAdd 호출 |
| DPAPI 도메인 백업 키 탈취 | ATT&CK 매핑 확인 필요 | dce_rpc(lsarpc) | DC가 아닌 host의 LsarRetrievePrivateData로 백업 키 비밀 조회 |
| LDAP 대량 조회(BloodHound류) | T1087.002, T1069.002, T1482 | ldap.log | 출발지별 검색 수, `servicePrincipalName=*`·`adminCount=1`·`trustedDomain` 필터 |

### P2

| 룰 | ATT&CK | 비고 |
|---|---|---|
| RDP 무차별 대입 | T1110.001 | 짧은 RDP 연결 반복(1 출발지 → 1 대상) |
| DoH·DoT 우회 | T1572, T1071.004 | 공용 DoH 리졸버 SNI, 853/tcp 외부향 |
| Tor·익명 프록시 | T1090.003 | Tor 포트, 인증서 패턴 |
| ICMP 터널·유출 | T1095, T1048 | echo 페이로드 크기·고유성 |
| 평문 인증정보 노출 | T1552, T1040 | HTTP Basic, FTP, Telnet, LDAP simple bind |
| FTP·SMTP 유출 | T1048.003 | 외부향 FTP STOR 바이트, 메일 서버가 아닌 host의 외부 SMTP |
| ARP 스푸핑·비인가 DHCP | T1557.002, T1557.003 | 자산 식별 L2·DHCP 신호 재사용 |
| ICMP 스윕 | T1018 | 02 확장 |
| 평소 활동 대비 이상 | - | host별 시간 단위 활동 요약을 쌓은 뒤 Manager에서 판정(설계 검토 중) |

### 실측 자료 후보 (R3)

| 자료 | 내용 | 비고 |
|---|---|---|
| [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) | 실제 공격 도구로 기법마다 캡처한 pcap 26개(DCSync, Zerologon, SpoolSample, kerbrute, samr·srvsvc 조회, PsExec·WMI·DCOM·RDP, DNS TXT 명령, DGA, DCShadow, DPAPI 백업 키) | 라이선스 표시 없음. 로컬 시험만, 저장소에 넣지 않음 |
| [corelight/zerologon](https://github.com/corelight/zerologon) 시험 trace | Windows 2016·2019 DC 대상 Zerologon exploit·test 4개 | 라이선스 확인 후 사용 |
| AI 인프라 | 공개 pcap 없음 | Ray·Ollama를 실험실에 띄워 공개된 요청을 보내며 캡처 |

---

## 7. 연동·주변 기능 현황

| 항목 | 상태 |
|---|---|
| 자산 식별 | 머지 완료(`nsm_rules/asset-id/`, SRS 5.5절). 서버 역할을 센서 판정에 쓰는 것은 미완(자산 그룹 예외 E4) |
| 메타데이터 선별 전송 | 구현 완료(`docs/SRS_METADATA_EXPORT.md`) |
| 예외 엔진 | 구현 완료, 기존 룰 이관 완료(SRS 5.4절). 신규 룰은 입구에서 `exception_drop`·`exception_drop_agg` 호출 |
| 통합 리포트 | 공격 스토리(진행 단계·확산 경로·내러티브), 메타데이터 관측(같은 공격 인프라, 확인이 필요한 내부 접속), 자산·전송량·예외·센서 상태 |
| OCSF 변환기 | 신규 탐지와 Impact 단계 매핑 미반영(SRS 10장) |

---

## 8. 권장 작업 순서

| 순서 | 작업 | 이유 |
|---|---|---|
| 1 | DoS·DDoS 룰 | CIC에서 확인된 유일한 공격 유형 공백(R1) |
| 2 | 룰 레지스트리(심각도·ATT&CK·단계) | 1차 검토 미처리 2건 해소, Manager 우선순위 표시의 전제(R2) |
| 3 | AD 공개 pcap 로컬 실행과 임계 조정 | 합성 pcap 가정 검증(R3) |
| 4 | 비콘 오탐 대응 | 운영 알림 품질(R4) |
| 5 | 고객 미러 장기 측정 | 실제 오탐률·처리 부하로 SRS 7장 값 조정 |
| 6 | P1 나머지(DCShadow, DPAPI 백업 키, LDAP 대량 조회) | 자격증명·정찰 커버리지 |

---

## 9. 검토 이후 변경 (2026-11-23, PR #129까지)

| 항목 | 변경 | 관련 |
|---|---|---|
| 룰 | 35번 IOC 일치(`IOC_Match`, T1071) 추가. 룰 파일 34개, 탐지 유형 48종 + 킬체인 상관 1종 | #104, #107 |
| 명시적 프록시 인식 | 유출 10·12·14(#101), C2·AI 09·24·33 기본 적용, 07·30은 스위치(기본 끔). 고객 프록시 환경 측정(1.4시간)에서 프록시를 거친 AI 사용 37쌍이 이전에는 보이지 않았음 | #101, #102, #105, #117 |
| R4 비콘 오탐 | 일부 진행: 프록시 경유 주기 접속을 켤 때 쓰는 기본 예외 목록(흔한 OS·SaaS 주기 통신 8묶음) 제공. 비콘 위험 등급은 남음 | #117 |
| 예외 엔진 | 프록시 경유 연결은 실제 목적지 이름·포트로 판정(`dst` 축 없음) | #117 |
| 자산 식별 | 라우팅 구간 신호(Kerberos 서비스 티켓, HTTP Server), 고객 정의 에이전트 정책, 지문 입력(SMB 원문·인증서·SNMP·TCP SYN), 서비스 배너, 기기 형태. 리포트에서 OUI·Recog·장비 유형 | #108, #110\~#113, #115, #116 |
| 연동 설계 | 소급검색 화면 범위, Suricata 경보를 NSM 탐지 흐름에 합치는 설계안, MDS·MTA·NSM 통합 상관 설계안 | #106, #109, #122 |
| 로그 형식(Manager 연동) | 탐지 요약 필드(`rule`·`severity_id`·`victim_count`·계정·목적지 이름·프록시), 계정 나누기, 상관 탐지 갈래 합치기·`revision`, 근거 포트·Community ID 등 공통 필드, JSON Schema와 CI 검증, 데이터 파일 지문, 센서 상태 로그, 선별 전송 필드 이름 통일. 기준 문서 [LOG_SCHEMA.md](LOG_SCHEMA.md) | #121, #123\~#129 |
| 리포트 | 목업형 리포트(목업 화면을 템플릿으로), 센서 등급 그대로 표시 | #119, #120 |
| 테스트 | btest 149개(룰·계약·예외·선별 전송 100개, 클러스터 11개, 자산 식별 38개), 합성 pcap 64개 | |

5장의 남은 위험 R1\~R3, R5\~R9와 8장의 작업 순서는 그대로입니다.
