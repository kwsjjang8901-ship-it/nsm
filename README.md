# NSM 탐지룰 (nsm_rules)

Zeek 기반 NSM(Network Security Monitoring) 탐지 룰 패키지입니다.
미러 트래픽에서 킬체인 단계별(정찰 → 자격증명 → 확산 → C2 → 유출 → 영향) 위협을 탐지하고,
`notice.log` / `nsm_detection.log` / `evidence.log`로 탐지와 근거를 남깁니다.

- 대상 Zeek 버전: **9.x** (자산 식별 PoC와 동일 기준)
- 현재 상태: PoC 단계. 룰 파일 34개(01\~35, 11은 08에 통합)·탐지 48종, 예외 엔진, 명시적 프록시 인식, 자산 식별 센서, 메타데이터 선별 전송, 센서 상태 로그, 통합 리포트(결과는 [docs/POC_RESULT.md](docs/POC_RESULT.md)). Manager로 가는 로그 형식은 [docs/LOG_SCHEMA.md](docs/LOG_SCHEMA.md)(JSON Schema, CI 검증)

## 구조

```
nsm_rules/
  __load__.zeek             # 패키지 로더 (@load nsm_rules)
  detections/
    main.zeek               # Notice 타입, 공통 파라미터·헬퍼
    evidence_log.zeek       # 증적(evidence.log) 스트림
    auth_context.zeek       # 확산 근거의 계정(최근 NTLM·Kerberos 서비스 티켓 인증)
    detection_log.zeek      # 탐지 요약(nsm_detection.log) 스트림
    attack_mapping.zeek     # Notice → ATT&CK 매핑
    notice_aggregation.zeek # 동일 notice 집계
    correlation_killchain.zeek # 킬체인 상관분석
    nsm_config_fixed.zeek   # 운영 튜닝(redef 전용)
    nsm_config_custom.zeek  # 고객 환경별 설정 — 저장소에서는 빈 파일, 배포 시 별도 기록
    intel_ja3.zeek          # JA3 차단 목록
    exceptions.zeek         # 예외 엔진(예외 파일 TSV, drop·suppress, 재시작 없이 반영)
    proxy_common.zeek       # 명시적 프록시 인식(CONNECT·절대 URL로 실제 목적지, 유출·C2·AI 룰 공용)
    web_common.zeek         # 웹 공격 룰(03·04·28·29) 공용: 대상 판정, 입력 정규화
    ai_common.zeek          # AI 서비스 도메인 목록·이름 판정
    01~35_*.zeek            # 탐지 룰 (1파일 = 1탐지 주제)
  rules/
    ja3/                    # Salesforce JA3 패키지 (BSD)
    filter_log.zeek         # 로그 출력 필터/경로
  metadata/
    main.zeek               # 메타데이터 선별 전송 (/log/zeek/meta, docs/METADATA_EXPORT_PLAN.md)
    community_id.zeek       # 연결 단위 선별 로그·conn 의 Community ID (Suricata 경보 등과 잇는 키)
  asset-id/                 # 자산 식별 센서 (asset_signal.log, claudtest2 PoC 에서 머지, docs/asset-id/)
  sensor/                   # 센서 상태 로그(nsm_sensor.log, 1분마다)·패키지 버전·스키마 버전(schema/build.py 가 생성)
tests/
  gen_pcaps.py              # 합성 pcap 생성기 (scapy)
  pcaps/                    # 룰별 테스트 pcap (생성기 출력, 커밋됨)
  pcaps/zeek/               # Zeek 공개 테스트 trace 발췌 (실제 프로토콜 동작 검증용)
  pcaps/asset-id/           # 자산 식별 테스트 pcap (PoC 에서 가져온 고정 파일, 생성기 재현 대상 아님)
  asset-id/                 # 자산 식별 PoC 의 합성 pcap 생성기(출처 기록용, 바이트 재현되지 않음)
  extract_zeek_traces.py    # 위 발췌 스크립트
  btest/                    # btest 회귀 테스트 (rules/: 단일 프로세스, cluster/: 매니저+워커 2, asset-id/: 자산 식별 단독 + Baseline/, tools/, setup.zeek)
    output/                 # 실행 결과: 테스트별 Zeek 로그(JSON), 커밋 안 함
  run_tests.sh              # 로컬 zeek 또는 Docker(zeek/zeek)로 실행
  measure_meta_export.sh    # 선별 전송·자산 식별 전송량·처리 시간 측정 (pcap 입력, 반복 실행)
  run_pcap.sh               # pcap 1회 실행 결과 요약 + 통합 리포트(<pcap 이름>_report.html): 공격 스토리·탐지·킬체인·자산·선별 전송·전송량·예외·센서 상태. -S 면 Suricata 도 함께
                            #   디렉터리나 pcap 여러 개를 주면 파일마다 따로 실행하고 결과 표·index.html 을 만든다
                            #   -x 예외 파일, -u OUI 파일(IEEE·maclookup 형식), -g Recog XML 폴더(리포트 자산 보강)
  report_pcap.py            # run_pcap.sh 결과로 통합 리포트 생성(단독 실행 가능, 외부 라이브러리 없음)
  report_mockup.py          # 같은 데이터로 목업형 리포트(<pcap 이름>_report_mockup.html, ui/mockup/ 을 템플릿으로)
  suricata_alerts.py        # Suricata 경보 -> 시그니처 탐지(Manager 정규화 규칙의 PoC, run_pcap.sh -s)
  suricata/                 # 테스트 룰·경보 고정본(killchain_story)·생성 스크립트·정규화 단위 테스트·run_pcap.sh -S 통합 테스트(e2e.sh, Docker)·S5 측정 요약(measure.py)
  asset_enrich.py           # 리포트 자산 보강: OUI 제조사, Recog 지문, TCP SYN OS, 장비 유형 판정
schema/
  logs/                     # Manager 로 가는 로그의 JSON Schema(생성됨, docs/LOG_SCHEMA.md 와 함께)
  fields.zeek               # Zeek 레코드 정의에서 필드·열거값을 뽑는 스크립트
  overlay.json              # 필드 설명·열거값·형식(사람이 고침)
  build.py                  # 스키마·문서 생성(--check: 코드와 다르면 실패)
  validate.py               # 로그를 스키마로 검사(CI 가 btest 전체 출력에 실행)
ui/
  mockup/mdsm_nsm_mockup.html  # MDS Manager NSM 화면 목업(예시 데이터). 목업형 리포트의 템플릿(ui/README.md)
  mockup/mdsm_nsm_mockup_phase1.html  # 1차 범위 목업(공격 스토리·과거 기록 검색은 하반기, ui/README.md)
  mockup/integrated_story_mockup.html  # 통합 공격 스토리·통합 상관 룰 목업(MDS·MTA·NSM, 예시 데이터)
docs/
  SRS.md                    # 요구사항 명세·설정 가이드(원본)
  DETECTION_GUIDE.md        # 탐지 룰 쉬운 설명(관제·운영 담당자용, 탐지 48종, 실제 공격 사례·위험도)
  REPORT_SPEC.md            # 통합 리포트(run_pcap.sh·report_pcap.py) 생성 구조와 스펙
  SRS_METADATA_EXPORT.md    # 메타데이터 선별 전송 요구사항 명세·설정 가이드(원본)
  METADATA_EXPORT_PLAN.md   # 메타데이터 선별 전송 개발 계획·스펙
  POC_RESULT.md             # 통합 PoC 결과 보고(자산 식별·탐지·메타데이터, CIC-IDS2017 검증)
  DETECTION_POC_RESULT.md   # 탐지 룰 PoC 결과 보고(룰 34개·48종, CIC-IDS2017 검증)
  METADATA_EXPORT_POC_RESULT.md # 메타데이터 선별 전송 PoC 결과 보고(전송량 측정·Manager 전송량 예측)
  asset-id/                 # 자산 식별 SPEC·DESIGN·POC_RESULT (센서는 claudtest2 에서 머지)
  NSM_RULES_REVIEW.md       # 전체 검토 결과·확대 계획
  EXCEPTION_ENGINE_REVIEW.md # 탐지 예외 엔진(예외를 데이터로) 개발 검토
  LOG_SCHEMA.md             # Manager 로 가는 로그의 필드·타입·열거값(schema/build.py 가 생성, Manager 테이블 기준)
  LOG_SCHEMA_REVIEW.md      # 센서 로그 형식 검토(Manager 개발 관점: 등급 숫자, 센서 식별, 상관 갱신, 근거 필드)
  RETRO_SEARCH_DESIGN.md    # 소급검색 설계안(지표 색인·결손 표시·센서 보강)
  SURICATA_INTEGRATION_DESIGN.md  # Suricata 경보를 Manager로 바로 보내 합치는 설계(정규화·예외·통합 상관·중복 정리)
  INTEGRATED_CORRELATION_DESIGN.md # MDS·MTA·NSM 통합 공격 스토리와 Sigma 상관 룰 기반 통합 상관 설계안
  examples/                 # 예외 파일 예시(exceptions.example.tsv, 문서용 주소만), 기본 예외 목록(exceptions.proxy-beacon.tsv)
```

## 탐지 룰

| 파일 | 탐지 | ATT&CK | 상태 |
|---|---|---|---|
| 01_port_scan | 포트 스캔 | T1046 | 활성 |
| 02_host_scan | 호스트 스캔 | T1018 | 활성 |
| 03_sqli | SQL Injection (내부 웹서버 대상) | T1190 | 활성 |
| 04_webshell | 웹쉘 접근 (내부 웹서버 대상) | T1505.003 | 활성 |
| 05_ntlm_spray | NTLM 패스워드 스프레이 (인증 실패 기반) | T1110.003 | 활성 |
| 06_smb_admin_share | SMB 관리공유 확산 | T1021.002 | 활성 |
| 07_http_beaconing | HTTP 비커닝 | T1071.001 | 활성 |
| 08_dns_tunneling | DNS 터널링 + DNS 유출 (통합) | T1071.004 / T1048.003 | 활성 |
| 09_encrypted_c2 | 암호화 C2 | T1573.002 | 활성 |
| 10_large_transfer_exfil | 단일 연결 대용량 유출 | T1041 | 활성 |
| 12_web_upload_exfil | 클라우드 업로드 유출 | T1567.002 | 활성 |
| 13_dga | DGA 도메인 | T1568.002 | 활성 |
| 14_large_transfer_exfil | 호스트 단위 볼륨 유출 | T1041 | 활성 |
| 15_rdp_lateral | RDP 확산 | T1021.001 | 활성 |
| 16_ssh_lateral | SSH 확산 | T1021.004 | 활성 |
| 17_kerberos_spray | Kerberos 패스워드 스프레이 / 무차별 대입 | T1110.003 / T1110.001 | 활성 |
| 18_kerberoasting | Kerberoasting / AS-REP Roasting | T1558.003 / T1558.004 | 활성 |
| 19_outbound_smb | 외부향 SMB 연결 / 외부 NTLM 인증(자격증명 유출) | T1048 / T1187 | 활성 |
| 20_winrm_dcom_lateral | WinRM / DCOM 내부 확산 | T1021.006 / T1021.003 | 활성 |
| 21_smb_ransomware | 랜섬웨어성 SMB 파일 변경 (Impact) | T1486 | 활성 |
| 22_name_poisoning | LLMNR / NBT-NS / mDNS 포이즈닝 (Responder 류) | T1557.001 | 활성 |
| 23_dcsync | DCSync (DC 가 아닌 host 의 디렉터리 복제 요청) | T1003.006 | 활성 |
| 24_nonstd_port | 외부향 비표준 포트 프로토콜 / 장기 외부 연결 | T1571 / T1572 | 활성 |
| 25_unknown_protocol | 식별 안 된 프로토콜의 외부 통신(역방향 셸 등) | T1095 | 활성 |
| 26_service_bruteforce | SSH / FTP 무차별 대입 | T1110.001 | 활성 |
| 27_heartbleed | TLS Heartbleed(OpenSSL CVE-2014-0160) 시도·성공 | T1190 | 활성 |
| 28_xss | 크로스 사이트 스크립팅 시도(내부 웹서버) | T1190 | 활성 |
| 29_http_bruteforce | 웹 로그인 무차별 대입(폼·JSON·Basic 인증) | T1110.001 | 활성 |
| 30_tls_beaconing | TLS(HTTPS) 비커닝(주기 + 일정한 크기) | T1071.001 | 활성 |
| 31_remote_exec | 단일 대상 원격 실행(원격 서비스·예약 작업·WMI) | T1569.002 / T1053.005 / T1047 | 활성 |
| 32_machine_account | 남의 머신 계정 사용(NTLM 릴레이·해시 전달) | T1557.001 | 활성 |
| 33_ai_threats | AI 관련 위협(AI 서비스 대량 업로드, 서버의 AI API 접속, 사내 AI 인프라 관리 API 공격) | T1567 / T1102 / T1190 | 활성 |
| 34_ad_attacks | AD 공격(강제 인증, 원격 레지스트리 하이브 저장, Zerologon, AD 정보 수집) | T1187 / T1003.002 / T1210 / T1087.002 | 활성 |
| 35_ioc_match | IOC 일치(위협 정보의 IP·도메인·URL과 일치하는 통신, `ioc_file` 지정 시) | T1071 | 활성 |

PC가 명시적 프록시(예: 3128/tcp)로 나가는 환경에서는 CONNECT 대상·절대 URL로 실제 목적지를 알아내 판정합니다(`proxy_common.zeek`).
유출 10·12·14와 C2·AI 09·24·33은 기본으로 켜져 있고, 주기 접속 07·30은 `NSM::proxy_aware_beacon`(기본 끔)으로 켭니다.
켤 때는 기본 예외 목록 `docs/examples/exceptions.proxy-beacon.tsv`를 예외 파일에 붙입니다(SRS 7.8절).

## 사용

```zeek
# local.zeek
@load /path/to/nsm_rules
```

고객 환경 값(내부 대역, 예외 파일 경로 `NSM::exception_file`, IOC 파일 `NSM::ioc_file`, 남길 로그 스트림 등)은 `nsm_rules/detections/nsm_config_custom.zeek`에 `redef`로 둡니다.
예외는 예외 파일(TSV, 재시작 없이 반영)로 관리합니다. 형식은 [docs/SRS.md](docs/SRS.md) 7.8절, 예시는 [docs/examples/](docs/examples/)에 있습니다.
이 파일은 저장소에서는 **빈 파일로 유지**하고, 배포 시 고객 환경별로 별도 기록합니다.

## 테스트

```bash
tests/run_tests.sh                               # btest 전체 (로컬 zeek 없으면 Docker zeek/zeek:9.0.1)
ZEEK_IMAGE=zeek/zeek:8.0.9 tests/run_tests.sh    # Zeek 8.0 으로
tests/run_tests.sh rules/13-dga.zeek             # 일부만
```

- 실행 결과(Zeek 로그, 운영과 같은 JSON)는 테스트마다 `tests/btest/output/<테스트 이름>/`에 남습니다.
  예: `tests/btest/output/rules.17-kerberos-spray/notice.log`. 클러스터 테스트는 `manager/`, `worker-1/` 등 노드별 하위 폴더에 있습니다.
  다음 실행 때 새로 만들어지며 커밋되지 않습니다.
- 로그 검사 도구(`tests/btest/tools/`): `assert-rows`(조건에 맞는 행 수), `assert-evidence-join`(notice ↔ evidence 조인),
  `log-cut`(zeek-cut 대용, JSON·TSV 모두 읽음).

- 룰마다 합성 pcap 하나에 **탐지돼야 하는 호스트와 탐지되면 안 되는 호스트**를 함께 넣고,
  `notice.log` / `nsm_detection.log` / `evidence.log`의 행 수로 검사합니다(`tests/btest/tools/assert-rows`).
- 공통 계약도 검사합니다: notice 1건 = detection 1건, notice의 `evidence_id`는 evidence.log에서 조회 가능, 룰 억제창 적용, 운영 로그 필터.
- pcap은 `python3 tests/gen_pcaps.py tests/pcaps`로 다시 만들 수 있고(결정적 출력), CI가 커밋된 pcap과 생성기 출력이 같은지 확인합니다.
- CI(`.github/workflows/zeek-check.yml`)는 Zeek 9.0.1 / 8.0.9에서 문법 검사, 기동 검사, btest를 실행합니다.

## 요구사항 명세(SRS)

[docs/SRS.md](docs/SRS.md) — 탐지 룰별 요구사항, 로그 형식, 상관 규칙, 설정 파라미터와 고객별 설정 예시, 테스트, 한계.
[docs/SRS_METADATA_EXPORT.md](docs/SRS_METADATA_EXPORT.md) — 메타데이터 선별 전송(탐지와 별도 기능)의 요구사항, 출력 명세, 설정, 운영 절차.
[docs/LOG_SCHEMA.md](docs/LOG_SCHEMA.md) — Manager 로 가는 로그(탐지·근거·예외·자산 신호·선별 전송)의 필드·타입·필수 여부·열거값. 기계가 읽는 정의는 `schema/logs/`의 JSON Schema이고, CI가 테스트 출력 전체를 이 스키마로 검사합니다.
룰·설정·로그 형식을 바꾸는 PR에서는 이 문서도 함께 고칩니다.

## 검토 결과와 작업 계획

[docs/NSM_RULES_REVIEW.md](docs/NSM_RULES_REVIEW.md) 참고 — 1차 검토 지적의 처리 결과, 룰별 검증 상태(합성 pcap·CIC-IDS2017 실측),
남은 위험, 확대 후보(P1/P2), 작업 순서를 정리했습니다.

[docs/EXCEPTION_ENGINE_REVIEW.md](docs/EXCEPTION_ENGINE_REVIEW.md) — 룰별 예외를 공통 예외 엔진(데이터·동적 로딩·사유/만료 필수)으로 옮기는 구조의 개발 검토와 단계별 계획.

## 관련 저장소

- 자산 식별 PoC: `kwsjjang8901-ship-it/claudtest2` — 센서 패키지는 `nsm_rules/asset-id/`로 머지됨. PoC 도구(리졸버·리포트)는 그 저장소에 남음
- OCSF 변환기(zeek-bzar-ocsf, Go): `kwsjjang8901-ship-it/claudtest`
