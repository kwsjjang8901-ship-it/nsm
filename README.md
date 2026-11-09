# NSM 탐지룰 (nsm_rules)

Zeek 기반 NSM(Network Security Monitoring) 탐지 룰 패키지입니다.
미러 트래픽에서 킬체인 단계별(정찰 → 자격증명 → 확산 → C2 → 유출) 위협을 탐지하고,
`notice.log` / `nsm_detection.log` / `evidence.log`로 탐지와 근거를 남깁니다.

- 대상 Zeek 버전: **9.x** (자산 식별 PoC와 동일 기준)
- 현재 상태: 원본(nsm_rules_4.zip) 반입 + 전체 검토 완료, 정리·확대 작업 진행 예정

## 구조

```
nsm_rules/
  __load__.zeek             # 패키지 로더 (@load nsm_rules)
  detections/
    main.zeek               # Notice 타입, 공통 파라미터·헬퍼
    evidence_log.zeek       # 증적(evidence.log) 스트림
    detection_log.zeek      # 탐지 요약(nsm_detection.log) 스트림
    attack_mapping.zeek     # Notice → ATT&CK 매핑
    notice_aggregation.zeek # 동일 notice 집계
    correlation_killchain.zeek # 킬체인 상관분석
    nsm_config_fixed.zeek   # 운영 튜닝(redef 전용)
    nsm_config_custom.zeek  # 고객 환경별 설정 — 저장소에서는 빈 파일, 배포 시 별도 기록
    intel_ja3.zeek          # JA3 차단 목록
    01~20_*.zeek            # 탐지 룰 (1파일 = 1탐지 주제)
  rules/
    ja3/                    # Salesforce JA3 패키지 (BSD)
    filter_log.zeek         # 로그 출력 필터/경로
tests/
  gen_pcaps.py              # 합성 pcap 생성기 (scapy)
  pcaps/                    # 룰별 테스트 pcap (생성기 출력, 커밋됨)
  pcaps/zeek/               # Zeek 공개 테스트 trace 발췌 (실제 프로토콜 동작 검증용)
  extract_zeek_traces.py    # 위 발췌 스크립트
  btest/                    # btest 회귀 테스트 (rules/: 단일 프로세스, cluster/: 매니저+워커 2, tools/, setup.zeek)
  run_tests.sh              # 로컬 zeek 또는 Docker(zeek/zeek)로 실행
docs/
  NSM_RULES_REVIEW.md       # 전체 검토 결과·확대 계획
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

## 사용

```zeek
# local.zeek
@load /path/to/nsm_rules
```

고객 환경 값(내부 대역, 예외 목록, 남길 로그 스트림 등)은 `nsm_rules/detections/nsm_config_custom.zeek`에 `redef`로 둡니다.
이 파일은 저장소에서는 **빈 파일로 유지**하고, 배포 시 고객 환경별로 별도 기록합니다.

## 테스트

```bash
tests/run_tests.sh                               # btest 전체 (로컬 zeek 없으면 Docker zeek/zeek:9.0.1)
ZEEK_IMAGE=zeek/zeek:8.0.9 tests/run_tests.sh    # Zeek 8.0 으로
tests/run_tests.sh rules/13-dga.zeek             # 일부만
```

- 룰마다 합성 pcap 하나에 **탐지돼야 하는 호스트와 탐지되면 안 되는 호스트**를 함께 넣고,
  `notice.log` / `nsm_detection.log` / `evidence.log`의 행 수로 검사합니다(`tests/btest/tools/assert-rows`).
- 공통 계약도 검사합니다: notice 1건 = detection 1건, notice의 `evidence_id`는 evidence.log에서 조회 가능, 룰 억제창 적용, 운영 로그 필터.
- pcap은 `python3 tests/gen_pcaps.py tests/pcaps`로 다시 만들 수 있고(결정적 출력), CI가 커밋된 pcap과 생성기 출력이 같은지 확인합니다.
- CI(`.github/workflows/zeek-check.yml`)는 Zeek 9.0.1 / 8.0.9에서 문법 검사, 기동 검사, btest를 실행합니다.

## 검토 결과와 작업 계획

[docs/NSM_RULES_REVIEW.md](docs/NSM_RULES_REVIEW.md) 참고 — 우선 수정 항목(Critical/High), 비활성 룰 재활성화 조건,
신규 룰 후보(P1/P2), 자산 식별 PoC 머지 이슈, 작업 순서를 정리했습니다.

## 관련 저장소

- 자산 식별 PoC: `kwsjjang8901-ship-it/claudtest2` — `nsm_rules/asset-id/`로 머지 예정
- OCSF 변환기(zeek-bzar-ocsf, Go): `kwsjjang8901-ship-it/claudtest`
