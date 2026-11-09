# nsm_rules 검토 결과

- 검토일: 2026-11-09
- 대상: `nsm_rules/` (nsm_rules_4.zip, 원본 반입 커밋이 베이스라인) — 탐지 룰 16개, 공통 인프라 8개, JA3 패키지, 로그 필터
- 목적: (1) 현재 룰의 동작 정확성·운영 리스크 점검, (2) 비활성 룰 재활성화 판단, (3) NSM 관점 탐지룰 확대 후보 도출, (4) 자산 식별 PoC(`claudtest2`) 머지 시 충돌 점검

## 진행 현황

| 단계 | 항목 | 상태 |
|---|---|---|
| 0 | C1 notice 억제 무력화 → 룰 억제창 존중(`dedup_override_suppression`, 기본 F) | PR (phase0/infra-cleanup) |
| 0 | C2 detection 중복 → "notice.log 1건 = detection 1건" | PR (phase0/infra-cleanup) |
| 0 | C3 로그 필터 → `keep_log_streams`/`log_paths` 설정화, reporter 유지 | PR (phase0/infra-cleanup) |
| 0 | 로그 디렉터리 생성 경쟁 조건: `system("mkdir -p")`는 백그라운드 실행이라 writer가 먼저 파일을 열면 스트림 종료 (CI로 재현) → 동기식 `mkdir()` BIF로 교체 | PR (phase0/infra-cleanup) |
| 0 | H1 03_sqli 정규식 문법 | PR (phase0/infra-cleanup) |
| 0 | 08_dns_tunneling 지역 변수 `sub`가 내장 함수와 충돌해 로드 실패 (CI로 추가 발견) | PR (phase0/infra-cleanup) |
| 0 | 로더 일원화(`detections/__load__.zeek` 삭제, 비활성 룰 경로 수정) | PR (phase0/infra-cleanup) |
| 0 | 정합성: 상관 진단명(RDP/SSH), T1573.002 통일, `172.16.0.0/12`, 주석·파일명, JA3/JA4 문서 | PR (phase0/infra-cleanup) |
| 0 | CI: Zeek 9.0.1/8.0.9 문법 검사 + 런타임 스모크 | PR (phase0/infra-cleanup) |
| 0 | `nsm_config_custom.zeek` 원본 확인 | 확인 완료 — 원래 빈 파일이며 배포 시 별도로 기록됨(저장소에서는 수정하지 않음) |
| 1 | 테스트 체계: 합성 pcap 생성기 + btest 17개(활성 룰 11개 탐지/미탐, 상관, 계약 C1~C3) + CI | PR (phase1/test-framework) |
| 1 | H6 07 비커닝 누락 허용 오탐 → 허용오차 고정 + 연속 누락 상한(`beacon_max_missed`=2) | PR (phase1/test-framework) |
| 2 | H4 13 DGA 미탐 → 지표 변경: qname 평균 엔트로피 대신 **등록 라벨 무작위성 점수**(모음 비율·연속 자음·정규화 엔트로피·숫자 혼합·길이·16진수형) 기반 "무작위형 라벨 비율" | PR (phase2/dga-label-metric) |
| 2 | H5 `parent_domain()` 2단계 공용 접미사(`co.kr` 등) 처리 — `multi_label_suffixes` | PR (phase2/dga-label-metric) |
| 2 | H3 14 볼륨 유출 성능 → `tcp_packet`(패킷마다) 제거, `ConnThreshold`로 step(1MB)마다 깨어나 **페이로드 증가분**만 집계(ACK 헤더 미포함, 장기 연결도 종료 전 탐지) | PR (phase2/volume-connthreshold) |
| 2 | 09 SNI-인증서 불일치를 부분문자열 비교 대신 Zeek `sni_matches_cert`(와일드카드·SAN 반영)로 판정, 증적 버킷을 억제창과 일치 | PR (phase2/tls-sni-match) |
| 2 | 소규모: 15 RDP 근거에 계정(cookie 값이 이미 접두어 없이 전달되어 기존 추출 함수는 항상 빈 값) / 16 SSH 인증 성공 이벤트 1순위 + 연결 휴리스틱 폴백(비표준 포트 포함) / 06 `print$` 제외 / 01 notice 에 대상 IP | PR (phase2/small-fixes) |
| 2 | H2 클러스터 상관: 모든 노드가 notice 요약을 `Cluster::publish`로 매니저에 전달, 상관은 매니저 한 곳에서만. 전이 시간창은 notice 발생 시각 기준. chain_id 에 시각 포함 | PR (phase2/cluster-correlation) |
| 2 | 07 비커닝 클러스터: 워커는 관측값만 만들어 (src,dst) HRW 로 프록시 1대(없으면 매니저)에 전달, 주기 상태는 그 노드에서만. 과거 시각 관측 무시 | PR (phase2/beacon-cluster) |
| 3 | 08+11 DNS 터널링·유출 통합 재작성·활성화: (src,등록도메인) 집계, 수상한 질의(TXT/NULL·긴 라벨·무작위형 라벨) 비율 게이트, 리졸버 제외·AV/DNSBL 기본 예외, 유출 임계 256KB/5분 | PR (phase3/dns-tunnel-exfil) |
| 3 | 03/04 웹 공격 재작성·활성화: 내부 웹서버 대상만, URL 이중 디코딩 정규화, SQL 구문 구조 요구(주석·select-from 단독 제거), 웹쉘은 명령 '값'·페이로드 서명 기준(파라미터 이름 단독 제거), 본문 검사 상한 | PR (phase3/web-attack) |
| 3 | 05 NTLM 스프레이 재작성·활성화: 인증 실패만 집계(SMB 세션 설정 실패 NTSTATUS + SPNEGO reject — Zeek ntlm.log success 는 SMB 실패 시 비어 있음), 계정 대소문자 정규화, 내부 서버 대상·예외 출발지 | PR (phase3/ntlm-spray) |
| 4~5 | 신규 룰, 연동 | 예정 |

## 0. 검토 방법과 한계

| 구분 | 내용 |
|---|---|
| 정적 분석 | 전체 `.zeek` 파일 정독 (로드 순서, 룰 로직, 공통 프레임워크, 설정 파일) |
| Zeek 소스 대조 | GitHub `zeek/zeek` 태그 **v3.0.14 / v6.0.0 / v9.0.1** 소스를 직접 읽어 확인: 사용 이벤트·BIF 존재 여부, 정규식 문법, SSL subject/issuer 채움 시점, Notice 억제 로직, SumStats 클러스터 동작, `log_notice` 발생 위치, `Site::local_nets` 기본값 |
| 수치 검증 | DGA/터널링 엔트로피 임계를 Shannon 엔트로피 시뮬레이션으로 검증 (부록 A) |
| **미수행** | **Zeek 실행 검증(`zeek -a`, pcap 재생)은 하지 못함** — 이 작업 환경에서 Zeek 설치가 막혀 있음. 아래 "[소스확인]"은 Zeek 소스로 확인한 항목, "[정적분석]"은 코드 해석 기반, "[확인필요]"는 실측이 필요한 항목 |

**대상 Zeek 버전 전제:** 자산 식별 PoC 결론이 "센서 Zeek **9.x 필수**"이고 nsm_rules에 머지할 예정이므로 **Zeek 9.x 기준**으로 검토했다. nsm_rules 쪽 주석(16번 SSH, JA3 README)은 아직 **Zeek 3.0.14** 기준 설명이 남아 있다. nsm_rules가 사용하는 이벤트·BIF는 v9.0.1 소스에 모두 존재함을 확인했다(호환성 문제 없음) [소스확인].

---

## 1. 요약 (TL;DR)

**바로 고쳐야 할 것 (운영 영향 큼)**

| # | 심각도 | 문제 | 위치 | 영향 |
|---|---|---|---|---|
| C1 | **Critical** | `notice_aggregation`이 **모든 notice의 `suppress_for`를 0으로 덮어씀** → 룰마다 정한 억제창(1hr 등)과 `nsm_config_fixed`의 `suppress_*` 설정이 전부 무력화 | `detections/notice_aggregation.zeek:87` | 연결 단위 룰(09/10/12, 03/04)은 연결마다 notice 생성. 1분 dedup만 남음 [소스확인] |
| C2 | **Critical** | `detection_log`가 dedup으로 **로깅이 제거된 중복 notice와 요약 notice까지 매번 detection 행을 기록** | `detections/detection_log.zeek:68-129` | `nsm_detection.log` 중복·폭증, notice.log와 건수 불일치 [정적분석] |
| C3 | **Critical** | `filter_log`가 **활성 로그 스트림을 전부 끄고** detection/evidence/notice/capture_loss/stats/loaded_scripts만 켬 | `rules/filter_log.zeek:13-19` | conn/dns/ssl 등이 없어 evidence의 `uid` 조인 불가, **reporter.log도 꺼져 스크립트 런타임 에러가 안 보임**, 자산 식별 머지 시 **`asset_signal.log`도 꺼짐**, zeek-bzar-ocsf Go 변환기(claudtest 저장소) 입력 소실 [정적분석] |
| H1 | High | `03_sqli` 정규식 `(?:...)`는 **Zeek 정규식 문법에 없음** → 주석 해제 시 로드 실패 | `detections/03_sqli.zeek:28` | Zeek는 `(?i:` `(?s:`만 지원 [소스확인] |
| H2 | High | 클러스터에서 **상관분석(kill-chain)이 노드별로 쪼개짐**: SumStats 룰은 매니저에서, 연결 단위 룰(07/09/10/12)은 워커에서 notice → `Notice::log_notice`가 각 노드에서 발생 → `primes` 상태 불일치 | `detections/correlation_killchain.zeek:307` | C2(워커)→확산(매니저), 확산(매니저)→단일연결유출(워커) 전이가 **클러스터에서는 연결되지 않음**. standalone에서는 정상 [소스확인] |
| H3 | High | `14_large_transfer_exfil`이 **`tcp_packet`(패킷마다 발생)** 으로 집계 | `detections/14_large_transfer_exfil.zeek:88` | 고대역 CPU 부하 → 패킷 손실 → 전체 룰 품질 저하. Zeek 문서도 사용 자제 권고 |
| H4 | High | `13_dga` 평균 엔트로피 임계 **4.0은 일반 DGA(라벨 8~16자)가 도달 불가** | `main.zeek:181`, `nsm_config_fixed.zeek:120` | 16자 라벨도 4.0 이상은 8.9%뿐 → **사실상 미탐** (부록 A) |
| H5 | High | `parent_domain()`이 "마지막 2라벨" 근사 → **`co.kr`/`or.kr`/`go.kr`/`ac.kr` 전체가 한 부모 도메인**으로 묶임 | `main.zeek:244-251` | 08/11(비활성)이 국내 사이트 정상 조회로 오탐. 재활성화 전제 조건 |
| H6 | High | `07_http_beaconing` 비콘 누락 허용 오차가 `기준주기×jitter×k`로 배수에 비례 → jitter 0.25면 기준주기 1.5배 이상인 **모든 간격이 박자 맞음** | `07_http_beaconing.zeek:106` | 같은 외부 IP로 불규칙 HTTP 연결 13회 이상이면 비커닝 오탐 (1단계 회귀 테스트로 발견) |

**구조/정합성:** 로더 2개 중복·주석 해제 시 경로 오류, 문서·주석의 파일명/임계값 불일치, 룰 번호 체계 불일치(파일 번호 ≠ enum 주석 번호), ATT&CK 코드 이중 관리(09: evidence `T1573` vs notice `T1573.002`), 상관 진단명 버그(RDP/SSH 종료 체인) 등. → 3장.

**확대 방향:** 현재 룰은 정찰·확산·C2·유출 "골격"은 갖췄지만 **AD 인증 공격(Kerberos), 외부향 정책 위반, HTTPS 기반 C2, 영향(랜섬웨어) 단계**가 비어 있다. 우선순위 P1 9개를 6장에 정리했다.

---

## 2. 룰 현황

| 파일 | Notice | ATT&CK | 상태 | 방식 | 핵심 이슈 | 권고 |
|---|---|---|---|---|---|---|
| 01_port_scan | Port_Scan | T1046 | 활성 | SumStats UNIQUE(포트) | TCP만(UDP 스캔 미탐), notice에 `$dst` 없음 → detection victims 공란 | 유지 + `$dst` 추가 |
| 02_host_scan | Host_Scan | T1018 | 활성 | SumStats UNIQUE(호스트) | 포트 스윕은 T1046에 더 가까움, ICMP ping sweep 미탐 | 유지 (매핑 검토) |
| 03_sqli | SQL_Injection | T1190 | **비활성** | URI/본문 정규식 | **로드 실패 문법(H1)**, `#` 단독·`select…from` 등 오탐성 패턴, 방향 미제한 | 재작성 후 재활성화 (5장) |
| 04_webshell | Webshell_Access | T1505.003 | **비활성** | URI 정규식 | `[?&]c=`, `cmd=`, `run=` 등 매우 광범위 → 오탐 | 재작성 후 재활성화 (5장) |
| 05_ntlm_spray | NTLM_Spray | T1110.003 | **비활성** | SumStats UNIQUE(계정) | **성공/실패 구분 없음**, 방향·allowlist 없음 → 프록시/Exchange/Citrix 오탐 | 실패 기반으로 재작성 + Kerberos 추가 |
| 06_smb_admin_share | SMB_Admin_Share | T1021.002 | 활성 | SumStats epoch_result | `print$` 등 정상 `$` 공유 포함, 계정(WHO) 미채움(주석과 다름), 표본 기반 피해 host 누락 가능 | 패턴 정교화 |
| 07_http_beaconing | HTTP_Beaconing | T1071.001 | 활성 | 상태머신(워커 로컬) | **평문 HTTP만**, (src,dst IP) 키라 CDN IP 변경 시 미탐, 종료 순서로 처리해 시각 역행 가능, keep-alive 다중 요청 미반영 | TLS/SNI 확장 (6장 N5) |
| 08_dns_tunneling | DNS_Tunneling | T1071.004 | **비활성** | SumStats UNIQUE(서브도메인) | H5, 리졸버 서버가 src로 집계, TXT 정상 조회(SPF/DMARC/AV 평판) 오탐, allowlist 없음 | 11과 통합 재작성 |
| 09_encrypted_c2 | Encrypted_C2 | T1573(.002) | 활성 | 가중 스코어 | **TLS 1.3은 인증서가 암호화되어 selfsigned/mismatch 신호 소실**, SNI 불일치를 부분문자열로 판정(와일드카드·SAN 인증서 오탐), JA3 인텔 노후 | `sni_matches_cert`(Zeek 6+) 사용 |
| 10_large_transfer_exfil | Exfil_Large_Transfer | T1041 | 활성 | 연결 종료 시 orig 바이트 | 장기 연결은 **종료 시점에만** 탐지, allowlist 없음 | ConnThreshold로 실시간화 |
| 11_dns_exfil | Exfil_DNS | T1048.003 | **비활성** | SumStats SUM(qname 길이) | H5, 1MB/5분은 실제 DNS 유출 속도 대비 과대, 리졸버 집계 | 08과 통합 재작성 |
| 12_web_upload_exfil | Exfil_Web_Upload | T1567.002 | 활성 | 연결 종료 + SNI/Host 패턴 | `.*\.amazonaws\.com` 등 범위 과대(백업/CI), 10과 동시 발화(문서화됨) | 패턴 세분화 |
| 13_dga | DGA_Domain | T1568.002 | 활성 | SumStats epoch_result 3중 게이트 | **H4 엔트로피 임계 도달 불가** | 임계/지표 재설계 |
| 14_large_transfer_exfil | Exfil_Volume_Aggregate | T1041 | 활성 | `tcp_packet` SumStats | **H3 성능**, 설정 주석 "5MB" ≠ 실제 50MB | ConnThreshold 전환 |
| 15_rdp_lateral | RDP_Lateral | T1021.001 | 활성 | SumStats epoch_result | `rdp_user_from_cookie()` 정의만 있고 미사용 → 계정(WHO) 없음 | 계정 채움 |
| 16_ssh_lateral | SSH_Lateral | T1021.004 | 활성 | 연결 종료 바이트 휴리스틱 | 22/tcp 고정(비표준 포트 미탐), Zeek 3.0.14 우회 로직 | Zeek 9.x면 `ssh_auth_successful` 복원 |

---

## 3. 공통·인프라 상세

### 3.1 Notice 억제/집계/Detection 로그 (C1, C2)

- `notice_aggregation.zeek:87` `n$suppress_for = 0secs;` — Zeek 9 `Notice::notice` 훅은 `suppress_for != 0`일 때만 억제를 시작한다(`base/frameworks/notice/main.zeek`) [소스확인]. 결과적으로 **어떤 notice도 프레임워크 억제를 받지 않는다.** 1분 dedup 창이 끝나면 같은 이벤트가 다시 "첫 건"으로 나간다.
  - 09(연결 단위 스코어), 10/12(연결 종료) 같은 룰은 **연결마다** notice → 1분마다 첫 건 + 요약 notice 반복.
  - `nsm_config_fixed`의 `suppress_enc_c2 = 1hr` 등은 **효과 없음**.
- `detection_log.zeek` 정책 훅(priority -6)은 dedup 훅(-5) 뒤에 실행되는데, `ACTION_LOG`가 제거된 중복 건과 `dup_count`가 붙은 요약 건을 **걸러내지 않는다** → notice.log에는 1건인데 nsm_detection.log에는 N+1건.
- **권고**
  1. 집계 레이어는 **룰이 정한 `suppress_for`를 존중**하도록 변경 (0으로 덮지 말고, dedup 대상 notice에만 적용하거나 `dedup_notes`를 명시 목록으로 운영).
  2. `detection_log` 훅 첫머리에 `if ( n?$dup_count || Notice::ACTION_LOG !in n$actions ) return;` 추가 — "notice.log에 남는 건 = detection 1건" 계약으로 정리.
  3. dedup 상태(`dedup_tbl`)는 노드 로컬임을 문서화(클러스터에서 워커별 집계).

### 3.2 로그 필터 (C3)

`rules/filter_log.zeek`는 `Log::active_streams` 전체를 `disable_stream` 한 뒤 6개만 켠다.

| 꺼지는 로그 | 영향 |
|---|---|
| conn / dns / http / ssl / smb_* / dce_rpc / kerberos / files | evidence 설계("원본은 uid/fuid로 다시 조인", `evidence_log.zeek:10`)가 성립하지 않음. zeek-bzar-ocsf Go 변환기(claudtest `configs/config.yaml` logs 목록)가 읽을 파일이 없음 |
| **reporter** | 스크립트 런타임 에러·경고가 보이지 않음 → 룰 고장 감지 불가 |
| weird | 분석기 이상(evasion 징후) 확인 불가 |
| **asset_signal** (머지 후) | 자산 식별 PoC 결과물이 출력되지 않음 (DESIGN.md 7장 5번 "선별 전송 대상에 asset_signal 추가"와 충돌) |

추가로 `zeek_init`에서 `system("mkdir -p ...")`를 모든 노드가 실행하는데, Zeek `system()`은 명령을 **백그라운드로** 실행하므로 디렉터리가 생기기 전에 로그 writer가 파일을 열면 `No such file or directory`로 스트림이 종료되는 경쟁 조건이 있다(CI에서 재현). 또 경로가 하드코딩(`/hdd_tmp`, `/log`)되어 있다. CaptureLoss/Stats/LoadedScripts 스트림은 해당 policy 스크립트가 로드돼 있어야 컴파일된다(기본 local.zeek 의존).

**권고:** "전부 끄고 일부 켜기" 대신 **켜둘 목록을 설정값(`const keep_streams: set[Log::ID] &redef`)으로 분리**하고 최소한 `Reporter::LOG`, `AssetID` 로그, evidence 조인에 필요한 원본 로그(용량 문제면 별도 경로/짧은 보존)를 포함. 디렉터리 생성은 배포 스크립트로 이동.

### 3.3 상관분석 (H2 외)

| # | 문제 | 위치 | 권고 |
|---|---|---|---|
| a | **클러스터 분할** (H2): SumStats 콜백은 매니저에서 실행되고(`sumstats/cluster.zeek`), `Notice::log_notice`는 `Log::write`를 호출한 노드에서 발생(`logging/Manager.cc:1024`) [소스확인]. 07/09/10/12 notice는 워커의 `primes`에, 01/02/06/13/14/15/16 notice는 매니저의 `primes`에 쌓인다 | `correlation_killchain.zeek:77,307` | 워커는 notice 요약을 `Cluster::publish(Cluster::manager_topic, ...)`로 매니저에 보내고, 상관은 **매니저에서만** 수행 (`@if ( Cluster::local_node_type() == Cluster::MANAGER )`) |
| b | 진단명 버그: `stage_tag_map`에 `RDP_Lateral`, `SSH_Lateral` 없음 → `NSM.Correlation.C2.NSM::RDP_Lateral` 형태로 출력 | `:140-155` | 두 항목 추가 (또는 `stage_name_map`과 단일화) |
| c | 전이 규칙 순서가 현실과 어긋남: **Recon→C2**만 있고 **C2→Recon**, **Recon→Lateral**(같은 host가 스캔 후 SMB 확산), **C2→Exfil**(확산 없이 감염 host가 직접 유출) 전이가 없음. 감염 → 비커닝 시작 → 내부 스캔 순서가 일반적이라 현재 규칙으로는 이어지지 않음 | `:21-48` | 전이 추가: C2→Recon, Recon→Lateral(SRC_TO_SRC), C2→Exfil(SRC_TO_SRC), Lateral→Exfil_Web_Upload/Exfil_DNS |
| d | `chain_id = "kc-<counter>"` → 재시작 시 번호 재사용, 과거 로그와 충돌 | `:136` | `cat("kc-", peer, "-", network_time(), "-", counter)` 등 |
| e | `stage_attack[Encrypted_C2] = "T1573"` vs `attack_map` `"T1573.002"` | `:57`, `attack_mapping.zeek:19` | ATT&CK 매핑 단일 소스화 (3.5) |

### 3.4 로드 구조

- 루트 `__load__.zeek:10-12,17,20` 비활성 룰 경로가 `./03_sqli` 형태 → **주석만 풀면 파일을 못 찾아 로드 실패** (`./detections/03_sqli`가 맞음).
- `detections/__load__.zeek`는 루트 로더와 **목록이 다른 두 번째 로더**이고 `@load nsm_rules/detections/main`(ZEEKPATH 의존 경로)을 쓴다. `@load nsm_rules/detections`로 로드하면 filter_log·JA3 패키지가 빠진 다른 구성이 된다 → 삭제하거나 루트 로더 하나로 일원화.
- `nsm_config_fixed.zeek` 머리말은 "가장 마지막에 로드"라고 하지만 실제로는 뒤에 custom/intel_ja3/policy/filter_log가 온다. 또 `nsm-detection`, `nsm-config.zeek`, `correlation-killchain.zeek`, `intel-ja3` 등 **하이픈 이름**으로 참조 — 실제 파일명(언더스코어)과 불일치.
- `rules/PACKAGES-README.md`는 "JA4 주력, `# @load ./rules/ja4` 해제"를 안내하지만 루트 로더에 ja4 줄이 없고, `nsm_config_fixed.zeek:99`는 "JA4는 라이선스상 제품 미사용"이라 서로 모순.

### 3.5 설정·문서 정합성

| 항목 | 불일치 |
|---|---|
| 룰 번호 | 파일 번호와 `main.zeek` enum 주석·파일 헤더 번호가 다름 (예: 08 파일 = "[9] DNS 터널링", 13 파일 = "[16] DGA", 10 파일 = "[13]") |
| 10번 임계 | 헤더/`main.zeek` "100MB" vs `nsm_config_fixed.zeek:142` 50MB |
| 14번 임계 | `nsm_config_fixed.zeek:156` 주석 "5MB/1min" vs 값 `50.0*1024*1024` |
| 06번 임계 | 룰 기본 `vector(3,5,30)` / 설정 `vector(2.0,3.0)` — `epoch_result`는 `[0]`만 사용하므로 나머지 단계값은 의미 없음 (15/16 동일) |
| 06번 문서 | 헤더는 "observe 시점마다 evidence 적재, NTLM 계정(WHO) 채움"이나 실제는 탐지 시점 표본 적재·계정 없음 |
| ATT&CK | 각 룰이 `write_evidence($technique=...)`를 하드코딩 + `attack_map` + `stage_attack` 3중 관리. `DNS_Tunneling = "T1071.004, T1572"`만 공백 포함 |
| local_nets 예시 | `nsm_config_fixed.zeek:30` **`172.0.0.0/8`** — 사설 대역은 `172.16.0.0/12`. 그대로 쓰면 공인 IP 상당 부분이 내부로 판정되어 C2/유출 미탐 |
| custom 설정 | `nsm_config_custom.zeek`는 **원래 빈 파일**이고 고객 환경 값(local_nets, allowlist 등)은 배포 시 별도로 기록됨(사용자 확인). config 주석의 "custom에 포함됨"은 이 배포 시점 기록을 가리킴. 저장소에서는 이 파일을 수정하지 않는다 |
| 심각도 | `detection_log`는 단일 탐지를 전부 `"Information"`으로 기록 — 룰별 심각도 없음 |

**권고:** `main.zeek`에 룰 레지스트리 하나(`rule_id`, note, ATT&CK, 단계, 심각도)를 두고 evidence/detection/상관이 모두 거기서 읽도록 정리.

### 3.6 Zeek 9.x 전환 시 활용할 수 있는 것

| 항목 | 현재 | Zeek 9.x에서 |
|---|---|---|
| 09 SNI 불일치 | `server_name !in subject` 부분문자열 | `c$ssl$sni_matches_cert` (Zeek 6+, `x509_check_cert_hostname` 기반, 와일드카드·SAN 처리) [소스확인] |
| 16 SSH | 바이트/지속시간 휴리스틱 | `ssh_auth_successful` / `ssh_auth_failed` (주석에도 복원 권장) [확인필요: 운영 OpenSSH 버전으로 실측] |
| 10/14 볼륨 | 종료 시점 / `tcp_packet` | `ConnThreshold::set_bytes_threshold()` + `ConnThreshold::bytes_threshold_crossed` (연결 진행 중 실시간) |
| 15 RDP | `rdp_connect_request(c, cookie)` | 2인자 시그니처는 9.0.1에도 유지됨(3인자 `flags` 버전 병존) — 호환 문제 없음 [소스확인] |
| 내부망 | `local_nets` 미설정 시 전 룰 무력화 걱정 | `Site::private_address_space_is_local = T`(기본)로 사설 대역이 `local_nets`에 자동 병합 [소스확인]. **내부에 공인 IP를 쓰는 고객은 반드시 지정** (자산 식별 README와 동일 주의) |

---

## 4. 룰별 상세 (활성 룰)

**01/02 스캔** — 구조 양호. `connection_attempt/rejected/established`는 TCP 이벤트라 UDP·ICMP 스캔은 대상 밖. 01 notice에 `$dst=to_addr(target)`를 넣으면 detection victims와 상관 DST 피벗에 쓸 수 있다. 표본 수 `10` 하드코딩 → `lm_num_samples`로 통일.

**06 SMB 관리공유** — `/(?i:.*\\[A-Za-z]*\$$)/`는 `print$`(프린터 드라이버 공유) 같은 정상 숨김 공유도 매칭. `ADMIN$`, `C$`~`Z$` 등 명시 목록 + `IPC$` 제외가 더 정확. SAMPLE은 "관측 표본"이라 같은 목적지 반복 접근이 많으면 표본 20개에 고유 목적지가 다 안 들어올 수 있음(UNIQUE 수와 victims 수 불일치). BZAR `T1021.002`와 역할 중복 — 06은 "다수 host 확산(fan-out)", BZAR는 "개별 행위"로 역할 정의 필요(8장).

**07 HTTP 비커닝** — (H6, 1단계에서 수정) 비콘 누락 허용 오차가 배수 k에 비례해 불규칙 트래픽도 비커닝으로 판정하던 결함이 있었다. 현재 C2 대부분이 HTTPS라 커버리지가 낮다. `connection_state_remove`에서 `c$start_time`으로 순서를 판단해 장기 연결이 늦게 끝나면 `last_seen`이 과거로 되돌아감. `http_request` 이벤트 기반 + 키를 (src, Host/SNI)로 바꾸고 TLS까지 확장하는 것을 권장(6장 N5).

**09 암호화 C2** — 점수 구성상 TLS 1.3(인증서 암호화)에서는 `no_sni`(1) + JA3(3)만 남아 **사실상 JA3 단독 룰**. JA3 인텔 97개는 abuse.ch SSLBL 기반(Tofsee/Adware 다수)이고 해당 피드는 더 이상 갱신되지 않는다. Chrome 등은 확장 순서를 무작위화해 브라우저 JA3는 불안정(악성코드 고정 지문 매칭은 여전히 유효). 들여쓰기(탭/스페이스 혼용 `:75-79`) 정리 필요. evidence `$technique="T1573"`, eid 버킷 `time_bucket(1hr)` 고정(설정 `suppress_enc_c2`와 별개).

**10/12/14 유출** — 10과 14는 의미가 겹치고(단일 연결 vs 호스트 합계) 10·12는 같은 연결에 동시 발화. 14의 `tcp_packet`은 재전송 바이트까지 합산. 권고: 10·14를 ConnThreshold 기반 하나의 "외부향 대용량 전송" 룰(연결 단위 + 호스트 합계 2단)로 통합하고, 12는 서비스 식별 컨텍스트 룰로 유지. 백업/동기화 서버용 src allowlist 필요.

**13 DGA** — (H4, 2단계에서 지표 변경) 3중 게이트 중 엔트로피가 병목(H4). 실제 판별력은 NXDOMAIN 수·비율에서 나오므로 (1) 엔트로피 임계 3.3~3.5로 하향 또는 (2) 전체 qname 대신 **등록 라벨만**(eTLD+1의 첫 라벨) 길이 정규화 엔트로피 + 자음/숫자 비율 사용을 권장. 내부 DNS 서버(재귀 리졸버)가 src로 잡히지 않도록 리졸버 제외 집합 필요(자산 식별의 DNS 서버 역할 활용 가능).

**15 RDP / 16 SSH** — 구조 양호(06과 동일 패턴). 15는 쿠키 계정을 SAMPLE 문자열에 함께 실어(`dst|user`) evidence `$account`로 채우면 됨. 16은 `"SSH" in c$service` 조건을 추가하면 비표준 포트도 커버.

---

## 5. 비활성 룰 재활성화 판단

| 룰 | 비활성 원인 추정 | 판단 | 재활성화 조건 |
|---|---|---|---|
| 03 SQLi | **로드 실패 문법**(`(?:`) + 오탐 패턴 | 재작성 | `(?:` 제거, `#`·`--`·`/*` 단독 패턴 삭제(조합 조건으로만), **외부→내부 웹서버 방향**으로 제한, 서버 응답코드(5xx/200)·요청 빈도 조합, URL 디코딩 2회 대응 |
| 04 Webshell | 광범위 파라미터 패턴 오탐 | 재작성 | 파라미터 단독 매칭 제거, "스크립트 확장자 + 명령 파라미터 + 비정상 응답 크기" 조합, 신규 업로드(POST multipart로 .jsp/.php 업로드) 후 같은 경로 접근 시퀀스 |
| 05 NTLM Spray | 성공/실패 미구분 → 프록시·메일 서버 오탐 | 재작성 | `hook NTLM::log_policy`에서 `rec$success == F`만 집계 (ntlm 스트림에는 `$ev` 이벤트가 없음 [소스확인]), 내부 src·allowlist, **Kerberos 스프레이(6장 N1)와 함께** 운영 |
| 08 DNS 터널링 | **로드 실패**(지역 변수 `sub`가 내장 함수 `sub()`와 충돌, CI로 확인 → 0단계에서 수정) + H5(`co.kr` 묶임) + 리졸버 집계 + TXT 오탐 | 11과 통합 재작성 | 국내 2단계 도메인(co/or/go/ac/ne/re.kr 등) + 주요 공용 접미사 소형 목록 내장, 리졸버 src 제외, 도메인 allowlist(AV 평판 조회 등), 신호를 OR가 아닌 **점수 합산** |
| 11 DNS 유출 | 08과 동일 + 1MB/5분 과대 | 08과 통합 | (src, 부모도메인)별 "고유 서브도메인 수 + 누적 인코딩 바이트 + 평균 라벨 길이" 하나의 SumStats로 집계 → 터널링/유출을 심각도로 구분 |

---

## 6. 탐지룰 확대 후보 (없는 룰)

선정 기준: Zeek 기본 로그/이벤트로 구현 가능, 미러 구간에서 관측 가능, 기존 프레임워크(SumStats·evidence·상관) 재사용, 오탐 통제 가능.

### P1 — 우선 구현 권장

| ID | 룰 | ATT&CK | 데이터 | 방식 | 오탐 통제 | 비고 |
|---|---|---|---|---|---|---|
| N1 | **Kerberos 패스워드 스프레이/무차별 대입** | T1110.003 / .001 | kerberos.log (`KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`) | src별 실패 고유 계정 수(스프레이) / 계정별 실패 수(브루트포스) SumStats | 내부 src, 서비스 계정 allowlist | AD 환경 인증은 NTLM보다 Kerberos가 주류 → 05보다 우선 |
| N2 | **Kerberoasting / AS-REP Roasting** | T1558.003 / .004 | kerberos.log (TGS-REQ cipher `rc4-hmac`, 서비스 수 / AS-REQ 사전인증 없이 성공) | src별 RC4 TGS 고유 서비스 수 SumStats | AES 강제 환경에서 RC4 자체가 강한 신호 | 소량 이벤트, 고신뢰 |
| N3 | **외부향 SMB/NTLM 인증** | T1187, T1048 | conn(445/139 외부), ntlm(외부 서버) | 내부→외부 445 성립·NTLM 인증 단건 | 거의 없음(정책 위반 자체) | 구현 난이도 최저, NTLM 해시 유출 차단 확인용 |
| N4 | **랜섬웨어성 SMB 대량 파일 변경** | T1486 / T1485 | smb_files (`SMB::FILE_RENAME`, `FILE_DELETE`, 쓰기) | src별 짧은 창 내 rename/delete 수·고유 디렉터리 수 SumStats, 확장자 변경 패턴 | 백업/동기화 서버 allowlist | 영향(Impact) 단계 공백 해소, 상관 최종 단계로 연결 |
| N5 | **TLS/SNI 비커닝** (07 확장) | T1071.001 / T1573 | ssl (SNI), conn | 07 상태머신을 (src, SNI 또는 dst) 키로 TLS에 적용, 주기·간격 분산 기반 | 도메인 allowlist(업데이트/텔레메트리) 공용화 | 현재 C2 커버리지의 가장 큰 공백 |
| N6 | **LLMNR/NBT-NS/mDNS 포이즈닝 (Responder)** | T1557.001 | dns(LLMNR 5355, mDNS), NBNS 137 | 한 host가 짧은 창에 **서로 다른 다수 이름**에 응답 | DNS 서버 제외 | 자산 식별 PoC가 LLMNR/NBNS/mDNS를 이미 파싱 → 이벤트 재사용 |
| N7 | **DCSync** | T1003.006 | dce_rpc (`drsuapi` `DRSGetNCChanges`) | **DC가 아닌** src의 복제 요청 단건 | DC 목록 필요 → 자산 식별 "도메인 컨트롤러" 역할 / 설정 | 고신뢰. BZAR 커버 여부 확인 후 중복 회피 |
| N8 | **WinRM/DCOM 내부 확산** | T1021.006 / .003 | conn(5985/5986), dce_rpc(`IRemoteSCMActivator`) | 15/16과 동일 fan-out 구조 | 관리 서버 allowlist | 06/15/16 템플릿 재사용 → 구현 비용 낮음 |
| N9 | **비표준 포트 프로토콜 / 장기 연결** | T1571 / T1572 | conn (`service` vs `resp_p`, `duration`) | 외부향 HTTP/TLS/SSH가 비표준 포트, 외부 연결 N시간 이상 지속 | 포트·목적지 allowlist | 정책형, 단순 |

### P2 — 다음 단계

| ID | 룰 | ATT&CK | 데이터/방식 |
|---|---|---|---|
| N10 | LDAP 대량 조회 (BloodHound류) | T1087.002 / T1069.002 / T1482 | Zeek 9 ldap.log·ldap_search: src별 검색 수, `servicePrincipalName=*`, `adminCount=1`, `(objectClass=trustedDomain)` 필터 |
| N11 | DoH/DoT 우회 | T1572 / T1071.004 | SNI가 공용 DoH 리졸버, 853/tcp 외부향 (브라우저 정책과 연계) |
| N12 | Tor/익명 프록시 | T1090.003 | Tor 기본 포트, Tor 인증서 패턴(무작위 `www.*.com` SNI + 짧은 유효기간) |
| N13 | ICMP 터널링/유출 | T1095 / T1048 | ICMP echo 페이로드 크기·고유성, 누적 바이트 |
| N14 | 평문 인증정보 노출 | T1552 / T1040 | HTTP Basic, FTP USER/PASS, Telnet, LDAP simple bind(389) — 정책 점검형 |
| N15 | 대체 프로토콜 유출 (FTP/SMTP) | T1048.003 | 외부향 FTP STOR 바이트, 메일 서버가 아닌 host의 외부 SMTP |
| N16 | SSH/RDP 무차별 대입 | T1110.001 | Zeek 9 `ssh_auth_failed`, RDP 단시간 다수 짧은 연결(1 src → 1 dst) |
| N17 | ARP 스푸핑 / 불법 DHCP 서버 | T1557.002 / .003 | 게이트웨이 IP의 MAC 변경, 비인가 DHCP OFFER — 자산 식별 L2/DHCP 신호 재사용 |
| N18 | ICMP ping sweep, UDP 스캔 | T1018 / T1046 | 01/02 확장 |
| N19 | 미관리 자산 통신 | — | 자산 식별 Next 단계(MDS Agent 목록 대조) 이후 |

### 상관 규칙 확대

N1/N2(자격증명) → 06/15/16/N8(확산), N7(DCSync) → 유출, 확산 → N4(랜섬웨어 영향) 전이를 추가하면 킬체인이 "정찰 → 자격증명 → 확산 → 영향/유출"까지 이어진다. 3.3 c항의 순서 보정과 함께 진행.

---

## 7. 자산 식별 PoC 머지 관점

| 항목 | 내용 | 조치 |
|---|---|---|
| 로그 필터 충돌 | C3: `asset_signal.log`가 꺼짐 | `filter_log` 유지 목록에 AssetID 스트림 추가 |
| Zeek 버전 | 자산 식별은 9.x 필수, nsm_rules 주석은 3.0.14 기준 | **9.x로 기준 통일**, 16번 SSH 등 3.0.14 우회 로직 정리 |
| 이벤트 공유 | 자산 식별이 dhcp/kerberos/ntlm/ldap/nbns/llmnr를 이미 처리 | N1/N2/N6/N10/N17은 같은 이벤트 핸들러를 추가하는 구조라 **충돌 없음**(AssetID는 Info 레코드를 redef하지 않음, DESIGN.md 7장) |
| 오탐 감소 연계 | 역할 판정(DC, DNS 서버, 파일 서버)은 현재 Python 리졸버(Manager)에서 수행 | 센서 단계에서 쓰려면 `service` 신호 기반 역할 집합을 Zeek 쪽에 노출하거나 설정 파일로 주입 → 13(DNS 서버 제외), N7(DC 목록), 06/N4(파일 서버) allowlist에 사용 |
| 테스트 체계 | 자산 식별은 btest 28개 + 합성/공개 pcap + 버전 교차 검증 | nsm_rules는 **테스트 없음** → 동일 체계 도입(9장) |

---

## 8. zeek-bzar-ocsf Go 변환기(claudtest 저장소)와의 연동

| 항목 | 현재 | 영향 |
|---|---|---|
| notice 처리 | claudtest `internal/bzar/mitre.go:207` `IsBZARNotice()`가 `BZAR::` 접두어만 통과 | **`NSM::` notice는 OCSF Detection Finding으로 변환되지 않음** |
| 입력 로그 | conn/dns/http/ssl/smb_*/dce_rpc/notice를 `/opt/zeek/logs/current`에서 tail | filter_log가 대부분 끄고, notice는 `/hdd_tmp/log/zeek/notice`로 경로 변경 |
| 신규 로그 | `nsm_detection`, `evidence` 미지원 | detection → OCSF 2004, evidence → `evidences[]` 매핑 추가 필요 |
| BZAR 중복 | README 기준 BZAR가 SMB Admin Share·WinRM·DCOM 등 커버 | nsm_rules 06·N8과 역할 정의 필요 (fan-out 집계 vs 개별 행위). BZAR 병행 운영 여부 결정 필요 |

---

## 9. 권장 작업 순서와 저장소 구성

### 작업 순서

| 단계 | 작업 | 산출물 |
|---|---|---|
| **0. 정리 (선행)** | C1~C3, H1 수정 / 로더 일원화·경로 수정 / 문서·주석 정합 / Zeek 9.x 기준 확정 / `nsm_config_custom.zeek` 원본 확인 | 동작 변화 없이 "믿을 수 있는" 베이스 |
| **1. 테스트 체계** | 자산 식별과 같은 btest + pcap 구조. 룰마다 "발화 1건 + 미발화(정상) 1건" 케이스, 합성 pcap 생성기(scapy) | 회귀 테스트 |
| **2. 기존 룰 정확도** | H3(14 ConnThreshold), H4(13 엔트로피), H2(상관 매니저 집약), 09 `sni_matches_cert`, 16 `ssh_auth_successful`, 07 TLS 확장(N5) | 성능·정확도 개선 |
| **3. 비활성 룰 재작성** | 03/04 웹 공격, 05+N1, 08+11 통합(H5 해결 포함) | 재활성화 |
| **4. 신규 룰 P1** | N3 → N8 → N1/N2 → N4 → N6 → N7 → N9 (구현 비용 낮은 순) | 커버리지 확대 |
| **5. 연동** | Go 변환기 `NSM::`/detection/evidence 지원, 자산 식별 머지, P2 | 제품 연동 |

### 저장소 구성안 (자산 식별 PoC 구조 준용)

```
nsm_rules/                  # Zeek 패키지 루트 (현재 베이스라인 그대로)
  __load__.zeek             # 로더 1개로 일원화
  detections/               # 룰 + 공통 인프라
  rules/                    # 외부 패키지(ja3), 로그 필터
  asset-id/                 # (머지 예정) claudtest2 scripts/
  zkg.meta                  # (추가) script_dir, test_command
  tests/
    btest/                  # btest.cfg, 룰별 테스트, Baseline/
    pcaps/                  # 합성 pcap + Zeek 공개 trace
    gen_pcaps.py            # scapy 합성기
    run_tests.sh            # 로컬 zeek 없으면 docker zeek/zeek:9.x
docs/
  NSM_RULES_REVIEW.md       # 이 문서
```

---

## 부록 A. 엔트로피 임계 검증

Zeek `find_entropy()`는 입력 문자열의 바이트 분포 Shannon 엔트로피(bit/byte)를 반환하므로, 길이 n인 문자열의 최댓값은 log2(n)이다. 무작위 소문자 라벨 + TLD로 시뮬레이션(각 2,000개)한 결과:

| DGA 라벨 길이 | 평균 엔트로피 | ≥ 4.0 비율 | ≥ 3.5 비율 |
|---|---|---|---|
| 8 | 3.27 | 0.0% | 12.8% |
| 10 | 3.42 | 0.0% | 46.2% |
| 12 | 3.55 | 0.4% | 65.8% |
| 16 | 3.75 | 8.9% | 91.6% |
| 20 | 3.90 | 30.1% | 99.1% |
| 24 | 4.01 | 53.9% | 99.9% |

정상 도메인 예: `www.google.com` 2.84, `ocsp.digicert.com` 3.45, `update.microsoft.com` 3.68, `settings-win.data.microsoft.com` 3.82, `r3---sn-ab5l6nrs.googlevideo.com` 4.06.

→ 13번의 "NXDOMAIN 평균 엔트로피 ≥ 4.0"은 일반 DGA 길이에서 거의 충족되지 않는다. 동시에 원시 엔트로피만으로는 정상 CDN 도메인과 분리가 약하므로, 임계 하향과 함께 **등록 라벨 기준·길이 정규화** 지표로 바꾸는 것이 맞다.

08번(터널링) 서브도메인: hex 인코딩(dnscat2 등) 32자 평균 3.61, base32 32자 평균 4.19 → 3.5 임계는 hex 터널을 간신히 잡는 수준이므로 엔트로피 단독이 아닌 길이·고유 수와 합산 점수로 쓰는 것이 안전하다.
