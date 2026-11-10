# 메타데이터 선별 전송 — 개발 계획과 스펙

작성: 2026-11-10 · 상태: P0 결정 확정(2026-11-10, 5장), P1·P2·P3 구현(conn·dns는 요약), P4 예정 · 관련: [선별 전송 SRS](SRS_METADATA_EXPORT.md), [탐지 SRS](SRS.md) 5.2·5.3절, 자산 식별 PoC(`claudtest2`) 선별 전송, OCSF 변환기(`claudtest`)

## 1. 배경과 목표

지금 센서는 탐지 결과(`nsm_detection`·`evidence`·`notice`)와 센서 상태 로그만 남기고, conn·dns·ssl 같은 프로토콜 로그는 `filter_log.zeek`에서 모두 끕니다(SRS 5.2절). 그래서 다음이 안 됩니다.

- 탐지가 난 뒤 앞뒤 맥락(그 host가 어디와 통신했는지, 어떤 계정으로 인증했는지)을 Manager에서 볼 수 없습니다.
- `evidence.log`의 `uid`로 원본 연결을 조인할 수 없습니다(검토 문서 C3).
- 탐지 룰이 없는 위협을 사후에 찾는 헌팅이 불가능합니다.

반대로 Zeek 로그를 전부 보내는 것은 현실적이지 않습니다. 자산 식별 PoC가 운영 pcap으로 잰 값은 200초에 Zeek 전체 로그 423.5MB(초당 약 2.1MB, 하루 약 180GB 규모)였습니다. 같은 측정에서 `asset_signal`은 0.2%였습니다.

**목표:** 조사·헌팅에 꼭 필요한 메타데이터만 골라 Manager로 보낸다. 전송량과 센서 부하를 예산 안에 묶고, 예산을 넘는 상황에서도 탐지와 센서가 영향을 받지 않게 한다.

| 지표 | 목표(안) | 확정 |
| --- | --- | --- |
| 전송량 | 기준 pcap에서 Zeek 전체 로그 대비 5% 이하 | P0 |
| 센서 CPU 추가 부하 | 선별 전송 끔 대비 5% 이하(자산 식별 PoC와 같은 기준) | P0 |
| 탐지 영향 | 탐지 결과·근거는 선별 전송과 무관하게 100% 기록 | 고정 |
| 과부하 시 동작 | 스트림별 상한을 넘으면 버리고, 버린 건수를 기록 | 고정 |

## 2. 설계 원칙

1. **계층을 나눈다.** 모든 것을 같은 방식으로 보내지 않습니다.

   | 계층 | 내용 | 전송 | 비고 |
   | --- | --- | --- | --- |
   | T0 탐지 | `nsm_detection`, `evidence`, `notice` | 항상 전송 | 지금과 같음 |
   | T1 선별 메타데이터 | 이 문서의 대상. 행·필드를 줄인 프로토콜 로그와 요약 로그 | 전송 | 예산 적용 |
   | T2 원본 | 줄이지 않은 Zeek 로그 | 센서 로컬 보관(N일), 필요할 때 `uid`·시간으로 조회 | 선택. 디스크 여유가 있는 센서만 |
   | 상태 | `capture_loss`, `reporter`, `stats`, 선별 전송 통계 | 전송 | 소량 |

2. **양이 적고 가치가 큰 것부터.** Windows·AD 프로토콜(Kerberos, NTLM, SMB 공유·파일 변경, 주요 RPC, RDP, SSH)은 양이 적고 침해 조사에 바로 쓰입니다. conn·dns·http처럼 양이 큰 로그는 줄이는 장치를 갖춘 뒤에 넣습니다.

3. **줄이는 순서: 행 → 필드 → 요약.**
   - 행 선별: 방향(내부↔외부, 내부 관리 포트), 상태, 예외 목록으로 보낼 행만 고릅니다.
   - 필드 축소: 조사에 쓰는 필드만 남깁니다(`Log::Filter`의 `include`).
   - 중복 억제·요약: 같은 내용이 반복되면 일정 시간 한 번만 보내거나 건수를 묶은 요약 행으로 보냅니다.

4. **센서에서 줄인다.** 줄이는 판단은 로그를 쓰는 노드(클러스터에서는 워커)의 필터에서 합니다. 버린 행은 로거·디스크·네트워크로 가지 않습니다.

5. **과부하에도 안전하게.** 스트림마다 분당 상한을 두고, 넘치면 버리되 버린 건수를 상태 로그에 남깁니다. 탐지 경로(T0)는 상한의 영향을 받지 않습니다.

6. **개인정보를 최소로.** 자산 식별 PoC의 SRS 반영 제안과 같이 인증 응답값과 URL 값(쿼리 문자열)은 보내지 않습니다. 계정 이름은 보내되 보관 기간·접근 권한은 Manager 쪽에서 정합니다.

## 3. 스펙

### 3.1 구성

```
           Log::write (워커)
 프로토콜 로그 ──┬─ default 필터 ──▶ T2 원본: /hdd_tmp/log/zeek/<stream>   (선택, meta_keep_raw_local)
                └─ nsm_meta 필터 ──▶ T1 선별: /log/zeek/meta/<stream>      (JSON, 전송 대상)
                     ├ policy 훅: 범위 판정 → 예외 → 중복 억제 → 분당 상한
                     └ include: 스트림별 필드 목록
 요약 로그(신규) ─────────────────▶ /log/zeek/meta/flow_summary, dns_summary
 선별 전송 통계(신규) ────────────▶ /log/zeek/meta/meta_export_stats   (스트림별 보냄·버림 건수, 1분)
```

- 새 모듈 `nsm_rules/metadata/`(가칭)에 둡니다. 룰과 마찬가지로 설정은 `&redef` 상수이고 운영 값은 `nsm_config_fixed.zeek`, 고객별 값은 `nsm_config_custom.zeek`에 둡니다.
- `filter_log.zeek`와의 관계: 선별 전송 대상 스트림은 켜 두되, `meta_keep_raw_local = F`면 default 필터를 지워 원본은 남기지 않습니다.
- 출력 형식: 필터 설정(`config`의 `use_json`)으로 JSON을 강제합니다. 회전 주기는 전송 에이전트와 맞춥니다(현재 4시간, P0에서 확정).
- `/log/zeek` 아래를 전송 대상으로 본다는 가정은 현재 경로 규칙(탐지 로그는 `/log/zeek`, 그 밖은 `/hdd_tmp`)에서 나온 것입니다. P0에서 수집 에이전트와 확인합니다.

### 3.2 스트림별 선별 규칙 (T1)

범위 표기: **경계** = 내부↔외부 연결, **내부 관리** = 내부→내부 중 관리·인증 포트·프로토콜, **전체** = 방향 제한 없음.

| 우선 | 스트림 | 범위 | 남기는 필드(요지) | 줄이는 방법 | 예상 양 |
| --- | --- | --- | --- | --- | --- |
| 1 | kerberos | 전체 | ts, uid, id, request_type, client, service, success, error_msg, cipher | 없음 | 적음 |
| 1 | ntlm | 전체 | ts, uid, id, username, domainname, hostname, success | 없음 | 적음 |
| 1 | smb_mapping | 전체 | ts, uid, id, path, share_type | (출발지, 경로) 1시간 중복 억제 | 적음 |
| 1 | smb_files | 전체 | ts, uid, id, action, path, name, prev_name, size | 쓰기·이름 변경·삭제만(읽기 제외), (출발지, 목적지, 동작, 경로, 파일) 10분 중복 억제 | 중간 |
| 1 | dce_rpc | 전체(인터페이스로 선별) | ts, uid, id, endpoint, operation | 주요 인터페이스만(drsuapi, svcctl, atsvc·ITaskSchedulerService, winreg, IRemoteSCMActivator, IWbemLevel1Login·IWbemServices, samr, lsarpc, netlogon, efsrpc), (출발지, 목적지, 인터페이스, 호출) 10분 중복 억제 | 적음 |
| 1 | rdp | 전체 | ts, uid, id, cookie, security_protocol, result | 없음 | 적음 |
| 1 | ssh | 전체 | ts, uid, id, auth_success, auth_attempts, client, server, direction | 없음 | 적음 |
| 2 | ssl | 경계 | ts, uid, id, version, cipher, server_name, established, ja3 | 예외 도메인(SNI) 제외, (출발지, SNI, JA3) 1시간 중복 억제 | 중간 |
| 2 | dns → `dns_summary` | 전체(내부 리졸버의 질의 제외) | 3.3절 요약 스키마 | 역방향 조회·예외 도메인·`dns_tunnel_resolvers` 출발지 제외, (출발지, 등록 도메인, 유형, 결과)별 1시간 요약, 출발지당 도메인 행 100개 상한 | 큼 → 축소 |
| 2 | http | 경계 | ts, uid, id, method, host, uri_path(쿼리 제거), status_code, user_agent, 요청·응답 본문 길이 | 예외 도메인(Host) 제외, (출발지, Host, 메서드, 경로, 상태) 10분 중복 억제 | 큼 → 축소 |
| 3 | conn → `flow_summary` | 경계 + 내부 관리 포트 | 3.3절 요약 스키마 | (출발지, 목적지, 목적지 포트)별 10분 요약 | 가장 큼 → 축소 |
| 3 | asset_signal | 전체 | 자산 식별 SPEC 스키마 그대로 | 자산 식별 모듈의 중복 억제 | 원본 대비 0.1~0.3% |
| - | 상태 | - | capture_loss, reporter, stats, meta_export_stats | 없음 | 적음 |

- 내부 관리 포트·프로토콜 기본값: 88, 135, 139, 389, 445, 636, 3268, 3389, 5985, 5986, 22와 DCE-RPC 동적 포트(분석기 기준).
- files·x509·weird는 1차 범위에서 뺍니다(양 대비 활용도가 낮음). 필요하면 실행 파일 해시만 보내는 방식을 별도로 검토합니다.

### 3.3 요약 로그 (양이 큰 스트림 대체용)

conn·dns는 요약 로그로 보냅니다(2026-11-10 결정). 원본 스트림에 행을 쓰지 않는 필터를 붙여 policy 훅에서 묶고, 주기마다 요약 행을 씁니다. 범위·조건 판정은 행 단위 스트림과 같습니다.

**flow_summary** — (출발지, 목적지, 목적지 포트)별, 10분(`meta_flow_interval`) 주기

| 필드 | 의미 |
| --- | --- |
| ts, ts_end | 주기 안 첫·마지막 연결 시작 시각 |
| node | 기록한 노드 |
| orig_h, resp_h, resp_p, proto | 묶는 키 |
| service | 관측된 서비스(쉼표 구분) |
| conns | 연결 수 |
| orig_bytes, resp_bytes, duration | 바이트 합, 지속 시간 합(초) |
| states | 연결 상태별 건수(예: `SF:12,S0:3`) |
| sample_uid | 대표 연결 uid 1개(T2 원본 조회용) |

**dns_summary** — (출발지, 등록 도메인, 유형, 결과)별, 1시간(`meta_dns_interval`) 주기

| 필드 | 의미 |
| --- | --- |
| ts, ts_end, node, orig_h | flow_summary와 같음 |
| domain | 등록 도메인(`parent_domain`, co.kr 등 2단계 접미사 처리). 출발지 상한을 넘은 도메인은 `(other)` |
| qtype_name, rcode_name | 질의 유형, 결과 |
| queries | 질의 수 |
| unique_names, unique_names_capped | 고유 질의 이름 수(1000개까지 셈, 넘으면 capped = T) |
| sample_names | 처음 관측한 질의 이름(최대 5개) |
| answers | 처음 관측한 응답(최대 5개) |
| sample_uid | 대표 uid |

- 질의 이름 단위가 아니라 등록 도메인 단위로 묶습니다. CDN·터널링처럼 서브도메인이 매번 다른 트래픽이 도메인 하나로 묶입니다.
- DGA처럼 등록 도메인 자체가 매번 다르면 등록 도메인 단위로도 줄지 않습니다. 그래서 출발지 하나가 한 주기에 만드는 도메인 행을 `meta_dns_max_domains_per_src`(100)로 제한하고, 넘는 도메인은 `(other)` 한 행에 질의 수·고유 이름 수만 더합니다.
- 요약 상태는 노드 메모리에 둡니다. 키 수 상한(`meta_summary_max_keys`)을 넘으면 그 시점에 내보내고 새로 시작합니다.
- 클러스터에서는 워커별로 따로 요약합니다. 같은 키가 워커 수만큼 여러 행이 될 수 있으며, Manager에서 합칩니다.

### 3.4 중복 억제와 분당 상한

- 중복 억제: 스트림별 키와 기간을 설정합니다(`table` + `create_expire`). 워커별 상태라 클러스터에서는 최대 워커 수만큼 중복될 수 있습니다.
- 분당 상한: 스트림별로 노드당 1분(로그를 쓰는 시각의 분 단위)에 보낼 최대 행 수(`rate_limit`)를 두고, 넘으면 그 분의 나머지는 버립니다.
- `meta_export_stats`: 1분마다 노드·스트림별 `sent`, `dropped_scope`, `dropped_filter`, `dropped_dedup`, `dropped_rate` 건수를 남깁니다. 상한에 걸린 분이 생기면 Manager에서 경고할 수 있습니다.
- 메모리 상한: 중복 억제 테이블은 전체 항목 수 상한(`meta_dedup_max_entries`, 20만)을 두고, 넘치면 새 키는 억제하지 않고 보냅니다(누락보다 중복을 택함). 항목은 `meta_dedup_expire`(1시간) 뒤 지워집니다.

### 3.5 설정

`nsm_rules/metadata/main.zeek`의 `&redef` 상수입니다. 운영 값은 룰 파일 기본값을 그대로 쓰고, 바꿀 때는 `nsm_config_fixed.zeek`(운영 공통) 또는 `nsm_config_custom.zeek`(고객별)에 적습니다.

| 파라미터 | 기본값 | 의미 | 단계 |
| --- | --- | --- | --- |
| `meta_export_enable` | T | 선별 전송 전체 토글 | P1 |
| `meta_export_streams` | 우선 1 스트림 + 상태 로그 | 스트림별 설정 표. 항목마다 `name`(출력 이름), `fields`(남길 필드), `scope`(범위), `dedup`(중복 억제 기간), `rate_limit`(노드당 분당 상한, 0 = 무제한) | P1·P2 |
| `meta_path_prefix` | `/log/zeek/meta/` | 출력 경로 앞부분 | P1 |
| `meta_admin_ports` | 22, 88, 135, 139, 389, 445, 636, 3268, 3269, 3389, 5985, 5986 | `META_ADMIN_INTERNAL` 범위의 내부 관리 포트 | P1 |
| `meta_smb_file_actions` | 쓰기·이름 변경·삭제 | smb_files에서 남길 동작 | P2 |
| `meta_dce_rpc_endpoints` | 3.2절 목록 | dce_rpc에서 남길 인터페이스 | P2 |
| `meta_dedup_max_entries` / `meta_dedup_expire` | 200000 / 1hr | 중복 억제 테이블 상한·보관 시간 | P1 |
| `meta_stats_interval` | 1min | 통계 로그 주기 | P1 |
| `meta_keep_raw_local` / `meta_raw_path_prefix` | F / `/hdd_tmp/log/zeek/` | T2 원본 로컬 보관과 경로 | P1 |
| `meta_domain_allowlist` | 비어 있음 | ssl(SNI)·http(Host)·dns(질의)에서 뺄 도메인(접미사 일치) | P3 |
| `meta_export_streams` 의 `summary` | conn·dns = T | 행 대신 요약 로그로 묶음(Conn::LOG, DNS::LOG만 지원) | P3 |
| `meta_flow_interval` / `meta_dns_interval` | 10min / 1hr | 요약 주기 | P3 |
| `meta_summary_max_keys` | 100000 | 노드당 요약 키 상한(넘으면 즉시 내보냄) | P3 |
| `meta_dns_max_domains_per_src` | 100 | 출발지별 주기당 도메인 행 상한(넘으면 `(other)`) | P3 |
| `meta_dns_max_samples` / `meta_dns_max_answers` / `meta_dns_max_unique` | 5 / 5 / 1000 | 표본 이름·응답 수, 고유 이름을 셀 최대 수 | P3 |

범위(`scope`) 값: `META_ALL`(제한 없음), `META_BOUNDARY`(내부↔외부), `META_ADMIN_INTERNAL`(내부→내부 관리 포트), `META_BOUNDARY_OR_ADMIN`(둘 중 하나). 연결 정보가 없는 상태 로그는 범위와 무관하게 통과합니다.

### 3.6 성능 설계

- 프로토콜 분석기는 탐지 룰 때문에 이미 돌고 있으므로, 추가 비용은 로그 레코드 생성·필터·쓰기입니다.
- policy 훅은 행마다 실행되므로 집합·서브넷 조회와 테이블 조회 몇 번으로 끝나게 합니다. 도메인 예외는 기존 `NSM::domain_matches`(접미사 비교)를 쓰고, 비용이 크면 P3에서 결과 캐시를 검토합니다.
- 행을 버리면 그 행의 JSON 직렬화·로거 전송·디스크 쓰기 비용이 사라집니다. 그래서 범위 판정을 가장 먼저 합니다.
- T2를 켜면 같은 스트림을 두 번 쓰게 되므로(원본 + 선별) 디스크 쓰기가 늘어납니다. T2는 센서별 선택 기능으로 둡니다.
- 요약 로그는 연결 종료 이벤트(`connection_state_remove`)에서 테이블을 갱신하므로 패킷 단위 비용이 없습니다.

## 4. 개발 계획

각 단계는 기준 pcap으로 전송량·CPU를 측정해 예산 안인지 확인한 뒤 다음 단계로 갑니다. 단계마다 PR 하나, SRS 갱신 포함.

| 단계 | 기간(안) | 작업 | 완료 기준 |
| --- | --- | --- | --- |
| **P0 측정·합의** | 1주 | 운영 pcap(자산 식별 PoC와 같은 구간 + DC 구간)으로 스트림별 로그 양·행 수 측정(전체 로그 켠 상태). 전송 경로(수집 에이전트, 디렉터리, 회전, JSON), 예산(전송량·CPU), 개인정보 범위를 Manager 쪽과 합의 | 스트림별 양 표, 예산·경로 확정, 3.2절 우선순위 확정 |
| **P1 프레임워크** | 1주 | `nsm_rules/metadata/` 모듈: `nsm_meta` 필터 추가, 범위 판정·필드 축소·중복 억제·분당 상한·`meta_export_stats`. `filter_log`와 연동, 설정 분리 | btest: 범위 밖 행 제외, include 필드만 출력, 중복 억제, 상한 초과 시 버림과 카운트, 끈 상태에서 기존 출력 불변 |
| **P2 저볼륨 고가치** | 1주 | 우선 1 스트림(kerberos, ntlm, smb_mapping, smb_files, dce_rpc, rdp, ssh)과 상태 로그 | 기준 pcap 전송량·CPU가 예산의 절반 이하 |
| **P3 고볼륨 축소** | 1~2주 | ssl·dns·http 행 선별·중복 억제, conn 경계 + 관리 포트. 예산 초과 시 `flow_summary`·`dns_summary` | 기준 pcap 전송량·CPU가 예산 이하, 상한에 걸리는 분 0 |
| **P4 연동** | 1주 | asset_signal 포함(자산 식별 머지 후), T2 로컬 보관 옵션, OCSF 변환기 입력 경로·매핑 갱신(`claudtest`) | 변환기가 T1 로그를 읽어 OCSF로 변환, 클러스터 btest 통과 |

측정 방법(P0·각 단계 공통): `tests/measure_meta_export.sh <pcap> [반복 횟수]`

1. 같은 pcap을 (full) nsm_rules 없이 Zeek 전체 로그, (off) 선별 전송 끔, (on) 켬으로 각각 실행합니다(기본 3회, 처리 시간은 최솟값).
2. 선별 전송 로그의 스트림별 바이트·행 수, Zeek 전체 로그 대비 비율, off 대비 on의 처리 시간 증가율을 출력합니다.
3. 결과를 부록 A에 표로 남깁니다.

## 5. 결정 사항 (P0, 2026-11-10 확정)

제안안대로 확정했습니다. 운영 pcap 측정(부록 A)이 나오면 예산과 conn·dns 방식을 다시 확인합니다.

| 항목 | 결정 |
| --- | --- |
| 전송 경로 | `/log/zeek/meta/<이름>.log`, JSON. 회전은 운영 기본(4시간)을 쓰고 수집 에이전트에 맞춰 조정 |
| 예산 | Zeek 전체 로그 대비 5% 이하, CPU 추가 부하 5% 이하에서 시작 |
| 대상 | AD·Windows 프로토콜 우선(3.2절 우선 1), 그다음 SSL·DNS·HTTP, conn |
| conn·dns | 요약 로그로 보냄(2026-11-10 결정, 3.3절). 운영 측정 후 주기·상한 조정 |
| T2 원본 | 선택 기능, 기본 끔(`meta_keep_raw_local = F`) |
| 개인정보 | 계정 이름·URL 경로는 보냄, URL 쿼리 문자열·인증값은 보내지 않음 |
| 클러스터 | 워커별 중복 억제로 생기는 중복은 Manager에서 합침 |

## 6. 진행 현황

| 단계 | 상태 | 내용 |
| --- | --- | --- |
| P0 | 결정 확정, 운영 pcap 측정 대기 | 측정 스크립트 `tests/measure_meta_export.sh` |
| P1 | 구현 | `nsm_rules/metadata/main.zeek`: `nsm_meta` 필터, 범위·스트림별 조건·중복 억제·분당 상한, `meta_export_stats`, `filter_log` 연동(`keep_enabled_streams`), T2 옵션 |
| P2 | 구현 | kerberos, ntlm, smb_mapping, smb_files, dce_rpc, rdp, ssh + capture_loss, stats, reporter |
| P3 | 구현 | ssl·http 행 선별(경계, 도메인 예외, 중복 억제, URL 쿼리 문자열 제거), conn → `flow_summary`, dns → `dns_summary`(등록 도메인 단위, 출발지 상한) |
| P4 | 예정 | asset_signal, OCSF 변환기 연동 |

테스트: `rules/meta-export`(스트림별 출력·필드·조건·중복 억제·범위·통계), `rules/meta-export-rate`(분당 상한), `rules/meta-export-off`(끔·T2), `rules/meta-export-summary`(ssl·http 행 선별, 쿼리 문자열 제거, 흐름·DNS 요약, 출발지별 도메인 상한), `cluster/meta-export-worker`(판정이 워커에서 일어나고 로거에는 통과한 행·요약만 기록). 합성 pcap `meta_export.pcap`, `meta_summary.pcap`.

## 부록 A. 측정 결과

### A.1 합성 pcap (참고용, 2026-11-10, P3 포함)

`tests/pcaps/*.pcap` 전체를 시간순으로 합친 pcap(9,806패킷), Zeek 9.0.1, 5회 최솟값.

| 선별 전송 로그 | 바이트 | 행 |
| --- | --- | --- |
| dns_summary | 151,627 | 538 |
| smb_files | 63,800 | 241 |
| flow_summary | 44,902 | 168 |
| http | 38,037 | 133 |
| kerberos | 32,298 | 120 |
| ntlm | 15,714 | 80 |
| ssl | 3,527 | 12 |
| dce_rpc | 3,129 | 16 |
| smb_mapping, rdp, ssh | 4,265 | 23 |
| capture_loss·stats | 4,138 | 13 |
| **합계** | **361,437** | |

- Zeek 전체 로그 1,793,845바이트 대비 20.15%. 처리 시간 off 0.91\~0.93초 → on 1.00\~1.01초(두 번 측정에서 7.2%, 11.0% 증가, 절대값 약 0.07\~0.1초).
- 합성 pcap은 탐지 테스트용 공격 트래픽이라 비율이 실제보다 훨씬 높게 나옵니다. dns_summary 538행 중 418행은 DGA 테스트 호스트(호스트당 무작위 도메인 60개)의 NXDOMAIN이고, http 133행 대부분은 비커닝 테스트의 매번 다른 경로입니다.
- 처리 시간은 pcap이 작아(1초 미만) 로그 파일 생성 같은 고정 비용과 측정 오차가 큽니다. 예산 판단에는 쓰지 않습니다.
- 질의 이름 단위 요약(초기 구현)에서는 dns_summary가 1,467행·303KB였고, 등록 도메인 단위로 바꿔 538행·152KB가 됐습니다.

### A.2 운영 pcap

측정 대기. 운영 미러 구간(1시간 이상, DC 구간 포함) pcap으로 `tests/measure_meta_export.sh`를 실행해 이 절에 남깁니다.
