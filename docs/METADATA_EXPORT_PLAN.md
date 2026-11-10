# 메타데이터 선별 전송 — 개발 계획과 스펙

작성: 2026-11-10 · 상태: 초안(P0 결정 대기) · 관련: [SRS](SRS.md) 5.2·7.6절, 자산 식별 PoC(`claudtest2`) 선별 전송, OCSF 변환기(`claudtest`)

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
 선별 전송 통계(신규) ────────────▶ /log/zeek/meta/meta_stats   (스트림별 보냄·버림 건수, 1분)
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
| 1 | smb_files | 전체 | ts, uid, id, action, path, name, prev_name, size | 쓰기·이름 변경·삭제만(읽기 제외) | 중간 |
| 1 | dce_rpc | 내부 관리 | ts, uid, id, endpoint, operation | 주요 인터페이스만(drsuapi, svcctl, atsvc·ITaskSchedulerService, winreg, ISystemActivator, samr, lsarpc) | 적음 |
| 1 | rdp | 전체 | ts, uid, id, cookie, security_protocol, result | 없음 | 적음 |
| 1 | ssh | 전체 | ts, uid, id, auth_success, auth_attempts, client, server, direction | 없음 | 적음 |
| 2 | ssl | 경계 | ts, uid, id, version, server_name, established, ja3·ja4(있으면) | (출발지, SNI, JA4) 1시간 중복 억제 | 중간 |
| 2 | dns | 경계 질의(내부 리졸버 → 외부 포함) | ts, uid, id.orig_h, id.resp_h, query, qtype_name, rcode_name, answers(앞 5개) | 예외 도메인 제외, (출발지, 질의, 유형, 결과) 1시간 중복 억제. 또는 `dns_summary`로 대체 | 큼 → 축소 |
| 2 | http | 경계 | ts, uid, id, method, host, URI 경로(쿼리 제거), status_code, user_agent, 요청·응답 본문 길이 | 예외 도메인 제외, User-Agent는 (출발지, UA) 1일 한 번만 | 큼 → 축소 |
| 3 | conn | 경계 + 내부 관리 포트 | ts, uid, id, proto, service, duration, orig_bytes, resp_bytes, conn_state | 응답 없는 내부 시도 제외. 또는 `flow_summary`로 대체 | 가장 큼 |
| 3 | asset_signal | 전체 | 자산 식별 SPEC 스키마 그대로 | 자산 식별 모듈의 중복 억제 | 원본 대비 0.1~0.3% |
| - | 상태 | - | capture_loss, reporter, stats, meta_stats | 없음 | 적음 |

- 내부 관리 포트·프로토콜 기본값: 88, 135, 139, 389, 445, 636, 3268, 3389, 5985, 5986, 22와 DCE-RPC 동적 포트(분석기 기준).
- files·x509·weird는 1차 범위에서 뺍니다(양 대비 활용도가 낮음). 필요하면 실행 파일 해시만 보내는 방식을 별도로 검토합니다.

### 3.3 요약 로그 (양이 큰 스트림 대체용)

conn·dns를 행 단위로 보내도 예산을 넘으면 요약 로그로 바꿉니다. P0 측정에서 어느 쪽을 쓸지 정합니다.

**flow_summary** — (출발지, 목적지, 목적지 포트, 프로토콜, 서비스)별, 10분 창

| 필드 | 의미 |
| --- | --- |
| ts_start, ts_end | 창의 첫·마지막 연결 시각 |
| orig_h, resp_h, resp_p, proto, service | 묶는 키 |
| conns | 연결 수 |
| orig_bytes, resp_bytes | 바이트 합 |
| states | 연결 상태별 건수(예: `SF:12,S0:3`) |
| sample_uid | 대표 연결 uid 1개(T2 원본 조회용) |

**dns_summary** — (출발지, 질의, 유형, 결과)별, 1시간 창: 첫·마지막 시각, 건수, 대표 응답, 대표 uid.

- 요약 상태는 워커 메모리에 둡니다. 키 수 상한(`meta_summary_max_keys`)을 넘으면 그 창은 즉시 내보내고 새로 시작합니다.
- 클러스터에서는 워커별로 따로 요약합니다. 같은 키가 워커 수만큼 여러 행이 될 수 있으며, Manager에서 합칩니다.

### 3.4 중복 억제와 분당 상한

- 중복 억제: 스트림별 키와 기간을 설정합니다(`table` + `create_expire`). 워커별 상태라 클러스터에서는 최대 워커 수만큼 중복될 수 있습니다.
- 분당 상한: 스트림별로 1분에 보낼 최대 행 수(`meta_rate_limit`)를 두고, 넘으면 그 분의 나머지는 버립니다.
- `meta_stats`: 1분마다 스트림별 `sent`, `dropped_scope`, `dropped_dedup`, `dropped_rate` 건수를 남깁니다. 상한에 걸린 분이 생기면 Manager에서 경고할 수 있습니다.
- 메모리 상한: 중복 억제 테이블은 스트림별 최대 크기를 두고, 넘치면 오래된 항목부터 지웁니다(자산 식별 P3과 같은 방침).

### 3.5 설정 (가칭)

| 파라미터 | 기본값(안) | 의미 |
| --- | --- | --- |
| `meta_export_enable` | T | 선별 전송 전체 토글 |
| `meta_export_streams` | 우선 1·2 스트림 | 보낼 스트림 목록 |
| `meta_fields` | 3.2절 필드 | 스트림별 `include` 필드 |
| `meta_dedup_interval` | 스트림별(3.2절) | 중복 억제 기간 |
| `meta_rate_limit` | 스트림별, P0 측정 후 | 분당 최대 행 수 |
| `meta_admin_ports` | 3.2절 목록 | 내부 관리 포트 |
| `meta_domain_allowlist` | 비어 있음(+ 고객별) | dns·http에서 뺄 도메인(업데이트·CDN 등) |
| `meta_dce_rpc_endpoints` | 3.2절 목록 | 남길 RPC 인터페이스 |
| `meta_summary` | conn·dns 요약 사용 여부 | 행 단위 대신 요약 로그 |
| `meta_keep_raw_local` | F | T2 원본을 로컬에 남길지 |
| `meta_path_prefix` | `/log/zeek/meta` | 출력 경로 |

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
| **P1 프레임워크** | 1주 | `nsm_rules/metadata/` 모듈: `nsm_meta` 필터 추가, 범위 판정·필드 축소·중복 억제·분당 상한·`meta_stats`. `filter_log`와 연동, 설정 분리 | btest: 범위 밖 행 제외, include 필드만 출력, 중복 억제, 상한 초과 시 버림과 카운트, 끈 상태에서 기존 출력 불변 |
| **P2 저볼륨 고가치** | 1주 | 우선 1 스트림(kerberos, ntlm, smb_mapping, smb_files, dce_rpc, rdp, ssh)과 상태 로그 | 기준 pcap 전송량·CPU가 예산의 절반 이하 |
| **P3 고볼륨 축소** | 1~2주 | ssl·dns·http 행 선별·중복 억제, conn 경계 + 관리 포트. 예산 초과 시 `flow_summary`·`dns_summary` | 기준 pcap 전송량·CPU가 예산 이하, 상한에 걸리는 분 0 |
| **P4 연동** | 1주 | asset_signal 포함(자산 식별 머지 후), T2 로컬 보관 옵션, OCSF 변환기 입력 경로·매핑 갱신(`claudtest`) | 변환기가 T1 로그를 읽어 OCSF로 변환, 클러스터 btest 통과 |

측정 방법(P0·각 단계 공통):

1. 같은 pcap을 `zeek -r`로 (a) 선별 전송 끔, (b) 켬으로 각각 3회 실행해 처리 시간·최대 메모리를 비교합니다.
2. 출력 디렉터리의 스트림별 바이트·행 수를 집계하고, (c) 모든 로그를 켠 실행과 비교해 비율을 냅니다.
3. 결과를 이 문서의 부록에 표로 남깁니다.

## 5. 결정이 필요한 항목 (P0)

| 항목 | 질문 | 제안 |
| --- | --- | --- |
| 전송 경로 | 수집 에이전트가 어느 디렉터리를 읽는가, 회전 주기·압축은 | `/log/zeek/meta`, JSON, 회전은 에이전트에 맞춤 |
| 예산 | 센서당 하루 전송량·초당 이벤트 상한은 | 전체 대비 5% 이하에서 시작 |
| 대상 | 3.2절 우선순위에 빠지거나 더할 메타데이터는 | AD·Windows 프로토콜 우선 |
| conn·dns | 행 단위와 요약 중 무엇을 기본으로 | P0 측정 후 결정 |
| T2 원본 | 센서 로컬 원본 보관이 필요한가, 보관 일수는 | 선택 기능, 기본 끔 |
| 개인정보 | 계정 이름·URL 경로·User-Agent 전송 허용 범위 | 계정·경로 전송, 쿼리 문자열·인증값 제외 |
| 클러스터 | 워커별 중복 억제로 생기는 중복을 Manager에서 합칠 수 있는가 | 허용 |
