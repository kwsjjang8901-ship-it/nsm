# 센서 로그 스키마 (Manager 연동 기준)

이 문서는 `schema/build.py`가 만듭니다. 직접 고치지 말고 `schema/overlay.json`(설명·열거값)이나 Zeek 코드(필드)를 고친 뒤 다시 만드세요. 기계가 읽는 정의는 `schema/logs/`의 JSON Schema(draft 2020-12)입니다.

- 스키마 버전: `cbb6703be7d3`(`schema/logs` 내용의 SHA-256 앞 12자리). 센서는 이 값을 센서 상태 로그(`nsm_sensor.log`)의 `schema_version`에 남기므로, Manager는 센서별로 어떤 스키마로 해석할지 고를 수 있습니다.
- 형식: JSON 한 줄 = 한 행. 값이 없는 선택 필드는 쓰지 않습니다(키가 없음). 필수 필드는 항상 있습니다.
- 타입: `time`은 epoch 초(소수), IP는 문자열, 목록은 JSON 배열, 정해 두지 않은 필드는 없습니다(`additionalProperties: false`).
- 검증: CI가 btest 전체 출력의 해당 로그를 이 스키마로 검사하고(`schema/validate.py`), 코드의 필드가 스키마와 달라지면 실패합니다(`schema/build.py --check`).
- 근거 문서: 탐지 로그는 [SRS 6장](SRS.md), 자산 신호는 [자산 식별 SPEC 2장](asset-id/SPEC.md), 선별 전송은 [메타데이터 SRS](SRS_METADATA_EXPORT.md). 형식 결정 배경은 [로그 형식 검토](LOG_SCHEMA_REVIEW.md).

## 로그 목록

| 로그 | 이름 | 경로(기본) | 필드 수 | 스키마 |
| --- | --- | --- | --- | --- |
| `nsm_detection` | 탐지 요약 | `/log/zeek/nsm_detection.log` | 26 | [`nsm_detection.schema.json`](../schema/logs/nsm_detection.schema.json) |
| `evidence` | 근거 | `/log/zeek/evidence.log` | 25 | [`evidence.schema.json`](../schema/logs/evidence.schema.json) |
| `nsm_exception` | 예외 적재·적중 | `/log/zeek/nsm_exception.log` | 10 | [`nsm_exception.schema.json`](../schema/logs/nsm_exception.schema.json) |
| `nsm_ioc` | IOC 파일 적재 | `/log/zeek/nsm_ioc.log` | 6 | [`nsm_ioc.schema.json`](../schema/logs/nsm_ioc.schema.json) |
| `nsm_sensor` | 센서 상태 | `/log/zeek/nsm_sensor.log` | 16 | [`nsm_sensor.schema.json`](../schema/logs/nsm_sensor.schema.json) |
| `asset_signal` | 자산 신호 | `/log/zeek/asset_signal.log` | 11 | [`asset_signal.schema.json`](../schema/logs/asset_signal.schema.json) |
| `asset_agent_policy` | 에이전트 정책 적재 | `/log/zeek/asset_agent_policy.log` | 5 | [`asset_agent_policy.schema.json`](../schema/logs/asset_agent_policy.schema.json) |
| `meta/meta_export_stats` | 선별 전송 통계 | `/log/zeek/meta/meta_export_stats.log` | 9 | [`meta/meta_export_stats.schema.json`](../schema/logs/meta/meta_export_stats.schema.json) |
| `meta/flow_summary` | 연결 요약 | `/log/zeek/meta/flow_summary.log` | 12 | [`meta/flow_summary.schema.json`](../schema/logs/meta/flow_summary.schema.json) |
| `meta/dns_summary` | DNS 요약 | `/log/zeek/meta/dns_summary.log` | 13 | [`meta/dns_summary.schema.json`](../schema/logs/meta/dns_summary.schema.json) |
| `meta/http_ua_summary` | HTTP User-Agent 요약 | `/log/zeek/meta/http_ua_summary.log` | 8 | [`meta/http_ua_summary.schema.json`](../schema/logs/meta/http_ua_summary.schema.json) |
| `meta/capture_loss` | 선별 전송: capture_loss | `/log/zeek/meta/capture_loss.log` | 6 | [`meta/capture_loss.schema.json`](../schema/logs/meta/capture_loss.schema.json) |
| `meta/dce_rpc` | 선별 전송: dce_rpc | `/log/zeek/meta/dce_rpc.log` | 9 | [`meta/dce_rpc.schema.json`](../schema/logs/meta/dce_rpc.schema.json) |
| `meta/http` | 선별 전송: http | `/log/zeek/meta/http.log` | 13 | [`meta/http.schema.json`](../schema/logs/meta/http.schema.json) |
| `meta/kerberos` | 선별 전송: kerberos | `/log/zeek/meta/kerberos.log` | 13 | [`meta/kerberos.schema.json`](../schema/logs/meta/kerberos.schema.json) |
| `meta/ntlm` | 선별 전송: ntlm | `/log/zeek/meta/ntlm.log` | 11 | [`meta/ntlm.schema.json`](../schema/logs/meta/ntlm.schema.json) |
| `meta/rdp` | 선별 전송: rdp | `/log/zeek/meta/rdp.log` | 10 | [`meta/rdp.schema.json`](../schema/logs/meta/rdp.schema.json) |
| `meta/reporter` | 선별 전송: reporter | `/log/zeek/meta/reporter.log` | 4 | [`meta/reporter.schema.json`](../schema/logs/meta/reporter.schema.json) |
| `meta/smb_files` | 선별 전송: smb_files | `/log/zeek/meta/smb_files.log` | 12 | [`meta/smb_files.schema.json`](../schema/logs/meta/smb_files.schema.json) |
| `meta/smb_mapping` | 선별 전송: smb_mapping | `/log/zeek/meta/smb_mapping.log` | 9 | [`meta/smb_mapping.schema.json`](../schema/logs/meta/smb_mapping.schema.json) |
| `meta/ssh` | 선별 전송: ssh | `/log/zeek/meta/ssh.log` | 12 | [`meta/ssh.schema.json`](../schema/logs/meta/ssh.schema.json) |
| `meta/ssl` | 선별 전송: ssl | `/log/zeek/meta/ssl.log` | 12 | [`meta/ssl.schema.json`](../schema/logs/meta/ssl.schema.json) |
| `meta/stats` | 선별 전송: stats | `/log/zeek/meta/stats.log` | 27 | [`meta/stats.schema.json`](../schema/logs/meta/stats.schema.json) |

## 탐지 요약 (`nsm_detection`)

notice 1건 = 탐지 1건. 단독 탐지(Single)와 킬체인 상관 탐지(Correlated)가 같은 형식이다. 상관 탐지는 같은 detection_id 로 갱신되며 revision 이 가장 큰 행이 현재 상태(SRS 5.1.2). 근거는 evidence_ids 로 evidence.log 와 조인한다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 탐지 시각 |
| `detection_id` | string | 필수 | 형식 `^\S+$` | 탐지 id. 단독은 evidence_id 와 같고, 상관은 kc-<체인 시작 epoch>-<프로세스 값 6자리 16진수>-<번호>. 센서가 여러 대면 Manager 키는 (센서, detection_id) |
| `diagnosis` | string | 필수 | 열거값 또는 형식 | 진단명(표시용 분류). 단독은 룰별 고정값, 상관은 NSM.Correlation.<첫 단계>.<가장 많이 진행된 단계> |
| `rule` | string |  | 열거값 49개(아래 표) | 탐지를 낸 룰(notice 이름에서 NSM:: 를 뺀 값). 상관은 Correlated_KillChain. Manager 룰 정책·예외와 잇는 키 |
| `techniques` | array<string> |  |  | ATT&CK 기법 id. 상관은 구성 탐지마다 하나(처음 탐지된 시각 순, 같은 기법 반복 가능) |
| `category` | string | 필수 | `Single`, `Correlated` | Single(단독) 또는 Correlated(킬체인 상관) |
| `killchain_stages` | array<string> |  | 각 값: `Command and Control`, `Credential Access`, `Exfiltration`, `Impact`, `Initial Access`, `Lateral Movement`, `Recon` | 킬체인 단계명. 상관은 처음 본 순서, 중복 없음 |
| `severity` | string | 필수 | `Information`, `Suspicious` | 등급 문자열: 단독 Information, 상관 Suspicious |
| `severity_id` | integer |  | `1`, `3` | 등급 숫자(OCSF severity_id 척도): 단독 1, 상관 3 |
| `first_seen` | time(epoch 초) |  |  | 관측 시작. 같은 사건의 갱신(occurrence > 1)은 사건의 첫 탐지 시각, 상관은 체인 시작 |
| `last_seen` | time(epoch 초) |  |  | 관측 끝(상관은 가장 최근 단계) |
| `attacker` | string(IP) |  |  | 공격 host(notice src, 상관은 체인 출발지) |
| `attacker_subnet` | string(대역) |  |  | 공격 host 의 대역(Site::local_nets 에 있으면 그 대역, 없으면 /24·/64) |
| `victims` | array<string> |  |  | 피해 host 주소(최대 chain_max_victims=8). 확산 룰은 주소 순, 상관은 가장 최근 단계 host 가 맨 앞이고 체인 출발지는 넣지 않음 |
| `victim_count` | integer |  | 최소 1 | 피해 host 전체 수(victims 가 잘려도 실제 수) |
| `accounts` | array<string> |  |  | 근거에서 모은 계정(정렬, 최대 evidence_summary_max=5) |
| `dst_names` | array<string> |  |  | 근거에서 모은 목적지 이름(host·sni·name·DNS 상위 도메인, 소문자, IP 제외, 정렬, 최대 5) |
| `relays` | array<string> |  |  | 거쳐 간 프록시 주소:포트(정렬, 최대 5) |
| `evidence_count` | integer | 필수 |  | evidence.log 에 기록된 근거 행 수 |
| `evidence_ids` | array<string> |  |  | 근거 키(evidence.log 의 evidence_id). 상관은 체인 근거 id + 구성 탐지 id |
| `disposition` | string |  | `suppressed` | suppress 예외에 맞은 탐지만 suppressed(Manager 는 알림을 올리지 않음) |
| `exception_id` | string |  |  | 맞은 예외 id |
| `incident_id` | string |  |  | 같은 사건 묶음 id. 단독은 사건의 첫 탐지 detection_id, 상관은 detection_id 와 같음 |
| `occurrence` | integer |  | 최소 1 | 사건 안에서 몇 번째인지(1부터). 1 에서만 새 알림. 상관은 revision 과 같음 |
| `revision` | integer |  | 최소 1 | 상관 탐지만: 같은 체인의 갱신 번호(1부터). detection_id 별 가장 큰 행이 현재 상태 |
| `member_detection_ids` | array<string> |  |  | 상관 탐지만: 체인을 이루는 단독 탐지의 detection_id(처음 본 순서) |

## 근거 (`evidence`)

탐지 1건에 근거 여러 행. evidence_id 로 nsm_detection.evidence_ids 와 조인하고, uid·fuid 로 conn.log·files.log·선별 전송 로그와 조인한다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 근거 시각 |
| `evidence_id` | string | 필수 |  | 어느 탐지의 근거인지(notice·nsm_detection 과 공유하는 키) |
| `note` | string |  | 형식 `^NSM::[A-Za-z0-9_]+$` | 탐지 종류(Zeek notice 이름, NSM::<룰>) |
| `rule` | string |  | 열거값 49개(아래 표) | note 에서 NSM:: 를 뺀 값(nsm_detection.rule 과 같음) |
| `killchain_stage` | string |  | `Command and Control`, `Credential Access`, `Exfiltration`, `Impact`, `Initial Access`, `Lateral Movement`, `Recon` | 킬체인 단계명 |
| `technique` | string |  | 형식 `^T[0-9]{4}(\.[0-9]{3})?((, ?\|->)T[0-9]{4}(\.[0-9]{3})?)*$` | ATT&CK 기법 id. 여러 개면 쉼표, 상관 근거는 단계 순서를 -> 로 이음 |
| `account` | string |  |  | 관련 계정 원문(알 때만). 여러 개면 쉼표. 확산 근거는 인증 맥락에서 찾은 값 |
| `user_name` | string |  |  | account(첫 계정)의 사용자 부분, 소문자 |
| `user_domain` | string |  |  | account(첫 계정)의 도메인 부분. domain\user 의 domain, user@realm 의 realm |
| `user_domain_type` | string |  | `dns`, `netbios` | user_domain 에 점이 있으면 dns, 없으면 netbios |
| `src` | string(IP) |  |  | 출발 host |
| `dst` | string(IP) |  |  | 대상 host |
| `operation` | string |  |  | 행위(예: kerberos_as_failure, smb_tree_connect, killchain) |
| `uid` | string |  | 형식 `^C[0-9A-Za-z]+$` | 근거 연결의 Zeek uid(conn.log 등과 조인). 집계형은 표본 대상마다 대표 연결 하나 |
| `src_port` | integer |  | 최소 0, 최대 65535 | 근거 연결의 src 쪽 포트(근거 src·dst 방향에 맞춤) |
| `dst_port` | integer |  | 최소 0, 최대 65535 | 근거 연결의 dst 쪽 포트(프록시 경유면 프록시 포트) |
| `proto` | string |  | `tcp`, `udp`, `icmp` | 근거 연결의 전송 프로토콜 |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 근거 연결의 Community ID v1(seed community_id_seed, 기본 0) |
| `dst_name` | string |  |  | 목적지 이름(sni > host > name > DNS 상위 도메인 > 질의). 소문자, IP 제외 |
| `proxy` | string |  | 형식 `^\S+:[0-9]+$` | 거쳐 간 명시적 프록시 주소:포트 |
| `bytes` | integer |  |  | 출발지가 보낸 바이트 |
| `window_s` | number |  | 최소 0 | 집계형 근거의 집계 창(초) |
| `fuid` | string |  |  | 근거 파일의 Zeek fuid(files.log 조인) |
| `parent_id` | array<string> |  |  | 상관 근거가 묶는 하위 evidence_id |
| `detail` | string |  |  | 사람이 읽는 부가 정보(key=value). 형식은 룰마다 다르며 파싱하지 않는다 |

## 예외 적재·적중 (`nsm_exception`)

예외 파일을 읽은 결과(loaded·rejected·expired·error), 읽은 파일의 지문(file), 주기별 적중 수(hits).

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 기록 시각. 적재 결과 행(loaded·rejected·expired·error·file)은 실제 시각(벽시계), 적중 집계(hits)는 패킷 시각 |
| `node` | string | 필수 |  | 기록한 노드(standalone 은 zeek) |
| `kind` | string | 필수 | `loaded`, `rejected`, `expired`, `hits`, `error`, `file` | loaded(적재), rejected(형식 오류로 뺌), expired(기한 지남), hits(적중 수), error(파일 읽기 오류), file(읽은 예외 파일의 지문) |
| `exception_id` | string | 필수 |  | 예외 id |
| `disposition` | string |  | `drop`, `suppress` | 예외 처리: drop(탐지 안 함) 또는 suppress(탐지는 남기고 알림 안 함) |
| `scope` | array<string> |  |  | 적용 탐지(notice 이름 또는 group:<묶음>, 이름순) |
| `hits` | integer |  |  | 주기 안 적중 수(kind=hits) |
| `last_hit` | time(epoch 초) |  |  | 마지막 적중 시각(kind=hits) |
| `msg` | string |  |  | 거부 이유·출처(file, legacy) 등. kind=file 은 예외 파일 경로 |
| `file_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | kind=file: 읽은 예외 파일의 SHA1(파일 내용 그대로, sha1sum 과 같음). 파일을 다시 읽을 때마다 한 행. Manager 가 배포한 파일과 비교한다 |

## IOC 파일 적재 (`nsm_ioc`)

IOC 파일을 읽은 결과.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 기록 시각(실제 시각, 벽시계) |
| `kind` | string | 필수 | `summary`, `invalid`, `error`, `file` | summary(읽은 결과), invalid(형식이 틀려 뺀 항목), error(파일 읽기 오류), file(읽은 IOC 파일의 지문) |
| `indicator` | string |  |  | IOC 값(invalid 행) |
| `ioc_type` | string |  |  | IOC 종류(ip, domain, url 등. 모르면 -) |
| `msg` | string |  |  | 요약·이유. kind=file 은 IOC 파일 경로 |
| `file_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | kind=file: 읽은 IOC 파일의 SHA1. 파일을 다시 읽을 때마다 한 행 |

## 센서 상태 (`nsm_sensor`)

노드별 1분마다 한 행(종료 때 마지막 구간 한 행 더). 장비 현황(패킷·누락·지연·버전·적용 중인 데이터 파일)에 쓴다. CPU·메모리·디스크·전송 지연은 수집 에이전트가 채운다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 기록 시각(패킷 시각) |
| `node` | string | 필수 |  | 노드(standalone 은 zeek, 클러스터는 manager·worker-1 등). 패킷은 워커가 받는다 |
| `schema_version` | string | 필수 | 형식 `^[0-9a-f]{12}$` | 로그 스키마 버전(schema/logs 내용의 SHA-256 앞 12자리). Manager 는 이 값으로 해석할 스키마를 고른다 |
| `pkg_version` | string | 필수 |  | nsm_rules 패키지 버전(엔진 업데이트 화면) |
| `zeek_version` | string | 필수 |  | Zeek 버전 |
| `interval_s` | number | 필수 | 최소 0 | 이 행이 덮는 시간(초). 보통 60, 종료 행은 더 짧을 수 있음 |
| `pkts` | integer | 필수 |  | 이 구간에 받은 패킷 |
| `bytes` | integer | 필수 |  | 이 구간에 받은 바이트 |
| `pkts_dropped` | integer | 필수 |  | 이 구간에 캡처 장치(NIC·커널)가 놓친 패킷 |
| `drop_pct` | number | 필수 | 최소 0, 최대 100 | 놓친 패킷 비율(%): pkts_dropped / (pkts + pkts_dropped) |
| `gap_pct` | number |  | 최소 0, 최대 100 | TCP 누락 비율(%): 이 구간에 ACK 된 데이터 중 센서가 못 본 구간의 비율(미러 품질, capture_loss 와 같은 계산). TCP ACK 가 없던 구간은 없음 |
| `capture_lag_s` | number | 필수 |  | 처리 지연(초): 벽시계 - 패킷 시각. 커지면 센서가 밀리는 것. Manager 가 늦게 오는 이벤트를 기다릴 시간을 정할 때 쓴다. pcap 재생에서는 의미 없음 |
| `uptime_s` | number | 필수 | 최소 0 | 시작 후 시간(초, 벽시계) |
| `exc_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | 이 노드가 마지막으로 읽은 예외 파일 SHA1(파일을 읽는 노드만, 클러스터는 매니저) |
| `ioc_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | 마지막으로 읽은 IOC 파일 SHA1 |
| `policy_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | 마지막으로 읽은 에이전트 정책 파일 SHA1 |

## 자산 신호 (`asset_signal`)

자산 식별에 쓰는 관측 사실. 판정(엔티티 리졸루션)은 Manager 가 한다. 신호 정의는 docs/asset-id/SPEC.md.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 관측 시각 |
| `uid` | string |  |  | 근거 연결 uid(있을 때) |
| `ip` | string(IP) | 필수 |  | 신호가 가리키는 자산 IP |
| `mac` | string |  |  | 관측 시점의 MAC(알 때) |
| `signal` | string | 필수 | 열거값 19개(아래 표) | 신호 종류(SPEC 2.1) |
| `value` | string | 필수 |  | 신호 값(정규화됨) |
| `source` | string | 필수 | 형식 `^[a-z0-9_]+$` | 신호 출처(프로토콜·분석기 이름, SPEC 3장) |
| `confidence` | integer | 필수 | 최소 0, 최대 100 | 출처 기준 신뢰도 0~100 |
| `user_name` | string |  |  | 계정 신호만: 사용자 부분(소문자) |
| `user_domain` | string |  |  | 계정 신호만: 도메인 부분 |
| `user_domain_type` | string |  | `dns`, `netbios` | 계정 신호만: dns 또는 netbios |

## 에이전트 정책 적재 (`asset_agent_policy`)

고객 정의 에이전트 정책 파일을 읽은 결과(SPEC 3.17).

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 기록 시각(실제 시각, 벽시계) |
| `kind` | string | 필수 | `summary`, `invalid`, `error`, `file` | summary(읽은 결과), invalid(형식이 틀려 뺀 정책), error(파일 읽기 오류), file(읽은 정책 파일의 지문) |
| `policy_id` | string |  |  | 정책 id(invalid 행) |
| `msg` | string | 필수 |  | 요약·이유. kind=file 은 정책 파일 경로 |
| `file_sha1` | string |  | 형식 `^[0-9a-f]{40}$` | kind=file: 읽은 정책 파일의 SHA1. 파일을 다시 읽을 때마다 한 행 |

## 선별 전송 통계 (`meta/meta_export_stats`)

선별 전송 스트림별 주기(meta_stats_interval) 통계.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 기록 시각 |
| `node` | string | 필수 |  | 기록한 노드 |
| `stream` | string | 필수 |  | 선별 전송 이름(meta_export_streams 의 name) |
| `sent` | integer | 필수 |  | 보낸 행 |
| `dropped_scope` | integer | 필수 |  | 범위 밖이라 뺀 행 |
| `dropped_filter` | integer | 필수 |  | 스트림별 조건으로 뺀 행 |
| `dropped_dedup` | integer | 필수 |  | 중복 억제로 뺀 행 |
| `dropped_rate` | integer | 필수 |  | 분당 상한 초과로 뺀 행 |
| `summarized` | integer | 필수 |  | 요약 로그로 묶은 행 |

## 연결 요약 (`meta/flow_summary`)

conn.log 대신 보내는 주기별 (출발, 목적지, 포트, 프로토콜) 요약(SRS_METADATA_EXPORT).

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 주기 안 첫 연결 시작 시각 |
| `node` | string | 필수 |  | 기록한 노드 |
| `orig_h` | string(IP) | 필수 |  | 출발 주소 |
| `resp_h` | string(IP) | 필수 |  | 목적지 주소 |
| `resp_p` | integer | 필수 | 최소 0, 최대 65535 | 목적지 포트 |
| `proto` | string | 필수 | `icmp`, `tcp`, `udp`, `unknown_transport` | 전송 프로토콜 |
| `service` | array<string> |  |  | 관측된 서비스(이름순) |
| `conns` | integer | 필수 |  | 연결 수 |
| `orig_bytes` | integer | 필수 |  | 출발 쪽이 보낸 바이트 합 |
| `resp_bytes` | integer | 필수 |  | 목적지 쪽이 보낸 바이트 합 |
| `states` | string |  |  | 연결 상태별 건수(예: SF:12,S0:3) |
| `sample_uid` | string |  |  | 대표 연결 uid(원본 conn 로그를 남길 때만) |

## DNS 요약 (`meta/dns_summary`)

dns.log 대신 보내는 주기별 (출발, 도메인) 요약(SRS_METADATA_EXPORT).

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 주기 안 첫 질의 시각 |
| `ts_end` | time(epoch 초) | 필수 |  | 주기 안 마지막 질의 시각 |
| `node` | string | 필수 |  | 기록한 노드 |
| `orig_h` | string(IP) | 필수 |  | 질의한 주소 |
| `domain` | string | 필수 |  | 등록 도메인(co.kr 등 2단계 접미사 처리). 출발지당 상한을 넘은 도메인은 (other) |
| `qtypes` | array<string> |  |  | 관측된 질의 유형(이름순) |
| `rcodes` | string |  |  | 결과별 질의 수(예: NOERROR:12,NXDOMAIN:1) |
| `queries` | integer | 필수 |  | 질의 수 |
| `unique_names` | integer | 필수 |  | 고유 질의 이름 수 |
| `unique_names_capped` | boolean |  |  | 참일 때만 기록: 고유 이름 상한에 닿아 그 뒤는 세지 않음 |
| `sample_names` | array<string> | 필수 |  | 처음 관측한 질의 이름(최대 meta_dns_max_samples) |
| `answers` | array<string> |  |  | 처음 관측한 응답(최대 meta_dns_max_answers) |
| `sample_uid` | string |  |  | 대표 uid(원본 dns 로그를 남길 때만) |

## HTTP User-Agent 요약 (`meta/http_ua_summary`)

주기별 (출발, User-Agent) 요약(SRS_METADATA_EXPORT).

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  | 주기 안 첫 요청 시각 |
| `ts_end` | time(epoch 초) | 필수 |  | 주기 안 마지막 요청 시각 |
| `node` | string | 필수 |  | 기록한 노드 |
| `orig_h` | string(IP) | 필수 |  | 요청한 주소 |
| `user_agent` | string | 필수 |  | User-Agent |
| `requests` | integer | 필수 |  | 선별 대상 http 요청 수(중복 억제 전) |
| `hosts` | integer | 필수 |  | 고유 Host 수(100개까지 셈) |
| `sample_host` | string |  |  | 대표 Host |

## 선별 전송: capture_loss (`meta/capture_loss`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `ts_delta` | number(초) | 필수 |  |  |
| `peer` | string | 필수 |  |  |
| `gaps` | integer | 필수 |  |  |
| `acks` | integer | 필수 |  |  |
| `percent_lost` | number | 필수 |  |  |

## 선별 전송: dce_rpc (`meta/dce_rpc`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `endpoint` | string |  |  |  |
| `operation` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: http (`meta/http`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `method` | string |  |  |  |
| `host` | string |  |  |  |
| `request_body_len` | integer | 필수 |  |  |
| `response_body_len` | integer | 필수 |  |  |
| `status_code` | integer |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |
| `uri_path` | string |  |  |  |

## 선별 전송: kerberos (`meta/kerberos`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `request_type` | string |  |  |  |
| `client` | string |  |  |  |
| `service` | string |  |  |  |
| `success` | boolean |  |  |  |
| `error_msg` | string |  |  |  |
| `cipher` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: ntlm (`meta/ntlm`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `username` | string |  |  |  |
| `hostname` | string |  |  |  |
| `domainname` | string |  |  |  |
| `success` | boolean |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: rdp (`meta/rdp`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `cookie` | string |  |  |  |
| `result` | string |  |  |  |
| `security_protocol` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: reporter (`meta/reporter`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `level` | string | 필수 |  |  |
| `message` | string | 필수 |  |  |
| `location` | string |  |  |  |

## 선별 전송: smb_files (`meta/smb_files`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `action` | string |  |  |  |
| `path` | string |  |  |  |
| `name` | string |  |  |  |
| `size` | integer | 필수 |  |  |
| `prev_name` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: smb_mapping (`meta/smb_mapping`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `path` | string |  |  |  |
| `share_type` | string | 필수 |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: ssh (`meta/ssh`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `auth_success` | boolean |  |  |  |
| `auth_attempts` | integer | 필수 |  |  |
| `direction` | string |  |  |  |
| `client` | string |  |  |  |
| `server` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: ssl (`meta/ssl`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `uid` | string | 필수 |  |  |
| `orig_h` | string(IP) | 필수 |  |  |
| `orig_p` | integer | 필수 |  |  |
| `resp_h` | string(IP) | 필수 |  |  |
| `resp_p` | integer | 필수 |  |  |
| `version` | string |  |  |  |
| `cipher` | string |  |  |  |
| `server_name` | string |  |  |  |
| `established` | boolean | 필수 |  |  |
| `ja3` | string |  |  |  |
| `community_id` | string |  | 형식 `^1:[A-Za-z0-9+/]{27}=$` | 연결의 Community ID v1(seed community_id_seed, 기본 0, base64). conn 5-tuple 로 계산하며 근거(evidence)의 community_id 와 같은 값이다. Manager 가 Suricata 경보 등 다른 제품의 이벤트와 연결 단위로 잇는 키(SURICATA_INTEGRATION_DESIGN 3.3) |

## 선별 전송: stats (`meta/stats`)

Zeek 기본 로그의 선별본(필드는 meta_export_streams 의 fields). 필드 뜻은 Zeek 문서의 같은 로그를 따른다.

| 필드 | 타입 | 필수 | 값 | 설명 |
| --- | --- | --- | --- | --- |
| `ts` | time(epoch 초) | 필수 |  |  |
| `peer` | string | 필수 |  |  |
| `mem` | integer | 필수 |  |  |
| `pkts_proc` | integer | 필수 |  |  |
| `bytes_recv` | integer | 필수 |  |  |
| `pkts_dropped` | integer |  |  |  |
| `pkts_link` | integer |  |  |  |
| `pkt_lag` | number(초) |  |  |  |
| `pkts_filtered` | integer |  |  |  |
| `events_proc` | integer | 필수 |  |  |
| `events_queued` | integer | 필수 |  |  |
| `active_tcp_conns` | integer | 필수 |  |  |
| `active_udp_conns` | integer | 필수 |  |  |
| `active_icmp_conns` | integer | 필수 |  |  |
| `tcp_conns` | integer | 필수 |  |  |
| `udp_conns` | integer | 필수 |  |  |
| `icmp_conns` | integer | 필수 |  |  |
| `timers` | integer | 필수 |  |  |
| `active_timers` | integer | 필수 |  |  |
| `files` | integer | 필수 |  |  |
| `active_files` | integer | 필수 |  |  |
| `dns_requests` | integer | 필수 |  |  |
| `active_dns_requests` | integer | 필수 |  |  |
| `reassem_tcp_size` | integer | 필수 |  |  |
| `reassem_file_size` | integer | 필수 |  |  |
| `reassem_frag_size` | integer | 필수 |  |  |
| `reassem_unknown_size` | integer | 필수 |  |  |

## 열거값

### 룰과 진단명 (`rule`, `diagnosis`)

단독 탐지의 `diagnosis`는 룰마다 고정입니다. 상관 탐지(`Correlated_KillChain`)는 `NSM.Correlation.<첫 단계>.<가장 많이 진행된 단계>`입니다.

| `rule` | `diagnosis` |
| --- | --- |
| `AD_Enumeration` | `NSM.Recon.AdEnumeration` |
| `AI_API_From_Server` | `NSM.C2.AiApiFromServer` |
| `AI_Service_Exploit` | `NSM.WebAttack.AiServiceExploit` |
| `AI_Service_Upload` | `NSM.Exfiltration.AiServiceUpload` |
| `ASREP_Roasting` | `NSM.CredentialAccess.AsrepRoasting` |
| `Coerced_Authentication` | `NSM.CredentialAccess.CoercedAuth` |
| `Correlated_KillChain` | `NSM.Correlation.<첫 단계>.<마지막 단계>` |
| `Cross_Site_Scripting` | `NSM.WebAttack.Xss` |
| `DCOM_Lateral` | `NSM.LateralMovement.DcomExec` |
| `DCSync` | `NSM.CredentialAccess.DcSync` |
| `DGA_Domain` | `NSM.C2.DgaDomain` |
| `DNS_Tunneling` | `NSM.C2.DnsTunneling` |
| `Encrypted_C2` | `NSM.C2.EncryptedChannel` |
| `Exfil_DNS` | `NSM.Exfiltration.DnsTunnel` |
| `Exfil_Large_Transfer` | `NSM.Exfiltration.LargeTransfer` |
| `Exfil_Volume_Aggregate` | `NSM.Exfiltration.VolumeAggregate` |
| `Exfil_Web_Upload` | `NSM.Exfiltration.WebUpload` |
| `FTP_Bruteforce` | `NSM.CredentialAccess.FtpBruteforce` |
| `HTTP_Beaconing` | `NSM.C2.HttpBeaconing` |
| `HTTP_Bruteforce` | `NSM.CredentialAccess.HttpBruteforce` |
| `Host_Scan` | `NSM.Recon.HostScan` |
| `IOC_Match` | `NSM.C2.IocMatch` |
| `Kerberoasting` | `NSM.CredentialAccess.Kerberoasting` |
| `Kerberos_Bruteforce` | `NSM.CredentialAccess.KerberosBruteforce` |
| `Kerberos_Spray` | `NSM.CredentialAccess.KerberosSpray` |
| `Long_Connection` | `NSM.C2.LongConnection` |
| `Machine_Account_Misuse` | `NSM.CredentialAccess.MachineAccountMisuse` |
| `NTLM_Credential_Leak` | `NSM.CredentialAccess.NtlmCredentialLeak` |
| `NTLM_Spray` | `NSM.CredentialAccess.NtlmSpray` |
| `Name_Poisoning` | `NSM.CredentialAccess.NamePoisoning` |
| `Nonstandard_Port` | `NSM.C2.NonstandardPort` |
| `Outbound_SMB` | `NSM.Exfiltration.OutboundSmb` |
| `Port_Scan` | `NSM.Recon.PortScan` |
| `RDP_Lateral` | `NSM.LateralMovement.RdpAccess` |
| `Remote_Registry_Dump` | `NSM.CredentialAccess.RemoteRegistryDump` |
| `Remote_Service_Creation` | `NSM.LateralMovement.RemoteService` |
| `Remote_Task_Creation` | `NSM.LateralMovement.RemoteTask` |
| `Remote_WMI_Execution` | `NSM.LateralMovement.RemoteWmi` |
| `SMB_Admin_Share` | `NSM.LateralMovement.SmbAccess` |
| `SMB_Ransomware` | `NSM.Impact.SmbRansomware` |
| `SQL_Injection` | `NSM.WebAttack.SqlInjection` |
| `SSH_Bruteforce` | `NSM.CredentialAccess.SshBruteforce` |
| `SSH_Lateral` | `NSM.LateralMovement.SshAccess` |
| `TLS_Beaconing` | `NSM.C2.TlsBeaconing` |
| `TLS_Heartbleed` | `NSM.WebAttack.Heartbleed` |
| `Unknown_Protocol` | `NSM.C2.UnknownProtocol` |
| `Webshell_Access` | `NSM.WebAttack.Webshell` |
| `WinRM_Lateral` | `NSM.LateralMovement.WinrmAccess` |
| `Zerologon_Attempt` | `NSM.CredentialAccess.Zerologon` |

### 킬체인 단계 (`killchain_stages`, `killchain_stage`)

`Command and Control`, `Credential Access`, `Exfiltration`, `Impact`, `Initial Access`, `Lateral Movement`, `Recon`

### 자산 신호 종류 (`asset_signal.signal`)

`device`, `dhcp_client_id`, `dhcp_fingerprint`, `dhcp_vendor_class`, `dns_name`, `domain`, `form_factor`, `fqdn`, `hostname`, `mac`, `machine_account`, `os_hint`, `security_agent`, `service`, `smb_client_guid`, `software`, `ssh_host_key`, `tcp_fp`, `user_account`. 각 신호의 뜻은 [자산 식별 SPEC 2.1](asset-id/SPEC.md).

