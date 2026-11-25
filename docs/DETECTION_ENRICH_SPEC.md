# 탐지 정보 보강 스펙 (Manager)

작성: 2026-11-25 · 상태: 1차 범위 스펙 · 화면 목업: [`ui/mockup/mdsm_nsm_mockup_phase1.html`](../ui/mockup/mdsm_nsm_mockup_phase1.html)(NSM 분석 › NSM 탐지 › 상세) · PoC 구현: [`tests/detection_enrich.py`](../tests/detection_enrich.py) · 관련: [메타데이터 선별 전송 SRS](SRS_METADATA_EXPORT.md), [로그 스키마](LOG_SCHEMA.md), [리포트 스펙](REPORT_SPEC.md) 3.3절

## 0. 요약

MDS Manager가 NSM 탐지 상세에 **선별 전송 로그(메타데이터)로 판단 보조 정보**를 붙이는 규칙입니다. 센서는 바꾸지 않습니다.

- **화면:** 한눈에 보기(성공 흔적 · 지금도 통신 중 · 목적지 이름 · 계정 맥락), 핵심 사실, 30분별 추이, 기록 표(근거 연결 · 같은 연결 묶음 · 같은 시간대). 목록에는 "성공 흔적"·"통신 중" 칩을 붙입니다.
- **구조:** 룰별 코드는 두지 않습니다. **조회 4개 → 로그별 요약기 12개 → 판단 4개 → 공통 화면 1개**가 모든 룰에 같습니다. 룰마다 다른 점은 **설정 표 한 줄**(6장)입니다.
- **검증:** PoC(`tests/detection_enrich.py`)가 이 규칙을 그대로 구현하고, 목업형 리포트가 그 결과로 탐지 상세를 그립니다. btest `rules/report-enrich`와 규칙 단위 테스트가 확인합니다.

```
탐지·근거 ─▶ ① 조회(Q1~Q4) ─▶ ② 로그별 요약기 ─▶ ③ 판단 4개 ─▶ ④ 공통 화면
                 ▲ 룰 설정 표(보여 줄 로그 · Kerberos 접두사 · 조회 방식 · 시간 범위 · 성공 판단)
```

## 1. 범위

| 포함 | 제외(하반기, 소급검색 지표 색인과 함께) |
| --- | --- |
| 단독 탐지 상세의 보강, 탐지 목록·상관 탐지 구성 표의 칩 | 처음 본 대상(보관 기간 중 처음 접속인지) |
| 탐지마다 정한 시간 범위 안의 조회(보관 중인 원 로그) | 목적지 보급도(최근 7일 같은 목적지 접속 장비 수) |
| | 평소 하던 통신(탐지 전 며칠 같은 쌍), 기준선 비교("평소 응답 크기") |

상관 탐지(`Correlated_KillChain`)는 보강하지 않습니다. 구성 탐지마다 보강하고, 상관 탐지 상세의 구성 탐지 표에 칩만 보여 줍니다.

## 2. 입력

| 입력 | 필드 | 쓰는 곳 |
| --- | --- | --- |
| 탐지 요약(`nsm_detection`) | `attacker`, `victims`, `first_seen`, `last_seen`, `killchain_stages`, `rule`(또는 `diagnosis`) | 출발지·대상·시간, 룰 설정 찾기 |
| 근거(`evidence`) | `uid`, `src`, `dst`, `ts`, `window_s`, `account`, `dst_name`, `proxy` | Q1 정확 일치, 대상이 없는 탐지의 대상(근거 `dst`), 집계 창, 계정 맥락, DNS 계열 도메인 |
| 선별 전송(`meta/*`) | 행 단위 9종: `kerberos`, `ntlm`, `smb_mapping`, `smb_files`, `dce_rpc`, `rdp`, `ssh`, `ssl`, `http`. 요약 3종: `flow_summary`, `dns_summary`, `http_ua_summary` | 조회 대상 |

필드 이름은 [LOG_SCHEMA.md](LOG_SCHEMA.md)와 같습니다(연결 주소는 `orig_h`·`resp_h`).

## 3. 조회

시간 범위의 기준은 탐지 처음·마지막 시각입니다(`first`, `last`). 집계형 룰(설정 표 `window=agg`)은 처음 시각을 근거 `window_s`만큼 앞으로 넓힙니다.

| # | 이름 | 조건 | 로그 | 시간 범위 |
| --- | --- | --- | --- | --- |
| Q1 | 근거 연결 | 근거 `uid`와 같은 행 | 행 단위 9종 | 제한 없음 |
| Q1' | 같은 연결 묶음 | Q1에서 그 로그의 행이 없을 때, 같은 출발지이고 목적지(`resp_h` = 근거 `dst`) 또는 이름(ssl `server_name`·http `host` = 근거 `dst_name`)이 같은 앞선 행 | `ssl`, `http`, `smb_mapping`(설정 표의 보여 줄 로그에 있을 때) | 근거 시각 전 억제 기간: ssl 24시간, http 10분, smb 공유 1시간 |
| Q2 | 연결 요약 | 출발지, 대상 | `flow_summary` | 처음 30분 전 \~ 마지막 10분 뒤 |
| Q3 | DNS | `query=domain`: 출발지, 등록 도메인이 근거 `dst_name`·대상과 맞는 행. `query=ip`: 출발지, `answers`에 대상 IP | `dns_summary` | 처음 30분 전 \~ 마지막 10분 뒤 |
| Q4 | 같은 시간대(추정) | 출발지, 대상(Kerberos는 6장 접두사로), Q1·Q1'에 든 행은 뺌 | 행 단위 중 보여 줄 로그 | 처음 10분 전 \~ 마지막 10분 뒤 |
| (UA) | 프로그램 | 출발지 | `http_ua_summary`(보여 줄 로그에 있을 때) | 처음 24시간 전 \~ 마지막 10분 뒤 |

- **Q1'가 필요한 이유:** 센서는 같은 키의 행을 억제 기간 동안 한 번만 보냅니다([SRS_METADATA_EXPORT](SRS_METADATA_EXPORT.md) 4.1절). 예를 들어 비커닝의 31번째 연결은 `ssl` 행이 없습니다. Q1'가 없으면 반복 탐지 대부분이 "근거 연결 기록 없음"이 됩니다.
- **대상이 없는 탐지**(비커닝 등 `victims`가 빈 탐지)는 근거의 `dst`를 대상으로 씁니다.
- **Kerberos:** 요청이 KDC로 가므로 대상 대신 서비스(SPN) 접두사로 거릅니다(6장). 자격증명 탐지(`kpre=()`)는 대상과 무관하게 출발지의 모든 요청이 근거입니다.

## 4. 로그별 요약기

각 요약기는 그 로그의 행(Q1 + Q1' + Q4, 요약 로그는 Q2·Q3·UA)을 받아 `[(항목, 값)]`을 냅니다. 항목 이름은 아래 표로 고정이며, 룰마다 다른 항목은 없습니다. 행은 로그별 200개까지 씁니다.

| 로그 | 항목 | 값 |
| --- | --- | --- |
| `http` | 요청 경로 | `uri_path` 상위 3개와 건수, "외 N개" |
| | Host | `host`가 둘 이상일 때만, 상위 3개 |
| | 상태 코드 | `status_code`를 시각순 연속 구간으로(예: `500 × 12 → 200 × 3`), 6구간까지 |
| | 가장 큰 응답 | `response_body_len` 최댓값 |
| `ssl` | 접속 도메인 | `server_name` 상위 3개(없으면 "SNI 없음") |
| | TLS | `version` 상위 2개 · 핸드셰이크 완료 수/행 수(`established`) |
| | JA3 | `ja3` 최다 1개 |
| `kerberos` | 요청 서비스 | `service` 상위 3개 |
| | 티켓 암호 | `cipher` 상위 2개 |
| | 결과 | 성공·실패 수(`success`), 실패면 `error_msg` 상위 2개 |
| | 계정 | `client`의 계정 부분 상위 3개 |
| `ntlm` | 계정 | `domainname\username` 상위 3개 |
| | 결과 | 성공·실패 수(`success`가 있을 때) |
| `smb_mapping` | 공유 | `path` 상위 3개 |
| `smb_files` | 파일 동작 | `action`(write·rename·delete) 상위 4개 |
| | 파일 예 | `prev_name → name` 또는 `name`, 2개와 "외 N개" |
| `dce_rpc` | 원격 호출 | `endpoint::operation`을 처음 본 순서로 4개 |
| `rdp` | 접속 계정 힌트 | `cookie` 상위 3개 |
| | 결과 | `result` 상위 2개 |
| `ssh` | 인증 | 시도 합(`auth_attempts`) · 성공한 연결 수/행 수(`auth_success`) |
| | 클라이언트 | `client` 상위 2개 |
| `flow_summary` | 연결 | 연결 수(`conns`) · 보냄(`orig_bytes`) · 받음(`resp_bytes`) |
| | 연결 상태 | `states` 합계 상위 4개(예: `S0 27 · REJ 11 · SF 3`) |
| | 범위 또는 포트 | 대상이 둘 이상이거나 포트가 4개 이상이면 "대상 N개 · 포트 M개", 아니면 `포트/프로토콜` 목록 |
| `dns_summary` | 질의 이름 예 | `sample_names` 2개 |
| | 고유 이름 | `unique_names` 합 / 질의 수(`queries`) |
| | 결과 | `rcodes` 합계 상위 3개 |
| | 응답 | `answers` 3개 |
| `http_ua_summary` | 프로그램(User-Agent) | `user_agent`별 요청 수 상위 2개 |

**표기:** 바이트는 B·KB·MB(소수 한 자리), 건수가 1이면 숫자를 붙이지 않고 2 이상이면 "N번", 값은 200자까지.

**핵심 사실의 순서:** 6장 "보여 줄 로그" 순서대로 각 요약기의 항목을 잇습니다. 보여 줄 로그가 아닌 로그는 기록 표에만 나옵니다.

## 5. 판단

| 칩 | 규칙 | 화면 |
| --- | --- | --- |
| **성공 흔적** | 보여 줄 로그 가운데 **행 단위 로그**의 성공·실패 표시를 셉니다. 하나도 없을 때만 `flow_summary` 연결 상태를 씁니다(Kerberos·SMB 탐지에서 연결이 정상 종료됐다는 것만으로 성공이라 하지 않게). 성공만 있으면 `hi`, 둘 다면 `mid`, 실패만이면 `no`, 표시가 없으면 칩 없음 | `hi` "성공 흔적"(빨강), `mid` "일부 응답"(주황), `no` "실패만"(초록). 근거로 로그별 성공·실패 수 |
| **지금도 통신 중** | 탐지 마지막 시각 1분 뒤부터 같은 (출발지, 대상)의 `flow_summary`·행 단위 행이 있으면 켬. DNS 계열(`query=domain`)은 같은 도메인의 `dns_summary` 행으로 | "지금도 통신 중" 또는 "멈춤", 마지막으로 본 시각 |
| **목적지 이름** | 대상이 외부 IP이고 근거에 `dst_name`이 없을 때, 출발지가 탐지 1시간 전 \~ 마지막에 조회한 `dns_summary`의 `answers`에 그 IP가 있으면 그 도메인. 없으면 "이름 없음". `dns_summary`를 받지 않는 센서면 칩 없음 | "목적지 이름 X" 또는 "이름 없음(IP로 바로 접속)" |
| **계정 맥락** | 근거 `account`가 있으면, 앞뒤 1시간 kerberos(`client`)·ntlm(`username`)에서 같은 계정(소문자, 도메인 제외)으로 요청한 출발지 장비 | 계정, 장비 수, 목록(10대까지) |

성공·실패 표시:

| 로그 | 성공 | 실패 |
| --- | --- | --- |
| `http` | 상태 2xx·3xx | 4xx·5xx |
| `http`(`result=web`) | 같은 연결(`uid`)에서 4xx·5xx 뒤에 2xx·3xx | 같은 연결에 오류만 있음(2xx만인 연결은 세지 않음) |
| `kerberos`, `ntlm` | `success` = 참 | `success` = 거짓 |
| `ssh` | `auth_success` = 참 | `auth_success` = 거짓 |
| `ssl` | `established` = 참 | `established` = 거짓 |
| `rdp` | `result` = `Success` | (세지 않음) |
| `smb_files` | 행이 있음(쓰기·이름 변경·삭제가 일어남) | (세지 않음) |
| `flow_summary` | `states`의 `SF` 수 | `S0`·`REJ` 수 |

판단은 참고 정보입니다. 화면에 "통신 기록(메타데이터)으로 판단한 참고 정보"라고 표시하고, 탐지 등급이나 알림에는 쓰지 않습니다.

## 6. 룰 설정 표

| 열 | 값 | 기본 |
| --- | --- | --- |
| `logs` | 핵심 사실에 올릴 로그와 순서 | `flow_summary` |
| `kpre` | Kerberos 서비스 접두사. 없음 = 대상으로 간 행만, `()` = 출발지의 모든 요청 | 없음 |
| `query` | `ip` 또는 `domain`(DNS 계열) | `ip` |
| `window` | `near` 또는 `agg`(근거 `window_s`만큼 앞으로) | `near` |
| `result` | `any` 또는 `web` | `any` |

단독 탐지 룰 48개 전체(PoC `RULES`와 같음, 표에 없는 룰은 기본):

| 룰 | `logs` | `kpre` | `query` | `window` | `result` |
| --- | --- | --- | --- | --- | --- |
| `Port_Scan`, `Host_Scan`, `FTP_Bruteforce` | flow\_summary | | | agg | |
| `Unknown_Protocol`, `Name_Poisoning` | flow\_summary | | | | |
| `SQL_Injection`, `Cross_Site_Scripting`, `AI_Service_Exploit` | http, flow\_summary | | | | web |
| `Webshell_Access` | http, flow\_summary | | | | |
| `HTTP_Bruteforce` | http, flow\_summary | | | agg | |
| `HTTP_Beaconing` | http, http\_ua\_summary, flow\_summary | | | agg | |
| `TLS_Beaconing` | ssl, flow\_summary | | | agg | |
| `Encrypted_C2`, `Long_Connection`, `TLS_Heartbleed` | ssl, flow\_summary | | | | |
| `Nonstandard_Port`, `Exfil_Large_Transfer` | ssl, http, flow\_summary | | | | |
| `Exfil_Volume_Aggregate`, `Exfil_Web_Upload` | ssl, http, flow\_summary | | | agg | |
| `AI_API_From_Server` | ssl, http, http\_ua\_summary, flow\_summary | | | | |
| `AI_Service_Upload` | ssl, http, http\_ua\_summary, flow\_summary | | | agg | |
| `IOC_Match` | ssl, http, dns\_summary, flow\_summary | | | | |
| `DGA_Domain`, `DNS_Tunneling`, `Exfil_DNS` | dns\_summary | | domain | agg | |
| `NTLM_Spray` | ntlm, flow\_summary | | | agg | |
| `Kerberos_Spray`, `Kerberos_Bruteforce`, `Kerberoasting`, `ASREP_Roasting` | kerberos, flow\_summary | `()` | | agg | |
| `Machine_Account_Misuse` | ntlm, kerberos, flow\_summary | `()` | | | |
| `NTLM_Credential_Leak`, `Outbound_SMB` | ntlm, smb\_mapping, flow\_summary | | | | |
| `SSH_Bruteforce`, `SSH_Lateral` | ssh, flow\_summary | | | agg | |
| `DCSync` | dce\_rpc, kerberos, flow\_summary | `e3514235-…/`, `ldap/` | | | |
| `Zerologon_Attempt` | dce\_rpc, flow\_summary | | | agg | |
| `AD_Enumeration`, `SMB_Admin_Share` | ntlm, kerberos, smb\_mapping, smb\_files, dce\_rpc, flow\_summary | `cifs/`, `host/` | | agg | |
| `Coerced_Authentication`, `Remote_Registry_Dump` | 위와 같음 | `cifs/`, `host/` | | | |
| `Remote_Service_Creation`, `Remote_Task_Creation` | 위와 같음 | `cifs/`, `host/`, `rpcss/` | | | |
| `RDP_Lateral` | ntlm, kerberos, rdp, flow\_summary | `termsrv/` | | agg | |
| `WinRM_Lateral` | ntlm, kerberos, flow\_summary | `http/`, `wsman/` | | agg | |
| `DCOM_Lateral` | ntlm, kerberos, dce\_rpc, flow\_summary | `rpcss/`, `host/` | | agg | |
| `Remote_WMI_Execution` | ntlm, kerberos, dce\_rpc, flow\_summary | `rpcss/`, `host/` | | | |
| `SMB_Ransomware` | ntlm, kerberos, smb\_mapping, smb\_files, flow\_summary | `cifs/` | | agg | |

**새 룰을 추가할 때:** 이 표와 PoC `RULES`에 한 줄을 넣습니다. 단위 테스트가 `RULES`와 룰 목록이 같은지 검사합니다.

## 7. 출력 형식 (Manager 화면 API)

```json
{
  "rule": "Kerberoasting",
  "judge": {
    "result":  {"level": "hi", "ok": 6, "bad": 0, "why": "kerberos 성공 6·실패 0"},
    "live":    {"on": false, "last_seen": 1794182946.05},
    "name":    {"domain": "partner.example", "how": "dns_answer"},
    "account": {"name": "svc_web@corp.example", "hosts": ["10.0.10.81"], "n": 1}
  },
  "facts":   [{"log": "kerberos", "label": "티켓 암호", "value": "rc4-hmac 6번", "rows": 6}],
  "series":  {"label": "30분별 연결 수", "unit": "conns", "points": [[1794181800, 31], [1794183600, 30]]},
  "records": {"exact": [{"ts": 1794182941.0, "log": "kerberos", "src": "10.0.10.81", "dst": "10.0.0.10", "text": "TGS svc_web → MSSQLSvc/db01… · rc4-hmac · 성공", "uid": "CCWniJ3itzTlM3lE7"}],
              "grouped": [], "nearby": []},
  "limits":  ["ssl·http 는 내부↔외부 통신만, 예외 도메인은 기록하지 않음"]
}
```

- `judge`의 키는 판단할 수 있을 때만 있습니다. `name.domain`이 `null`이면 "이름 없음"입니다.
- `series`는 `flow_summary`가 30분 구간 2개 이상일 때만 있습니다. 정보 유출 단계는 보낸 바이트(`bytes`), 그 밖은 연결 수(`conns`)입니다.
- `records`는 종류마다 시각순 50행까지입니다. `text`는 사람이 읽는 한 줄이고, 주소는 `src`·`dst`로 따로 둡니다.
- 보강할 것이 하나도 없으면 빈 객체입니다(화면은 기본 정보만).

## 8. 계산 시점과 성능

| 대상 | 시점 |
| --- | --- |
| 상세 화면 | 열 때 계산하고 탐지 `revision`(단독 탐지는 `occurrence`)마다 저장 |
| 목록 칩(성공 흔적, 통신 중) | 탐지를 받을 때 계산. "통신 중"은 종료되지 않은 탐지만 30분마다(`flow_summary` 주기) 다시 계산 |

필요한 색인(1차에 필요, 소급검색 지표 색인과 별개):

| 로그 | 색인 |
| --- | --- |
| 행 단위 9종 | `uid`, `(orig_h, ts)` |
| `flow_summary` | `(orig_h, resp_h, ts)` |
| `dns_summary`, `http_ua_summary` | `(orig_h, ts)` |
| `kerberos`, `ntlm` | 계정(`client`의 계정 부분, `username`, 소문자), `ts` |

조회는 모두 출발지와 시간 범위로 좁혀지므로 탐지 하나에 행 수백 개 안쪽입니다. 원 로그 보관 기간(최소 90일 권장)은 하반기 기능(소급검색·공격 스토리)과 함께 정합니다.

## 9. 한계 (화면에 같이 표시)

`limits`에 해당하는 것만 넣어 화면 아래에 "※"로 보여 줍니다.

| 상황 | 문구 |
| --- | --- |
| Q1'로 묶은 행이 있음 | 같은 연결 묶음: 센서 중복 억제로 근거 연결의 행이 없어 같은 키의 앞선 행을 보여 줌 |
| 보여 줄 로그에 `ssl`·`http` | ssl·http는 내부 ↔ 외부 통신만, 예외 도메인은 기록하지 않음 |
| 목적지 이름을 판단함 | DNS 응답은 요약 행마다 3개까지만 남아 이름을 못 찾을 수 있음 |
| `http_ua_summary`를 씀 | User-Agent는 출발지 기준 요약이라 이 목적지에 쓴 것으로 단정할 수 없음 |
| 대상이 프록시 | 메타데이터의 대상은 프록시이고 실제 목적지는 CONNECT의 Host |

그 밖에 `flow_summary`는 30분, `dns_summary`는 1시간 단위라 시각이 정확하지 않습니다. Q4는 같은 시간대의 무관한 통신이 섞일 수 있어 "추정, 참고용"으로 표시합니다.

## 10. 화면 (목업)

[1차 범위 목업](../ui/mockup/mdsm_nsm_mockup_phase1.html) 탐지 상세의 위에서부터:

1. **한눈에 보기:** 칩 + 근거 문구(5장)
2. **핵심 사실:** 항목 · 값 · 출처 로그(4장)
3. **30분별 추이:** 막대(7장 `series`)
4. 한계 문구(9장)
5. 기본 정보 · 어떤 공격인가 · ATT&CK · 탐지한 근거(기존)
6. **기록 표:** 근거 연결의 기록(연결 ID 표시) → 같은 연결 묶음(있을 때만) → 같은 시간대 통신 기록(추정)

탐지 목록과 상관 탐지의 구성 탐지 표에는 탐지명 옆에 "성공 흔적"(`hi`·`mid`)과 "통신 중" 칩만 붙입니다.

## 11. 검증

| 테스트 | 확인하는 것 |
| --- | --- |
| `tests/test_detection_enrich.py`(btest `rules/report-enrich`가 실행) | 설정 표 = 룰 48개, Q1 정확 일치와 Q4 분리, Kerberos 성공은 kerberos 행으로만, Q1' 같은 연결 묶음(ssl 24시간 안만), 웹 공격 성공 판단(오류 뒤 2xx만, 2xx만이면 판단 안 함), 연결 상태로 성공·지금도 통신 중, DNS 응답으로 목적지 이름, DNS 계열은 도메인으로 조회·통신 중, 보강할 것이 없으면 빈 객체 |
| btest `rules/report-enrich`(`killchain_story.pcap`) | 목업형 리포트의 탐지 상세: Kerberoasting(RC4 6, 성공 6, 근거 연결 kerberos 행, 계정 맥락), 랜섬웨어(이름 변경·공유), HTTP 비콘(User-Agent, 상태 코드, 근거 연결 1행), 항목 이름이 4장 고정 목록 안, 기존 리포트 HTML에는 기록 표 없음 |

PoC는 pcap 한 개 안에서 계산합니다. "지금도 통신 중"은 캡처 끝까지를 기준으로 합니다.
