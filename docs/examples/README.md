# 예외 파일 예시

`exceptions.example.tsv`는 예외 엔진(`docs/SRS.md` 5.4절·7.8절) 형식의 **일반 예시**입니다. 주소는 문서용 대역(`203.0.113.0/24`, `198.51.100.0/24`)과 사설 대역, 도메인은 `*.example`이라 실제 고객 값이 아닙니다. 그대로 쓰지 말고 복사해서 값을 바꿉니다.

| id | 보여 주는 것 |
| --- | --- |
| `EX-epp-server`, `EX-edr-server` | 보안 제품 관리 서버(자체서명 인증서·비표준 포트)를 목적지 축으로 `Encrypted_C2`·`Nonstandard_Port`에서 뺌 |
| `EX-agent-beacon` | 에이전트 주기 통신을 도메인 축으로 `HTTP_Beaconing`에서 뺌(Host 헤더가 있을 때) |
| `EX-agent-beacon-ip` | Host 헤더가 없는 주기 통신은 도메인이 비어 있으므로 목적지·포트로 뺌 |
| `EX-jump-servers` | `group:lateral`로 측면 이동 탐지 묶음 전체에서 점프 서버를 뺌 |
| `EX-ansible-pair` | 출발지·목적지 대역·포트를 함께 줘서 특정 경로만 뺌(집계형 룰의 쌍 예외) |
| `EX-scanner` | 기간이 정해진 예외에 `expires`(epoch 초)와 근거 `ref`를 남김 |
| `EX-observe` | `disposition=suppress`: 탐지 기록은 남기고 알림만 끔(관찰용) |

## 쓰는 법

- pcap 확인: `tests/run_pcap.sh -x <예외 파일> <pcap>`. 리포트의 "예외" 절과 `zeek/nsm_exception.log`에서 `loaded`·`rejected`·적중 수를 봅니다.
- 운영: `redef NSM::exception_file = "/opt/nsm/conf/exceptions.tsv";`(부록 A.1). 파일은 임시 파일에 쓴 뒤 이름을 바꿔 교체합니다(7.8절).
- 열은 탭으로 구분합니다. 편집기가 탭을 공백으로 바꾸지 않게 주의합니다. 빈 값은 `-`입니다.
- `reason`·`owner`는 필수입니다. `<작성자>` 자리에 실제 담당자를 넣습니다.

## 고객 예외 파일은 저장소에 넣지 않는다

이 저장소는 공개 저장소입니다. 고객 환경에서 만든 예외 파일(실제 서버 IP·도메인·담당자)은 배포 설정(`nsm_config_custom.zeek`와 같은 위치)이나 별도 비공개 저장소에 둡니다.
