# Zeek 공개 테스트 trace 발췌

합성 pcap으로 만들기 어려운 실제 프로토콜 동작을 검증하기 위해 Zeek 프로젝트 테스트 trace에서 필요한 세션만 발췌했습니다.

| 파일 | 원본 | 내용 |
|---|---|---|
| `ssh_auth_internal.pcap` | zeek/zeek v9.0.1 `testing/btest/Traces/ssh/ssh.pcap` | 내부→내부 SSH 인증 성공 세션 5개(포트 22, 비표준 포트 2200 포함) + epoch 종료용 tick 패킷 1개 |

- 발췌 방법: `tests/extract_zeek_traces.py` (세션 목록과 재현 명령이 스크립트에 있음)
- 라이선스: Zeek 프로젝트 BSD 라이선스 (https://github.com/zeek/zeek/blob/master/COPYING)
