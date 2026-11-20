# AssetID 자산 식별 스펙

> **nsm 저장소 사본(2026-11-12 머지).** 원본은 `kwsjjang8901-ship-it/claudtest2`의 `docs/`입니다. 센서 코드(원본 `scripts/`)는 이 저장소의 `nsm_rules/asset-id/`에 있고, 센서 테스트는 `tests/btest/asset-id/`(pcap은 `tests/pcaps/asset-id/`)에 있습니다. PoC 도구(`tools/`: 실행 스크립트·리졸버·리포트)와 리졸버 테스트는 머지 대상이 아니어서 claudtest2에 남아 있습니다. 센서 동작을 바꾸면 이 문서와 [탐지 SRS](../SRS.md) 5.5절을 함께 고칩니다.

문서 버전: 0.7 (2026-11-20) · 대상 코드: `scripts/` (센서), `tools/asset_resolver.py` (판정)
관련 문서: 설계 배경과 측정 기록 [DESIGN.md](DESIGN.md), 검증·개선 계획 [PLAN.md](https://github.com/kwsjjang8901-ship-it/claudtest2/blob/main/docs/PLAN.md)

이 문서는 **프로토콜별로 무엇을 보고, 어떤 신호를 만들고, 그 신호를 자산 판정에 어떻게 쓰는지**를 정의한다.
코드와 다를 경우 코드가 우선이며, 코드를 바꾸면 이 문서도 함께 고친다.

---

## 1. 범위와 역할

| 구분 | 담당 | 하는 일 | 하지 않는 일 |
|---|---|---|---|
| 센서 (Zeek 패키지 `scripts/`) | NSM 센서 | 트래픽에서 관측 사실을 **신호**로 기록 (`asset_signal.log`) | 자산 판정, 신호 간 결합 |
| 판정 (`tools/asset_resolver.py`) | MDS Manager (PoC에서는 리졸버가 대신) | 신호를 묶어 **자산**을 만들고 대표 키·역할·OS를 정함 | 패킷 분석 |

- 지원 Zeek 버전: 8.0.9, 9.0.1 (운영 권장: **9.x**, 일부 신호는 9.x에서만 나옴 — 9장)
- 범위 밖(Next): MDS Agent 목록 대조(미관리 판정), DHCP 서버 로그·AD 연동, MeDCore 파라미터 활용

---

## 2. 신호 로그 스키마 (`asset_signal.log`)

| 필드 | 타입 | 설명 |
|---|---|---|
| `ts` | time | 관측 시각 |
| `uid` | string (선택) | 근거 연결 uid (conn.log 등과 연결) |
| `ip` | addr | 신호가 가리키는 자산 IP |
| `mac` | string (선택) | 관측 시점의 MAC |
| `signal` | string | 신호 종류 (2.1) |
| `value` | string | 정규화된 값 |
| `source` | string | 출처 (3장 각 프로토콜의 source) |
| `confidence` | count | 출처 기준 신뢰도 0~100 |
| `user_name` | string (선택) | 계정 신호(`user_account`·`machine_account`)의 사용자 부분(소문자). 그 밖의 신호는 없음 |
| `user_domain` | string (선택) | 계정 신호의 도메인 부분. `domain\user`의 domain, `user@realm`의 realm. 도메인 없는 계정은 없음 |
| `user_domain_type` | string (선택) | `user_domain`에 점이 있으면 `dns`(Kerberos realm, LDAP DNS 도메인), 없으면 `netbios`(NTLM 도메인, RDP 쿠키) |

**공통 규칙 (`AssetID::emit`)**
- 대상 IP: `asset_nets` → `Site::local_nets` → `Site::private_address_space` 순으로 정한 내부 대역만. 0.0.0.0, 브로드캐스트, 멀티캐스트 제외
- 중복 억제: 같은 `(ip, signal, value, source)`는 `suppress_interval`(기본 1시간)에 한 번. 계속 관측되면 1시간마다 다시 기록(점유 구간 갱신용)
- 빈 값은 기록하지 않음. `ignore_hostnames`(localhost 등)는 hostname으로 기록하지 않음
- 계정 나누기: 계정 신호는 `value`(`domain\user`)와 함께 `user_name`·`user_domain`·`user_domain_type`을 남긴다. 탐지 근거 `evidence.log`의 같은 이름 필드와 규칙이 같아(SRS 6.3) Manager가 자산의 계정과 탐지 계정을 그대로 잇는다. 같은 도메인의 NetBIOS 이름과 DNS 이름(`corp`·`corp.local`)을 맞추는 것은 Manager(`domain` 신호로 대응표를 만든다)
- 이름 정규화: 소문자, 앞뒤 공백·NUL 제거, 끝의 `.` 제거. MAC은 소문자 `aa:bb:cc:dd:ee:ff`, 00/FF 주소 제외

### 2.1 신호 종류

| 분류 | signal | 값 예 | 판정에서의 쓰임 |
|---|---|---|---|
| **식별 키** | `machine_account` | `corp.local\pc01$` | 1순위 키 |
| | `dhcp_client_id` | `1:3c:52:82:11:22:33` | 2순위 키 |
| | `mac` | `3c:52:82:11:22:33` | 3순위 키 (출처에 따라 신뢰도 다름) |
| | `hostname` | `pc01` | 4순위 키 |
| **보조 정보** | `fqdn`, `domain` | `pc01.corp.local`, `corp.local` | 표시, 도메인 대표값 |
| | `os_hint` | `windows nt 10.0 build 26100` | OS 추정 |
| | `service` | `tcp/445`, `tcp/8081/http` | 역할 추정 |
| | `device` | `vmware-esxi`, `ahnlab-mds` | 장비·제품 역할(MDS 장비는 인증서 또는 에이전트 통신으로) |
| | `dns_name` | `portal.corp.local` | 표시 이름(이름 없는 서버) |
| | `software` | `ssh:SSH-2.0-OpenSSH_8.9p1`, `ua:git/2.52.0`, `http_server:Microsoft-IIS/10.0`, `smb_os:Windows 5.1`, `snmp_sysdescr:…`, `x509_subject:…`, `http_wwwauth:Basic realm="…"`, `sip_ua:…`, `ftp_banner:…`, `mysql:8.0.36` | 소프트웨어 정보, 지문 대조 입력(4.11) |
| | `form_factor` | `phone`, `tablet`, `mobile` | 기기 형태 힌트(User-Agent, 3.11). 장비 유형 판정(4.12) |
| | `tcp_fp` | `syn ittl=128 hops=0 win=64240 ws=8 mss=1460 sack=1 ts=0 df=1` | TCP SYN 모양(OS 계열 추정, 3.19) |
| | `security_agent` | `ahnlab:V3ES90ASD/5.6.0.55`, `ahnlab:mds-agent`, `policy:edr-cloud` | AhnLab 제품 설치 여부(통신으로 판단), 고객 정의 에이전트 정책(3.17) |
| | `user_account` | `corp\kim` | 최근 로그온 사용자 |
| **검증 중 후보** | `smb_client_guid` | `a1eefcb2-2495-6541-893f-bf5b2c69acd4` | 참고 정보, 공유·변경 통계 |
| | `ssh_host_key` | `e4:b1:8e:…` | 참고 정보, 공유 통계 |
| | `dhcp_vendor_class`, `dhcp_fingerprint` | `MSFT 5.0`, `1,3,6,15,…` | 참고 정보 |

---

## 3. 프로토콜별 스펙

각 항목: **관측 조건**(미러에서 보여야 하는 것) / **트리거** / **추출 → 신호** / **대상 IP** / **예외 처리** / **활용** 순서.
신뢰도 숫자는 PoC 초기값이며 정답 비교(PLAN V3) 후 조정한다.

### 3.1 프로토콜 요약

| 프로토콜 | 파일 | 주요 신호 | 필요한 관측 위치 | Zeek 버전 |
|---|---|---|---|---|
| DHCP | `dhcp.zeek` | client-id, MAC, hostname, fqdn, domain, OS | 단말 L2 구간 또는 DHCP 서버 앞 | 8/9 |
| ARP | `l2.zeek` | MAC | 단말 L2 구간 | 8/9 |
| 연결 L2 주소 | `l2.zeek` | MAC(약함) | 어디서나 (라우팅 구간이면 게이트웨이 MAC) | 8/9 |
| Kerberos AS-REQ | `kerberos.zeek` | 머신 계정, hostname, domain, 사용자 | DC 앞 | 8/9 |
| Kerberos 서비스 티켓(AP-REQ) | `server_names.zeek` | 서버 이름(dns_name), 서버 domain | 어디서나 (클라이언트 → 서버) | SMB 8/9, LDAP SASL 안은 **9** |
| NTLM | `ntlm.zeek` | hostname, 머신 계정, domain, fqdn, OS 빌드, 사용자 | 인증하는 서버 앞 | 8/9 (LDAP 안 NTLM은 9) |
| CLDAP/LDAP | `ldap.zeek` | hostname, domain, fqdn, 머신 계정 | DC 앞 | 8/9 |
| NBNS / LLMNR / mDNS | `names.zeek` | hostname, domain(워크그룹) | 단말 L2 구간 | 8/9 |
| DNS 응답 | `names.zeek` | dns_name | DNS 서버 앞 | 8/9 |
| DNS 동적 업데이트 | `names.zeek` | hostname, fqdn, domain | DC(DNS) 앞 | **9** |
| SMB | `software.zeek`, `server_names.zeek`, `smb_guid.zeek` | OS(SMB1, 클라이언트·서버 원문), 서버 이름, 클라이언트 GUID | 파일 서버·DC 앞 | 8/9 |
| RDP | `software.zeek` | 클라이언트 hostname, 사용자 | RDP 서버 앞 | 8/9 |
| HTTP | `software.zeek`, `server_names.zeek` | OS, 소프트웨어, AhnLab 제품, 서버 이름, 서버 소프트웨어·OS(Server 헤더) | 어디서나 (평문 HTTP) | 8/9 |
| TLS | `server_names.zeek`, `x509.zeek` | 서버 이름, 장비·제품, 인증서 주체·발급자 | 어디서나 (인증서는 TLS 1.2 이하) | 8/9 |
| SSH | `software.zeek` | 소프트웨어, OS, 호스트 키 | 어디서나 | 8/9 (group18 키는 9) |
| syslog | `syslog.zeek` | 장비 hostname, 장비 종류, 수집 서버 | 장비 → 수집 서버 경로 | UDP 8/9, TCP **9** |
| 서비스(응답) | `services.zeek` | service | 양방향 미러 | 8/9 |
| AhnLab MDS Agent | `mds_agent.zeek` | 보안 에이전트(MDS Agent), 장비(MDS) | 단말 → MDS 장비 경로 | 8/9 |
| SNMP | `snmp.zeek` | 장비 이름, sysDescr·sysObjectID | NMS → 장비 경로 | 8/9 |
| TCP SYN 지문 | `tcp_fp.zeek` | TCP SYN·SYN-ACK 모양 | 어디서나 | 8/9 |
| 서비스 배너 | `banners.zeek`, `banners_extra.zeek` | HTTP 인증 realm, SIP User-Agent·Server, FTP·SMTP·POP3 접속 인사, MySQL 버전 | 사용자 → 서버 구간 | 8/9 |
| 고객 정의 에이전트 정책 | `agent_policy.zeek` | 보안 에이전트(`policy:<id>`), 관리 서버 장비 | 단말 → 관리 서버 또는 인터넷·프록시 경로 | 8/9 |

### 3.2 DHCP (`dhcp`)

- **관측 조건:** 클라이언트 요청과 서버 ACK. 단말 L2 구간, 또는 릴레이를 거쳐 DHCP 서버로 가는 구간
- **트리거:** `dhcp_message`. 클라이언트 요청(op=1: DISCOVER/REQUEST/INFORM)의 옵션을 트랜잭션 ID(xid)별로 `dhcp_xid_timeout`(5분) 동안 모아 두고, 서버 **ACK(m_type 5)**에서 할당 IP가 확정될 때 기록
- **추출 → 신호**

  | DHCP 필드 | 신호 | 신뢰도 |
  |---|---|---|
  | chaddr | `mac` | 90 |
  | option 61 client-id (`hwtype:hwaddr`) | `dhcp_client_id` | 90 |
  | option 12 host name | `hostname` (FQDN이면 첫 레이블, 전체는 `fqdn`) | 85 |
  | option 81 client FQDN | `fqdn`, `hostname`, `domain` | 85 / 85 / 70 |
  | option 15 domain (ACK) | `domain` | 70 |
  | option 60 vendor class | `dhcp_vendor_class`, `os_hint`(MSFT→windows, android-dhcp→android, dhcpcd→linux, udhcp→linux(embedded)) | 60 |
  | option 55 파라미터 목록 | `dhcp_fingerprint` | 60 |
  | option 54 server id | 서버 IP에 `service udp/67` | 90 |
- **대상 IP:** ACK의 yiaddr (없으면 ciaddr). ciaddr가 있는 REQUEST/INFORM(갱신)은 ACK 없이 ciaddr로 기록
- **예외:** ACK 없는 DISCOVER만 있으면 기록하지 않음(IP 미확정)
- **릴레이 구간:** 단말 L2 구간이 아니라 릴레이(라우터) ↔ DHCP 서버 구간(67/udp 양쪽, giaddr 있음)만 보여도 같은 방식으로 기록한다. 요청(op=1)과 ACK(op=2)를 방향이 아니라 BOOTP op로 가르기 때문이다(btest `dhcp-relay`). 같은 트랜잭션이 L2 구간과 릴레이 구간에서 두 번 보여도 중복 억제로 한 번만 남는다
- **활용:** client-id·L2 MAC은 강한 키. IP 재할당 감지(점유 구간 분할)의 핵심 근거. DHCP 서버 역할 판정

### 3.3 ARP와 연결 L2 주소 (`arp`, `conn`)

- **ARP:** request/reply의 송신자(SPA, SHA) → `mac`(85). SPA 0.0.0.0(ARP probe) 제외
- **연결 L2 주소:** 새 연결의 orig/resp L2 주소 → 각 IP의 `mac`(40)
- **활용**
  - ARP MAC은 강한 키(신뢰도 중간)
  - 연결 L2 주소는 **라우팅 구간이면 게이트웨이 MAC**이므로 약한 증거:
    - 같은 conn MAC이 IP 2개 이상에 보이면 공유 MAC(게이트웨이·라우터·방화벽)으로 보고 식별 키에서 제외 → 자산 상세의 "게이트웨이 경유 MAC"
    - conn MAC은 점유 구간 분할 근거로 쓰지 않음(비대칭 경로에서 자기 MAC과 방화벽 MAC이 번갈아 보임)
    - conn MAC으로만 식별된 자산은 신뢰도 "낮음"

### 3.4 Kerberos (`kerberos`, `krb`)

**AS-REQ (`kerberos`)**


- **관측 조건:** 클라이언트 → DC(88)의 AS-REQ
- **트리거:** `krb_as_request`의 클라이언트 주체(client_name)와 realm
- **추출 → 신호**

  | 주체 형태 | 신호 | 신뢰도 |
  |---|---|---|
  | `HOST$` (머신 계정) | `machine_account` `realm\host$` + `hostname` `host` | 95 / 90 |
  | 사용자 | `user_account` `realm\user` | 70 |
  | realm | `domain` | 90 |
- **예외:** 서비스 주체(`a/b`)는 제외, enterprise principal(`user@REALM`)은 앞부분만
- **활용:** 1순위 키. 부팅 시와 TGT 갱신(약 10시간) 때 발생하므로 DC 앞 장시간 캡처 필요. 사용자 계정은 "최근 로그온 사용자"

**서비스 티켓 AP-REQ (`krb`)**

- **관측 조건:** 클라이언트가 서버에 Kerberos로 인증할 때 보내는 서비스 티켓. SMB2 SESSION_SETUP, LDAP SASL(GSSAPI, Zeek 9.x) 안의 SPNEGO. DC가 보이지 않는 사용자 → 서버 라우팅 구간에서도 보인다
- **트리거:** `krb_ap_request`의 티켓 서비스 이름(`ticket$service_name`)과 realm. 티켓의 사용자 정보는 암호화돼 있어 **서버 쪽 정보만** 나온다
- **추출 → 신호 (대상: 응답측 서버 IP)**

  | 티켓 필드 | 신호 | 신뢰도 |
  |---|---|---|
  | 서비스 이름의 호스트 부분 (`cifs/FS01.corp.local` → `fs01.corp.local`, `MSSQLSvc/db01.corp.local:1433` → `db01.corp.local`, `ldap/dc01.corp.local/corp.local` → `dc01.corp.local`) | `dns_name` | 50 |
  | realm | `domain` | 70 |
- **예외:** `krbtgt`(TGS-REQ 안 TGT), `kadmin`은 서버 이름이 아님. 호스트 부분이 realm과 같은 티켓(DFS 도메인 루트 `cifs/corp.local`)은 특정 서버가 아니라 이름·도메인 모두 기록하지 않음. 서버 이름 상한(`max_server_names`)과 끄기(`enable_server_names`)는 다른 서버 이름 신호와 같음
- **활용:** 별칭 SPN(CNAME, 클러스터 이름)일 수 있어 **식별 키가 아니라 표시 이름**(SMB 공유 경로·SNI와 같은 등급). 이름 없는 서버의 이름과 도메인을 라우팅 구간에서 얻는 주 경로

### 3.5 NTLM (`ntlm`)

- **관측 조건:** NTLMSSP를 쓰는 모든 프로토콜(SMB, HTTP, DCE-RPC, LDAP SASL*). *LDAP 안 NTLM은 Zeek 9.x만
- **AUTHENTICATE (클라이언트 → 서버), 대상 IP = 클라이언트**

  | 필드 | 신호 | 신뢰도 |
  |---|---|---|
  | workstation | `hostname` | 85 |
  | user (`$`로 끝남) | `machine_account` `domain\user$` | 90 |
  | user (그 외) | `user_account` | 70 |
  | domain (workstation과 같으면 로컬 로그인이라 제외) | `domain` | 60 |
  | version | `os_hint` `windows nt M.m build N` | 80 |
- **CHALLENGE (서버 → 클라이언트), 대상 IP = 서버**

  | 필드 | 신호 | 신뢰도 |
  |---|---|---|
  | target info NetBIOS 컴퓨터 이름 | `hostname` | 85 |
  | DNS 도메인 (컴퓨터 이름과 다를 때) / NetBIOS 도메인 | `domain` | 85 / 80 |
  | DNS 컴퓨터 이름 | `fqdn` | 85 |
  | version | `os_hint` | 80 |
- **활용:** 서버·클라이언트 이름, Windows 빌드(9장 OS 판정). 머신 계정은 다중 계정 검사(4.6) 대상

### 3.6 CLDAP / LDAP — Netlogon ping (`ldap`)

- **관측 조건:** 도메인 PC → DC의 CLDAP(udp/389) 또는 LDAP 검색. DC 찾기(로그온, 그룹 정책 갱신 약 90분 주기)
- **트리거:** `LDAP::search_request`의 필터에 `(NtVer=` 포함 (MS-ADTS 6.3.3)
- **추출 → 신호** (대상 IP = 요청한 PC)

  | 필터 값 | 신호 | 신뢰도 |
  |---|---|---|
  | `Host` | `hostname` | 85 |
  | `DnsDomain` | `domain` | 85 |
  | `Host` + `DnsDomain` | `fqdn` | 80 |
  | `User` (`$`로 끝남) | `machine_account` `domain\user` | 85 |
  | `User` 없음/사용자 계정 | `machine_account` `domain\host$` (DC 찾기는 도메인 가입 PC가 함) | 75 |
- **활용:** 라우팅 구간에서도 DC 앞이면 PC를 식별할 수 있는 주요 신호

### 3.7 NBNS / LLMNR / mDNS (`nbns`, `llmnr`, `mdns`)

| 프로토콜 | 트리거 | 신호 | 신뢰도 |
|---|---|---|---|
| NBNS (137) | 이름 등록·갱신 요청(opcode 5/8/15) 또는 자기 이름 응답 | `<20>` → `hostname` / `<00>` → `hostname` / `<1b,1c,1d,1e>` → `domain`(워크그룹) | 75 / 50 / 60 |
| LLMNR (5355) | 응답자가 자기 주소로 답한 A/AAAA | `hostname` | 70 |
| mDNS (5353) | `<host>.local` A/AAAA/PTR 응답 | `hostname` | 70 |

- **예외:** mDNS 프로브(이름 충돌 후보 `host(1)` 등)와 서비스 인스턴스 이름(`x._smb._tcp.local`)은 기록하지 않음(운영 1차 측정에서 VM 복제로 오염 확인). A/AAAA 응답은 답한 주소가 연결 양 끝 IP(응답자 자신)일 때만 인정. mDNS PTR 응답은 역방향 이름의 IP에 기록
- **판정:** NBNS `<00>` 이름이 도메인/워크그룹 이름과 같으면 호스트명으로 쓰지 않음
- **활용:** 단말 L2 구간에서만 보임. 비도메인 PC·Mac·IoT 식별

### 3.8 DNS (`dns`, `dns_update`)

- **일반 DNS 응답 (53):** A/AAAA 응답 → 답 주소 IP에 `dns_name`(40), PTR 응답 → 해당 IP에 `dns_name`(50) PTR은 정규 역방향 이름(IPv4 네 옥텟 `d.c.b.a.in-addr.arpa`, IPv6 니블 32개 `….ip6.arpa`)만 쓰고, RFC 2317 클래스 없는 위임 이름(`71.64/27.37.40.113.in-addr.arpa`)처럼 주소로 바꿀 수 없는 이름은 무시(Zeek `ptr_name_to_addr` 오류 방지).
  - 별칭·로드밸런서일 수 있어 **식별 키가 아님**. 이름 없는 서버의 표시 이름으로만 사용
- **DNS 동적 업데이트 (RFC 2136, opcode 5) — Zeek 9.x**
  - 트리거: UPDATE 요청(QR=0)의 등록 레코드(FQDN → IP)
  - 신호: 등록 IP에 `hostname`(첫 레이블), `fqdn`, `domain` (각 75)
  - 등록 주체: PC 자신 또는 대신 등록하는 DHCP 서버. 부팅·IP 변경·24시간 주기

### 3.9 SMB (`smb`)

| 항목 | 트리거 | 신호 | 대상 IP | 신뢰도 |
|---|---|---|---|---|
| SMB1 native OS | Session Setup AndX 요청 | `os_hint`, `domain`(primary domain) | 클라이언트 | 70 / 60 |
| SMB1 native OS·LAN Manager 원문 | Session Setup AndX 요청·응답 | `software` `smb_os:<원문>`, `smb_lm:<원문>`(64자) | 클라이언트·서버 | 70 |
| 서버 이름 | SMB1/2 Tree Connect 경로 `\\server\share` | `dns_name` (IP 형태 제외) | 서버 | 50 |
| SMB2 클라이언트 GUID | NEGOTIATE 요청(연결 첫 메시지)의 ClientGuid | `smb_client_guid` | 클라이언트 | 70 |

- **SMB2 GUID 추출:** Zeek가 이벤트로 넘기지 않아 시그니처(`smb2-negotiate.sig`)로 연결 첫 메시지만 잡고 오프셋 76에서 16바이트를 읽어 GUID 문자열로 변환. 전부 0인 값 제외. SMB1으로 시작하는 연결은 대상 아님
- **비용:** SMB만 있는 트래픽 기준 처리 시간 약 +7%. 끄려면 `signals/__load__.zeek`에서 `@load ./smb_guid` 제거
- **활용:** GUID는 PC별 고정 여부가 검증되지 않아 **참고 정보**. 리포트의 공유(복제 VM 의심)·변경 통계로 식별 키 승격을 판단

### 3.10 RDP (`rdp`)

- 클라이언트 core data의 client name → 클라이언트 IP에 `hostname`(80)
- 연결 요청의 mstshash 쿠키 → `user_account`(50, 사용자 입력값)

### 3.11 HTTP (`http_ua`, `ahnlab`, `http`, `http_server`)

| 항목 | 조건 | 신호 | 대상 IP | 신뢰도 |
|---|---|---|---|---|
| 브라우저 UA (`Mozilla/…`) | 요청 User-Agent | `os_hint` (OS 계열만: `windows 10/11`, `macos`, `android 14` 등) | 클라이언트 | 50 |
| 프로그램 UA | Mozilla가 아닌 UA | `software` `ua:<제품토큰>` (예: `ua:git/2.52.0`) | 클라이언트 | 50 |
| Windows 시스템 UA | `Microsoft NCSI`, `WinHttp-Autoproxy-Service`, `Microsoft-CryptoAPI/…` 등 | `os_hint` `windows` | 클라이언트 | 50 |
| AhnLab 제품 | `v3inet*/<버전>/<제품코드>/`, `MeDCore` | `security_agent` `ahnlab:<제품코드>/<버전>`, `ahnlab:MeDCore` | 클라이언트 | 80 |
| 서버 이름 | 요청 Host 헤더 | `dns_name` | 서버 | 50 |
| 기기 형태 | 요청 User-Agent: `iPhone`·`iPod` → `phone`, `iPad` → `tablet`, 안드로이드 브라우저(`Mozilla/`)는 `Mobile`이 있으면 `phone`·없으면 `tablet`, 안드로이드 앱(Dalvik 등) → `mobile` | `form_factor` | 클라이언트 | 50 |
| Apple 연결 확인 | `CaptiveNetworkSupport…` UA(Wi-Fi 접속 때 captive.apple.com 확인, iOS·macOS 공통) | `os_hint` `apple` | 클라이언트 | 50 |
| 서버 소프트웨어 | 응답 Server 헤더 | `software` `http_server:<값 앞 64자>` | 서버 | 50 |
| 서버 OS | 응답 Server 헤더: IIS 10.0 → `windows server 2016+`, 8.5 → `windows server 2012 r2`, 8.0 → `windows server 2012`, 7.5 → `windows server 2008 r2`, 7.0 → `windows server 2008`, 6.0 → `windows server 2003`, `Microsoft-HTTPAPI/…`·`(Win32)`·`(Win64)` → `windows`, `(Ubuntu)`·`(Debian)`·`(CentOS)`·`(Red Hat)`·`(Rocky)` → `linux(…)` | `os_hint` | 서버 | 45 |

- **예외:** Windows 10과 11은 UA(`Windows NT 10.0`)로 구분 불가 → `windows 10/11`. MeDCore 요청 파라미터 값은 의미 미확인으로 기록하지 않음. 프록시 요청(CONNECT, 절대 URL)의 Host와 그 응답의 Server 헤더는 외부 사이트의 것이므로 제외. Server 헤더는 `enable_http_server`로 따로 끈다. IIS 버전은 클라이언트 Windows에도 있지만 다른 PC에 웹 응답을 주는 쪽은 대부분 서버라 서버 OS로 본다(신뢰도는 UA보다 낮은 45). nginx처럼 OS를 밝히지 않는 서버는 `software`만
- **활용:** OS 추정, 소프트웨어 목록, AhnLab 제품 설치 현황(리포트 "능동 IP 중 AhnLab 제품 통신")

### 3.12 TLS (`tls`, `x509`)

| 항목 | 조건 | 신호 | 대상 IP | 신뢰도 |
|---|---|---|---|---|
| SNI | ClientHello server_name | `dns_name` | 서버 | 50 |
| 인증서 이름 | 서버 leaf 인증서 CN·SAN DNS (와일드카드·IP·localhost·공백 제외) | `dns_name` | 서버 | 50 |
| 인증서 주체·발급자 원문 | 서버 leaf 인증서 | `software` `x509_subject:<DN>`, `x509_issuer:<DN>`(160자, Zeek 출력 순서) | 서버 | 60 |
| 인증서 제품·장비 | 주체/발급자: `CN=AhnLab MDS`, `CN=AhnLab EPP`, VMware, Fortinet, Palo Alto, iDRAC, iLO, Synology | `device` | 서버 | 70 |

- **예외:** 프록시 경유(CONNECT) 연결 제외. 서버 이름 신호(SMB·HTTP·TLS·x509·Kerberos 합계)는 IP당 `max_server_names`(20)개까지
- **한계:** TLS 1.3은 인증서가 암호화되어 보이지 않음. 핸드셰이크 끝이 캡처되지 않은 연결도 연결 종료 시 인증서를 확인

### 3.13 SSH (`ssh`)

| 항목 | 신호 | 대상 IP | 신뢰도 |
|---|---|---|---|
| 클라이언트/서버 배너 | `software` `ssh:<배너>` | 각 송신자 | 70 |
| 배너의 OS 표기 (ubuntu > raspbian > debian > freebsd > centos > redhat, for_windows, cisco 순) | `os_hint` | 각 송신자 | 60 |
| 서버 호스트 키 지문 | `ssh_host_key` | 서버 | 80 |

- **활용:** 호스트 키는 같은 이미지로 만든 장비·VM이 공유하므로(운영 7차: AhnLab MDS 여러 대가 같은 키) **식별 키가 아님**. 리포트에 "같은 SSH 호스트 키, 다른 자산" 표시

### 3.14 syslog (`syslog`)

- **트리거:** `syslog_message` (UDP; TCP는 Zeek 9.x). 송신 장비별로 `suppress_interval` 동안 최대 50건만 해석, 본문은 저장하지 않음
- **호스트명 추출** (송신 IP 대상, 신뢰도 70)

  | 형식 | 예 | 호스트명 위치 |
  |---|---|---|
  | RFC 5424 | `1 2026-11-03T00:00:06Z app-srv01.lab.corp sshd …` | 세 번째 토큰 |
  | ISO 시각 (ESXi 등) | `2026-11-03T00:00:01.123Z esx01.lab.corp Vpxa: …` | 두 번째 토큰 |
  | RFC 3164 | `Nov  3 09:00:03 core-sw01 %LINK-3-UPDOWN: …` | 네 번째 토큰 |
  | FortiGate | `devname="FGT-HQ01"` | devname 값 |
  - 시각·IP·콜론으로 끝나는 태그는 호스트명으로 쓰지 않음. 점이 있으면 `fqdn`도 기록
- **장비 종류** (`device`, 80): `%ASA-`(cisco-asa), `%FTD-`(cisco-ftd), `%XXX-n-YYY:`(cisco-ios), `Vpxa:`/`Hostd:` 등(vmware-esxi), `devid=FG`(fortinet-fortigate), 백틱 구분 `UTM_`(utm)
- **수집 서버:** 수신 IP에 `service udp/514`(또는 tcp/514) → 역할 "로그 수집 서버"

### 3.15 서비스 (`service`)

- **TCP:** `service_ports`에 있는 포트로 연결이 성립(SYN-ACK)하면 `service` `tcp/<port>`
- **응답 확인:** 연결 종료 시 응답측이 패킷을 보냈고 분석기가 프로토콜을 확인하면, `service_ports` 포트는 `udp/53`처럼, 그 밖의 포트는 `tcp/8081/http`처럼 기록
- **예외:** `ignore_service_ports`(137, 138, 1900, 5353, 5355/udp), 임시 포트(49152 이상), 다른 프로토콜 안에서 확인된 분석기(`nested_analyzers`: ntlm, gssapi, krb, dce_rpc, smb 등)
- **활용:** 역할 판정(4.8). 양방향 미러가 필요

### 3.16 AhnLab MDS Agent (`mds`)

- **관측 조건:** 단말과 MDS 장비 사이 경로가 미러에 있어야 함
- **트리거:** `connection_established`(TCP 연결 성립). 목적지 포트가 `mds_agent_ports`(기본 8290·8291·8293·50007·50502/tcp)

| 조건 | 신호 | 대상 IP | 신뢰도 |
|---|---|---|---|
| `mds_servers`(MDS 장비 주소) 지정, 그 주소의 에이전트 포트에 연결 성립 1건 | `security_agent` `ahnlab:mds-agent` / `device` `ahnlab-mds` | 단말 / 장비 | 90 / 80 |
| `mds_servers` 비어 있음, 같은 서버의 서로 다른 에이전트 포트 `mds_agent_min_ports`(2)개 이상에 `mds_agent_window`(1시간) 안에 연결 성립 | 같음 | 단말 / 장비 | 70 / 60 |

- **예외:** 응답 없거나 거부된 연결은 세지 않음. 8291/tcp는 다른 제품(MikroTik Winbox 등)도 쓰므로 장비 주소를 모르면 포트 하나로는 판단하지 않음. 장비가 내부 대역 밖이면 장비 쪽 `device`는 남지 않음(단말 신호는 남음)
- **활용:** 자산별 MDS Agent 설치 현황. 신호가 없는 단말은 미설치 **후보**일 뿐임(센서가 그 경로를 못 보거나, 관측 시간이 에이전트 보고 주기보다 짧거나, 단말이 꺼져 있었을 수 있음). 정확한 미설치 판정은 MDS Manager의 에이전트 목록과 대조

### 3.17 고객 정의 에이전트 정책 (`agent_policy`)

고객이 식별하고 싶은 제품(EDR, 백신·EPP 관리 서버, 패치·자산관리, NAC, DLP 등)의 에이전트 통신을 정책 파일로 정의합니다. 맞는 통신이 보인 단말에 `security_agent` `policy:<id>`를 남깁니다. MDS Agent(3.16)는 지금 규칙을 그대로 두고, 그 밖의 제품을 이 정책으로 다룹니다.

- **정책 파일:** `agent_policy_file`(TSV, 비어 있으면 꺼짐). 재시작 없이 다시 읽음(Input REREAD). 클러스터에서는 노드마다 같은 경로의 파일을 읽음. pcap을 읽을 때는 정책을 다 읽을 때까지 패킷 처리를 멈춤

  ```
  #fields	id	product	server	ports	domain	user_agent	min_ports	device
  ep-mgr	사내 백신 관리 서버	10.0.55.5	8443/tcp	-	-	-	epp-server
  nac	NAC 에이전트	-	7001/tcp,7002/tcp	-	-	2	-
  edr-cloud	클라우드 EDR	-	-	*.sensor.edr-vendor.example	-	-	-
  patch	패치 관리	-	-	-	PatchAgent/	-	-
  ```

  | 필드 | 뜻 |
  |---|---|
  | `id` | 정책 id(영문·숫자·`._-`). 신호 값은 `policy:<id>` |
  | `product` | 화면에 보일 제품명(센서는 쓰지 않음) |
  | `server` | 관리 서버 주소·대역, 쉼표로 여러 개 |
  | `ports` | 에이전트 포트, 쉼표로 여러 개. 프로토콜을 안 적으면 tcp |
  | `domain` | 접속 도메인(하위 도메인 포함, 앞의 `*.`는 무시). TLS SNI, HTTP Host, 프록시 CONNECT 대상과 맞춤 |
  | `user_agent` | HTTP User-Agent에 들어 있어야 하는 문자열(대소문자 무시, 정규식 아님) |
  | `min_ports` | 같은 서버의 서로 다른 포트를 몇 개 이상 봐야 하는지(연결 정책만). 기본 1, 서버 없이 포트만이면 기본 2 |
  | `device` | 서버 IP에 남길 `device` 값(서버 주소를 적은 정책만) |
- **맞추는 방식** (적은 조건은 모두 맞아야 함)

  | 정책 | 트리거 | 조건 | 신뢰도 (단말 / 서버 `device`) |
  |---|---|---|---|
  | 연결 정책 (`domain`·`user_agent` 없음) | `connection_established`(TCP 연결 성립) | 응답측이 `server`·`ports`에 맞음. `agent_policy_window`(1시간) 안에 같은 서버의 서로 다른 포트 `min_ports`개 이상 | 서버 주소 있음 90 / 80, 포트만 70 / - |
  | 앱 정책 (`domain` 또는 `user_agent` 있음) | `ssl_extension_server_name`, `http_message_done`(요청) | SNI·Host가 `domain`에, User-Agent가 `user_agent`에 맞음. `server`·`ports`를 적었다면 응답측도 맞아야 함 | 서버 주소 있음 90 / 80, 없음 80 / - |
- **정책 검사:** 아래는 정책을 빼고 `asset_agent_policy.log`에 `kind=invalid`와 이유를 남김. 읽을 때마다 `kind=summary`(`active=N invalid=N`), 파일 읽기 오류는 `kind=error`
  - id 형식이 틀림, 주소·포트·도메인 형식이 틀림
  - `server`·`ports`·`domain`·`user_agent`가 모두 없음
  - 서버 주소 없이 포트만 적었는데 `min_ports` < 2(8291/tcp처럼 다른 제품과 겹치는 포트 때문), 또는 `min_ports`가 적은 포트 수보다 큼
  - `device`를 적었는데 `server`가 없음
- **예외:** 거부·무응답 연결은 세지 않음. 프록시를 거치면 응답측이 프록시이므로 도메인 정책에 `server`를 적으면 맞지 않음(도메인 정책은 보통 `server` 없이). User-Agent는 평문 HTTP에서만 보임. UDP만 쓰는 에이전트는 연결 정책으로 잡히지 않음
- **활용:** 자산별 에이전트 확인. **신호가 없다고 미설치가 아님** → 미설치 후보 판정은 Manager가 4.10절 규칙으로 함

### 3.18 SNMP (`snmp`)

- **관측 조건:** 관리 서버(NMS)가 장비에 보낸 SNMP 질의와 장비의 응답(161/udp). NMS의 수집 경로가 미러에 걸려야 함. SNMPv3 암호화 응답은 보이지 않음
- **트리거:** `snmp_response`. 응답한 쪽(장비) IP에 기록

  | OID | 신호 | 신뢰도 |
  |---|---|---|
  | sysDescr `1.3.6.1.2.1.1.1.0` | `software` `snmp_sysdescr:<값>`(제어 문자는 공백, 200자) | 70 |
  | sysObjectID `1.3.6.1.2.1.1.2.0` | `software` `snmp_sysobjid:<OID>`(제조사 번호) | 70 |
  | sysName `1.3.6.1.2.1.1.5.0` | `hostname`(점이 있으면 `fqdn`도) | 70 |
- **예외:** 커뮤니티 문자열은 기록하지 않음. 트랩은 보지 않음
- **활용:** 네트워크 장비·프린터·UPS의 이름과 모델. sysDescr·sysObjectID는 지문 대조(4.11 Recog `snmp_sysdescr`·`snmp_sysobjid`) 입력

### 3.19 TCP SYN 지문 (`tcp_fp`)

- **관측 조건:** 연결을 여는 SYN(클라이언트)과 SYN-ACK(서버). 어느 구간이든 보임
- **트리거:** `connection_SYN_packet`. IP·방향(syn·synack)마다 `suppress_interval`(1시간)에 첫 패킷 한 번
- **추출 → 신호:** `tcp_fp`(30) `"<syn|synack> ittl=<추정 초기 TTL> hops=<거리> win=<윈도> ws=<스케일|-> mss=<MSS|-> sack=<0|1> ts=<0|1> df=<0|1>"`. 초기 TTL은 관측 TTL 이상인 32·64·128·255 중 가장 작은 값
  - 예: `syn ittl=128 hops=0 win=64240 ws=8 mss=1460 sack=1 ts=0 df=1`(Windows 10/11), `synack ittl=64 hops=0 win=65160 ws=7 mss=1460 sack=1 ts=1 df=1`(Linux)
- **한계:** Zeek가 주는 값에는 TCP 옵션 순서·세부 특이점이 없어 p0f 지문을 그대로 맞출 수 없음(계열 수준). NAT·프록시 뒤 장비는 마지막 장비의 값, 튜닝된 서버·가상 머신은 틀릴 수 있음. SYN마다 이벤트가 생기므로 운영 부하는 실측 필요(`enable_tcp_fp`로 끔)
- **활용:** OS 근거가 없는 자산의 OS 계열(4.4, 4.11). 식별 키가 아님

### 3.20 서비스 배너 (`http_wwwauth`, `sip`, `ftp`, `smtp`, `pop3`, `mysql`)

지문 대조(4.11 Recog) 입력용 원문입니다. 응답·메시지를 보낸 쪽(서버·장비) IP에 `software`로 남기며 연결마다 처음 한 번만 봅니다.

| 출처 | 트리거 | 값 | 신뢰도 | 파일 |
|---|---|---|---|---|
| `http_wwwauth` | HTTP 응답 `WWW-Authenticate` | `http_wwwauth:Basic realm="…"` 또는 `Digest realm="…"`(realm만, nonce 등은 뺌) | 60 | `banners.zeek` |
| `sip` | SIP 메시지 `User-Agent`·`Server` 헤더(보낸 쪽) | `sip_ua:…`, `sip_server:…` | 60 | `banners.zeek` |
| `ftp` | 첫 220 응답 본문 | `ftp_banner:…` | 60 | `banners.zeek` |
| `smtp` | 연결의 첫 응답이 220일 때 그 본문(STARTTLS 응답의 220은 아님) | `smtp_banner:…` | 60 | `banners.zeek` |
| `pop3` | 첫 `+OK` 응답 본문 | `pop3_banner:…` | 60 | `banners_extra.zeek` |
| `mysql` | 핸드셰이크의 서버 버전 | `mysql:…` | 70 | `banners_extra.zeek` |

- **남기지 않는 것:** Negotiate·NTLM·Bearer 인증 값(연결마다 바뀌는 토큰), 프록시 경유 응답(외부 사이트 것)
- **IMAP:** Zeek가 접속 인사를 이벤트로 주지 않아 대상이 아님
- **POP3:** 클라이언트가 POP3 명령(USER·CAPA 등)을 보내야 Zeek가 프로토콜을 인식함(DPD)
- **부하 (2026-11-20, Zeek 9.0.1):** 해당 프로토콜만 있는 짧은 연결 2만 개(서버 50대), 5회 평균
  - 이 기능 없음: 5,742ms
  - `banners.zeek`: 5,903ms(+2.8%). Zeek 기본 스크립트가 이미 처리하는 이벤트라 핸들러 비용만 추가
  - `banners_extra.zeek`까지: 6,125ms(+6.7%). POP3·MySQL 이벤트가 새로 생김
  - 실제 망은 이 프로토콜의 짧은 연결 비율이 훨씬 낮아 차이가 더 작을 것으로 보지만, 운영 pcap으로 확인 필요
- **끄기:** `enable_http_wwwauth`·`enable_sip`·`enable_service_banners`는 기록만 멈춥니다(이벤트는 그대로 생김). POP3·MySQL 부하를 없애려면 `signals/__load__.zeek`에서 `@load ./banners_extra`를 뺍니다

---

## 4. 판정 스펙 (`tools/asset_resolver.py`)

### 4.1 식별 키와 우선순위

| 순위 | 키 | 정규화 | 신뢰도 |
|---|---|---|---|
| 1 | 머신 계정 | `도메인 첫 레이블\계정` (`corp.local\pc$` = `corp\pc$`) | 높음 |
| 2 | DHCP client-id | 그대로 | 높음 |
| 3 | MAC | 소문자 | ARP/DHCP 확인 시 중간, 연결 기록만이면 낮음 |
| 4 | 호스트명 | 소문자 단축명, 앞 15자(NetBIOS 길이 제한 반영) | 중간 |
| 5 | IP+시간 | `ip@첫 관측 시각` | 낮음 |

**강한 키:** 머신 계정, DHCP client-id, MAC. 값이 다르면 같은 호스트명을 공유해도 합치지 않는다("오결합보다 중복" 정책).

### 4.2 처리 순서

1. **공유 MAC 판별** (`--shared-mac-threshold`, 기본 2): conn 출처 MAC이 IP 2개 이상 → 게이트웨이·라우터·방화벽 MAC, conn 출처일 때만 식별 키에서 제외
2. **다중 머신 계정 판별** (`--multi-account-window`, 기본 10분): 4.6
3. **IP 점유 구간(tenancy) 분할:** IP별 신호를 시간순으로 보며, 강한 키(머신 계정·client-id·ARP/DHCP MAC)가 기존 값과 다르게 나오거나 `--max-idle`(24시간) 넘게 끊기면 새 구간 → DHCP 재할당으로 인한 오결합 방지
4. **구간 결합:** 우선순위 높은 키부터 같은 키를 공유하는 구간을 union-find로 묶음. 강한 키 값이 서로 다르면 묶지 않고 "결합 보류"로 보고
5. **자산 요약:** 대표 키, 이름, 도메인, OS, 역할, 장비, 서비스, 사용자, 참고 정보

### 4.3 이름 처리

- 표시 이름: 자기 신고 호스트명 → 없으면 `dns_name` 단축명 + `(dns)` 표시(식별 키 아님)
- NBNS `<00>` 이름이 도메인/워크그룹 이름과 같으면 호스트명 제외
- 도메인 대표값: NetBIOS 형식과 DNS 형식이 섞이면(`corp`, `corp.example.com`) DNS 형식 선택

### 4.4 OS 판정

- 출처 우선순위: ntlm > smb > ssh > http_ua > dhcp. 이 근거가 하나도 없으면 지문(Recog) OS, 그다음 TCP SYN 계열(`tcp_fp`)로 채우고 출처를 표시한다(4.11). `http_server`(서버의 HTTP Server 헤더, 0.3에서 추가)는 리졸버(claudtest2) 우선순위에 아직 없다. nsm 통합 리포트는 신뢰도가 높은 값을 고르므로 다른 출처가 있으면 그것이 쓰인다
- NTLM 빌드 번호 → 버전: Windows 10(1507\~22H2), Windows 11(21H2\~25H2), Server 2016/2019/2022/2025. 표에 없는 빌드는 22000 이상이면 Windows 11
- PC/서버 공용 빌드(14393, 17763, 26100) 구분
  - 서버: 서버 역할(DC·DNS·DHCP·웹·DB·메일·프록시)이 있거나, 호스트명이 Windows Server 기본 이름(`WIN-` + 11자)
  - PC: 호스트명이 PC 기본 이름(`DESKTOP-`/`LAPTOP-` + 7자)이거나 근거 없음
  - 파일 공유·RDP·SSH는 PC에서도 흔해 근거로 쓰지 않음
- UA·DHCP만 있으면 Windows 10/11 구분 불가 → `windows 10/11`

### 4.5 최근 로그온 사용자

Kerberos·NTLM 인증, RDP 접속의 사용자 계정을 마지막 관측 순으로 최대 5개. 리포트 "최근 사용자" 컬럼, CSV `last_user`.

### 4.6 다중 머신 계정 인증

- 조건: 한 IP가 10분 안에 서로 다른 머신 계정 2개 이상으로 인증
- 처리: 그 IP의 머신 계정과 Kerberos 파생 호스트명을 식별 키에서 제외(자산 상세 "다중 인증 머신 계정"으로만 표시), 리포트에 IP·계정 목록
- 이유: 머신 계정은 자기 PC에서만 쓰인다. 이 패턴은 NTLM 릴레이·해시 전달 등 공격(또는 NAT, 장애 조치 클러스터)이며, 그대로 쓰면 신뢰도 "높음"의 가짜 자산·가짜 IP 재사용·피해 PC 자산과의 오결합이 생긴다

### 4.7 장비·제품

- `device` 값 → 역할 이름: vmware-esxi "VMware ESXi", vmware "VMware(vCenter/ESXi)", cisco-asa "Cisco ASA 방화벽", cisco-ftd "Cisco FTD 방화벽", cisco-ios "Cisco 네트워크 장비", fortinet-fortigate "FortiGate 방화벽", fortinet "Fortinet 장비", paloalto "Palo Alto 방화벽", utm "UTM 장비", ahnlab-mds "AhnLab MDS", ahnlab-epp "AhnLab EPP 서버", dell-idrac "Dell iDRAC", hpe-ilo "HPE iLO", synology "Synology NAS"
- `security_agent`: 자산별 AhnLab 제품 목록. 식별률과 별개 지표

### 4.8 역할 판정 (서비스 포트 조합)

| 역할 | 조건 |
|---|---|
| 도메인 컨트롤러 | 88 + (389, 636, 3268 중 하나) |
| DNS 서버 | 53 |
| DHCP 서버 | 67 |
| 웹 서버 | 80, 443, 8080, 8443 |
| 파일 서버(SMB) | 445, 139 |
| DB 서버 | 1433, 1521, 3306, 5432, 6379, 27017, 9200 |
| 메일 서버 | 25, 465, 587, 110, 143, 993, 995 |
| SSH 서버 | 22 |
| RDP 호스트 | 3389 |
| 원격관리(WinRM/VNC) | 5985, 5986, 5900 |
| 프린터 | 9100, 515, 631 |
| SNMP 장비 | 161 |
| 로그 수집 서버 | 514 |
| 게이트웨이/라우터(추정) | 자기 ARP/DHCP MAC이 공유 MAC |
| 프록시/로드밸런서(추정) | 3128 포트 또는 서버 이름 20개 이상 |

### 4.9 검증 중 후보 키의 통계

| 후보 | 리포트 통계 | 식별 키 승격 조건(안) |
|---|---|---|
| SMB2 클라이언트 GUID | 확인 자산 수, 여러 자산이 같은 GUID(복제 VM 의심), 한 자산에 GUID 여러 개(변경) | 공유·변경이 0에 가깝고 정답 비교로 고정성 확인 |
| SSH 호스트 키 | 같은 키를 쓰는 자산 | 승격하지 않음(이미지 공유 확인됨) |

### 4.10 에이전트 미확인 판정 (Manager)

센서는 "맞는 통신이 보였다"만 남깁니다. 통신이 안 보이는 이유는 미설치 말고도 많습니다(미러가 경로를 못 봄, 단말이 꺼짐, VPN·외부망 사용). 그래서 Manager는 정책마다 결과를 셋으로 나눕니다.

| 결과 | 조건 |
|---|---|
| 설치 확인 | `expect_every`(정책별, 예: 24시간) 안에 `policy:<id>` 신호가 있음 |
| 미확인 (미설치 후보) | 대상 범위(정책별: 대역, OS, 역할)에 들고 그 기간에 충분히 활동했는데(능동 연결이 일정 수 이상) 신호가 없음. **그리고 같은 /24 대역의 대상 자산 중 일정 비율 이상(예: 50%)에서는 신호가 보임** |
| 판정 불가 | 같은 대역에서 신호가 거의 안 보임(미러가 그 경로를 못 보는 것으로 봄), 또는 활동이 적음 |

- 대상 범위·`expect_every`·대역 비율은 Manager 정책 화면에서 정하고 센서 파일에는 넣지 않습니다.
- 대역 조건이 없으면 측정 구간 때문에 대역 전체가 "미설치"로 보이는 오판이 납니다(운영 측정에서 미러 위치에 따라 결과가 크게 달랐던 것과 같은 이유).
- 정확한 기준은 각 제품 관리 콘솔의 에이전트 목록입니다. 목록을 받을 수 있으면 "콘솔에 있는데 통신 없음", "통신은 있는데 콘솔에 없음"까지 나눕니다(MDS Agent 목록 대조와 같은 작업).

### 4.11 지문 DB 보강 (Manager 후처리, PoC는 통합 리포트)

센서 신호를 외부 지문 DB로 해석해 제조사·제품·장비 종류·OS를 더합니다. 센서(Zeek)에서는 대조하지 않습니다. PoC는 통합 리포트(`tests/report_pcap.py`, `tests/asset_enrich.py`)가 Manager 역할을 대신합니다. DB는 저장소에 넣지 않고 실행 때 경로로 줍니다(`run_pcap.sh -u OUI.csv -g recog/xml`).

| DB | 입력 신호 | 결과 | 규칙 |
|---|---|---|---|
| IEEE OUI 목록 (MA-L `oui.csv`·MA-M `mam.csv`·MA-S `oui36.csv`, standards-oui.ieee.org) | `mac` (ARP·DHCP 우선, 라우터 공유 MAC 제외) | 제조사 | 긴 접두어 먼저(MA-S > MA-M > MA-L). IEEE 원본 열(Assignment·Organization Name)과 maclookup.app 내보내기 열(Mac Prefix·Vendor Name)을 모두 읽고, 접두어 구분자(`:`·`-`)는 무시. 한 줄도 못 읽은 파일은 경고. 로컬 관리 비트가 켜진 MAC은 제조사 대신 "로컬·랜덤 MAC"(모바일 랜덤 MAC·가상 머신·직접 정한 주소) |
| Recog (Rapid7 `xml/*.xml`) | `software` `ssh:`(→ `ssh.banner`, `SSH-x.y-` 뗌), `http_server:`(→ `http_header.server`), `smb_os:`·`smb_lm:`(→ `smb.native_os`·`smb.native_lm`), `snmp_sysdescr:`·`snmp_sysobjid:`, `x509_subject:`·`x509_issuer:`(Zeek 순서와 CN 먼저 순서 둘 다), `dhcp_vendor_class`, `http_wwwauth:`(→ `http_header.wwwauth`), `sip_ua:`·`sip_server:`(→ `sip_header.user_agent`·`sip_header.server`), `ftp_banner:`·`smtp_banner:`·`pop3_banner:`(→ `ftp.banner`·`smtp.banner`·`pop3.banner`), `mysql:`(→ `mysql.banners`) | 제조사·제품·버전·OS·장비 종류(`hw.device`) | 파일 순서대로 처음 맞는 지문 하나. Ruby 정규식을 Python으로 옮기지 못한 지문은 건너뛰고 수를 셈(2026-11 기준 4,336개 모두 변환) |
| TCP SYN 계열 (DB 없음) | `tcp_fp` | OS 계열 | SYN 먼저. MSS 옵션이 없는 SYN은 판단 안 함(스캐너·직접 만든 패킷). 초기 TTL 128 → Windows, 255 → 네트워크 장비, 64 + 윈도 65535 + 타임스탬프 → macOS·iOS·BSD, 그 밖 64 → Linux·Unix, 32 → 구형·임베디드 |

- **OS 칸 채우기:** 센서 OS 힌트(4.4)가 없을 때만 Recog OS, 그것도 없으면 TCP SYN 계열로 채우고 출처를 표시합니다.
- **프록시·중계 추정:** 한 IP가 서로 다른 HTTP Server 값 3개 이상으로 응답하면 실제 서버가 아니라 투명 프록시·로드밸런서·NAT 뒤 여러 서버로 봅니다. 이 IP에는 HTTP로 얻은 OS(Recog HTTP Server·인증 realm 지문의 OS, 센서 `http_server` OS 힌트)를 쓰지 않고 "프록시·중계 추정"으로 표시합니다. 지문 목록과 다른 출처(SSH·SMB 등)의 OS는 그대로입니다. 센서의 프록시 제외(CONNECT·절대 URL)로 걸러지지 않는 투명 프록시용입니다.
- **라이선스(제품 반영 전 법무 확인):** Recog은 BSD-2-Clause(출처 표기, Rapid7은 운영 제품 사용 전 연락 요청). IEEE OUI 목록은 공개 목록이며 이용 조건 확인 필요(Wireshark `manuf`는 GPL 배포물이라 쓰지 않음). p0f(LGPL-2.1) 지문 DB는 쓰지 않음.

### 4.12 장비 유형 판정 (Manager 후처리, PoC는 통합 리포트)

자산마다 장비 유형 하나와 근거·신뢰도를 붙입니다(`tests/asset_enrich.py` `device_class`). 앞 규칙이 이깁니다.

| 순서 | 유형 | 근거 | 신뢰도 |
|---|---|---|---|
| 1 | 프록시·중계 | 서로 다른 HTTP Server 값 3개 이상(4.11) | 보통 |
| 2 | 네트워크 장비 | `device`(Cisco·Fortinet·Palo Alto·UTM), Recog 장비 종류(Router·Switch·Firewall·AP 등) | 높음 |
| 2-1 | 네트워크 장비(추정) | TCP SYN 초기 TTL 255(네트워크 장비 계열)이고 SSH·웹 말고 다른 서버 포트 응답이 없음 | 낮음 |
| 3 | 프린터 | Recog 장비 종류(Printer·Print Server·MFP), 또는 9100·515·631 응답 | 높음·보통 |
| 4 | 보안 장비, 서버(가상화), 서버 관리 포트(BMC), NAS, 카메라·IoT, IP 전화기 | `device`(AhnLab MDS·EPP, VMware, iDRAC·iLO, Synology), Recog 장비 종류 | 높음 |
| 5 | 모바일(스마트폰·태블릿), 모바일 | `form_factor`(3.11) → OS 힌트 `ios`·`android` → 호스트 이름(iPhone·iPad·Galaxy 등) | 높음 → 보통 |
| 6 | PC(노트북), PC(데스크톱) | 호스트 이름: Windows 기본 이름(`LAPTOP-`·`DESKTOP-`, 설치 때 본체 종류로 정해짐), Apple 기기 모델이 든 이름(MacBook, iMac, Mac mini) | 보통 |
| 7 | 서버 | OS가 서버(Windows Server 등), 리졸버 역할, 도메인 컨트롤러 포트 응답 | 높음 |
| 8 | 서버(추정) | OS를 모르거나 Linux·Unix 계열이면서 서버 포트(웹·DB·메일·DNS·SSH 등)에 응답 | 보통·낮음 |
| 9 | PC, PC 또는 모바일(Apple) | 클라이언트 OS(Windows 10/11·macOS 등). TCP SYN `macOS·iOS·BSD 계열`과 Apple 연결 확인(`apple`)은 Mac과 iPhone을 가를 수 없음 | 보통·낮음 |
| 10 | 알 수 없음(Linux 계열), 알 수 없음 | 그 밖 | - |

- **노트북·데스크톱 구분의 한계:** 네트워크 트래픽에는 본체 종류가 거의 없습니다. 이름을 회사 규칙으로 바꾸면 "PC"로만 나옵니다. 정확한 구분은 고객 대역 정보(무선·VPN 대역)나 MDS Agent·EPP 자산 정보 연동이 필요합니다.
- **모바일의 한계:** iPadOS 13 이후 Safari는 Mac UA를 써서 iPad가 macOS로 보일 수 있습니다. 모바일 앱 트래픽 대부분은 HTTPS라 UA가 보이지 않습니다.

---

## 5. 품질 지표 (리포트)

리포트의 "식별 품질" 앞에 **OS·역할 통계**를 둔다.
- OS 계열(Windows, Windows Server, Linux, macOS, 모바일, 기타, 미확인)과 세부 OS별 자산 수·비율. 세부 OS는 버전 없는 표시(예: `Windows 11 24H2 (build 26100)` → `Windows 11`)로 묶되, PC/서버를 가를 수 없는 구형 빌드는 원래 이름(예: `Windows 7/Server 2008 R2`)을 유지
- 역할별 자산 수·비율(장비 종류 포함). 자산 하나가 여러 역할을 가질 수 있어 합이 100%를 넘을 수 있고, 역할이 없는 자산은 "미확인"

| 지표 | 정의 |
|---|---|
| 식별률 | 대표 키가 IP+시간이 아닌 자산 비율 |
| 신뢰 식별률 | 식별 중 신뢰도 "낮음"(연결 기록 MAC만) 제외 |
| 능동 / 수동 IP 식별률 | conn.log에서 연결을 먼저 연 IP / 상대로만 보인 IP 기준 |
| 식별 내역 | 대표 키·신뢰도별 자산 수 |
| 캡처 시간별 식별률 | 시점 t까지 관측된 자산 중 t까지 식별된 비율 |
| 식별 소요 시간 | 첫 관측 → 식별 키 확보까지 시간 분포 |
| 구간(/24)별 식별률 | 첫 IP의 /24 기준, 상위 20개 |
| 능동 IP 중 AhnLab 제품 통신 | 능동 IP 중 `security_agent`가 있는 비율 |
| 캡처 품질 | 시작측이 데이터를 보낸 TCP 연결 중 응답이 보인 비율(50% 미만이면 단방향 미러 경고). 데이터 없는 연결 시도는 따로 집계하고 상위 5개 IP 표시 |

"식별"은 키를 얻었는지만 본다. 키가 맞는지(정확도)는 AD·DHCP 정답 목록과 비교해야 한다(PLAN V2·V3).

---

## 6. 관측 위치별로 기대할 수 있는 신호

| 미러 위치 | 얻을 수 있는 식별 키 | 주요 보조 정보 | PC 식별 기대 |
|---|---|---|---|
| 단말 L2 구간 | MAC(ARP·DHCP), client-id, 호스트명(DHCP·NBNS·LLMNR·mDNS) | OS(DHCP·UA), 사용자 | 높음 (비도메인 단말 포함) |
| DC 앞 (서버팜) | 머신 계정(Kerberos·CLDAP·NTLM), 호스트명, DNS 동적 업데이트(9.x) | 도메인, 사용자, SMB2 GUID | 도메인 PC 높음 (2시간 이상, 출근 시간 포함) |
| DHCP 서버 앞 (릴레이 구간 포함) | client-id, MAC(DHCP), 호스트명 | DHCP 지문 | DHCP 단말 높음 (갱신 주기에 좌우) |
| 사용자 → 서버 라우팅 구간 (DC·DHCP 없음) | 거의 없음 (가끔 NTLM) | 서버 역할·이름, 서버 도메인(Kerberos 서비스 티켓), 서버 소프트웨어·OS(HTTP Server 헤더), 장비 종류, AhnLab 제품, UA OS | 낮음 (운영 5~9차에서 확인) |
| 인터넷 경계 | 거의 없음 | 프록시, UA | 낮음 |

---

## 7. 설정 (`scripts/config.zeek`)

| 항목 | 기본값 | 설명 |
|---|---|---|
| `asset_nets` | `{}` | 자산 대역 (`run_poc.sh -n`) |
| `suppress_interval` | 1hr | 중복 억제 기간 |
| `dhcp_xid_timeout` | 5min | DHCP 트랜잭션 보관 |
| `enable_*` | T | 출처별 on/off: dhcp, arp, conn_mac, kerberos, ntlm, ldap, nbns, llmnr, mdns, dns, dns_update, server_names, http_server, rdp, smb, http_ua, ssh, services, agents, syslog, x509, ssh_host_key, smb_guid, mds_agent, agent_policy, snmp, tcp_fp, http_wwwauth, sip, service_banners |
| `service_ports` | 주요 포트 | 포트만으로 서비스 인정 |
| `ignore_service_ports` | 137,138,1900,5353,5355/udp | 거의 모든 단말이 응답하는 포트 |
| `nested_analyzers` | ntlm, gssapi, krb, … | 다른 프로토콜 안에서 확인되는 분석기 |
| `max_server_names` | 20 | IP당 서버 이름 상한 |
| `ignore_hostnames` | localhost 등 | 식별에 쓸 수 없는 일반 이름 |
| `ephemeral_port_min` | 49152 | 임시 포트 기준 |
| `syslog_parse_limit` | 50 | 송신 장비별 해석 메시지 수 |
| `mds_agent_ports` | 8290, 8291, 8293, 50007, 50502/tcp | AhnLab MDS Agent → MDS 장비 포트 |
| `mds_servers` | `{}` | MDS 장비 주소. 지정하면 연결 1건으로 판단(신뢰도 90) |
| `mds_agent_min_ports`, `mds_agent_window` | 2, 1hr | 장비 주소가 없을 때 같은 서버의 서로 다른 에이전트 포트 수와 세는 시간 |
| `agent_policy_file` | `""` | 고객 정의 에이전트 정책 파일(3.17). 비어 있으면 꺼짐 |
| `agent_policy_window` | 1hr | 연결 정책의 서로 다른 포트를 세는 시간, 같은 (단말, 정책)을 다시 기록하기까지의 시간 |

리졸버 옵션: `--shared-mac-threshold`(2), `--multi-account-window`(10분), `--max-idle`(24시간), `--tz`(9).

---

## 8. 개인정보·보안 고려

- SNMP 커뮤니티 문자열은 기록하지 않는다. 내부 서버 인증서 주체·발급자(회사·부서 이름이 들어 있을 수 있음)는 기록한다
- 기록하지 않는 것: 인증 응답값(NTLM 해시 등), 비밀번호, syslog 본문, HTTP URL·쿼리 값(MeDCore 파라미터 포함), 프록시 경유 외부 사이트 이름
- 기록하는 개인 정보: 사용자 계정 이름(로그온 사용자 표시용). Manager 연동 시 보관 기간·접근 권한을 SRS에서 정한다
- 다중 머신 계정 인증(4.6)은 자산 판정 보호 장치이면서 탐지 관점의 이상 징후다

---

## 9. Zeek 버전별 차이와 한계

| 신호 | 8.0.9 | 9.0.1 |
|---|---|---|
| DNS 동적 업데이트 | 파싱 안 함 | 지원 |
| LDAP(SASL) 안의 NTLM | 꺼내지 않음 | 지원 |
| TCP syslog | 분석기 없음 | 지원 |
| SSH DH group18 호스트 키 | 못 꺼냄 | 지원 |
| LDAP(SASL) 안의 Kerberos 서비스 티켓 | 꺼내지 않음 | 지원 |

그 밖의 한계: DHCPv6·NDP 미수집, TLS 1.3 인증서 미관측, SMB1로 시작하는 SMB 연결의 GUID 미추출, MAC 랜덤화 단말은 여러 자산으로 보일 수 있음, Zeek 클러스터(워커 여러 개)에서의 중복 억제·DHCP 트랜잭션 결합은 미검증(PLAN V4).

---

## 10. 변경 이력

| 버전 | 날짜 | 내용 |
|---|---|---|
| 0.2 | 2026-11-06 | 최초 작성 (센서 22개 출처, 판정 규칙, 품질 지표, 버전 차이) |
| 0.3 | 2026-11-19 | 라우팅 구간 신호: Kerberos 서비스 티켓(AP-REQ)의 서버 이름·도메인(`krb`), HTTP 응답 Server 헤더의 서버 소프트웨어·OS(`http_server`, `enable_http_server`). DHCP 릴레이 구간 동작 명시와 테스트 |
| 0.7 | 2026-11-20 | 기기 형태 힌트 `form_factor`(3.11), Apple 연결 확인 OS 힌트, 장비 유형 판정 규칙(4.12) |
| 0.6 | 2026-11-20 | 서비스 배너(3.20): HTTP 인증 realm, SIP User-Agent·Server, FTP·SMTP·POP3 접속 인사, MySQL 버전과 Recog 연결(4.11), 부하 측정 |
| 0.5 | 2026-11-20 | 지문 대조 입력 신호: SMB1 native OS·LM 원문(클라이언트·서버), 인증서 주체·발급자, SNMP(3.18), TCP SYN 지문(3.19). 지문 DB 보강 규칙(4.11: OUI, Recog, TCP SYN 계열)과 라이선스 메모 |
| 0.4 | 2026-11-19 | 고객 정의 에이전트 정책(3.17, `agent_policy_file`, `asset_agent_policy.log`), Manager의 에이전트 미확인 판정 규칙(4.10) |
