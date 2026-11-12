##! ============================================================================
##! 웹 공격 룰(03 SQLi, 04 웹쉘) 공통 — 대상 판정, 입력 정규화, 예외
##! ============================================================================

@load base/protocols/http
@load base/utils/site
@load ./main
@load ./exceptions

module NSM;

export {
    ## 내부(local_nets) 웹서버로 들어오는 요청만 검사한다. 내부 사용자의 외부 사이트 접속은
    ## 검색어·게시글에 SQL 문법이 섞여 오탐이 크고 보호 대상도 아니다.
    const web_attack_local_servers_only = T &redef;

    ## 예외 출발지(사내 취약점 스캐너·모의해킹 장비 등). 예외 엔진에 drop 예외로 등록된다(호환).
    ##   새 예외는 예외 파일(docs/SRS.md 7.8절)에 SQL_Injection·Webshell_Access 범위로 쓴다.
    const web_attack_allowlist: set[subnet] = {} &redef;

    ## 본문 검사 최대 바이트(요청당). 대용량 업로드 본문 전체를 정규식에 넣지 않는다.
    const web_attack_body_max = 4096 &redef;

    ## 이 연결의 요청을 note 탐지로 검사할지(내부 웹서버 대상, 예외 엔진 판정).
    global web_attack_target: function(c: connection, note: Notice::Type): bool;

    ## URI·본문 정규화: URL 디코딩 2회(이중 인코딩 우회 대응), 폼 인코딩의 '+' -> 공백, 소문자.
    global web_normalize: function(s: string): string;

    ## 요청 본문 조각(length 바이트)을 검사할 여유가 남았는지. 연결별로 web_attack_body_max 까지만 T.
    global web_body_budget: function(c: connection, length: count): bool;
}

## 연결(uid)별 이미 검사한 본문 바이트. (c$http$request_body_len 은 메시지가 끝나야 채워진다)
global web_body_seen: table[string] of count &create_expire=10min &default=0;

function web_attack_target(c: connection, note: Notice::Type): bool
    {
    if ( web_attack_local_servers_only && ! Site::is_local_addr(c$id$resp_h) )
        return F;
    # 예외(예외 파일 + 기존 web_attack_allowlist). 요청 줄 시점에는 Host 헤더가 아직 없어 domain 축은 맞지 않는다.
    if ( NSM::exception_drop(note, c) )
        return F;
    return T;
    }

event zeek_init()
    {
    if ( |web_attack_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:web_attack_allowlist",
            [$scope=set("SQL_Injection", "Webshell_Access"), $src=web_attack_allowlist]);
    }

function web_normalize(s: string): string
    {
    local v = gsub(s, /\+/, " ");
    v = unescape_URI(unescape_URI(v));
    return to_lower(v);
    }

function web_body_budget(c: connection, length: count): bool
    {
    return web_body_seen[c$uid] < web_attack_body_max;
    }

# 검사 후(낮은 우선순위) 한 번만 누적한다. 03·04 가 같은 조각을 각각 검사해도 이중 차감되지 않는다.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-10
    {
    if ( is_orig )
        web_body_seen[c$uid] += length;
    }
