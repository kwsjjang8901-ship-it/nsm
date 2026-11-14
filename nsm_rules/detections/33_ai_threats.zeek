##! ============================================================================
##! [33] AI 관련 위협 — 생성형 AI 서비스로의 자료 업로드, 서버의 AI API 호출, 사내 AI 인프라 관리 API 공격
##!
##! 외부 AI 서비스와의 통신은 HTTPS 라 프롬프트·응답 내용은 보지 않는다. 누가·어디로·얼마나·어떤 호출을
##! 했는지(SNI·바이트·평문 HTTP 요청)로 판정한다. AI 서비스 목록은 ai_common.zeek(ai_service_domains).
##!
##! AI_Service_Upload (T1567) — 내부 host 가 한 AI 서비스로 ai_upload_epoch(1시간) 안에 ai_upload_bytes(10MB) 이상
##!   올림. 대화 입력은 수 KB 라 이 정도면 문서·데이터 파일 첨부다(섀도 AI 를 통한 자료 유출).
##! AI_API_From_Server (T1102) — 서버로 학습된 host(DNS·Kerberos·LDAP·DB·메일 등 서버 포트에서 응답한 내부 host)
##!   또는 ai_server_nets 대역이 AI 서비스·LLM API 에 TLS 로 접속. 서버는 사람이 AI 를 쓰지 않으므로, LLM API 로
##!   명령을 만들거나 C2 로 쓰는 악성코드(예: LameHug)·무단 AI 연동을 의심한다.
##! AI_Service_Exploit (T1190) — 사내 AI 인프라의 관리·실행 API 호출(평문 HTTP): Ray 작업 제출(ShadowRay),
##!   Ollama 모델 pull·push·create·delete, TorchServe URL 모델 등록(ShellTorch), Jupyter 터미널 생성,
##!   MLflow 경로 조작(../). 정상 운영자도 쓰는 API 라 ML 팀·관리 대역은 예외(출발지 축)로 뺀다.
##!
##! 상관: 업로드 = 유출 묶음, 서버의 AI API 호출 = C2 묶음, 인프라 공격 = 초기 침투 묶음(lm_targets = 대상 서버).
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/krb
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./ai_common

module NSM;

export {
    const detect_ai_upload = T &redef;
    const ai_upload_epoch = 1hr &redef;
    ## 한 (출발지, AI 서비스)로 창 안에 올린 바이트(페이로드)
    const ai_upload_bytes = 10000000 &redef;

    const detect_ai_api_from_server = T &redef;
    ## 응답하면 서버로 학습하는 포트(PC 도 여는 445·139·3389 등은 넣지 않는다)
    const ai_server_ports: set[port] = {
        53/udp, 53/tcp, 88/udp, 88/tcp, 389/tcp, 389/udp, 636/tcp, 3268/tcp,
        1433/tcp, 1521/tcp, 3306/tcp, 5432/tcp, 27017/tcp, 6379/tcp, 9200/tcp,
        25/tcp, 587/tcp,
    } &redef;
    ## 학습과 별개로 서버로 볼 대역(서버팜 등). 고객 환경에서 지정
    const ai_server_nets: set[subnet] = {} &redef;
    ## 서버로 학습한 host 를 기억하는 시간(마지막 응답 후)
    const ai_server_learn_expire = 24hr &redef;

    const detect_ai_service_exploit = T &redef;
    ## 관리·실행 API 서명: 이름, 포트(0/tcp = 아무 포트), 메서드, 경로 패턴(쿼리 제외 경로·소문자)
    type AiApiSig: record {
        name:   string;
        p:      port;
        method: string;
        path:   pattern;
        query:  pattern &optional;     # 쿼리 문자열(URL 디코딩 2회·소문자)에 있어야 하는 패턴
    };
    const ai_service_sigs: vector of AiApiSig = {
        [$name="ray_job_submit",        $p=8265/tcp,  $method="POST", $path=/^\/api\/jobs\/?$/],
        [$name="ollama_model_manage",   $p=11434/tcp, $method="POST", $path=/^\/api\/(pull|push|create|delete|copy)$/],
        [$name="ollama_model_manage",   $p=11434/tcp, $method="DELETE", $path=/^\/api\/delete$/],
        [$name="torchserve_register",   $p=0/tcp,     $method="POST", $path=/^\/models\/?$/, $query=/(^|&)url=/],
        [$name="jupyter_terminal",      $p=0/tcp,     $method="POST", $path=/^\/api\/terminals\/?$/],
        [$name="mlflow_path_traversal", $p=0/tcp,     $method="GET",  $path=/(mlflow|get-artifact)/, $query=/\.\.\//],
    } &redef;
}

# ------------------------------------------------------------------ 서버 학습

global ai_learned_servers: table[addr] of port &read_expire=ai_server_learn_expire;

function ai_learn(h: addr, p: port)
    {
    if ( p in ai_server_ports && Site::is_local_addr(h) )
        ai_learned_servers[h] = p;
    }

# TCP: 3-way 핸드셰이크가 끝났으면 응답한 것이다.
event connection_established(c: connection) { ai_learn(c$id$resp_h, c$id$resp_p); }

# UDP 서버는 응답 메시지로 바로 배운다(연결 종료까지 기다리면 그 사이 첫 AI 접속을 놓친다).
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( ! is_orig )
        ai_learn(c$id$resp_h, c$id$resp_p);
    }
event krb_as_response(c: connection, msg: KRB::KDC_Response) { ai_learn(c$id$resp_h, c$id$resp_p); }
event krb_tgs_response(c: connection, msg: KRB::KDC_Response) { ai_learn(c$id$resp_h, c$id$resp_p); }
event krb_error(c: connection, msg: KRB::Error_Msg) { ai_learn(c$id$resp_h, c$id$resp_p); }

# 그 밖의 UDP(CLDAP 등)는 종료 때 응답 유무로 본다.
event connection_state_remove(c: connection) &priority=5
    {
    if ( get_port_transport_proto(c$id$resp_p) == udp && c$resp$num_pkts > 0 )
        ai_learn(c$id$resp_h, c$id$resp_p);
    }

function ai_is_server(a: addr): bool
    {
    return a in ai_learned_servers || a in ai_server_nets;
    }

# ------------------------------------------------------------------ AI_Service_Upload

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="nsm.ai_upload", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="nsm.ai_upload.sample", $apply=set(SumStats::SAMPLE), $num_samples=5);
    SumStats::create([
        $name="nsm-detect-ai-upload", $epoch=ai_upload_epoch, $reducers=set(r1, r2),
        $threshold=ai_upload_bytes + 0.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = { return result["nsm.ai_upload"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local svc = key$str;
            local total = double_to_count(result["nsm.ai_upload"]$sum);
            local n = result["nsm.ai_upload"]$num;
            local eid = cat(src, "|ai-upload|", svc, "|", time_bucket(ai_upload_epoch));
            local dst: addr = 0.0.0.0;
            if ( "nsm.ai_upload.sample" in result && result["nsm.ai_upload.sample"]?$samples )
                for ( i in result["nsm.ai_upload.sample"]$samples )
                    {
                    local o = result["nsm.ai_upload.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);       # "uid|목적지|이름|바이트"
                    if ( |p| < 4 || ! NSM::evidence_is_new(eid, p[0]) )
                        next;
                    if ( dst == 0.0.0.0 )
                        dst = to_addr(p[1]);
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=AI_Service_Upload,
                        $technique="T1567",
                        $src=src,
                        $dst=to_addr(p[1]),
                        $uid=p[0],
                        $operation="ai_service_upload",
                        $detail=fmt("service=%s name=%s conn_upload=%s total_upload=%d conns=%d window=%s",
                                    svc, p[2], p[3], total, n, ai_upload_epoch)]);
                    }
            NOTICE([$note=AI_Service_Upload,
                    $src=src,
                    $dst=dst,
                    $msg=fmt("Large upload to AI service %s from %s (%.1f MB in %s)", svc, src,
                             total / 1000000.0, ai_upload_epoch),
                    $sub=fmt("service=%s upload_mb=%.1f conns=%d", svc, total / 1000000.0, n),
                    $identifier=cat(src, "ai-upload", svc, time_bucket(ai_upload_epoch)),
                    $suppress_for=ai_upload_epoch,
                    $evidence_id=eid]);
            }
    ]);
    }

event connection_state_remove(c: connection)
    {
    if ( ! Site::is_local_addr(c$id$orig_h) || ! is_external(c$id$resp_h) )
        return;
    local name = conn_service_name(c);
    local svc = ai_service_match(name);
    if ( svc == "" )
        return;

    if ( detect_ai_upload && c$orig$size > 0 && ! NSM::exception_drop_agg(AI_Service_Upload, c) )
        {
        local key: SumStats::Key = [$host=c$id$orig_h, $str=svc];
        SumStats::observe("nsm.ai_upload", key, [$num=c$orig$size]);
        SumStats::observe("nsm.ai_upload.sample", key,
                          [$str=cat(c$uid, "|", c$id$resp_h, "|", name, "|", c$orig$size)]);
        }
    }

# ------------------------------------------------------------------ AI_API_From_Server

event ssl_established(c: connection)
    {
    if ( ! detect_ai_api_from_server || ! c$ssl?$server_name )
        return;
    local src = c$id$orig_h;
    if ( ! Site::is_local_addr(src) || ! is_external(c$id$resp_h) || ! ai_is_server(src) )
        return;
    local name = c$ssl$server_name;
    local svc = ai_service_match(name);
    if ( svc == "" )
        return;
    if ( NSM::exception_drop(AI_API_From_Server, c) )
        return;
    local nid = cat(src, "ai-api-server", svc);
    if ( NSM::notice_suppressed(AI_API_From_Server, nid) )
        return;
    local why = src in ai_learned_servers ? fmt("learned_server_port=%s", ai_learned_servers[src]) : "server_net";
    local eid = cat(src, "|ai-api-server|", svc, "|", c$uid);
    NSM::write_evidence([
        $ts=network_time(),
        $evidence_id=eid,
        $note=AI_API_From_Server,
        $technique="T1102",
        $src=src,
        $dst=c$id$resp_h,
        $uid=c$uid,
        $operation="ai_api_from_server",
        $detail=fmt("service=%s sni=%s %s", svc, name, why)]);
    NOTICE([$note=AI_API_From_Server,
            $conn=c,
            $msg=fmt("Server %s connected to AI service %s (%s)", src, name, why),
            $sub=fmt("service=%s sni=%s %s", svc, name, why),
            $identifier=nid,
            $suppress_for=24hr,
            $evidence_id=eid]);
    }

# ------------------------------------------------------------------ AI_Service_Exploit

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( ! detect_ai_service_exploit || ! Site::is_local_addr(c$id$resp_h) )
        return;
    local parts = split_string1(original_URI, /\?/);
    local path = to_lower(unescape_URI(unescape_URI(parts[0])));
    local query = |parts| > 1 ? to_lower(unescape_URI(unescape_URI(parts[1]))) : "";
    local m = to_upper(method);
    for ( i in ai_service_sigs )
        {
        local s = ai_service_sigs[i];
        if ( s$p != 0/tcp && s$p != c$id$resp_p )
            next;
        if ( m != s$method || s$path !in path )
            next;
        if ( s?$query && s$query !in query )
            next;
        if ( NSM::exception_drop(AI_Service_Exploit, c) )
            return;
        local nid = cat(c$id$orig_h, c$id$resp_h, "ai-exploit", s$name);
        if ( NSM::notice_suppressed(AI_Service_Exploit, nid) )
            return;
        local origin = Site::is_local_addr(c$id$orig_h) ? "internal" : "external";
        local eid = cat(c$id$orig_h, "|ai-exploit|", c$id$resp_h, "|", c$uid);
        NSM::write_evidence([
            $ts=network_time(),
            $evidence_id=eid,
            $note=AI_Service_Exploit,
            $technique="T1190",
            $src=c$id$orig_h,
            $dst=c$id$resp_h,
            $uid=c$uid,
            $operation=fmt("ai_service_%s", s$name),
            $detail=fmt("api=%s method=%s uri=%s port=%s source=%s", s$name, m, sub_bytes(original_URI, 1, 200),
                        c$id$resp_p, origin)]);
        NOTICE([$note=AI_Service_Exploit,
                $conn=c,
                $msg=fmt("AI service management/exec API call (%s) on %s from %s: %s %s", s$name, c$id$resp_h,
                         c$id$orig_h, m, sub_bytes(original_URI, 1, 120)),
                $sub=fmt("api=%s source=%s", s$name, origin),
                $identifier=nid,
                $suppress_for=1hr,
                $lm_targets=set(c$id$resp_h),
                $evidence_id=eid]);
        return;
        }
    }
