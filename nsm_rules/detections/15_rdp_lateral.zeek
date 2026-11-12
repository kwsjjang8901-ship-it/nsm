##! ============================================================================
##! [15] Lateral Movement (RDP) - 원격 데스크톱 내부 확산 (SumStats 집계형) - T1021.001
##!
##! 탐지 원리
##!   - 한 src 가 짧은 시간에 다수 내부 host 의 RDP(3389)로 접속 = 수평 확산.
##!   - 06(SMB)과 동일 구조: src 단위 "고유 목적지 host 수"를 SumStats 로 집계.
##!   - epoch_result 로 창 종료 시 1회 판정 + SAMPLE 로 근거/목적지 예시 첨부.
##!   - src allowlist(점프박스/IT관리자 PC/원격지원 서버)가 오탐 제어의 핵심.
##!
##!   ※ RDP 는 암호화라 본문은 못 본다. "누가 어디로 접속했는가"(메타데이터)만 본다.
##!   ※ 로컬->로컬(내부간 이동)만 대상. 외부->내부 인입 RDP 는 성격이 달라 제외.
##!   ※ rdp_connect_request 의 cookie(mstshash=<user>)에서 계정(WHO)을 추출해 evidence 의 account 에 남긴다.
##!
##! 증적(Evidence) 연동  ※ 집계형 (06 과 동일 패턴)
##!   - 집계형이라 threshold_crossed 에는 uid 가 없다 -> src 단위 합성 evidence_id
##!     ( cat(src, "|rdp-lm") ).
##!   - 근거(어떤 src->dst, 어떤 계정)는 탐지 시점(epoch_result)에 표본마다 evidence.log 에 1행씩 적재.
##!
##! 상관 계약: notice $src = 확산 기점 host, $lm_targets = 피해 host 집합.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/rdp
@load base/utils/site
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./auth_context

module NSM;

export {
    ## RDP 내부확산 탐지 마스터 토글.
    const detect_rdp_lateral = T &redef;

    ## ---- SumStats 집계 파라미터 ----
    const rdp_lm_epoch = 1min &redef;
    ## RDP 는 정상 다중접속이 SMB 보다 적어 임계를 다소 낮게. (운영 튜닝 대상)
    const rdp_lm_thresholds: vector of double = vector(3.0, 5.0, 10.0) &redef;

    ## 관리 인프라 src 예외 목록(오탐 제어 핵심).
    ## !!! 예시 -> 실제 점프박스/원격지원/IT관리자 PC 대역으로 교체 !!!
    const rdp_lm_allowlist: set[subnet] = { } &redef;
}

## 집계형 합성 증적 key. 탐지 시점(threshold_crossed)에서만 호출한다.
##   관측 시점에 재계산하면 time_bucket 이 어긋나 notice 와 evidence 의
##   key 가 달라진다(2026-09 수정 이전의 결함).
function rdp_evidence_id(src: addr): string
    {
    return cat(src, "|rdp-lm|", time_bucket(rdp_lm_epoch));
    }

## RDP cookie 에서 사용자명 추출.
##   rdp_connect_request 의 cookie 는 Zeek 분석기가 "Cookie: mstshash=" 를 떼어낸 값
##   (예: "administrator")으로 전달된다. 접두어가 남아 있는 경우도 처리한다.
##   (이전 구현은 접두어가 있을 때만 값을 돌려줘 항상 "" 였고, 호출되지도 않았다)
function rdp_user_from_cookie(cookie: string): string
    {
    local v = cookie;
    local m = find_all(v, /mstshash=[^\r\n]*/);
    for ( s in m )
        {
        v = sub(s, /mstshash=/, "");
        break;
        }
    return strip(v);
    }

event zeek_init()
    {
    # UNIQUE: 고유 목적지 수(판정) / SAMPLE: "목적지|계정" 표본(근거·WHO)
    #   계정을 UNIQUE 키에 섞으면 같은 목적지를 다른 계정으로 접속할 때 중복 집계되므로 분리한다.
    local r = SumStats::Reducer($stream="nsm.rdp_lm",
                                $apply=set(SumStats::UNIQUE));
    local r_who = SumStats::Reducer($stream="nsm.rdp_lm.who",
                                    $apply=set(SumStats::SAMPLE),
                                    $num_samples=lm_num_samples);
    SumStats::create([
        $name             = "nsm-detect-rdp-lateral",
        $epoch            = rdp_lm_epoch,
        $reducers         = set(r, r_who),
        # 창(epoch) 종료 시 1회만 평가한다.
        #   threshold_series 는 임계치 단계마다 재발화해 같은 창에서 detection 이
        #   여러 건 생기고, 각 건의 evidence_count 가 그 시점 스냅샷이 되어
        #   확정값과 달랐다. 또 마지막 발화 뒤 창 종료까지 적재된 근거는 어떤
        #   detection 도 가리키지 못했다. 창 단위 1건으로 두 문제를 함께 없앤다.
        #   대가: 최대 rdp_lm_epoch 지연, 단계별 임계치 소멸(최솟값 하나로 판정).
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.rdp_lm" !in result )
                return;

            local res   = result["nsm.rdp_lm"];
            local dst_n = res$unique;

            if ( dst_n + 0.0 < rdp_lm_thresholds[0] )
                return;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = rdp_evidence_id(key$host);

            local samples = "";
            local targets: set[addr] = set();
            if ( "nsm.rdp_lm.who" in result && result["nsm.rdp_lm.who"]?$samples )
                {
                local who = result["nsm.rdp_lm.who"];
                for ( i in who$samples )
                    {
                    if ( ! who$samples[i]?$str )
                        next;

                    local parts = split_string(who$samples[i]$str, /\|/);   # "목적지|계정|uid"
                    local sdst = parts[0];
                    local user = ( |parts| > 1 ) ? parts[1] : "";
                    local suid = ( |parts| > 2 ) ? parts[2] : "";
                    local item = cat(sdst, "|", user);        # 근거 1행 단위(연결마다가 아니라 목적지·계정마다)
                    if ( to_addr(sdst) !in targets )
                        samples += fmt("%s ", sdst);
                    add targets[to_addr(sdst)];   # 상관용 피해 host

                    # 표본(목적지,계정)마다 근거 1행. NOTICE 보다 먼저 적재해야
                    #   detection 의 evidence_count 가 정확히 잡힌다.
                    if ( ! NSM::evidence_is_new(eid, item) )
                        next;
                    local ev: EvidenceInfo = [
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=RDP_Lateral,
                        $technique="T1021.001",
                        $src=key$host,
                        $dst=to_addr(sdst),
                        $uid=suid,
                        $operation="rdp_connect",
                        $detail=fmt("unique_dst=%d window=%s", dst_n, rdp_lm_epoch)];
                    if ( user != "" )
                        ev$account = user;
                    else
                        # cookie 가 없으면(NLA 전용 클라이언트 등) 같은 대상 NTLM 이나 termsrv 티켓 계정
                        ev$account = NSM::auth_accounts(key$host, to_addr(sdst), set("termsrv"));
                    NSM::write_evidence(ev);
                    }
                }

            NOTICE([$note=RDP_Lateral,
                    $src=key$host,
                    $msg=fmt("RDP lateral movement: %s -> %d unique hosts in %s",
                             key$host, dst_n, rdp_lm_epoch),
                    $sub=fmt("unique_dst=%d sample=[%s]", dst_n, samples),
                    $identifier=cat(key$host, "rdp-lm-", time_bucket(rdp_lm_epoch)),   # 창 단위로 1건
                    $suppress_for=rdp_lm_epoch,
                    $evidence_id=eid,
                    $lm_targets=targets]);
            }
    ]);
    }

## RDP 연결 시도를 "관측" + 증적 1행 적재 (NOTICE 는 SumStats 가 담당)
# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |rdp_lm_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:rdp_lm_allowlist",
            [$scope=set("RDP_Lateral"), $src=rdp_lm_allowlist]);
    }

function observe_rdp(c: connection, cookie: string)
    {
    if ( ! detect_rdp_lateral )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # 내부간 이동만: 로컬 src -> 로컬 dst
    if ( src !in Site::local_nets || dst !in Site::local_nets )
        return;
    # 예외(예외 파일 + 기존 rdp_lm_allowlist). 집계 전 판정이라 (출발지, 목적지) 쌍 예외도 된다
    if ( NSM::exception_drop_agg(RDP_Lateral, c) )
        return;

    # 관측만 한다. 증적은 탐지 시점(threshold_crossed)에서 표본으로 적재한다.
    SumStats::observe("nsm.rdp_lm",
       [$host=src],
       [$str=cat(dst)]);
    SumStats::observe("nsm.rdp_lm.who",
       [$host=src],
       [$str=cat(dst, "|", rdp_user_from_cookie(cookie), "|", c$uid)]);
    }

# RDP 접속 요청 시 cookie(사용자 힌트 mstshash) 동반. 확산 관측의 진입점.
event rdp_connect_request(c: connection, cookie: string)
    {
    observe_rdp(c, cookie);
    }
