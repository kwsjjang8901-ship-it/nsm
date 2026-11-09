##! ============================================================================
##! [5] Lateral Movement (SMB Admin Share) - 관리 공유 접근 (SumStats 집계형)
##!
##! 탐지 원리
##!   - 관리 공유(ADMIN$/C$/IPC$/<drive>$) 접근을 매번 알리면 대상 수만큼 폭증.
##!   - src 단위로 "접근한 고유 목적지 호스트 수"를 SumStats 로 집계(수평 확산).
##!   - epoch_result 로 창 종료 시 1회 판정 + SAMPLE 로 근거/목적지 예시 첨부.
##!   - src allowlist(SCCM/백업/AV관리/PsExec 등)가 오탐 제어의 핵심.
##!
##! 증적(Evidence) 연동  ※ 집계형
##!   - 집계형이라 threshold_crossed 에는 uid 가 없다 -> src 단위 합성 evidence_id
##!     ( cat(src, "|smb-admin-lm") )를 쓴다.
##!   - 실제 근거(어떤 src->dst, 어떤 공유)는 observe 시점마다 evidence.log 에 1행씩
##!     적재한다. 가능하면 NTLM 세션에서 계정(WHO)도 채운다.
##!   - notice 는 동일 evidence_id 만 들고 가, 그 src 의 근거 묶음을 가리킨다.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/smb
@load base/protocols/ntlm
@load ./main
@load ./evidence_log

module NSM;

export {
    ## 관리 공유 경로 패턴 (끝이 '$' 인 공유): \\HOST\ADMIN$ , \\HOST\C$ ...
    const admin_share_pattern = /(?i:.*\\[A-Za-z]*\$$)/ &redef;

    ## IPC$ 는 정상 사용도 많아 기본 제외.
    const exclude_ipc_share = T &redef;

    ## SMB 관리공유 탐지 마스터 토글.
    const detect_smb_admin_share = T &redef;

    ## ---- SumStats 집계 파라미터 ----
    const smb_lm_epoch = 1min &redef;
    const smb_lm_thresholds: vector of double = vector(3.0, 5.0, 30.0) &redef;

    ## 관리 인프라 src 예외 목록(오탐 제어 핵심).
    ## !!! 예시 값 -> 실제 SCCM/WSUS/백업/AV관리/스캐너/점프박스 대역으로 교체 !!!
    const smb_lm_allowlist: set[subnet] = { } &redef;
}

## 집계형 합성 증적 key. 탐지 시점(threshold_crossed)에서만 호출한다.
##   관측 시점에 재계산하면 time_bucket 이 어긋나 notice 와 evidence 의
##   key 가 달라진다(2026-09 수정 이전의 결함).
function smb_evidence_id(src: addr): string
    {
    # smb_lm_epoch 창 단위로 구분된다(같은 창=동일, 다른 창=별개 탐지).
    return cat(src, "|smb-admin-lm|", time_bucket(smb_lm_epoch));
    }

event zeek_init()
    {
    # UNIQUE: 고유 목적지 수 / SAMPLE: 알림에 실을 목적지 예시(최대 5개)
    local r = SumStats::Reducer($stream="nsm.smb_admin",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=lm_num_samples);
    SumStats::create([
        $name             = "nsm-detect-smb-admin-share",
        $epoch            = smb_lm_epoch,
        $reducers         = set(r),
        # 창(epoch) 종료 시 1회만 평가한다.
        #   threshold_series 는 임계치 단계마다 재발화해 같은 창에서 detection 이
        #   여러 건 생기고, 각 건의 evidence_count 가 그 시점 스냅샷이 되어
        #   확정값과 달랐다. 또 마지막 발화 뒤 창 종료까지 적재된 근거는 어떤
        #   detection 도 가리키지 못했다. 창 단위 1건으로 두 문제를 함께 없앤다.
        #   대가: 최대 smb_lm_epoch 지연, 단계별 임계치 소멸(최솟값 하나로 판정).
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.smb_admin" !in result )
                return;

            local res   = result["nsm.smb_admin"];
            local dst_n = res$unique;

            if ( dst_n + 0.0 < smb_lm_thresholds[0] )
                return;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = smb_evidence_id(key$host);

            local samples = "";
            local targets: set[addr] = set();
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;

                    local sdst = res$samples[i]$str;
                    samples += fmt("%s ", sdst);
                    add targets[to_addr(sdst)];   # 상관용 피해 host

                    # 표본 목적지마다 근거 1행. NOTICE 보다 먼저 적재해야
                    #   detection 의 evidence_count 가 정확히 잡힌다.
                    if ( NSM::evidence_is_new(eid, sdst) )
                        NSM::write_evidence([
                            $ts=network_time(),
                            $evidence_id=eid,
                            $note=SMB_Admin_Share,
                            $technique="T1021.002",
                            $src=key$host,
                            $dst=to_addr(sdst),
                            $operation="smb_tree_connect",
                            $detail=fmt("unique_dst=%d observed=%d window=%s",
                                        dst_n, res$num, smb_lm_epoch)]);
                    }

            NOTICE([$note=SMB_Admin_Share,
                    $src=key$host,
                    $msg=fmt("SMB admin-share lateral movement: %s -> %d unique hosts in %s",
                             key$host, dst_n, smb_lm_epoch),
                    $sub=fmt("unique_dst=%d sample=[%s]", dst_n, samples),
                    $identifier=cat(key$host, "smb-lm-", time_bucket(smb_lm_epoch)),   # 창 단위로 1건
                    $suppress_for=smb_lm_epoch,
                    $evidence_id=eid,
                    $lm_targets=targets]);
            }
    ]);
    }

## 공유 경로가 관리 공유이면 "관측"만 한다 (NOTICE·증적은 SumStats 가 담당)
function observe_admin_share(c: connection, path: string)
    {
    if ( ! detect_smb_admin_share )
        return;
    if ( admin_share_pattern !in path )
        return;
    if ( exclude_ipc_share && /(?i:.*\\IPC\$$)/ in path )
        return;
    if ( c$id$orig_h in smb_lm_allowlist )
        return;

    # 고유 "목적지 호스트" 카운트(목적지+공유까지 보려면 cat(c$id$resp_h, path))
    SumStats::observe("nsm.smb_admin",
       [$host=c$id$orig_h],
       [$str=cat(c$id$resp_h)]);

    }

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
    {
    observe_admin_share(c, path);
    }

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header,
                                     path: string, service: string)
    {
    observe_admin_share(c, path);
    }
