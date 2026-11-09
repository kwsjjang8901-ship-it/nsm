##! ============================================================================
##! [16] Lateral Movement (SSH) - SSH 내부 확산 (SumStats 집계형) - T1021.004
##!
##! 탐지 원리
##!   - 한 src 가 짧은 시간에 다수 내부 host 로 SSH(22) "세션 성립" = 수평 확산.
##!   - 06(SMB)/15(RDP)과 동일 구조: src 단위 "고유 목적지 host 수"를 SumStats 집계.
##!   - src allowlist(CI/CD·Ansible·모니터링·백업·점프박스)가 오탐 제어의 핵심.
##!
##!   ※ [중요] 원래는 ssh_auth_successful(인증 성공) 이벤트 기반이었으나,
##!     Zeek 3.0.14 의 SSH 분석기가 최신 OpenSSH 9.x(ETM MAC 등)의 인증을
##!     패킷 크기로 판정하지 못해(auth_attempts=0) 미탐. 그래서 conn 레벨로 전환:
##!     "22/tcp + 양방향 실데이터(orig/resp bytes) + 최소 지속" = 세션 성립으로 간주.
##!   ※ 한계: "연결 성립"이라 "인증 성공"보다 느슨(인증 실패 후 정상종료는 드묾).
##!     양방향 바이트 + 최소 지속 필터로 단순 스캔(한쪽 0)·즉시끊김을 배제해 오탐 억제.
##!   ※ Zeek 7.x 로 업그레이드 시 ssh_auth_successful 로 복원 권장(의미 정확).
##!
##!   ※ SSH 는 암호화라 명령/파일은 못 본다. "누가 어디에 접속·세션했는가"만 본다.
##!   ※ 로컬->로컬(내부간 이동)만 대상. 외부->내부 인입 SSH 는 성격이 달라 제외.
##!
##! 증적(Evidence) 연동  ※ 집계형 (06 과 동일 패턴)
##!   - 집계형이라 threshold_crossed 에는 uid 가 없다 -> src 단위 합성 evidence_id
##!     ( cat(src, "|ssh-lm") ).
##!   - 실제 근거(어떤 src->dst)는 인증 성공 시점마다 evidence.log 에 1행씩 적재.
##!
##! 상관 계약: notice $src = 확산 기점 host, $lm_targets = 피해 host 집합.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/conn
@load base/utils/site
@load ./main
@load ./evidence_log

module NSM;

export {
    ## SSH 내부확산 탐지 마스터 토글.
    const detect_ssh_lateral = T &redef;

    ## ---- SumStats 집계 파라미터 ----
    const ssh_lm_epoch = 1min &redef;
    ## SSH 는 DevOps 자동화로 정상 다중접속이 흔함 -> allowlist 병행 필수.
    const ssh_lm_thresholds: vector of double = vector(3.0, 5.0, 10.0) &redef;

    ## 관리 인프라 src 예외 목록(오탐 제어 핵심).
    ## !!! 예시 -> 실제 CI/CD·Ansible·모니터링·백업·점프박스 대역으로 교체 !!!
    const ssh_lm_allowlist: set[subnet] = { } &redef;

    ## ---- conn 기반 "세션 성립" 판정 필터(오탐 억제) ----
    ## 단순 포트스캔/즉시끊김을 배제: 정상 수립·종료 + 최소 트래픽만 집계.
    const ssh_lm_min_orig_bytes = 1000 &redef;   # 클라->서버 최소 바이트(핸드셰이크+α)
    const ssh_lm_min_duration   = 0.05sec &redef; # 최소 세션 지속(즉시 RST 배제)
}

## 집계형 합성 증적 key. 탐지 시점(threshold_crossed)에서만 호출한다.
##   관측 시점에 재계산하면 time_bucket 이 어긋나 notice 와 evidence 의
##   key 가 달라진다(2026-09 수정 이전의 결함).
function ssh_evidence_id(src: addr): string
    {
    return cat(src, "|ssh-lm|", time_bucket(ssh_lm_epoch));
    }

event zeek_init()
    {
    local r = SumStats::Reducer($stream="nsm.ssh_lm",
                                $apply=set(SumStats::UNIQUE, SumStats::SAMPLE),
                                $num_samples=lm_num_samples);
    SumStats::create([
        $name             = "nsm-detect-ssh-lateral",
        $epoch            = ssh_lm_epoch,
        $reducers         = set(r),
        # 창(epoch) 종료 시 1회만 평가한다.
        #   threshold_series 는 임계치 단계마다 재발화해 같은 창에서 detection 이
        #   여러 건 생기고, 각 건의 evidence_count 가 그 시점 스냅샷이 되어
        #   확정값과 달랐다. 또 마지막 발화 뒤 창 종료까지 적재된 근거는 어떤
        #   detection 도 가리키지 못했다. 창 단위 1건으로 두 문제를 함께 없앤다.
        #   대가: 최대 ssh_lm_epoch 지연, 단계별 임계치 소멸(최솟값 하나로 판정).
        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            if ( "nsm.ssh_lm" !in result )
                return;

            local res   = result["nsm.ssh_lm"];
            local dst_n = res$unique;

            if ( dst_n + 0.0 < ssh_lm_thresholds[0] )
                return;

            # 증적 key 는 탐지 시점에 1회만 생성한다(관측 시점과 재계산 금지).
            local eid = ssh_evidence_id(key$host);

            local samples = "";
            local targets: set[addr] = set();
            if ( res?$samples )
                for ( i in res$samples )
                    {
                    if ( ! res$samples[i]?$str )
                        next;

                    local sdst = res$samples[i]$str;
                    samples += fmt("%s ", sdst);
                    add targets[to_addr(sdst)];

                    # 표본 목적지마다 근거 1행. NOTICE 보다 먼저 적재해야
                    #   detection 의 evidence_count 가 정확히 잡힌다.
                    if ( NSM::evidence_is_new(eid, sdst) )
                        NSM::write_evidence([
                            $ts=network_time(),
                            $evidence_id=eid,
                            $note=SSH_Lateral,
                            $technique="T1021.004",
                            $src=key$host,
                            $dst=to_addr(sdst),
                            $operation="ssh_session",
                            $detail=fmt("unique_dst=%d observed=%d window=%s",
                                        dst_n, res$num, ssh_lm_epoch)]);
                    }


            NOTICE([$note=SSH_Lateral,
                    $src=key$host,
                    $msg=fmt("SSH lateral movement: %s -> %d unique hosts in %s",
                             key$host, dst_n, ssh_lm_epoch),
                    $sub=fmt("unique_dst=%d sample=[%s]", dst_n, samples),
                    $identifier=cat(key$host, "ssh-lm-", time_bucket(ssh_lm_epoch)),   # 창 단위로 1건
                    $suppress_for=ssh_lm_epoch,
                    $evidence_id=eid,
                    $lm_targets=targets]);
            }
    ]);
    }

## SSH 인증 성공을 "관측" + 증적 1행 적재 (NOTICE 는 SumStats 가 담당)
function observe_ssh(c: connection)
    {
    if ( ! detect_ssh_lateral )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # 내부간 이동만: 로컬 src -> 로컬 dst
    if ( src !in Site::local_nets || dst !in Site::local_nets )
        return;
    if ( src in ssh_lm_allowlist )
        return;

    # 관측만 한다. 증적은 탐지 시점(threshold_crossed)에서 표본으로 적재한다.
    SumStats::observe("nsm.ssh_lm",
       [$host=src],
       [$str=cat(dst)]);
    }

## SSH 세션 종료 시점에 최종 conn 상태로 "성립 여부" 판정 -> 확산 관측.
##   connection_state_remove 는 연결 종료 시 1회 발화(최종 conn_state/bytes 확정).
event connection_state_remove(c: connection)
    {
    # SSH(22/tcp)만 대상
    if ( c$id$resp_p != 22/tcp )
        return;

    # "세션 성립" 판정: conn_state(c$conn) 는 connection_state_remove 시점에
    #   아직 안 채워졌을 수 있어(우선순위 의존) 사용하지 않는다. 대신 엔드포인트
    #   바이트로 직접 판정 -> 양방향 실데이터 교환 = 정상 세션(스캔/거부는 한쪽이 0).
    if ( ! c?$orig || ! c?$resp )
        return;
    if ( c$orig$size < ssh_lm_min_orig_bytes )   # 클라->서버 최소 바이트
        return;
    if ( c$resp$size <= 0 )                        # 서버 응답 없음 = 미성립(스캔/거부)
        return;
    if ( ! c?$duration || c$duration < ssh_lm_min_duration )
        return;

    observe_ssh(c);
    }
