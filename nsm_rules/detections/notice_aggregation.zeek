@load ./evidence_log

module NSM;

export {
    ## 동일 이벤트 집계 윈도우 (X분, 설정 가능). 예: 1min.
    const dedup_window = 1min &redef;

    ## 집계를 적용할 Notice 타입. 비어 있으면 "전체 notice" 에 적용.
    ## 특정 타입만 묶으려면: redef NSM::dedup_notes += { NSM::SMB_Admin_Share };
    const dedup_notes: set[Notice::Type] = {} &redef;

    ## 첫 건 즉시 발화 여부(위 모드 설명 참고). 기본 T(지연 없음).
    const dedup_emit_first = T &redef;

    ## notice.log 에 발생 횟수를 표시하는 컬럼.
    redef record Notice::Info += {
        dup_count: count &optional &log;
    };

    ## "완전히 동일" 판정 시그니처. 기본: note + 4-tuple(or src) + sub.
    ## msg 까지 포함해 더 엄격히 보려면 site 정책에서 redef 하세요.
    global dedup_signature: function(n: Notice::Info): string =
        function(n: Notice::Info): string
            {
            local key = cat(n$note);
            if ( n?$id )
                key = cat(key, "|", n$id$orig_h, "|", n$id$resp_h, "|", n$id$resp_p);
            else if ( n?$src )
                key = cat(key, "|", n$src);
            if ( n?$sub )
                key = cat(key, "|", n$sub);
            return key;
            };
}

## 윈도우별 집계 상태(요약 발화에 필요한 대표 필드 보관)
type DedupState: record {
    cnt:   count          &default=0;
    note:  Notice::Type;
    msg:   string         &default="";
    sub:   string         &optional;
    src:   addr           &optional;
    id:    conn_id        &optional;
    evidence_id: string   &optional;   # 증적 링크(요약 notice 로 전파)
};

## 윈도우 종료 시 호출: 발생 횟수를 담은 요약 notice 1건 발화 후 항목 삭제.
function dedup_expire(t: table[string] of DedupState, idx: string): interval
    {
    local st = t[idx];

    # emit_first 모드에서 단건(중복 없음)이면 이미 첫 건이 나갔으므로 요약 생략
    if ( dedup_emit_first && st$cnt <= 1 )
        return 0secs;

    local info: Notice::Info = [$note=st$note, $dup_count=st$cnt];
    info$msg = fmt("%s [duplicate event x%d in %s]", st$msg, st$cnt, dedup_window);
    if ( st?$sub ) info$sub = st$sub;
    if ( st?$src ) info$src = st$src;
    if ( st?$id )  info$id  = st$id;
    if ( st?$evidence_id ) info$evidence_id = st$evidence_id;

    NOTICE(info);   # dup_count 가 설정돼 있어 아래 훅에서 재집계되지 않음
    return 0secs;   # 항목 삭제
    }

## 시그니처별 윈도우 카운트. create_expire 로 "최초 발생 후 X분" 고정 윈도우.
global dedup_tbl: table[string] of DedupState
    &create_expire = dedup_window
    &expire_func   = dedup_expire;

## 기본 정책(우선순위 0)들이 actions 를 채운 뒤 실행되도록 낮은 우선순위 사용.
hook Notice::policy(n: Notice::Info) &priority=-5
    {
    # 요약 notice 자신(dup_count 설정됨)은 재집계 대상에서 제외
    if ( n?$dup_count )
        return;

    # 적용 대상 필터(비어 있으면 전체)
    if ( |dedup_notes| > 0 && n$note !in dedup_notes )
        return;

    local sig = dedup_signature(n);

    # 이 레이어가 dedup 을 전담하도록 프레임워크 자체 suppression 은 비활성화
    n$suppress_for = 0secs;

    if ( sig !in dedup_tbl )
        {
        # 윈도우 내 첫 발생
        local st: DedupState = [$note=n$note, $cnt=1];
        if ( n?$msg ) st$msg = n$msg;
        if ( n?$sub ) st$sub = n$sub;
        if ( n?$src ) st$src = n$src;
        if ( n?$id )  st$id  = n$id;
        if ( n?$evidence_id ) st$evidence_id = n$evidence_id;
        dedup_tbl[sig] = st;

        if ( ! dedup_emit_first )
            {
            # 보류 모드: 첫 건도 로깅/액션 제거(요약만 발화)
            delete n$actions[Notice::ACTION_LOG];
            delete n$actions[Notice::ACTION_ALARM];
            delete n$actions[Notice::ACTION_EMAIL];
            }
        # emit_first 모드면 첫 건은 그대로 통과(정상 발화)
        }
    else
        {
        # 2번째 이후: 카운트만 누적하고 로깅/액션 제거(묶음 처리)
        ++dedup_tbl[sig]$cnt;
        delete n$actions[Notice::ACTION_LOG];
        delete n$actions[Notice::ACTION_ALARM];
        delete n$actions[Notice::ACTION_EMAIL];
        }
    }
