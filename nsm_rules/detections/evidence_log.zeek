##! ============================================================================
##! 증적(Evidence) 전용 로그 스트림
##!
##! 설계 의도
##!   - notice.log = "탐지됐다"(dedup 된 인덱스), evidence.log = 그 탐지의 근거 레코드.
##!   - 둘은 evidence_id 로 연결한다.
##!       * 단일 연결 탐지     -> evidence_id = uid (연결 그 자체가 key)
##!       * 집계형(SumStats) 탐지 -> evidence_id = 그룹키로 결정적 계산한 합성 문자열
##!   - DC-3 컨텍스트(WHO/WHAT/WHEN/WHERE/HOW)를 구조화 컬럼으로 직접 설계.
##!   - 원본(conn/dce_rpc/smb/kerberos/dns)·추출 파일은 uid/fuid 로 다시 조인.
##!
##! 적재 시점 (2026-09 개정)
##!   - 단일 연결형 : notice 발화 지점에서 1건.
##!   - 집계형      : threshold_crossed / epoch_result(=탐지 시점)에서 표본 근거를
##!                   적재한다. evidence_id 를 그 자리에서 1회만 생성해 notice 와
##!                   같은 값을 쓰므로, 관측 시점과 탐지 시점의 time_bucket 이
##!                   어긋나 조회가 깨지던 문제가 구조적으로 제거된다.
##!   - 반드시 write_evidence() 를 NOTICE() 보다 먼저 호출한다
##!     (detection_log 가 evidence_count 를 그 시점에 읽는다).
##! ============================================================================

@load base/frameworks/logging
@load base/frameworks/notice
@load ./main

module NSM;

export {
    redef enum Log::ID += { EVIDENCE_LOG };

    ## 증적 1행의 스키마. 모든 필드 &log 이며, 알 수 없는 값은 생략(&optional).
    type EvidenceInfo: record {
        ts:          time         &log;            # WHEN
        evidence_id: string       &log;            # 상관 key (notice 와 공유)
        note:        Notice::Type &log &optional;  # 어떤 탐지에서 나온 근거인지
        killchain_stage: string   &log &optional;  # 킬체인 단계명(note 로 매핑, detection_log 와 동일 체계)
        technique:   string       &log &optional;  # WHAT  (ATT&CK 기법코드)
        account:     string       &log &optional;  # WHO   (가능할 때만)
        src:         addr         &log &optional;  # WHERE (출발)
        dst:         addr         &log &optional;  # WHERE (대상)
        operation:   string       &log &optional;  # HOW   (행위/오퍼레이션)
        uid:         string       &log &optional;  # 연결 조인 key (conn.log 등)
        fuid:        string       &log &optional;  # 파일 조인 key (files.log 등)
        parent_id:   string       &log &optional;  # 상관 행이 묶는 하위 evidence_id(쉼표 구분)
        detail:      string       &log &optional;  # 부가 컨텍스트
    };

    ## notice <-> evidence 연결 컬럼. (attack 컬럼과 동일한 확장 패턴)
    redef record Notice::Info += {
        evidence_id: string &optional &log;
    };

    ## 증적 1건 기록 헬퍼.
    global write_evidence: function(ev: EvidenceInfo);

    ## evidence_id 별 실제 기록 건수. detection 의 evidence_count 산출에 사용한다.
    ##   evidence_id 에 time_bucket 이 포함되므로 창이 바뀌면 자연히 새 키가 된다.
    ##   메모리 보호를 위해 일정 시간 뒤 만료시킨다.
    const evidence_count_expire = 2hr &redef;
    global evidence_counts: table[string] of count
        &create_expire=evidence_count_expire &default=0;

    ## evidence_id 의 누적 기록 건수(없으면 0).
    global evidence_count_of: function(eid: string): count;

    ## evidence_id 별 이미 적재한 항목 집합(중복 적재 방지).
    ##   threshold_series 는 한 창에서 임계치마다 재발화하므로, 같은 표본이
    ##   여러 번 들어와 evidence_count 가 부풀지 않도록 걸러낸다.
    global evidence_seen: table[string] of set[string]
        &create_expire=evidence_count_expire;

    ## (eid, item) 이 처음이면 T 를 돌려주고 기록한다. 두 번째부터는 F.
    global evidence_is_new: function(eid: string, item: string): bool;
}

event zeek_init() &priority=5
    {
    Log::create_stream(NSM::EVIDENCE_LOG, [$columns=EvidenceInfo, $path="evidence"]);
    }

function write_evidence(ev: EvidenceInfo)
    {
    # killchain_stage 미지정 시 note 로 자동 매핑(detection_log 와 동일 체계).
    if ( ! ev?$killchain_stage && ev?$note )
        {
        local stg = NSM::killchain_stage_of(ev$note);
        if ( stg != "" )
            ev$killchain_stage = stg;
        }
    # evidence_id 별 실제 기록 건수 누적(detection 의 evidence_count 산출용)
    if ( ev$evidence_id != "" )
        ++evidence_counts[ev$evidence_id];

    Log::write(NSM::EVIDENCE_LOG, ev);
    }

function evidence_count_of(eid: string): count
    {
    return ( eid in evidence_counts ) ? evidence_counts[eid] : 0;
    }

function evidence_is_new(eid: string, item: string): bool
    {
    if ( eid !in evidence_seen )
        evidence_seen[eid] = set();
    if ( item in evidence_seen[eid] )
        return F;
    add evidence_seen[eid][item];
    return T;
    }
