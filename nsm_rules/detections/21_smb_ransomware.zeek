##! ============================================================================
##! [21] 랜섬웨어성 SMB 파일 변경 — T1486 (2026-11 신규, 킬체인 Impact 단계)
##!
##! 탐지 원리 (파일 서버로 향한 SMB2, 출발지 단위 ransomware_interval 창)
##!   - 확장자 변경 이름 바꾸기: 원본 → 암호화본으로 이름을 바꾸며 확장자를 붙이거나 바꾼다
##!       (report.docx → report.docx.lockd). 확장자가 바뀐 rename 의 고유 파일 수를 센다.
##!       Office 저장 과정의 임시 파일(~ 로 시작, .tmp)은 제외.
##!   - 랜섬 노트: 여러 폴더에 같은 안내 파일(README_DECRYPT.txt, HOW_TO_RESTORE.html …)을 만든다.
##!       노트 이름 패턴 파일을 만든 고유 폴더 수를 센다.
##!   - 둘 중 하나라도 임계에 닿으면 즉시 탐지(창당 1건). 표본 파일명을 근거로 남긴다.
##!
##! 오탐 통제: 백업·동기화·DLP·아카이빙 서버는 대량 rename 을 하므로 ransomware_allowlist 에 등록.
##!
##! 상관 계약: notice $src = 파일을 바꾼 출발지(감염 host), $lm_targets = 파일 서버 집합.
##! ============================================================================

@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/protocols/smb
@load ./main
@load ./evidence_log
@load ./exceptions
@load ./auth_context

module NSM;

export {
    const ransomware_interval         = 1min &redef;  # 집계 윈도우
    const ransomware_rename_threshold = 30   &redef;  # 확장자가 바뀐 rename 고유 파일 수
    const ransomware_note_threshold   = 5    &redef;  # 랜섬 노트를 만든 고유 폴더 수

    ## 랜섬 노트 파일명(마지막 경로 요소, 소문자 기준)
    const ransomware_note_names =
        /^(readme|read_me|how_to|howto|help|restore|recover|decrypt|unlock|!).*(decrypt|restore|recover|unlock|files|readme|instruction|ransom).*\.(txt|html?|hta|rtf)$/
      | /^(decrypt|restore|recover|unlock)[-_ ]?(files|instructions|my_files)?.*\.(txt|html?|hta)$/
      &redef;

    ## 예외 출발지(백업·동기화·DLP·아카이빙 서버).
    const ransomware_allowlist: set[subnet] = {} &redef;
}

## 파일명(경로 포함)에서 마지막 요소
function smb_basename(path: string): string
    {
    local parts = split_string(path, /[\\\/]/);
    return |parts| > 0 ? parts[|parts| - 1] : path;
    }

## 마지막 요소의 확장자(소문자, 없으면 "")
function smb_extension(path: string): string
    {
    local base = to_lower(smb_basename(path));
    local dot = split_string(base, /\./);
    return |dot| > 1 ? dot[|dot| - 1] : "";
    }

## 경로의 폴더 부분
function smb_dirname(path: string): string
    {
    local base = smb_basename(path);
    return |path| > |base| ? sub_bytes(path, 1, |path| - |base| - 1) : "";
    }

## Office 등의 저장 과정 임시 파일
function smb_temp_file(path: string): bool
    {
    local base = to_lower(smb_basename(path));
    return /^~/ in base || /\.tmp$/ in base;
    }

event zeek_init()
    {
    # rename: 고유 파일 / note: 고유 폴더 / sample: "종류|서버|내용" 근거 표본
    local r_ren  = SumStats::Reducer($stream="nsm.ransom.rename", $apply=set(SumStats::UNIQUE));
    local r_note = SumStats::Reducer($stream="nsm.ransom.note", $apply=set(SumStats::UNIQUE));
    local r_smp  = SumStats::Reducer($stream="nsm.ransom.sample", $apply=set(SumStats::SAMPLE),
                                     $num_samples=lm_num_samples);
    SumStats::create([
        $name      = "nsm-detect-smb-ransomware",
        $epoch     = ransomware_interval,
        $reducers  = set(r_ren, r_note, r_smp),
        # 두 신호를 각자 임계로 나눈 비율의 최댓값이 1 이상이면 탐지
        $threshold = 1.0,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            local ren  = "nsm.ransom.rename" in result ? result["nsm.ransom.rename"]$unique : 0;
            local note = "nsm.ransom.note" in result ? result["nsm.ransom.note"]$unique : 0;
            local a = ren / (ransomware_rename_threshold + 0.0);
            local b = note / (ransomware_note_threshold + 0.0);
            return a > b ? a : b;
            },
        $epoch_result=sumstats_epoch_noop,   # epoch 마다 임계 판정을 초기화(main.zeek 설명)
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local ren  = "nsm.ransom.rename" in result ? result["nsm.ransom.rename"]$unique : 0;
            local note = "nsm.ransom.note" in result ? result["nsm.ransom.note"]$unique : 0;
            local eid = cat(key$host, "|smb-ransomware|", time_bucket(ransomware_interval));
            local servers: set[addr] = set();

            # 근거를 NOTICE 보다 먼저 적재한다.
            if ( "nsm.ransom.sample" in result && result["nsm.ransom.sample"]?$samples )
                for ( i in result["nsm.ransom.sample"]$samples )
                    {
                    local o = result["nsm.ransom.sample"]$samples[i];
                    if ( ! o?$str )
                        next;
                    local p = split_string(o$str, /\|/);
                    if ( |p| < 3 )
                        next;
                    add servers[to_addr(p[1])];
                    if ( ! NSM::evidence_is_new(eid, cat(p[0], "|", p[1], "|", p[2])) )
                        next;
                    NSM::write_evidence([
                        $ts=network_time(),
                        $evidence_id=eid,
                        $note=SMB_Ransomware,
                        $technique="T1486",
                        $src=key$host,
                        $dst=to_addr(p[1]),
                        $uid=( |p| > 3 ) ? p[3] : "",
                        $account=NSM::auth_accounts(key$host, to_addr(p[1]), set("cifs", "host")),
                        $operation=p[0] == "rename" ? "smb_rename_extension_change" : "smb_ransom_note_create",
                        $detail=fmt("%s renamed_files=%d note_dirs=%d window=%s",
                                    p[2], ren, note, ransomware_interval)]);
                    }

            NOTICE([$note=SMB_Ransomware,
                    $src=key$host,
                    $msg=fmt("Possible ransomware activity over SMB: %s renamed %d files with extension change, created ransom notes in %d folders in %s",
                             key$host, ren, note, ransomware_interval),
                    $sub=fmt("renamed_files=%d note_dirs=%d", ren, note),
                    $identifier=cat(key$host, "smb-ransomware"),
                    $suppress_for=1hr,
                    $evidence_id=eid,
                    $lm_targets=servers]);
            }
    ]);
    }

# 기존 redef 예외 목록을 예외 엔진에 drop 예외로 등록한다(호환).
event zeek_init()
    {
    if ( |ransomware_allowlist| > 0 )
        NSM::exception_add_legacy("legacy:ransomware_allowlist",
            [$scope=set("SMB_Ransomware"), $src=ransomware_allowlist]);
    }

function ransomware_target(c: connection): bool
    {
    # 예외(예외 파일 + 기존 ransomware_allowlist): 백업·동기화·DLP 서버 등. 집계 전 판정
    return ! NSM::exception_drop_agg(SMB_Ransomware, c);
    }

event smb2_file_rename(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, dst_filename: string)
    {
    # 기본 스크립트(우선순위 5)가 current_file 의 prev_name/name 을 채운 뒤 실행된다.
    if ( ! ransomware_target(c) || ! c?$smb_state || ! c$smb_state?$current_file )
        return;
    local f = c$smb_state$current_file;
    if ( ! f?$prev_name || ! f?$name )
        return;
    if ( smb_temp_file(f$prev_name) || smb_temp_file(f$name) )
        return;
    if ( smb_extension(f$prev_name) == smb_extension(f$name) )
        return;

    local src = c$id$orig_h;
    local fkey = to_lower(cat(c$id$resp_h, ":", f$prev_name));
    SumStats::observe("nsm.ransom.sample", [$host=src],
                      [$str=cat("rename|", c$id$resp_h, "|", f$prev_name, " -> ", smb_basename(f$name), "|", c$uid)]);
    SumStats::observe("nsm.ransom.rename", [$host=src], [$str=fkey]);
    }

event smb2_create_response(c: connection, hdr: SMB2::Header, response: SMB2::CreateResponse)
    {
    if ( hdr$status != 0 || ! ransomware_target(c) || ! c?$smb_state || ! c$smb_state?$current_file )
        return;
    local f = c$smb_state$current_file;
    if ( ! f?$name || ransomware_note_names !in to_lower(smb_basename(f$name)) )
        return;

    local src = c$id$orig_h;
    local share = ( c$smb_state?$current_tree && c$smb_state$current_tree?$path ) ? c$smb_state$current_tree$path : "";
    local dir = to_lower(cat(c$id$resp_h, ":", share, "\\", smb_dirname(f$name)));
    SumStats::observe("nsm.ransom.sample", [$host=src],
                      [$str=cat("note|", c$id$resp_h, "|", f$name, "|", c$uid)]);
    SumStats::observe("nsm.ransom.note", [$host=src], [$str=dir]);
    }
