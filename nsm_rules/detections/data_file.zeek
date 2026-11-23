##! 센서가 읽는 데이터 파일(예외·IOC)의 SHA1 지문.
##!
##! Manager 가 배포한 파일과 센서가 실제로 읽은 파일이 같은지 확인하는 데 쓴다(로그 형식 검토 X1).
##! 파일을 다 읽은 뒤(Input::end_of_data) 같은 파일을 파일 분석 프레임워크로 한 번 더 읽어 SHA1 을 계산한다.
##! 파일 내용 그대로의 SHA1 이라 sha1sum 결과와 같다. 다시 읽을 때(REREAD)마다 새로 계산한다.
##! 계산 결과는 NSM::data_file_hashed 이벤트로 알리고, data_file_sha1 에 마지막 값을 둔다(센서 상태 로그용).

@load base/frameworks/files
@load base/frameworks/input
@load base/files/hash

module NSM;

export {
    ## 파일 하나의 SHA1 계산을 요청한다. tag 는 파일 종류(exception, ioc 등).
    global hash_data_file: function(tag: string, path: string);

    ## SHA1 계산이 끝났을 때(빈 파일은 계산하지 않는다)
    global data_file_hashed: event(tag: string, path: string, sha1: string);

    ## 종류별 마지막 SHA1(이 노드가 읽은 파일)
    global data_file_sha1: table[string] of string = table();
}

type DataFileReq: record {
    tag:  string;
    path: string;
};

# 분석 이름 -> 요청. 계산이 끝나면 지운다(파일이 사라져 끝나지 않는 요청은 1시간 뒤 정리).
global df_pending: table[string] of DataFileReq &create_expire=1hr;
# files.log 에 남기지 않을 분석 이름
global df_names: set[string] &create_expire=1hr;
global df_seq = 0;

function hash_data_file(tag: string, path: string)
    {
    if ( path == "" )
        return;
    ++df_seq;
    local nm = fmt("nsm-datafile-%s-%d", tag, df_seq);
    df_pending[nm] = DataFileReq($tag=tag, $path=path);
    add df_names[nm];
    Input::add_analysis([$source=path, $name=nm]);
    }

event file_new(f: fa_file)
    {
    if ( f?$source && f$source in df_pending )
        Files::add_analyzer(f, Files::ANALYZER_SHA1);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind != "sha1" || ! f?$source || f$source !in df_pending )
        return;
    local req = df_pending[f$source];
    delete df_pending[f$source];
    data_file_sha1[req$tag] = hash;
    event NSM::data_file_hashed(req$tag, req$path, hash);
    }

# 데이터 파일 분석은 트래픽에서 나온 파일이 아니므로 files.log 에 쓰지 않는다.
hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
    {
    if ( rec?$source && rec$source in df_names )
        break;
    }
