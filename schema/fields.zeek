##! 로그 스키마 생성용: nsm_rules 를 로드한 Zeek 에서 Manager 로 가는 로그의 필드 정의와 열거값을 JSON 으로 출력한다.
##!   zeek ./nsm_rules ./schema/fields.zeek > fields.json      (schema/build.py 가 이 출력을 읽는다)
##! 탐지에는 쓰지 않는다(nsm_rules 의 __load__ 에 넣지 않음).

module SchemaGen;

type FieldDesc: record {
    name:        string;
    zeek_type:   string;
    optional:    bool;
    has_default: bool;
};

type LogDesc: record {
    log:    string;          # 출력 이름(경로의 마지막 부분, meta/ 는 앞에 붙임)
    fields: vector of FieldDesc;
};

type EnumDesc: record {
    name:   string;
    values: vector of string;
};

# 레코드의 &log 필드를 JSON 출력 이름(중첩은 "a.b")으로 편다.
function flatten(rt: any, prefix: string, out: vector of FieldDesc)
    {
    local fs = record_fields(rt);
    local names: vector of string = vector();
    for ( n in fs )
        names += n;
    # record_fields 는 순서를 보장하지 않으므로 선언 순서는 build.py 가 Zeek 소스 대신 이름순 + 고정 순서로 맞춘다
    for ( _i, n in names )
        {
        local f = fs[n];
        if ( ! f$log )
            next;
        local t = f$type_name;
        if ( /^record / in t )
            {
            flatten(sub(t, /^record /, ""), prefix + n + ".", out);
            next;
            }
        out += FieldDesc($name=prefix + n, $zeek_type=t, $optional=f$optional, $has_default=f?$default_val);
        }
    }

function log_desc(name: string, id: Log::ID, include: set[string]): LogDesc
    {
    # columns 는 레코드 타입 값(any). record_fields 는 타입 값도 받는다.
    local all: vector of FieldDesc = vector();
    flatten(Log::active_streams[id]$columns, "", all);
    local out: vector of FieldDesc = vector();
    for ( _i, f in all )
        if ( |include| == 0 || f$name in include )
            out += f;
    return LogDesc($log=name, $fields=out);
    }

event zeek_init() &priority=-100
    {
    local none: set[string] = set();
    local logs: vector of LogDesc = vector();
    logs += log_desc("nsm_detection", NSM::DETECTION_LOG, none);
    logs += log_desc("evidence", NSM::EVIDENCE_LOG, none);
    logs += log_desc("nsm_exception", NSM::EXCEPTION_LOG, none);
    logs += log_desc("nsm_ioc", NSM::IOC_LOG, none);
    logs += log_desc("nsm_sensor", NSM::SENSOR_LOG, none);
    logs += log_desc("asset_signal", AssetID::LOG, none);
    logs += log_desc("asset_agent_policy", AssetID::POLICY_LOG, none);
    logs += log_desc("meta/meta_export_stats", NSM::META_STATS_LOG, none);
    logs += log_desc("meta/flow_summary", NSM::META_FLOW_LOG, none);
    logs += log_desc("meta/dns_summary", NSM::META_DNS_LOG, none);
    logs += log_desc("meta/http_ua_summary", NSM::META_UA_LOG, none);
    for ( id, spec in NSM::meta_export_streams )
        {
        if ( spec$summary || id !in Log::active_streams )
            next;
        logs += log_desc("meta/" + spec$name, id, spec?$fields ? spec$fields : none);
        }

    local enums: vector of EnumDesc = vector();
    local rules: vector of string = vector();
    local diags: vector of string = vector();
    for ( n, dg in NSM::diagnosis_map )
        {
        rules += sub(cat(n), /^NSM::/, "");
        diags += dg;
        }
    enums += EnumDesc($name="rule", $values=rules);
    enums += EnumDesc($name="diagnosis", $values=diags);
    local stages: set[string] = set();
    for ( _n, sn in NSM::stage_name_map )
        add stages[sn];
    local sv: vector of string = vector();
    for ( s in stages )
        sv += s;
    enums += EnumDesc($name="killchain_stage", $values=sv);
    local tv: vector of string = vector();
    for ( tn in enum_names(transport_proto) )
        tv += tn;
    enums += EnumDesc($name="transport_proto", $values=tv);
    # 자산 신호 종류: AssetID 모듈의 대문자 문자열 상수(MACHINE_ACCOUNT = "machine_account" 등)
    local sig: vector of string = vector();
    for ( gid, info in global_ids() )
        if ( /^AssetID::[A-Z][A-Z_]*$/ in gid && info$constant && info$type_name == "string" && info?$value )
            {
            local v = cat(info$value);
            if ( /^[a-z][a-z_]*$/ in v )
                sig += v;
            }
    enums += EnumDesc($name="asset_signal", $values=sig);

    print to_json([$logs=logs, $enums=enums]);
    terminate();
    }
