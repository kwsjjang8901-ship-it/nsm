module NSM;

export {
    redef record Notice::Info += {
        attack: string &optional &log;
    };

    # 기법 값은 main.zeek 의 rule_registry 에 있다(NSM::rule_technique).
}

hook Notice::policy(n: Notice::Info)
    {
    if ( n?$attack )
        return;
    local t = rule_technique(n$note);
    if ( t != "" )
        n$attack = t;
    }
