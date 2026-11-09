redef Log::default_rotation_interval=4hr;

function change_log_path(id: Log::ID, name: string, path: string)
{
    Log::remove_filter(id, "default");
    Log::add_filter(id, [$name=name, $path=path]);
}

function filter_log()
{
    local ids: set[Log::ID];

    for (id in Log::active_streams) {
        add ids[id];
    }

    for (id in ids) {
        Log::disable_stream(id);
    }

    system("mkdir -p /hdd_tmp/log/zeek");
    system("mkdir -p /log/zeek");

    Log::enable_stream(NSM::DETECTION_LOG);
    change_log_path(NSM::DETECTION_LOG, "nsm_detection", "/log/zeek/nsm_detection");

    Log::enable_stream(NSM::EVIDENCE_LOG);
    change_log_path(NSM::EVIDENCE_LOG, "nsm_evidence", "/log/zeek/evidence");

    Log::enable_stream(Notice::LOG);
    change_log_path(Notice::LOG, "notice", "/hdd_tmp/log/zeek/notice");

    Log::enable_stream(CaptureLoss::LOG);
    change_log_path(CaptureLoss::LOG, "captureloss", "/hdd_tmp/log/zeek/capture_loss");

    Log::enable_stream(LoadedScripts::LOG);
    change_log_path(LoadedScripts::LOG, "loadedscripts", "/hdd_tmp/log/zeek/loadedscripts");

    Log::enable_stream(Stats::LOG);
    change_log_path(Stats::LOG, "stats", "/hdd_tmp/log/zeek/stats");
}

event zeek_init() &priority=-1
{
    filter_log();
}