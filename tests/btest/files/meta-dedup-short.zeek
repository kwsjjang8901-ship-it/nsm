# ssl 중복 억제 기간을 10분으로 줄인다(나머지 설정은 기본값과 같게)
redef NSM::meta_export_streams += {
    [SSL::LOG] = [$name="ssl", $scope=NSM::META_BOUNDARY, $dedup=10min,
                  $fields=set("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                              "version", "cipher", "server_name", "established", "ja3")],
};
