##! 센서 버전 정보(센서 상태 로그 nsm_sensor.log 에 남는다).

@load ./schema_version   # schema_version: schema/build.py 가 만든다

module NSM;

export {
    ## nsm_rules 패키지 버전. 릴리스할 때 올린다. Manager 의 엔진 업데이트 화면이 이 값을 보여 준다.
    const pkg_version = "0.1.0" &redef;
}
