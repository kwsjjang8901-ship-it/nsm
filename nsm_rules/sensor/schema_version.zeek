##! 로그 스키마 버전. schema/build.py 가 schema/logs 의 내용으로 만든다(직접 고치지 않는다).

module NSM;

export {
    ## schema/logs/**.schema.json 내용의 SHA-256 앞 12자리. 로그 형식이 바뀌면 값이 바뀐다.
    ##   Manager 는 센서 상태 로그의 이 값으로 해석할 스키마를 고른다(같은 값의 schema/logs 를 쓴다).
    const schema_version = "d19cbc1a2571";
}
