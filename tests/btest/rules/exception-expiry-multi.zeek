# @TEST-DOC: 예외 엔진 — 같은 확인 주기에 예외 두 개가 실행 중 만료되면 둘 다 kind=expired 행을 남긴다(전에는 첫 번째만 남고 나머지는 Manager 에 만료가 전해지지 않았다)
# @TEST-EXEC: python3 mk.py
# @TEST-EXEC: zeek $PKG $SETUP %INPUT NSM::exception_file=exc.tsv
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=expired exception_id=E-a
# @TEST-EXEC: assert-rows nsm_exception.log eq 1 kind=expired exception_id=E-b
# @TEST-EXEC: assert-rows nsm_exception.log eq 0 kind=expired exception_id=E-c

redef exit_only_after_terminate = T;
redef NSM::exception_stats_interval = 1sec;

global stop: event();
event stop() { terminate(); }
event zeek_init() { schedule 7sec { stop() }; }

@TEST-START-FILE mk.py
import time
t = time.time() + 3          # 시작 뒤 3초에 둘 다 만료(시작할 때는 유효)
rows = [("E-a", t), ("E-b", t), ("E-c", t + 3600)]
with open("exc.tsv", "w") as f:
    f.write("#fields\tid\tscope\tsrc\tdst\tdst_port\tservice\tdomain\tja4\tdisposition\treason\towner\texpires\tref\n")
    for i, (eid, exp) in enumerate(rows):
        f.write("%s\tEncrypted_C2\t-\t93.184.215.%d/32\t-\t-\t-\t-\t-\t시험\tkim\t%.1f\t-\n" % (eid, 30 + i, exp))
@TEST-END-FILE
