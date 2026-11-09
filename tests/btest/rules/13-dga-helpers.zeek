# @TEST-DOC: 13 DGA 헬퍼 단위 테스트 — 등록 라벨/부모 도메인 추출, 라벨 무작위성 점수, is_dga_like
# @TEST-EXEC: zeek $PKG $SETUP %INPUT > out
# @TEST-EXEC: cat out && grep -q '^checked ' out && ! grep -q FAIL out
#
# 기대값은 tests/ 의 파이썬 복제 구현과 동일 규칙으로 계산했다(13_dga.zeek 머리말의 점수 규칙).

global ncheck = 0;
global nfail = 0;

function eq_s(what: string, got: string, want: string)
    {
    ++ncheck;
    if ( got != want ) { ++nfail; print fmt("FAIL %s: got=%s want=%s", what, got, want); }
    }

function eq_c(what: string, got: count, want: count)
    {
    ++ncheck;
    if ( got != want ) { ++nfail; print fmt("FAIL %s: got=%d want=%d", what, got, want); }
    }

function eq_b(what: string, got: bool, want: bool)
    {
    ++ncheck;
    if ( got != want ) { ++nfail; print fmt("FAIL %s: got=%s want=%s", what, got, want); }
    }

event zeek_init()
    {
    eq_s("registered_label(www.example.com)", NSM::registered_label("www.example.com"), "example");
    eq_s("registered_label(a.b.Example.CO.KR.)", NSM::registered_label("a.b.Example.CO.KR."), "example");
    eq_s("registered_label(example)", NSM::registered_label("example"), "example");
    eq_s("registered_label(naver.com)", NSM::registered_label("naver.com"), "naver");
    eq_s("registered_label(x.y.naver.co.kr)", NSM::registered_label("x.y.naver.co.kr"), "naver");
    eq_s("registered_label(foo.bar.co.uk)", NSM::registered_label("foo.bar.co.uk"), "bar");
    eq_s("registered_label(co.kr)", NSM::registered_label("co.kr"), "co");
    eq_s("parent_domain(a.b.example.com)", NSM::parent_domain("a.b.example.com"), "example.com");
    eq_s("parent_domain(x.y.naver.co.kr)", NSM::parent_domain("x.y.naver.co.kr"), "naver.co.kr");
    eq_s("parent_domain(example.com)", NSM::parent_domain("example.com"), "example.com");
    eq_s("parent_domain(q.example.CO.KR)", NSM::parent_domain("q.example.CO.KR"), "example.CO.KR");
    eq_c("dga_label_score(google)", NSM::dga_label_score("google"), 0);
    eq_c("dga_label_score(microsoft)", NSM::dga_label_score("microsoft"), 1);
    eq_c("dga_label_score(naver)", NSM::dga_label_score("naver"), 0);
    eq_c("dga_label_score(wpad)", NSM::dga_label_score("wpad"), 0);
    eq_c("dga_label_score(dc01)", NSM::dga_label_score("dc01"), 0);
    eq_c("dga_label_score(printsrv01)", NSM::dga_label_score("printsrv01"), 4);
    eq_c("dga_label_score(xjwkqpzlrm)", NSM::dga_label_score("xjwkqpzlrm"), 3);
    eq_c("dga_label_score(qzkxvbnmtr)", NSM::dga_label_score("qzkxvbnmtr"), 3);
    eq_c("dga_label_score(a1b2c3d4e5f6)", NSM::dga_label_score("a1b2c3d4e5f6"), 4);
    eq_c("dga_label_score(3f9a0c7e12bd)", NSM::dga_label_score("3f9a0c7e12bd"), 4);
    eq_c("dga_label_score(kbstar)", NSM::dga_label_score("kbstar"), 3);
    eq_c("dga_label_score(desktop)", NSM::dga_label_score("desktop"), 1);
    eq_c("dga_label_score(mailportal)", NSM::dga_label_score("mailportal"), 0);
    eq_c("dga_label_score(backupserver)", NSM::dga_label_score("backupserver"), 1);
    eq_c("dga_label_score(xkqzvbnmplrtwhgd)", NSM::dga_label_score("xkqzvbnmplrtwhgd"), 4);
    eq_b("is_dga_like(www.google.com)", NSM::is_dga_like("www.google.com"), F);
    eq_b("is_dga_like(xjwkqpzlrm.com)", NSM::is_dga_like("xjwkqpzlrm.com"), T);
    eq_b("is_dga_like(www.qzkxvbnm.co.kr)", NSM::is_dga_like("www.qzkxvbnm.co.kr"), T);
    eq_b("is_dga_like(3f9a0c7e12bd.net)", NSM::is_dga_like("3f9a0c7e12bd.net"), T);
    eq_b("is_dga_like(mailportal.com)", NSM::is_dga_like("mailportal.com"), F);
    eq_b("is_dga_like(r3---sn-ab5l6nrs.googlevideo.com)", NSM::is_dga_like("r3---sn-ab5l6nrs.googlevideo.com"), F);
    print fmt("checked %d failed %d", ncheck, nfail);
    }
