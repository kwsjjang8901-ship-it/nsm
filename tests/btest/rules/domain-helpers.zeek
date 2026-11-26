# @TEST-DOC: 도메인 공용 함수 — 등록 도메인·등록 라벨(공용 접미사 목록, 국가 2단계 com.vn·co.th, 클라우드·동적 DNS 접미사), 12 클라우드 저장 서비스 판정(이름 전체 비교, S3·Blob·Drive 만, 일반 AWS·Google API 는 아님)과 서비스 이름
# @TEST-EXEC: zeek $PKG $SETUP %INPUT > out
# @TEST-EXEC: btest-diff out

module NSM;

event zeek_init() &priority=-10
	{
	for ( _i, n in vector("www.example.com", "x.y.naver.co.kr", "www.shop.com.vn", "mail.corp.co.th",
	                     "a.b.c.example.io", "x.evil.duckdns.org", "d111abcdef8.cloudfront.net",
	                     "bucket.s3.us-west-2.amazonaws.com", "app1.azurewebsites.net", "acct.blob.core.windows.net",
	                     "example.co", "news.net.io", "co.kr", "localhost", "Mixed.Example.COM") )
		print fmt("%-36s parent=%-28s label=%s", n, parent_domain(n), registered_label(n));
	for ( _j, h in vector("uploads.dropboxapi.com", "www.dropbox.com", "dropbox.com.mirror.example.net",
	                     "nsm-bucket.s3.us-west-2.amazonaws.com", "s3-eu-west-1.amazonaws.com", "nsm.s3-accelerate.amazonaws.com",
	                     "logs.us-east-1.amazonaws.com", "ec2-1-2-3-4.compute-1.amazonaws.com",
	                     "fcm.googleapis.com", "www.googleapis.com", "bucket.storage.googleapis.com", "drive.google.com",
	                     "acct.blob.core.windows.net", "corp-my.sharepoint.com", "API.Box.com", "notbox.com") )
		print fmt("%-40s cloud=%s svc=%s", h, cloud_hosts == to_lower(h) ? "T" : "F", cloud_service(h));
	}
