# dns_summary 출발지별 도메인 행 상한 검사용: 상한 1 -> 두 번째 도메인부터 "(other)" 행
redef NSM::meta_domain_allowlist += { "vendor.example" };
redef NSM::dns_tunnel_resolvers += { 10.0.0.54 };
redef NSM::meta_dns_max_domains_per_src = 1;
