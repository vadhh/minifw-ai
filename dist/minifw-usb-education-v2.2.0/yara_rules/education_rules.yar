rule EducationVpnProxy
{
    meta:
        category    = "education_vpn_proxy"
        severity    = "high"
        description = "Detects VPN and proxy beaconing used to bypass school content filters"
        author      = "MiniFW-AI"

    strings:
        $vpn1    = "nordvpn-bypass"  nocase
        $vpn2    = "vpn-tunnel-free" nocase
        $vpn3    = "hidemyass"       nocase
        $vpn4    = "proxysite"       nocase
        $vpn5    = "ultrasurf"       nocase
        $vpn6    = "psiphon"         nocase
        $bypass1 = "-bypass.proxy"   nocase
        $bypass2 = "vpn-bypass"      nocase
        $bypass3 = ".bypass.cc"      nocase

    condition:
        any of them
}

rule EducationSafeSearchBypass
{
    meta:
        category    = "education_safesearch_bypass"
        severity    = "high"
        description = "Detects SafeSearch circumvention and proxy search engine usage"
        author      = "MiniFW-AI"

    strings:
        $search1 = "safesearch-bypass" nocase
        $search2 = "unfiltered-search" nocase
        $search3 = "nosafesearch"       nocase
        $proxy1  = "startpage-proxy"    nocase
        $proxy2  = "searx.proxy"        nocase

    condition:
        any of them
}

rule EducationContentFilter
{
    meta:
        category    = "education_content_filter"
        severity    = "medium"
        description = "Detects content-filter evasion tools and bypass redirect domains"
        author      = "MiniFW-AI"

    strings:
        $filter1 = "filter-bypass.student" nocase
        $filter2 = "unblock-sites.school"  nocase
        $filter3 = "bypass-filter"         nocase
        $tiktok1 = "tiktok-proxy"          nocase
        $tiktok2 = "tiktok-unblock"        nocase
        $adult1  = "adult-content.proxy"   nocase

    condition:
        any of them
}
