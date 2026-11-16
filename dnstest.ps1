<#
.SYNOPSIS
    dns-speedtest: DNS, DoT and DoH speed test for Windows PowerShell 5.1 and PowerShell 7.
.DESCRIPTION
    https://github.com/mazixs/dns-speedtest (GPL-3.0)
    irm https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.ps1 | iex
    .\dnstest.ps1 -Modes dot,doh -Yes
    .\dnstest.ps1 -Help
#>
# ASCII only: a UTF-8 BOM breaks "irm | iex", and Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI.
# Russian strings are stored as \uXXXX and decoded at startup.
# The body runs in its own scope so "irm | iex" leaves no variables or functions in the caller's session.
& {
[CmdletBinding()]
param(
    [string[]]$Modes = @(),
    [string]$Providers = 'all',
    [string[]]$Variants = @(),
    [string]$Domains = '',
    [string[]]$CustomDomains = @(),
    [string]$Profile = 'quick',
    [int]$Runs = 0,
    [int]$Top = 0,
    [int]$Timeout = 1,
    [string]$Csv = '',
    [string]$Lang = '',
    [switch]$NoColor,
    [switch]$Yes,
    [switch]$List,
    [switch]$SelfTest,
    [switch]$Version,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$BoundCount = $PSBoundParameters.Count

$ScriptVersion = '4.0.0'
$ProjectUrl = 'https://github.com/mazixs/dns-speedtest'
$DomainsRu = @('ya.ru', 'mail.ru', 'vk.com', 'ozon.ru', 'gosuslugi.ru')
$DomainsGlobal = @('www.google.com', 'www.youtube.com', 'www.wikipedia.org', 'www.amazon.com', 'github.com')
$Root4 = '198.41.0.4'
$Root6 = '2001:503:ba3e::2:30'
$V6Probe = '2606:4700:4700::1111'
$AllModes = @('dns4', 'dns6', 'dot', 'doh')
$IsCore = $PSVersionTable.PSVersion.Major -ge 6
$Inv = [Globalization.CultureInfo]::InvariantCulture
# Shared mutable state: a hashtable is passed by reference, so nested functions can update it.
$G = @{ Msg = @{}; L = 'en'; Color = $true; Rng = (New-Object System.Random); Backend = @{}; Proto = [Security.Authentication.SslProtocols]::None }

# BEGIN CATALOG (must match dnstest.sh)
$Catalog = @'
@cloudflare|Cloudflare|global|plain|anycast
dns4 1.1.1.1
dns6 2606:4700:4700::1111
dot 1.1.1.1 one.one.one.one
doh 1.1.1.1 https://cloudflare-dns.com/dns-query
@cloudflare-security|Cloudflare Security|global|malware|anycast
dns4 1.1.1.2
dns6 2606:4700:4700::1112
dot 1.1.1.2 security.cloudflare-dns.com
doh 1.1.1.2 https://security.cloudflare-dns.com/dns-query
@google|Google|global|plain|anycast
dns4 8.8.8.8
dns6 2001:4860:4860::8888
dot 8.8.8.8 dns.google
doh 8.8.8.8 https://dns.google/dns-query
@google-alt|Google Alt|global|plain|anycast,alt
dns4 8.8.4.4
dns6 2001:4860:4860::8844
dot 8.8.4.4 dns.google
doh 8.8.4.4 https://dns.google/dns-query
@quad9|Quad9|global|malware|anycast
dns4 9.9.9.9
dns6 2620:fe::fe
dot 9.9.9.9 dns.quad9.net
doh 9.9.9.9 https://dns.quad9.net/dns-query
@quad9-alt|Quad9 Alt|global|malware|anycast,alt
dns4 149.112.112.112
dns6 2620:fe::9
dot 149.112.112.112 dns.quad9.net
doh 149.112.112.112 https://dns.quad9.net/dns-query
@quad9-unfiltered|Quad9 Unfiltered|global|plain|anycast
dns4 9.9.9.10
dns6 2620:fe::10
dot 9.9.9.10 dns10.quad9.net
doh 9.9.9.10 https://dns10.quad9.net/dns-query
@adguard|AdGuard|global|adblock|anycast
dns4 94.140.14.14
dns6 2a10:50c0::ad1:ff
dot 94.140.14.14 dns.adguard-dns.com
doh 94.140.14.14 https://dns.adguard-dns.com/dns-query
@adguard-family|AdGuard Family|global|family|anycast
dns4 94.140.14.15
dns6 2a10:50c0::bad1:ff
dot 94.140.14.15 family.adguard-dns.com
doh 94.140.14.15 https://family.adguard-dns.com/dns-query
@cleanbrowsing-family|CleanBrowsing Family|global|family|
dns4 185.228.168.168
dns6 2a0d:2a00:1::
dot 185.228.168.168 family-filter-dns.cleanbrowsing.org
doh 185.228.168.168 https://doh.cleanbrowsing.org/doh/family-filter/
@cleanbrowsing-security|CleanBrowsing Security|global|malware|
dns4 185.228.168.9
dns6 2a0d:2a00:1::2
dot 185.228.168.9 security-filter-dns.cleanbrowsing.org
doh 185.228.168.9 https://doh.cleanbrowsing.org/doh/security-filter/
@controld|ControlD|global|plain|anycast
dns4 76.76.2.0
dns6 2606:1a40::
dot 76.76.2.11 p0.freedns.controld.com
doh 76.76.2.0 https://freedns.controld.com/p0
@controld-malware|ControlD Malware|global|malware|anycast
dns4 76.76.2.1
dns6 2606:1a40::1
dot 76.76.2.11 p1.freedns.controld.com
doh 76.76.2.1 https://freedns.controld.com/p1
@controld-uncensored|ControlD Uncensored|global|plain|anycast
dns4 76.76.2.5
dns6 2606:1a40::5
dot 76.76.2.11 uncensored.freedns.controld.com
doh 76.76.2.5 https://freedns.controld.com/uncensored
@dnssb|DNS.SB|global|plain|anycast
dns4 185.222.222.222
dns6 2a09::
dot 185.222.222.222 dot.sb
doh 185.222.222.222 https://doh.dns.sb/dns-query
@dnssb-alt|DNS.SB Alt|global|plain|anycast,alt
dns4 45.11.45.11
dns6 2a11::
@mullvad|Mullvad|global|plain|encrypted-only
dot 194.242.2.2 dns.mullvad.net
doh 194.242.2.2 https://dns.mullvad.net/dns-query
@gcore|Gcore|global|plain|
dns4 95.85.95.85
dns6 2a03:90c0:999d::1
@gcore-alt|Gcore Alt|global|plain|alt
dns4 2.56.220.2
dns6 2a03:90c0:9992::1
@ultradns|UltraDNS (ex-Verisign)|global|plain|unofficial
dns4 64.6.64.6
@ultradns-alt|UltraDNS Alt|global|plain|unofficial,alt
dns4 64.6.65.6
@dnswatch|DNS.WATCH|global|plain|legacy
dns4 84.200.69.80
dns6 2001:1608:10:25::1c04:b12f
@dnswatch-alt|DNS.WATCH Alt|global|plain|legacy,alt
dns4 84.200.70.40
dns6 2001:1608:10:25::9249:d69b
@safedns|SafeDNS|global|plain|
dns4 195.46.39.39
dns6 2001:67c:2778::3939
@safedns-alt|SafeDNS Alt|global|plain|alt
dns4 195.46.39.40
dns6 2001:67c:2778::3940
@uncensoreddns|UncensoredDNS|global|plain|encrypted-only
dot 91.239.100.100 anycast.uncensoreddns.org
doh 91.239.100.100 https://anycast.uncensoreddns.org/dns-query
@uncensoreddns-unicast|UncensoredDNS Unicast|global|plain|encrypted-only
dot 89.233.43.71 unicast.uncensoreddns.org
doh 89.233.43.71 https://unicast.uncensoreddns.org/dns-query
@opendns|OpenDNS|global|plain|
dns4 208.67.222.222
dns6 2620:119:35::35
dot 208.67.222.222 dns.opendns.com
doh 208.67.222.222 https://dns.opendns.com/dns-query
@opendns-family|OpenDNS FamilyShield|global|family|
dns4 208.67.222.123
dns6 2620:119:35::123
dot 208.67.222.123 familyshield.opendns.com
doh 208.67.222.123 https://familyshield.opendns.com/dns-query
@comodo|Comodo|global|plain|legacy
dns4 8.26.56.26
@comodo-alt|Comodo Alt|global|plain|legacy,alt
dns4 8.20.247.20
@level3|Level3|global|plain|legacy,unofficial
dns4 4.2.2.1
@level3-a|Level3 A|global|plain|legacy,unofficial
dns4 209.244.0.3
@level3-b|Level3 B|global|plain|legacy,unofficial
dns4 209.244.0.4
@nextdns|NextDNS|global|plain|anycast
dns4 45.90.28.0
dns6 2a07:a8c0::
dot 45.90.28.0 dns.nextdns.io
doh 45.90.28.0 https://dns.nextdns.io/
@nextdns-alt|NextDNS Alt|global|plain|anycast,alt
dns4 45.90.30.0
dns6 2a07:a8c1::
dot 45.90.30.0 dns.nextdns.io
doh 45.90.30.0 https://dns.nextdns.io/
@nwpsfi|NWPS.fi|global|adblock|
dns4 95.217.11.63
dns6 2a01:4f9:c012:25a0::1
dot 95.217.11.63 public.ns.nwps.fi
doh 95.217.11.63 https://public.ns.nwps.fi/dns-query
@nwpsfi-kids|NWPS.fi Kids|global|family|
dns4 135.181.103.31
dns6 2a01:4f9:c011:aa31::1
dot 135.181.103.31 kids.ns.nwps.fi
doh 135.181.103.31 https://kids.ns.nwps.fi/dns-query
@yandex|Yandex|ru|plain|
dns4 77.88.8.8
dns6 2a02:6b8::feed:0ff
dot 77.88.8.8 common.dot.dns.yandex.net
doh 77.88.8.8 https://common.dot.dns.yandex.net/dns-query
@yandex-safe|Yandex Safe|ru|malware|
dns4 77.88.8.88
dns6 2a02:6b8::feed:bad
dot 77.88.8.88 safe.dot.dns.yandex.net
doh 77.88.8.88 https://safe.dot.dns.yandex.net/dns-query
@yandex-family|Yandex Family|ru|family|
dns4 77.88.8.7
dns6 2a02:6b8::feed:a11
dot 77.88.8.7 family.dot.dns.yandex.net
doh 77.88.8.7 https://family.dot.dns.yandex.net/dns-query
@comss|Comss.one|ru|adblock|
dns4 212.109.195.93
dot 212.109.195.93 dns.comss.one
doh 212.109.195.93 https://dns.comss.one/dns-query
@comss-alt|Comss.one Alt|ru|adblock|alt
dns4 83.220.169.155
dot 83.220.169.155 dns.comss.one
doh 83.220.169.155 https://dns.comss.one/dns-query
@nsdi|NSDI|ru|plain|unofficial
dns4 195.208.4.1
@nsdi-alt|NSDI Alt|ru|plain|unofficial,alt
dns4 195.208.5.1
@rostelecom|Rostelecom|ru|plain|isp
dns4 91.122.77.189
@mts|MTS|ru|plain|isp
dns4 195.210.172.43
@mts-alt|MTS Alt|ru|plain|isp,alt
dns4 195.210.172.46
@akado|AKADO|ru|plain|isp
dns4 217.10.44.35
'@
# END CATALOG

# key=text; one block per language.
$MsgText = @'
[ru]
error=\u043e\u0448\u0438\u0431\u043a\u0430
shell=\u0448\u0435\u043b\u043b
timer=\u0442\u0430\u0439\u043c\u0435\u0440
transport=\u0442\u0440\u0430\u043d\u0441\u043f\u043e\u0440\u0442
domains=\u0434\u043e\u043c\u0435\u043d\u044b
rounds=\u0440\u0430\u0443\u043d\u0434\u043e\u0432
targets=\u0446\u0435\u043b\u0435\u0439
hijack=\u043f\u0435\u0440\u0435\u0445\u0432\u0430\u0442 UDP/53
yes=\u0435\u0441\u0442\u044c
no=\u043d\u0435\u0442
unknown=\u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c
none=\u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d
hijack_warn=\u041f\u043e\u0440\u0442 53 \u043f\u0435\u0440\u0435\u0445\u0432\u0430\u0442\u044b\u0432\u0430\u0435\u0442\u0441\u044f: \u043a\u043e\u0440\u043d\u0435\u0432\u043e\u0439 DNS-\u0441\u0435\u0440\u0432\u0435\u0440, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u043d\u0435 \u0432\u044b\u043f\u043e\u043b\u043d\u044f\u0435\u0442 \u0440\u0435\u043a\u0443\u0440\u0441\u0438\u044e, \u0432\u0435\u0440\u043d\u0443\u043b \u0433\u043e\u0442\u043e\u0432\u044b\u0439 \u043e\u0442\u0432\u0435\u0442. \u0417\u0430\u043c\u0435\u0440\u044b \u043e\u0431\u044b\u0447\u043d\u043e\u0433\u043e DNS \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u044e\u0442 \u043f\u0435\u0440\u0435\u0445\u0432\u0430\u0442\u0447\u0438\u043a (\u0440\u043e\u0443\u0442\u0435\u0440, VPN \u0438\u043b\u0438 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0430), \u0430 \u043d\u0435 \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0435 \u0441\u0435\u0440\u0432\u0435\u0440\u044b. \u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0442\u0435\u0441\u0442 \u043d\u0430 \u0440\u043e\u0443\u0442\u0435\u0440\u0435 \u0438\u043b\u0438 \u043e\u0440\u0438\u0435\u043d\u0442\u0438\u0440\u0443\u0439\u0442\u0435\u0441\u044c \u043d\u0430 DoT \u0438 DoH.
hijack_note=\u043f\u0435\u0440\u0435\u0445\u0432\u0430\u0442: \u0437\u0430\u043c\u0435\u0440 \u043d\u0435\u0434\u043e\u0441\u0442\u043e\u0432\u0435\u0440\u0435\u043d, \u0440\u0435\u0439\u0442\u0438\u043d\u0433 \u043d\u0435 \u0441\u0442\u0440\u043e\u0438\u0442\u0441\u044f
probe=\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u043e\u0441\u0442\u0438
round=\u0420\u0430\u0443\u043d\u0434
c_name=\u041f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440
c_var=\u0412\u0430\u0440\u0438\u0430\u043d\u0442
c_addr=\u0410\u0434\u0440\u0435\u0441
c_med=\u041c\u0435\u0434\u0438\u0430\u043d\u0430
c_p90=p90
c_cold=\u0425\u043e\u043b\u043e\u0434\u043d\u044b\u0439
c_loss=\u041f\u043e\u0442\u0435\u0440\u0438
ms=\u043c\u0441
n_udp=\u041c\u0435\u0434\u0438\u0430\u043d\u0430 \u0438 p90 \u2014 \u0432\u0440\u0435\u043c\u044f \u043e\u0442\u0432\u0435\u0442\u0430 \u043d\u0430 \u0437\u0430\u043f\u0440\u043e\u0441, \u043c\u0441.
n_tls=\u041c\u0435\u0434\u0438\u0430\u043d\u0430 \u0438 p90 \u2014 \u0437\u0430\u043f\u0440\u043e\u0441 \u043f\u043e \u0443\u0436\u0435 \u043e\u0442\u043a\u0440\u044b\u0442\u043e\u043c\u0443 TLS-\u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044e, \u043a\u0430\u043a \u0443 DoT/DoH-\u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u0440\u043e\u0443\u0442\u0435\u0440\u0430. \u00ab\u0425\u043e\u043b\u043e\u0434\u043d\u044b\u0439\u00bb \u2014 \u043d\u043e\u0432\u043e\u0435 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0435 \u0438 \u043f\u0435\u0440\u0432\u044b\u0439 \u0437\u0430\u043f\u0440\u043e\u0441.
n_sys=\u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 \u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440, \u0432 \u0440\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u0430\u0446\u0438\u0438 \u043d\u0435 \u043f\u043e\u043f\u0430\u0434\u0430\u0435\u0442
n_h1=Windows PowerShell 5.1 \u0443\u043c\u0435\u0435\u0442 \u0442\u043e\u043b\u044c\u043a\u043e HTTP/1.1. \u0421\u0435\u0440\u0432\u0435\u0440\u044b, \u043a\u043e\u0442\u043e\u0440\u044b\u043c \u043d\u0443\u0436\u0435\u043d HTTP/2, \u043f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u0432 PowerShell 7 (pwsh).
rec=\u0427\u0442\u043e \u043f\u043e\u0441\u0442\u0430\u0432\u0438\u0442\u044c
norec=\u043d\u0435\u0442 \u043a\u0430\u043d\u0434\u0438\u0434\u0430\u0442\u043e\u0432 \u0431\u0435\u0437 \u043f\u043e\u0442\u0435\u0440\u044c
done=\u0413\u043e\u0442\u043e\u0432\u043e \u0437\u0430
sec=\u0441
csv_saved=CSV \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d
s_timeout=\u043d\u0435\u0442 \u043e\u0442\u0432\u0435\u0442\u0430
s_refused=\u043e\u0442\u043a\u0430\u0437 (REFUSED)
s_servfail=SERVFAIL
s_nxdomain=NXDOMAIN
s_empty=\u043f\u0443\u0441\u0442\u043e\u0439 \u043e\u0442\u0432\u0435\u0442
s_tls=\u043e\u0448\u0438\u0431\u043a\u0430 TLS
s_cert=\u0441\u0435\u0440\u0442\u0438\u0444\u0438\u043a\u0430\u0442 \u043d\u0435 \u043f\u0440\u043e\u0448\u0451\u043b \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0443
s_neterr=\u0441\u0435\u0442\u0435\u0432\u0430\u044f \u043e\u0448\u0438\u0431\u043a\u0430
s_badresp=\u043d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442
s_h2=\u043d\u0443\u0436\u0435\u043d HTTP/2
s_http=HTTP
q_lang=\u042f\u0437\u044b\u043a / Language: 1) \u0420\u0443\u0441\u0441\u043a\u0438\u0439  2) English
q_profile=\u041f\u0440\u043e\u0444\u0438\u043b\u044c: 1) \u0411\u044b\u0441\u0442\u0440\u044b\u0439 \u2014 3 \u0440\u0430\u0443\u043d\u0434\u0430  2) \u0421\u0442\u0430\u0431\u0438\u043b\u044c\u043d\u043e\u0441\u0442\u044c \u2014 10 \u0440\u0430\u0443\u043d\u0434\u043e\u0432
q_domains=\u0414\u043e\u043c\u0435\u043d\u044b: 1) \u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a\u0438\u0435  2) \u0437\u0430\u0440\u0443\u0431\u0435\u0436\u043d\u044b\u0435  3) \u0432\u0441\u0435  4) \u0441\u0432\u043e\u0438
q_custom=\u0414\u043e\u043c\u0435\u043d\u044b \u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043f\u044f\u0442\u0443\u044e
q_providers=\u041f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u044b: 1) \u0432\u0441\u0435  2) \u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a\u0438\u0435  3) \u0437\u0430\u0440\u0443\u0431\u0435\u0436\u043d\u044b\u0435  4) \u0442\u043e\u043b\u044c\u043a\u043e \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 DNS
q_modes=\u0420\u0435\u0436\u0438\u043c\u044b \u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043f\u044f\u0442\u0443\u044e: 1) DNS v4  2) DNS v6  3) DoT  4) DoH
q_default=\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e
u_title=\u0442\u0435\u0441\u0442 \u0441\u043a\u043e\u0440\u043e\u0441\u0442\u0438 DNS, DoT \u0438 DoH
u_run=\u0417\u0430\u043f\u0443\u0441\u043a: .\dnstest.ps1 [\u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b]   \u0431\u0435\u0437 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u043e\u0432 \u0432 \u043a\u043e\u043d\u0441\u043e\u043b\u0438 \u0437\u0430\u0434\u0430\u0451\u0442 \u0432\u043e\u043f\u0440\u043e\u0441\u044b
o_modes=dns4,dns6,dot,doh (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u0432\u0441\u0435)
o_providers=all, ru, global \u0438\u043b\u0438 system (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e all)
o_variants=plain,malware,family,adblock (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u0432\u0441\u0435)
o_domains=ru, global, all \u0438\u043b\u0438 custom (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e ru)
o_custom=\u0441\u0432\u043e\u0438 \u0434\u043e\u043c\u0435\u043d\u044b \u0447\u0435\u0440\u0435\u0437 \u0437\u0430\u043f\u044f\u0442\u0443\u044e (IDN \u2014 \u0432 punycode)
o_profile=quick \u2014 3 \u0440\u0430\u0443\u043d\u0434\u0430, stability \u2014 10 \u0440\u0430\u0443\u043d\u0434\u043e\u0432
o_runs=\u0447\u0438\u0441\u043b\u043e \u0440\u0430\u0443\u043d\u0434\u043e\u0432 \u0432\u043c\u0435\u0441\u0442\u043e \u043f\u0440\u043e\u0444\u0438\u043b\u044f
o_top=\u0441\u0442\u0440\u043e\u043a \u0432 \u0442\u0430\u0431\u043b\u0438\u0446\u0435 \u043a\u0430\u0436\u0434\u043e\u0433\u043e \u0440\u0435\u0436\u0438\u043c\u0430 (0 \u2014 \u0432\u0441\u0435)
o_timeout=\u0442\u0430\u0439\u043c\u0430\u0443\u0442 UDP-\u0437\u0430\u043f\u0440\u043e\u0441\u0430, \u0434\u043b\u044f TLS +2 \u0441 (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e 1)
o_csv=\u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c \u0441\u0432\u043e\u0434\u043a\u0443 \u0432 CSV
o_lang=ru \u0438\u043b\u0438 en (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u044f\u0437\u044b\u043a \u0441\u0438\u0441\u0442\u0435\u043c\u044b)
o_nocolor=\u0431\u0435\u0437 \u0446\u0432\u0435\u0442\u0430
o_yes=\u043d\u0435 \u0437\u0430\u0434\u0430\u0432\u0430\u0442\u044c \u0432\u043e\u043f\u0440\u043e\u0441\u043e\u0432
o_list=\u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u0438 \u0432\u044b\u0439\u0442\u0438
o_selftest=\u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u043a\u043e\u0434\u0438\u0440\u043e\u0432\u0449\u0438\u043a \u0438 \u043f\u0430\u0440\u0441\u0435\u0440 DNS
[en]
error=error
shell=shell
timer=timer
transport=transport
domains=domains
rounds=rounds
targets=targets
hijack=UDP/53 interception
yes=yes
no=no
unknown=cannot check
none=unavailable
hijack_warn=Port 53 is intercepted: a root DNS server, which never recurses, returned a full answer. Plain DNS results reflect the interceptor (router, VPN or ISP), not the selected servers. Run the test on the router or rely on DoT and DoH.
hijack_note=intercepted: results are not reliable, no ranking
probe=Availability check
round=Round
c_name=Provider
c_var=Variant
c_addr=Address
c_med=Median
c_p90=p90
c_cold=Cold
c_loss=Loss
ms=ms
n_udp=Median and p90 are query response times, ms.
n_tls=Median and p90 are queries over an already open TLS connection, as a router DoT/DoH client does. "Cold" is a new connection plus the first query.
n_sys=system resolver, never recommended
n_h1=Windows PowerShell 5.1 only speaks HTTP/1.1. Check servers that need HTTP/2 in PowerShell 7 (pwsh).
rec=What to use
norec=no candidates without losses
done=Done in
sec=s
csv_saved=CSV saved
s_timeout=no response
s_refused=refused
s_servfail=SERVFAIL
s_nxdomain=NXDOMAIN
s_empty=empty answer
s_tls=TLS error
s_cert=certificate check failed
s_neterr=network error
s_badresp=malformed response
s_h2=needs HTTP/2
s_http=HTTP
q_lang=\u042f\u0437\u044b\u043a / Language: 1) \u0420\u0443\u0441\u0441\u043a\u0438\u0439  2) English
q_profile=Profile: 1) Quick \u2014 3 rounds  2) Stability \u2014 10 rounds
q_domains=Domains: 1) Russian  2) global  3) all  4) custom
q_custom=Comma-separated domains
q_providers=Providers: 1) all  2) Russian  3) global  4) system DNS only
q_modes=Comma-separated modes: 1) DNS v4  2) DNS v6  3) DoT  4) DoH
q_default=default
u_title=DNS, DoT and DoH speed test
u_run=Usage: .\dnstest.ps1 [parameters]   asks questions in a console when run without parameters
o_modes=dns4,dns6,dot,doh (default: all)
o_providers=all, ru, global or system (default: all)
o_variants=plain,malware,family,adblock (default: all)
o_domains=ru, global, all or custom (default: ru)
o_custom=comma-separated domains (IDN in punycode)
o_profile=quick \u2014 3 rounds, stability \u2014 10 rounds
o_runs=number of rounds, overrides the profile
o_top=rows per mode table (0 \u2014 all)
o_timeout=UDP query timeout, TLS gets +2 s (default: 1)
o_csv=save the summary as CSV
o_lang=ru or en (default: system language)
o_nocolor=disable colors
o_yes=never ask questions
o_list=print the catalog and exit
o_selftest=check the DNS encoder and parser
'@
$MsgText = [regex]::Replace($MsgText, '\\u([0-9a-fA-F]{4})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) })
$Sep = ' ' + [char]0xB7 + ' '
$Dash = ' ' + [char]0x2014 + ' '

function Set-Lang([string]$Code) {
    $G.L = $Code
    $G.Msg = @{}
    $cur = ''
    foreach ($line in $MsgText -split "`n") {
        $line = $line.TrimEnd("`r")
        if ($line -match '^\[(\w+)\]$') { $cur = $Matches[1]; continue }
        if ($cur -ne $Code -or $line.IndexOf('=') -lt 1) { continue }
        $i = $line.IndexOf('=')
        $G.Msg[$line.Substring(0, $i)] = $line.Substring($i + 1)
    }
}
function T([string]$Key) { $G.Msg[$Key] }

function Out-Text([string]$Text, [string]$Color = '', [switch]$NoNewline) {
    if ($G.Color -and $Color) { Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline }
    else { Write-Host $Text -NoNewline:$NoNewline }
}
function Get-Cut([string]$s, [int]$w) { if ($s.Length -gt $w) { $s.Substring(0, $w - 2) + '..' } else { $s } }
function Format-Ms([double]$us) { ($us / 1000).ToString('0.0', $Inv) }

# ---------------------------------------------------------------------------
# DNS wire format

function Test-Domain([string]$d) {
    if ($d.Length -gt 253 -or $d -cnotmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$') { return $false }
    foreach ($l in $d.Split('.')) { if ($l.Length -gt 63) { return $false } }
    $true
}

function New-Query([string]$Domain, [int]$Id) {
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([byte[]]@((($Id -shr 8) -band 255), ($Id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($l in $Domain.Split('.')) {
        $b.Add([byte]$l.Length)
        $b.AddRange([Text.Encoding]::ASCII.GetBytes($l))
    }
    $b.AddRange([byte[]]@(0, 0, 1, 0, 1))
    , $b.ToArray()
}

# ok | empty | nxdomain | servfail | refused | badresp
function Get-DnsStatus([byte[]]$r, [int]$Id) {
    if ($null -eq $r -or $r.Length -lt 12) { return 'badresp' }
    if (((([int]$r[0]) -shl 8) + $r[1]) -ne $Id) { return 'badresp' }
    if (($r[2] -band 0x80) -eq 0) { return 'badresp' }
    switch ($r[3] -band 15) {
        0 { if (((([int]$r[6]) -shl 8) + $r[7]) -gt 0) { return 'ok' } else { return 'empty' } }
        2 { return 'servfail' }
        3 { return 'nxdomain' }
        5 { return 'refused' }
    }
    'badresp'
}

function ConvertTo-B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-Reason($e) {
    $chain = @()
    while ($e) { $chain += $e; $e = $e.InnerException }
    foreach ($x in $chain) {
        if ($x -is [TimeoutException] -or $x -is [OperationCanceledException]) { return 'timeout' }
        if ($x -is [Net.Sockets.SocketException] -and $x.SocketErrorCode -eq 'TimedOut') { return 'timeout' }
    }
    foreach ($x in $chain) {
        if ($x -is [Security.Authentication.AuthenticationException]) {
            if ($x.Message -eq 'cert' -or $x.Message -match 'certificate') { return 'cert' }
            return 'tls'
        }
    }
    foreach ($x in $chain) { if ($x -is [Net.Sockets.SocketException]) { return 'neterr' } }
    foreach ($x in $chain) { if ($x -is [IO.IOException]) { return 'tls' } }
    'neterr'
}

# ---------------------------------------------------------------------------
# UDP

function Invoke-Udp([string]$Ip, [string]$Domain) {
    $id = $G.Rng.Next(0, 65536)
    $q = New-Query $Domain $id
    $sock = $null
    try {
        $addr = [Net.IPAddress]::Parse($Ip)
        $sock = New-Object Net.Sockets.Socket($addr.AddressFamily, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
        $sock.ReceiveTimeout = $Timeout * 1000
        $sock.Connect($addr, 53)
        $buf = New-Object byte[] 4096
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [void]$sock.Send($q)
        $n = $sock.Receive($buf)
        $us = [long]($sw.Elapsed.TotalMilliseconds * 1000)
        $r = New-Object byte[] $n
        [Array]::Copy($buf, $r, $n)
        @{ Status = (Get-DnsStatus $r $id); Us = $us }
    }
    catch { @{ Status = (Get-Reason $_.Exception); Us = 0 } }
    finally { if ($sock) { $sock.Close() } }
}

# Availability check for all UDP targets at once: send everything, then collect with Socket.Select.
function Invoke-UdpProbe($List, [string]$Domain) {
    $res = @{}
    for ($off = 0; $off -lt $List.Count; $off += 50) {
        $pend = @{}
        foreach ($t in $List[$off..([Math]::Min($off + 49, $List.Count - 1))]) {
            $s = $null
            try {
                $addr = [Net.IPAddress]::Parse($t.Addr)
                $s = New-Object Net.Sockets.Socket($addr.AddressFamily, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
                $s.Connect($addr, 53)
                $id = $G.Rng.Next(0, 65536)
                [void]$s.Send((New-Query $Domain $id))
                $pend[$s] = @{ Key = $t.Key; Id = $id }
            }
            catch { $res[$t.Key] = Get-Reason $_.Exception; if ($s) { $s.Close() } }
        }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $buf = New-Object byte[] 4096
        while ($pend.Count) {
            $left = [long](($Timeout - $sw.Elapsed.TotalSeconds) * 1000000)
            if ($left -le 0) { break }
            $ready = New-Object Collections.ArrayList
            foreach ($s in $pend.Keys) { [void]$ready.Add($s) }
            [Net.Sockets.Socket]::Select($ready, $null, $null, [int]$left)
            foreach ($s in $ready) {
                $p = $pend[$s]
                try {
                    $n = $s.Receive($buf)
                    $r = New-Object byte[] $n
                    [Array]::Copy($buf, $r, $n)
                    $res[$p.Key] = Get-DnsStatus $r $p.Id
                }
                catch { $res[$p.Key] = Get-Reason $_.Exception }
                $s.Close()
                $pend.Remove($s)
            }
        }
        foreach ($s in @($pend.Keys)) { $res[$pend[$s].Key] = 'timeout'; $s.Close() }
    }
    $res
}

# ---------------------------------------------------------------------------
# TLS

function Read-Exact($Stream, [int]$Count) {
    $buf = New-Object byte[] $Count
    $off = 0
    while ($off -lt $Count) {
        $n = $Stream.Read($buf, $off, $Count - $off)
        if ($n -le 0) { throw (New-Object IO.IOException 'closed') }
        $off += $n
    }
    , $buf
}

function Read-Line($Stream) {
    $sb = New-Object Text.StringBuilder
    while ($true) {
        $ch = $Stream.ReadByte()
        if ($ch -lt 0) { throw (New-Object IO.IOException 'closed') }
        if ($ch -eq 10) { break }
        if ($ch -ne 13) { [void]$sb.Append([char]$ch) }
    }
    $sb.ToString()
}

function Open-Tls([string]$Ip, [int]$Port, [string]$HostName) {
    $addr = [Net.IPAddress]::Parse($Ip)
    $tcp = New-Object Net.Sockets.TcpClient($addr.AddressFamily)
    $ms = ($Timeout + 2) * 1000
    try {
        $tcp.NoDelay = $true
        $iar = $tcp.BeginConnect($addr, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms)) { throw (New-Object TimeoutException) }
        $tcp.EndConnect($iar)
        $tcp.ReceiveTimeout = $ms
        $tcp.SendTimeout = $ms
        # The callback runs synchronously inside AuthenticateAsClient and records why the certificate failed.
        $state = @{ Err = 'None' }
        $cb = [Net.Security.RemoteCertificateValidationCallback] {
            param($snd, $cert, $chain, $errs)
            $state.Err = [string]$errs
            $errs -eq [Net.Security.SslPolicyErrors]::None
        }.GetNewClosure()
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
        try { $ssl.AuthenticateAsClient($HostName, $null, $G.Proto, $false) }
        catch [ArgumentException] {
            # .NET Framework before 4.7 cannot take SslProtocols.None (system default).
            $G.Proto = [Security.Authentication.SslProtocols]::Tls12
            $ssl.AuthenticateAsClient($HostName, $null, $G.Proto, $false)
        }
        catch {
            if ($state.Err -ne 'None') { throw (New-Object Security.Authentication.AuthenticationException 'cert') }
            throw
        }
        @{ Tcp = $tcp; Ssl = $ssl }
    }
    catch { $tcp.Close(); throw }
}

function Close-Tls($c) { if ($c) { try { $c.Ssl.Dispose() } catch { }; try { $c.Tcp.Close() } catch { } } }

function Add-Rest($Out, [int]$Total, [string]$Status) {
    while ($Out.Count -lt $Total) { $Out.Add(@{ Phase = $(if ($Out.Count) { 'warm' } else { 'cold' }); Status = $Status; Us = 0 }) }
}

# One TLS connection per session: the first query is cold (TCP + TLS + query), the rest are warm.
function Invoke-DotSession([string]$Ip, [string]$HostName, [string[]]$List) {
    $out = New-Object System.Collections.Generic.List[object]
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $c = $null
    try {
        $c = Open-Tls $Ip 853 $HostName
        foreach ($d in $List) {
            $id = $G.Rng.Next(0, 65536)
            $q = New-Query $d $id
            $pkt = [byte[]](@(($q.Length -shr 8), ($q.Length -band 255)) + $q)
            $t0 = $(if ($out.Count) { $sw.Elapsed.TotalMilliseconds } else { 0 })
            $c.Ssl.Write($pkt, 0, $pkt.Length)
            $c.Ssl.Flush()
            $lb = Read-Exact $c.Ssl 2
            $us = [long](($sw.Elapsed.TotalMilliseconds - $t0) * 1000)
            $r = Read-Exact $c.Ssl ((([int]$lb[0]) -shl 8) + $lb[1])
            $out.Add(@{ Phase = $(if ($out.Count) { 'warm' } else { 'cold' }); Status = (Get-DnsStatus $r $id); Us = $us })
        }
    }
    catch { Add-Rest $out $List.Count (Get-Reason $_.Exception) }
    finally { Close-Tls $c }
    , $out
}

function Split-Url([string]$Url) {
    $u = [Uri]$Url
    @{ Host = $u.Host; Path = $u.AbsolutePath + $u.Query; Sep = $(if ($u.Query) { '&' } else { '?' }) }
}

# PowerShell 7: HttpClient with HTTP/2. The URL points at the catalog IP; SNI, certificate name and Host come from the endpoint.
function Invoke-DohSessionH2([string]$Ip, [string]$Url, [string[]]$List) {
    $out = New-Object System.Collections.Generic.List[object]
    $p = Split-Url $Url
    $ipHost = $(if ($Ip.Contains(':')) { "[$Ip]" } else { $Ip })
    $h = [System.Net.Http.SocketsHttpHandler]::new()
    $h.SslOptions.TargetHost = $p.Host
    $h.ConnectTimeout = [TimeSpan]::FromSeconds($Timeout + 2)
    $client = [System.Net.Http.HttpClient]::new($h)
    $client.Timeout = [TimeSpan]::FromSeconds($Timeout + 2)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("dns-speedtest/$ScriptVersion")
    try {
        foreach ($d in $List) {
            $phase = $(if ($out.Count) { 'warm' } else { 'cold' })
            $req = [System.Net.Http.HttpRequestMessage]::new('GET', "https://$ipHost$($p.Path)$($p.Sep)dns=$(ConvertTo-B64Url (New-Query $d 0))")
            $req.Version = [Version]'2.0'
            if ($req.PSObject.Properties['VersionPolicy']) { $req.VersionPolicy = 'RequestVersionOrLower' }
            $req.Headers.Host = $p.Host
            $req.Headers.Accept.ParseAdd('application/dns-message')
            try {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $r = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                $us = [long]($sw.Elapsed.TotalMilliseconds * 1000)
                $body = $r.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
                $code = [int]$r.StatusCode
                $r.Dispose()
                if ($code -ne 200) { $out.Add(@{ Phase = $phase; Status = "http$code"; Us = 0 }); continue }
                $out.Add(@{ Phase = $phase; Status = (Get-DnsStatus $body 0); Us = $us })
            }
            catch { $out.Add(@{ Phase = $phase; Status = (Get-Reason $_.Exception); Us = 0 }) }
        }
    }
    finally { $client.Dispose() }
    , $out
}

# Windows PowerShell 5.1: .NET Framework has no HTTP/2, so HTTP/1.1 keep-alive over SslStream.
function Invoke-DohSessionH1([string]$Ip, [string]$Url, [string[]]$List) {
    $out = New-Object System.Collections.Generic.List[object]
    $p = Split-Url $Url
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $c = $null
    foreach ($d in $List) {
        $fresh = -not $c
        $phase = $(if ($fresh) { 'cold' } else { 'warm' })
        try {
            $t0 = $sw.Elapsed.TotalMilliseconds
            if ($fresh) { $c = Open-Tls $Ip 443 $p.Host }
            $req = "GET $($p.Path)$($p.Sep)dns=$(ConvertTo-B64Url (New-Query $d 0)) HTTP/1.1`r`nHost: $($p.Host)`r`nAccept: application/dns-message`r`nUser-Agent: dns-speedtest/$ScriptVersion`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($req)
            if (-not $fresh) { $t0 = $sw.Elapsed.TotalMilliseconds }
            $c.Ssl.Write($bytes, 0, $bytes.Length)
            $c.Ssl.Flush()
            $first = $c.Ssl.ReadByte()
            $us = [long](($sw.Elapsed.TotalMilliseconds - $t0) * 1000)
            if ($first -lt 0) { throw (New-Object IO.IOException 'closed') }
            $status = [string][char]$first + (Read-Line $c.Ssl)
            $code = [int](($status -split ' ')[1])
            $len = -1; $chunked = $false; $close = $false
            while (($hl = Read-Line $c.Ssl) -ne '') {
                if ($hl -match '^content-length:\s*(\d+)') { $len = [int]$Matches[1] }
                elseif ($hl -match '^transfer-encoding:.*chunked') { $chunked = $true }
                elseif ($hl -match '^connection:\s*close') { $close = $true }
            }
            $body = New-Object System.Collections.Generic.List[byte]
            if ($chunked) {
                while ($true) {
                    $size = [Convert]::ToInt32(((Read-Line $c.Ssl) -split ';')[0].Trim(), 16)
                    if ($size -eq 0) { while ((Read-Line $c.Ssl) -ne '') { }; break }
                    $body.AddRange([byte[]](Read-Exact $c.Ssl $size))
                    [void](Read-Line $c.Ssl)
                }
            }
            elseif ($len -gt 0) { $body.AddRange([byte[]](Read-Exact $c.Ssl $len)) }
            elseif ($len -lt 0) { $close = $true }
            if ($close) { Close-Tls $c; $c = $null }
            if ($code -eq 505) { $st = 'h2' }
            elseif ($code -ne 200) { $st = "http$code" }
            else { $st = Get-DnsStatus $body.ToArray() 0 }
            $out.Add(@{ Phase = $phase; Status = $st; Us = $(if ($st -eq 'ok') { $us } else { 0 }) })
        }
        catch {
            $st = Get-Reason $_.Exception
            # A server that only speaks HTTP/2 drops the first HTTP/1.1 request right after the TLS handshake.
            if ($fresh -and $c -and ($st -eq 'tls' -or $st -eq 'neterr')) { $st = 'h2' }
            $out.Add(@{ Phase = $phase; Status = $st; Us = 0 })
            Close-Tls $c
            $c = $null
        }
    }
    Close-Tls $c
    , $out
}

function Invoke-Session($t, [string[]]$List) {
    if ($t.Mode -eq 'dot') { return Invoke-DotSession $t.Addr $t.Ep $List }
    if ($IsCore) { return Invoke-DohSessionH2 $t.Addr $t.Ep $List }
    Invoke-DohSessionH1 $t.Addr $t.Ep $List
}

# ---------------------------------------------------------------------------
# Targets

function Get-Targets([string[]]$ModeList, [string]$Prov, [string]$Vars) {
    $list = New-Object System.Collections.Generic.List[object]
    $id = ''; $name = ''; $region = ''; $variant = ''
    $vl = @($Vars.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($line in $Catalog -split "`n") {
        $line = $line.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('@')) {
            $f = $line.Substring(1).Split('|')
            $id = $f[0]; $name = $f[1]; $region = $f[2]; $variant = $f[3]
            continue
        }
        $f = $line -split '\s+'
        if ($ModeList -notcontains $f[0] -or $Prov -eq 'system') { continue }
        if ($Prov -ne 'all' -and $Prov -ne $region) { continue }
        if ($vl.Count -and $vl -notcontains $variant) { continue }
        $ep = $(if ($f.Count -gt 2) { $f[2] } else { '' })
        $list.Add(@{ Key = "$id.$($f[0])"; Name = $name; Variant = $variant; Mode = $f[0]; Addr = $f[1]; Ep = $ep; Kind = 'public' })
    }
    if ($Prov -eq 'all' -or $Prov -eq 'system') {
        $seen = @{}
        $n = 0
        $servers = @()
        try {
            foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
                if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
                foreach ($a in $nic.GetIPProperties().DnsAddresses) { if (-not $a.IsIPv6SiteLocal) { $servers += $a.ToString() } }
            }
        }
        catch { }
        foreach ($s in $servers) {
            if ($seen.ContainsKey($s)) { continue }
            $seen[$s] = 1
            $n++
            $m = $(if ($s.Contains(':')) { 'dns6' } else { 'dns4' })
            if ($ModeList -notcontains $m) { continue }
            $list.Add(@{ Key = "system$n.$m"; Name = "System $s"; Variant = 'system'; Mode = $m; Addr = $s; Ep = ''; Kind = 'system' })
        }
    }
    , $list
}

# ---------------------------------------------------------------------------
# Report

function Get-Median([double[]]$a) {
    $n = $a.Count
    if (-not $n) { return -1 }
    if ($n % 2) { return $a[($n - 1) / 2] }
    ($a[$n / 2 - 1] + $a[$n / 2]) / 2
}
# Nearest rank
function Get-P90([double[]]$a) {
    if (-not $a.Count) { return -1 }
    $a[[Math]::Max(1, [Math]::Ceiling($a.Count * 0.9)) - 1]
}
function Get-ReasonText([string]$st) {
    if ($st -like 'http?*') { return (T 's_http') + ' ' + $st.Substring(4) }
    if ($st -eq 'noipv6') { return 'IPv6: ' + (T 'no') }
    $t = T "s_$st"
    if ($t) { return $t }
    T 's_badresp'
}
function Get-Sorted($items) { , [double[]]@($items | ForEach-Object { [double]$_.Us } | Sort-Object) }

function Write-Report($Targets, $Results, $Down, [string[]]$ModeList, [hashtable]$Hijack, [int]$LossMax, [int]$Width) {
    $wide = $Width -ge 100
    $wn = $(if ($wide) { 24 } else { 20 })
    $wa = 34
    $rec = @{}
    $csvRows = New-Object System.Collections.Generic.List[string]
    $title = @{ dns4 = 'DNS v4 (UDP/53)'; dns6 = 'DNS v6 (UDP/53)'; dot = 'DoT (TLS/853)'; doh = 'DoH (HTTPS)' }
    foreach ($m in $ModeList) {
        $tls = ($m -eq 'dot' -or $m -eq 'doh')
        $hj = ($Hijack[$m] -eq 'yes')
        $rows = @()
        foreach ($t in $Targets) {
            if ($t.Mode -ne $m) { continue }
            $res = $Results[$t.Key].ToArray()
            $ok = @($res | Where-Object { $_.Status -eq 'ok' })
            $warm = Get-Sorted @($ok | Where-Object { $_.Phase -eq 'warm' })
            $cold = Get-Sorted @($ok | Where-Object { $_.Phase -eq 'cold' })
            $samples = $(if (-not $tls) { Get-Sorted @($ok | Where-Object { $_.Phase -eq 'single' }) } elseif ($warm.Count) { , $warm } else { , $cold })
            $loss = $(if ($res.Count) { ($res.Count - $ok.Count) * 100.0 / $res.Count } else { 100 })
            $bad = @($res | Where-Object { $_.Status -ne 'ok' } | Group-Object { $_.Status } | Sort-Object Count -Descending)
            $err = $(if ($Down.ContainsKey($t.Key)) { $Down[$t.Key] } elseif ($bad.Count) { $bad[0].Name } else { '' })
            $cls = $(if ($Down.ContainsKey($t.Key) -or -not $ok.Count) { 3 } elseif ($loss -gt $LossMax) { 1 } else { 0 })
            if ($t.Kind -eq 'system' -and $cls -lt 3) { $cls = 2 }
            $rows += [pscustomobject]@{
                T = $t; Cls = $cls; Med = (Get-Median $samples); P90 = (Get-P90 $samples)
                Avg = $(if ($samples.Count) { ($samples | Measure-Object -Average).Average } else { -1 })
                Cold = $(if ($tls) { Get-Median $cold } else { -1 }); Loss = $loss; Tot = $res.Count; Err = $err
            }
        }
        if (-not $rows.Count) { continue }
        $rows = @($rows | Sort-Object Cls, Med, P90)

        Out-Text ''
        Out-Text $title[$m] 'White' -NoNewline
        Out-Text ('  ' + $G.Backend[$m]) 'DarkGray'
        if ($hj) { Out-Text ('! ' + (T 'hijack_note')) 'Red' }
        $hdr = '  #  ' + (T 'c_name').PadRight($wn) + (T 'c_var').PadRight(9)
        if ($wide) { $hdr += (T 'c_addr').PadRight($wa) }
        $hdr += (T 'c_med').PadLeft(8) + (T 'c_p90').PadLeft(8)
        if ($tls) { $hdr += (T 'c_cold').PadLeft(10) }
        $hdr += (T 'c_loss').PadLeft(8)
        Out-Text $hdr 'DarkGray'

        $rank = 0; $shown = 0
        $rec[$m] = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $t = $r.T
            $addr = $(if ($tls) { $t.Ep } else { $t.Addr })
            $name = (Get-Cut $t.Name ($wn - 1)).PadRight($wn) + $t.Variant.PadRight(9)
            if ($wide) { $name += (Get-Cut $addr ($wa - 1)).PadRight($wa) }
            if ($r.Cls -eq 3) {
                if ($Top -gt 0 -and $shown -ge $Top) { continue }
                $shown++
                Out-Text ('  -  ' + $name) 'DarkGray' -NoNewline
                Out-Text (Get-ReasonText $r.Err) 'Red'
                $csvRows.Add(('{0},{1},{2},{3},{4},,,,,100,0,{5}' -f $m, $t.Name, $t.Variant, $t.Addr, $t.Ep, $r.Err))
                continue
            }
            if ($r.Cls -lt 2) { $rank++ }
            if ($Top -gt 0 -and $shown -ge $Top) { continue }
            $shown++
            $num = $(if ($r.Cls -lt 2) { "$rank" } else { '*' })
            $green = ($r.Cls -eq 0 -and $rank -le 3 -and -not $hj)
            Out-Text ($num.PadLeft(3) + '  ' + $name) $(if ($green) { 'Green' } else { '' }) -NoNewline
            $cell = (Format-Ms $r.Med).PadLeft(8) + (Format-Ms $r.P90).PadLeft(8)
            if ($tls) { $cell += $(if ($r.Cold -lt 0) { '-' } else { Format-Ms $r.Cold }).PadLeft(10) }
            Out-Text $cell -NoNewline
            Out-Text ($r.Loss.ToString('0', $Inv) + '%').PadLeft(8) $(if ($r.Loss -gt 0) { 'Yellow' } else { '' }) -NoNewline
            if ($r.Cls -eq 2) { Out-Text ('  ' + (T 'n_sys')) 'DarkGray' }
            elseif ($r.Loss -gt 0 -and $r.Err) { Out-Text ('  ' + (Get-ReasonText $r.Err)) 'DarkGray' }
            else { Out-Text '' }
            $csvRows.Add([string]::Format($Inv, '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9:0.0},{10},ok', $m, $t.Name, $t.Variant, $t.Addr, $t.Ep,
                    (Format-Ms $r.Med), (Format-Ms $r.P90), $(if ($r.Avg -lt 0) { '' } else { Format-Ms $r.Avg }), $(if ($r.Cold -lt 0) { '' } else { Format-Ms $r.Cold }), $r.Loss, $r.Tot))
            if ($r.Cls -eq 0 -and $t.Kind -eq 'public' -and $rec[$m].Count -lt 3 -and -not $hj) { $rec[$m].Add($r) }
        }
        if ($rows.Count -gt $shown) { Out-Text ('  ... +{0}' -f ($rows.Count - $shown)) 'DarkGray' }
        Out-Text $(if ($tls) { T 'n_tls' } else { T 'n_udp' }) 'DarkGray'
        if ($m -eq 'doh' -and -not $IsCore) { Out-Text (T 'n_h1') 'DarkGray' }
    }

    Out-Text ''
    Out-Text (T 'rec') 'White'
    $label = @{ dns4 = 'DNS v4'; dns6 = 'DNS v6'; dot = 'DoT'; doh = 'DoH' }
    foreach ($m in $ModeList) {
        if (-not $rec.ContainsKey($m) -or -not $rec[$m].Count) {
            Out-Text ('  ' + $label[$m].PadRight(8)) -NoNewline
            Out-Text $(if ($Hijack[$m] -eq 'yes') { T 'hijack_note' } else { T 'norec' }) 'DarkGray'
            continue
        }
        $i = 0
        foreach ($r in $rec[$m]) {
            $i++
            $t = $r.T
            $setup = $(if ($m -eq 'doh') { $t.Ep } elseif ($m -eq 'dot') { "$($t.Ep) ($($t.Addr))" } else { $t.Addr })
            Out-Text ('  ' + $(if ($i -eq 1) { $label[$m] } else { '' }).PadRight(8)) -NoNewline
            Out-Text "$i. $($t.Name)  " 'Green' -NoNewline
            Out-Text $setup 'Cyan' -NoNewline
            Out-Text ('  {0} {1}' -f (Format-Ms $r.Med), (T 'ms'))
        }
    }
    if ($Csv) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Csv)
        $all = @('mode,provider,variant,address,endpoint,median_ms,p90_ms,avg_ms,cold_ms,loss_pct,samples,status') + $csvRows
        [IO.File]::WriteAllLines($path, [string[]]$all)
    }
}

# ---------------------------------------------------------------------------
# Self-test: RFC 8484 vectors and hand-made responses

function Invoke-SelfTest {
    $st = @{ Fail = 0 }
    $check = {
        param($Name, $Got, $Want)
        if ("$Got" -ceq "$Want") { Write-Host "ok    $Name" } else { Write-Host "FAIL  $Name : $Got != $Want"; $st.Fail = 1 }
    }
    $hex = { param($h) , [byte[]]@($h -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }) }
    $q = New-Query 'www.example.com' 0
    & $check 'build_query' (($q | ForEach-Object { $_.ToString('x2') }) -join '') '00000100000100000000000003777777076578616d706c6503636f6d0000010001'
    & $check 'query length' $q.Length 33
    & $check 'base64url (RFC 8484)' (ConvertTo-B64Url $q) 'AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
    & $check 'base64url digits' (ConvertTo-B64Url (New-Query 'a-1.b2' 0)) 'AAABAAABAAAAAAAAA2EtMQJiMgAAAQAB'
    & $check 'parse ok' (Get-DnsStatus (& $hex 'abcd81800001000300000000') 0xabcd) 'ok'
    & $check 'parse nxdomain' (Get-DnsStatus (& $hex 'abcd81830001000000000000') 0xabcd) 'nxdomain'
    & $check 'parse refused' (Get-DnsStatus (& $hex 'abcd81850001000000000000') 0xabcd) 'refused'
    & $check 'parse servfail' (Get-DnsStatus (& $hex 'abcd81820001000000000000') 0xabcd) 'servfail'
    & $check 'parse empty' (Get-DnsStatus (& $hex 'abcd81800001000000000000') 0xabcd) 'empty'
    & $check 'parse wrong id' (Get-DnsStatus (& $hex 'abce81800001000300000000') 0xabcd) 'badresp'
    & $check 'parse query, not answer' (Get-DnsStatus (& $hex 'abcd01000001000300000000') 0xabcd) 'badresp'
    & $check 'parse short' (Get-DnsStatus (& $hex 'abcd8180') 0xabcd) 'badresp'
    & $check 'median' (Get-Median @(1, 2, 3, 10)) 2.5
    & $check 'p90 nearest rank' (Get-P90 @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)) 10
    & $check 'valid ya.ru' (Test-Domain 'ya.ru') $true
    & $check 'valid punycode' (Test-Domain 'xn--80ak6aa92e.com') $true
    & $check 'reject IDN' (Test-Domain ([string][char]0x43F + [char]0x440 + '.' + [char]0x440 + [char]0x444)) $false
    & $check 'reject empty label' (Test-Domain 'a..b') $false
    & $check 'catalog parse' ((Get-Targets $AllModes 'all' '' | Where-Object { $_.Kind -eq 'public' }).Count -gt 100) $true
    Set-Lang 'ru'
    & $check 'messages ru' ((T 'rec').Length -gt 0 -and (T 'rec') -ne 'What to use') $true
    Set-Lang 'en'
    if ($st.Fail) { Write-Host 'self-test failed' -ForegroundColor Red }
}

function Show-Usage {
    Write-Host ('dns-speedtest {0}{1}{2}' -f $ScriptVersion, $Dash, (T 'u_title'))
    Write-Host $ProjectUrl
    Write-Host ''
    Write-Host (T 'u_run')
    Write-Host ''
    $o = [ordered]@{
        '-Modes LIST' = 'o_modes'; '-Providers SET' = 'o_providers'; '-Variants LIST' = 'o_variants'; '-Domains SET' = 'o_domains'
        '-CustomDomains L' = 'o_custom'; '-Profile P' = 'o_profile'; '-Runs N' = 'o_runs'; '-Top N' = 'o_top'; '-Timeout SEC' = 'o_timeout'
        '-Csv FILE' = 'o_csv'; '-Lang ru|en' = 'o_lang'; '-NoColor' = 'o_nocolor'; '-Yes' = 'o_yes'; '-List' = 'o_list'; '-SelfTest' = 'o_selftest'
    }
    foreach ($k in $o.Keys) { Write-Host ('  {0}{1}' -f $k.PadRight(20), (T $o[$k])) }
    Write-Host '  -Version, -Help'
}

function Read-Answer([string]$Prompt, [string]$Default) {
    $a = Read-Host ('{0} [{1} {2}]' -f $Prompt, (T 'q_default'), $Default)
    if ($a) { $a.Trim() } else { $Default }
}

function Stop-WithError([string]$Text) { Write-Host ('{0}: {1}' -f (T 'error'), $Text) -ForegroundColor Red }

# ---------------------------------------------------------------------------

function Invoke-Main {
    $lc = $Lang
    if (-not $lc) { $lc = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'ru' -or (Get-Culture).TwoLetterISOLanguageName -eq 'ru') { 'ru' } else { 'en' }) }
    if (@('ru', 'en') -notcontains $lc) { $lc = 'en' }
    Set-Lang $lc
    if ($Help) { Show-Usage; return }
    if ($Version) { Write-Host "dns-speedtest $ScriptVersion"; return }
    if ($SelfTest) { Invoke-SelfTest; return }
    if ($List) {
        foreach ($line in $Catalog -split "`n") {
            $line = $line.Trim()
            if ($line.StartsWith('@')) { $f = $line.Substring(1).Split('|'); Write-Host ''; Write-Host ('{0}  [{1}, {2}]' -f $f[1], $f[2], $f[3]) }
            elseif ($line) { Write-Host "  $line" }
        }
        return
    }
    $G.Color = -not $NoColor -and -not $env:NO_COLOR

    $prof = $Profile; $dom = $Domains; $custom = $CustomDomains -join ','; $prov = $Providers; $mods = $Modes -join ','
    if ($custom) { $dom = 'custom' }
    $console = $true
    try { $console = -not [Console]::IsInputRedirected } catch { }
    if ($BoundCount -eq 0 -and $console -and [Environment]::UserInteractive) {
        $a = Read-Answer (T 'q_lang') $(if ($lc -eq 'ru') { '1' } else { '2' })
        Set-Lang $(if ($a -eq '2' -or $a -eq 'en') { 'en' } else { 'ru' })
        $prof = $(if ((Read-Answer (T 'q_profile') '1') -eq '2') { 'stability' } else { 'quick' })
        $dom = @{ '2' = 'global'; '3' = 'all'; '4' = 'custom' }[(Read-Answer (T 'q_domains') '1')]
        if (-not $dom) { $dom = 'ru' }
        if ($dom -eq 'custom') { $custom = Read-Answer (T 'q_custom') 'ya.ru' }
        $prov = @{ '2' = 'ru'; '3' = 'global'; '4' = 'system' }[(Read-Answer (T 'q_providers') '1')]
        if (-not $prov) { $prov = 'all' }
        $map = @{ '1' = 'dns4'; '2' = 'dns6'; '3' = 'dot'; '4' = 'doh' }
        $mods = ((Read-Answer (T 'q_modes') '1,2,3,4') -split ',' | ForEach-Object { $x = $_.Trim(); if ($map[$x]) { $map[$x] } else { $x } }) -join ','
        Write-Host ''
    }

    switch ($prof) {
        'quick' { $rounds = 3; $lossMax = 0 }
        'stability' { $rounds = 10; $lossMax = 5 }
        default { Stop-WithError '-Profile quick|stability'; return }
    }
    if ($Runs -gt 0) { $rounds = $Runs; if ($Runs -ge 5) { $lossMax = 5 } }
    if ($Timeout -lt 1) { Stop-WithError '-Timeout SEC'; return }
    if (@('all', 'ru', 'global', 'system') -notcontains $prov) { Stop-WithError '-Providers all|ru|global|system'; return }

    if (-not $dom) { $dom = 'ru' }
    switch ($dom) {
        'ru' { $domList = $DomainsRu }
        'global' { $domList = $DomainsGlobal }
        'all' { $domList = $DomainsRu + $DomainsGlobal }
        'custom' { $domList = @($custom -split '[,\s]+' | Where-Object { $_ }) }
        default { Stop-WithError '-Domains ru|global|all|custom'; return }
    }
    $domList = [string[]]@($domList)
    if (-not $domList.Count) { Stop-WithError '-CustomDomains'; return }
    foreach ($d in $domList) { if (-not (Test-Domain $d)) { Stop-WithError "domain: $d"; return } }

    $modeList = $AllModes
    if ($mods) {
        $modeList = @($mods -split '[,\s]+' | Where-Object { $_ })
        foreach ($m in $modeList) { if ($AllModes -notcontains $m) { Stop-WithError "-Modes dns4,dns6,dot,doh: $m"; return } }
    }

    $G.Backend = @{ dns4 = 'Socket'; dns6 = 'Socket'; dot = 'SslStream'; doh = $(if ($IsCore) { 'HttpClient HTTP/2' } else { 'SslStream HTTP/1.1' }) }
    $width = 120
    try { $width = $Host.UI.RawUI.WindowSize.Width } catch { }

    Out-Text "dns-speedtest $ScriptVersion  " 'White' -NoNewline
    Out-Text $ProjectUrl 'DarkGray'
    Out-Text ('  {0}: PowerShell {1}{2}{3}: Stopwatch' -f (T 'shell'), $PSVersionTable.PSVersion, $Sep, (T 'timer'))
    Out-Text ('  {0}: {1}' -f (T 'transport'), (($AllModes | ForEach-Object { "$_ $($G.Backend[$_])" }) -join $Sep))
    Out-Text ('  {0}: {1}' -f (T 'domains'), ($domList -join ' '))

    $hijack = @{}
    foreach ($m in @('dns4', 'dns6')) {
        if ($modeList -notcontains $m) { continue }
        $label = $(if ($m -eq 'dns4') { 'DNS v4' } else { 'DNS v6' })
        if ($m -eq 'dns6') {
            # IPv6 counts only if a real DNS answer came back.
            $st = (Invoke-Udp $V6Probe 'ya.ru').Status
            if (@('ok', 'empty', 'nxdomain', 'servfail', 'refused') -notcontains $st) {
                Out-Text ('  {0}: IPv6{1}{2}' -f $label, $Dash, (T 'no'))
                $modeList = @($modeList | Where-Object { $_ -ne 'dns6' })
                continue
            }
        }
        $st = (Invoke-Udp $(if ($m -eq 'dns4') { $Root4 } else { $Root6 }) 'ya.ru').Status
        $hijack[$m] = $(if ($st -eq 'ok') { 'yes' } elseif ($st -eq 'timeout' -or $st -eq 'neterr') { 'unknown' } else { 'no' })
        Out-Text ('  {0}: {1}{2}' -f $label, (T 'hijack'), $Dash) -NoNewline
        Out-Text (T $hijack[$m]) $(if ($hijack[$m] -eq 'yes') { 'Red' } else { '' })
    }
    if (-not $modeList.Count) { Stop-WithError ('-Modes: ' + (T 'none')); return }
    $targets = Get-Targets $modeList $prov ($Variants -join ',')
    Out-Text ('  {0}: {1}{2}{3}: {4}' -f (T 'rounds'), $rounds, $Sep, (T 'targets'), $targets.Count)
    if (-not $targets.Count) { return }
    if ($hijack['dns4'] -eq 'yes' -or $hijack['dns6'] -eq 'yes') { Out-Text ''; Out-Text (T 'hijack_warn') 'Red' }

    $start = [Diagnostics.Stopwatch]::StartNew()
    $d0 = $domList[0]
    $down = @{}
    Write-Progress -Activity (T 'probe') -Status 'UDP' -PercentComplete 0
    $udp = @($targets | Where-Object { $_.Mode -like 'dns*' })
    $st = Invoke-UdpProbe $udp $d0
    $retry = @($udp | Where-Object { $st[$_.Key] -ne 'ok' })
    if ($retry.Count) { $st2 = Invoke-UdpProbe $retry $d0; foreach ($k in $st2.Keys) { $st[$k] = $st2[$k] } }
    foreach ($t in $udp) { if ($st[$t.Key] -ne 'ok') { $down[$t.Key] = $st[$t.Key] } }
    $tlsT = @($targets | Where-Object { $_.Mode -notlike 'dns*' })
    $n = 0
    foreach ($t in $tlsT) {
        $n++
        Write-Progress -Activity (T 'probe') -Status $t.Name -PercentComplete ($n * 100 / $tlsT.Count)
        $s = (Invoke-Session $t @($d0))[0].Status
        # Quick failures get one more try; a timeout already cost several seconds.
        if ($s -ne 'ok' -and $s -ne 'timeout') { $s = (Invoke-Session $t @($d0))[0].Status }
        if ($s -ne 'ok') { $down[$t.Key] = $s }
    }

    $results = @{}
    foreach ($t in $targets) { $results[$t.Key] = New-Object System.Collections.Generic.List[object] }
    $alive = @($targets | Where-Object { -not $down.ContainsKey($_.Key) })
    $total = [Math]::Max(1, $alive.Count * $rounds)
    $n = 0
    for ($r = 1; $r -le $rounds; $r++) {
        # Each round: new target order and a rotated domain list, so cold queries and resolver caches spread evenly.
        $shift = ($r - 1) % $domList.Count
        $doms = [string[]]@($domList[$shift..($domList.Count - 1)] + $(if ($shift) { $domList[0..($shift - 1)] } else { @() }))
        foreach ($t in @($alive | Sort-Object { $G.Rng.Next() })) {
            $n++
            Write-Progress -Activity ('{0} {1}/{2}' -f (T 'round'), $r, $rounds) -Status $t.Name -PercentComplete ($n * 100 / $total)
            if ($t.Mode -like 'dns*') {
                foreach ($d in $doms) { $u = Invoke-Udp $t.Addr $d; $results[$t.Key].Add(@{ Phase = 'single'; Status = $u.Status; Us = $u.Us }) }
            }
            else { foreach ($x in (Invoke-Session $t $doms)) { $results[$t.Key].Add($x) } }
        }
    }
    Write-Progress -Activity (T 'round') -Completed

    Write-Report $targets $results $down $modeList $hijack $lossMax $width
    Out-Text ''
    Out-Text ('{0} {1} {2}' -f (T 'done'), [int]$start.Elapsed.TotalSeconds, (T 'sec')) 'DarkGray'
    if ($Csv) { Out-Text ('{0}: {1}' -f (T 'csv_saved'), $Csv) }
}

Invoke-Main
} @args
