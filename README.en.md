# dns-speedtest

[Русский](README.md) · [Releases](https://github.com/mazixs/dns-speedtest/releases) · GPL-3.0

A DNS server speed test over plain DNS (UDP), DNS over TLS (DoT) and DNS over HTTPS (DoH). It shows which public DNS is faster and more stable from your network, and what to put into your router settings.

One file, nothing to install:

- `dnstest.sh` — routers (OpenWrt, Keenetic with Entware, ASUSWRT-Merlin), Linux, Docker. POSIX sh: BusyBox ash, dash, bash, zsh;
- `dnstest.ps1` — Windows: the built-in PowerShell 5.1 or PowerShell 7.

## Quick start

### Router or Linux

SSH into the router and run:

```sh
wget -qO /tmp/dnstest.sh https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.sh && sh /tmp/dnstest.sh
```

With `curl` instead of `wget`:

```sh
curl -fsSLo /tmp/dnstest.sh https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.sh && sh /tmp/dnstest.sh
```

Without options the script asks five questions: language, profile, domains, providers and modes. To skip them, add `-y` and the options you need:

```sh
sh /tmp/dnstest.sh -y --modes dot,doh --providers global
```

If the router cannot download over HTTPS, download `dnstest.sh` on a computer and copy it over:

```sh
scp -O dnstest.sh root@192.168.1.1:/tmp/
```

`-O` is needed for Dropbear, the OpenWrt SSH server.

### Windows

Open PowerShell and run:

```powershell
irm https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.ps1 | iex
```

With options:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.ps1))) -Modes dot,doh -Yes
```

A downloaded file runs like this:

```powershell
powershell -ExecutionPolicy Bypass -File .\dnstest.ps1 -Yes
```

PowerShell 7 (`pwsh`) is better for DoH: Windows PowerShell 5.1 only speaks HTTP/1.1, so servers that require HTTP/2 get the "needs HTTP/2" status.

### Docker

```sh
docker build -t dns-speedtest .
docker run --rm -it dns-speedtest
```

## What is measured

| Mode | Protocol | Measured time |
|---|---|---|
| DNS v4, DNS v6 | UDP/53 | from sending the query to the answer |
| DoT | TLS, port 853 | a query over an already open TLS connection |
| DoH | HTTPS, RFC 8484 (GET) | a query over an already open HTTPS connection |

Every answer is validated: query ID, response flag, RCODE and the presence of records. NXDOMAIN, SERVFAIL, REFUSED and empty answers count as losses, not as fast answers.

In each round DoT and DoH open one TLS session and send all domains over it. The first query is cold: TCP, TLS handshake and the query. The rest are warm. Ranking uses warm queries, because a router DoT/DoH client keeps its connection open. Cold time has its own column.

The script connects to the IP address from the catalog directly and checks the certificate against the server name. The system DNS is not involved and cannot substitute the address.

Before measuring, the script:

1. Checks for port 53 interception. The a.root-servers.net root server never recurses, so a full answer for `ya.ru` means the query was intercepted by the router, a VPN or the ISP. Plain DNS is not ranked in that case: the numbers belong to the interceptor.
2. Checks availability of all servers. Unreachable servers go to the bottom of the table with the reason and do not waste time in the rounds.

Each round uses a random server order and a rotated domain list, so the cold first query and resolver caches spread evenly.

## Reading the report

A run on Keenetic:

```
DoT (TLS/853)  kdig
  #  Provider                Variant  Address                             Median     p90      Cold    Loss
  1  Cloudflare              plain    one.one.one.one                        3.5     4.0      67.8      0%
  2  Comss.one               adblock  dns.comss.one                          4.8    44.4      72.1      0%
  3  Cloudflare Security     malware  security.cloudflare-dns.com            5.8     8.1      70.2      0%
  4  Yandex Family           family   family.dot.dns.yandex.net             12.2    25.2      48.5      0%

What to use
  DNS v4  1. NSDI Alt  195.208.5.1  3.5 ms
  DoT     1. Cloudflare  one.one.one.one (1.1.1.1)  3.5 ms
  DoH     1. Cloudflare  https://cloudflare-dns.com/dns-query  5.3 ms
```

- **Median** — typical response time, ms. The table is sorted by it.
- **p90** — 90 % of answers are faster than this. A wide gap between median and p90 means an unstable server.
- **Cold** — a new connection plus the first query.
- **Loss** — share of queries without a valid answer.
- A row with `*` is the system resolver; it is never recommended.
- A row with `-` is an unreachable server, with the reason on the right.

"What to use" lists the three best servers without losses for each mode. DoT shows the server name and IP, DoH shows the URL.

## Options

| sh | PowerShell | Meaning |
|---|---|---|
| `--modes LIST` | `-Modes` | `dns4,dns6,dot,doh`, default: all available |
| `--providers SET` | `-Providers` | `all`, `ru`, `global` or `system` |
| `--variants LIST` | `-Variants` | `plain`, `malware`, `family`, `adblock` |
| `--domains SET` | `-Domains` | `ru`, `global`, `all` or `custom`, default: `ru` |
| `--custom-domains L` | `-CustomDomains` | comma-separated domains, IDN in punycode |
| `--profile P` | `-Profile` | `quick` — 3 rounds, `stability` — 10 rounds |
| `--runs N` | `-Runs` | number of rounds, overrides the profile |
| `--top N` | `-Top` | rows per mode table, 0 — all |
| `--timeout SEC` | `-Timeout` | UDP query timeout, TLS gets +2 s, default: 1 |
| `--csv FILE` | `-Csv` | save the summary as CSV |
| `--lang ru\|en` | `-Lang` | language, default: from the system |
| `--no-color` | `-NoColor` | disable colors |
| `-y`, `--yes` | `-Yes` | never ask questions |
| `--list` | `-List` | print the server catalog |
| `--self-test` | `-SelfTest` | check the DNS encoder and parser |
| `--version`, `--help` | `-Version`, `-Help` | version and help |

The `quick` profile treats a server as stable only without losses. The `stability` profile allows up to 5 % loss.

## What the script uses

The script picks the best available tool for each mode. A mode without a tool is skipped.

| Mode | Tools by priority |
|---|---|
| UDP | `kdig`, bash `/dev/udp`, `dig`, `nslookup` |
| DoT | `kdig`, `openssl s_client` |
| DoH | `curl` (HTTP/2, warm and cold queries), `uclient-fetch` or `wget` (cold only) |

Tested on:

| System | UDP | DoT | DoH |
|---|---|---|---|
| Keenetic, Entware | kdig | kdig | curl, HTTP/2 |
| OpenWrt 24.10 | nslookup | needs a package | uclient-fetch |
| Debian, dash | bash | openssl | curl |
| Alpine, BusyBox | nslookup | openssl | curl |
| Windows, PowerShell 7 | built-in | built-in | built-in, HTTP/2 |
| Windows PowerShell 5.1 | built-in | built-in | built-in, HTTP/1.1 |

For DoT on OpenWrt install `openssl-util` or `knot-dig`. Warm DoH measurements need `curl`.

The script does not change system settings. Temporary files live in `/tmp` and are removed on exit.

## Catalog

49 providers: Cloudflare, Google, Quad9, AdGuard, CleanBrowsing, ControlD, DNS.SB, Mullvad, Gcore, OpenDNS, NextDNS, Yandex, Comss.one, NSDI, ISP resolvers and more. The full list with addresses:

```sh
sh /tmp/dnstest.sh --list
```

The catalog is embedded in both scripts and is identical byte for byte, which CI checks. Entry format:

```
@id|Name|region|variant|tags
dns4 1.1.1.1
dot 1.1.1.1 one.one.one.one
doh 1.1.1.1 https://cloudflare-dns.com/dns-query
```

## FAQ

**Why do a computer and the router give different numbers?**
From a computer the query goes through Wi-Fi and the router, which adds their latency. The router may also intercept port 53. To pick a server for the router, run the test on the router.

**What if UDP/53 interception is detected?**
Plain DNS cannot be measured in such a network: the interceptor answers. Look at DoT and DoH, which cannot be intercepted without a certificate error.

**Why are DoT and DoH almost as fast as plain DNS in the table?**
The table shows warm queries over an open connection, without a handshake. The cost of a new connection is in the "Cold" column.

**How long does the test take?**
The quick profile on Keenetic with all providers and modes took 141 s, on Windows PowerShell 5.1 it took 204 s. Limit modes or providers to make it faster.

**How do I add a server?**
Add an entry to the catalog in both files and send a pull request.
