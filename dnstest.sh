#!/bin/sh
# dns-speedtest — тест скорости DNS, DoT и DoH одним POSIX sh-файлом.
# BusyBox ash (OpenWrt, Keenetic/Entware, ASUSWRT-Merlin), dash, bash, zsh.
# https://github.com/mazixs/dns-speedtest · GPL-3.0
# shellcheck disable=SC3043,SC2059
#   SC3043: local есть во всех целевых шеллах.
#   SC2059: DNS-запрос передаётся в printf как формат из \ooo-escape, символа % в нём нет.

VERSION=4.0.0
PROJECT_URL=https://github.com/mazixs/dns-speedtest

# Без $EPOCHREALTIME и dig замеры грубее: если в системе есть bash, перезапускаемся в нём.
if [ -z "${BASH_VERSION:-}" ] && [ -z "${DNSTEST_REEXEC:-}" ] && [ -f "$0" ] &&
  command -v bash >/dev/null 2>&1 &&
  { [ -z "${EPOCHREALTIME:-}" ] || ! command -v dig >/dev/null 2>&1; }; then
  DNSTEST_REEXEC=1
  export DNSTEST_REEXEC
  exec bash "$0" "$@"
fi

[ -n "${ZSH_VERSION:-}" ] && emulate sh
set -f
LC_ALL=C
export LC_ALL
umask 077

DOMAINS_RU="ya.ru mail.ru vk.com ozon.ru gosuslugi.ru"
DOMAINS_GLOBAL="www.google.com www.youtube.com www.wikipedia.org www.amazon.com github.com"
ROOT4=198.41.0.4             # a.root-servers.net: рекурсию не выполняет, ответ с записями = перехват
ROOT6=2001:503:ba3e::2:30
V6_PROBE=2606:4700:4700::1111
PAR=8                        # параллельных проверок доступности

OPT_LANG="" OPT_PROFILE="" OPT_RUNS="" OPT_DOMAINS="" OPT_CUSTOM="" OPT_PROVIDERS="" OPT_MODES=""
OPT_VARIANTS="" OPT_TOP=0 OPT_CSV="" OPT_TIMEOUT=1 OPT_YES=0 OPT_COLOR=auto ACTION=run

# ---------------------------------------------------------------------------
# Каталог. Строка провайдера: @id|Название|регион|вариант|теги
# Затем эндпоинты: "режим адрес [хост или URL]". Для dot/doh адрес — IP, к которому
# подключаемся напрямую (системный DNS не нужен и не может подменить адрес).
# Варианты: plain — без фильтрации, malware — защита, family — семейный, adblock — реклама.
catalog() {
  cat <<'EOF'
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
EOF
}

# ---------------------------------------------------------------------------
# Тексты

set_lang() {
  if [ "$1" = ru ]; then
    L=ru
    M_ERROR="ошибка" M_WARN="предупреждение"
    M_SHELL="шелл" M_TIMER="таймер" M_TRANSPORT="транспорт" M_DOMAINS="домены"
    M_ROUNDS="раундов" M_TARGETS="целей" M_HIJACK="перехват UDP/53" M_IPV6="IPv6"
    M_YES="есть" M_NO="нет" M_UNKNOWN="не проверить" M_NONE="недоступен"
    M_TIMER_LOW="низкая точность"
    M_HIJACK_WARN="Порт 53 перехватывается: корневой DNS-сервер, который не выполняет рекурсию, вернул готовый ответ. Замеры обычного DNS показывают перехватчик (роутер, VPN или провайдера), а не выбранные серверы. Запустите тест на роутере или ориентируйтесь на DoT и DoH."
    M_HIJACK_NOTE="перехват: замер недостоверен, рейтинг не строится"
    M_PROBE="Проверка доступности" M_ROUND="Раунд"
    M_C_NUM="#" M_C_NAME="Провайдер" M_C_VAR="Вариант" M_C_ADDR="Адрес"
    M_C_MED="Медиана" M_C_P90="p90" M_C_COLD="Холодный" M_C_LOSS="Потери" M_MS="мс"
    M_N_UDP="Медиана и p90 — время ответа на запрос, мс."
    M_N_TLS="Медиана и p90 — запрос по уже открытому TLS-соединению, как у DoT/DoH-клиента роутера. «Холодный» — новое соединение и первый запрос."
    M_N_COLD="Клиент не держит соединение, все замеры холодные (с TLS-рукопожатием)."
    M_N_SYS="системный резолвер, в рекомендации не попадает"
    M_REC="Что поставить" M_NOREC="нет кандидатов без потерь"
    M_DONE="Готово за" M_SEC="с" M_CSV_SAVED="CSV сохранён"
    S_timeout="нет ответа" S_refused="отказ (REFUSED)" S_servfail="SERVFAIL" S_nxdomain="NXDOMAIN"
    S_empty="пустой ответ" S_tls="ошибка TLS" S_cert="сертификат не прошёл проверку"
    S_neterr="сетевая ошибка" S_badresp="некорректный ответ" S_h2="нужен HTTP/2" S_http="HTTP"
    S_fail="не разрешилось"
    Q_LANG="Язык / Language: 1) Русский  2) English"
    Q_PROFILE="Профиль: 1) Быстрый — 3 раунда  2) Стабильность — 10 раундов"
    Q_DOMAINS="Домены: 1) российские  2) зарубежные  3) все  4) свои"
    Q_CUSTOM="Домены через запятую"
    Q_PROVIDERS="Провайдеры: 1) все  2) российские  3) зарубежные  4) только системный DNS"
    Q_MODES="Режимы через запятую: 1) DNS v4  2) DNS v6  3) DoT  4) DoH"
    Q_DEFAULT="по умолчанию"
  else
    L=en
    M_ERROR="error" M_WARN="warning"
    M_SHELL="shell" M_TIMER="timer" M_TRANSPORT="transport" M_DOMAINS="domains"
    M_ROUNDS="rounds" M_TARGETS="targets" M_HIJACK="UDP/53 interception" M_IPV6="IPv6"
    M_YES="yes" M_NO="no" M_UNKNOWN="cannot check" M_NONE="unavailable"
    M_TIMER_LOW="low resolution"
    M_HIJACK_WARN="Port 53 is intercepted: a root DNS server, which never recurses, returned a full answer. Plain DNS results reflect the interceptor (router, VPN or ISP), not the selected servers. Run the test on the router or rely on DoT and DoH."
    M_HIJACK_NOTE="intercepted: results are not reliable, no ranking"
    M_PROBE="Availability check" M_ROUND="Round"
    M_C_NUM="#" M_C_NAME="Provider" M_C_VAR="Variant" M_C_ADDR="Address"
    M_C_MED="Median" M_C_P90="p90" M_C_COLD="Cold" M_C_LOSS="Loss" M_MS="ms"
    M_N_UDP="Median and p90 are query response times, ms."
    M_N_TLS="Median and p90 are queries over an already open TLS connection, as a router DoT/DoH client does. \"Cold\" is a new connection plus the first query."
    M_N_COLD="This client cannot reuse connections, every sample is cold (includes the TLS handshake)."
    M_N_SYS="system resolver, never recommended"
    M_REC="What to use" M_NOREC="no candidates without losses"
    M_DONE="Done in" M_SEC="s" M_CSV_SAVED="CSV saved"
    S_timeout="no response" S_refused="refused" S_servfail="SERVFAIL" S_nxdomain="NXDOMAIN"
    S_empty="empty answer" S_tls="TLS error" S_cert="certificate check failed"
    S_neterr="network error" S_badresp="malformed response" S_h2="needs HTTP/2" S_http="HTTP"
    S_fail="not resolved"
    Q_LANG="Язык / Language: 1) Русский  2) English"
    Q_PROFILE="Profile: 1) Quick — 3 rounds  2) Stability — 10 rounds"
    Q_DOMAINS="Domains: 1) Russian  2) global  3) all  4) custom"
    Q_CUSTOM="Comma-separated domains"
    Q_PROVIDERS="Providers: 1) all  2) Russian  3) global  4) system DNS only"
    Q_MODES="Comma-separated modes: 1) DNS v4  2) DNS v6  3) DoT  4) DoH"
    Q_DEFAULT="default"
  fi
}


usage() {
  if [ "$L" = ru ]; then
    cat <<EOF
dns-speedtest $VERSION — тест скорости DNS, DoT и DoH
$PROJECT_URL

Запуск:  sh dnstest.sh [опции]     без опций в терминале задаёт вопросы

  --modes LIST        dns4,dns6,dot,doh (по умолчанию все доступные)
  --providers SET     all | ru | global | system (по умолчанию all)
  --variants LIST     plain,malware,family,adblock (по умолчанию все)
  --domains SET       ru | global | all | custom (по умолчанию ru)
  --custom-domains L  свои домены через запятую (IDN — в punycode)
  --profile P         quick — 3 раунда, stability — 10 раундов
  --runs N            число раундов вместо профиля
  --top N             строк в таблице каждого режима (0 — все)
  --timeout SEC       таймаут UDP-запроса, для TLS +2 с (по умолчанию 1)
  --csv FILE          сохранить сводку в CSV
  --lang ru|en        язык (по умолчанию из \$LANG)
  --no-color          без цвета
  -y, --yes           не задавать вопросов
  --list              показать каталог и выйти
  --self-test         проверить кодировщик и парсер DNS
  --version, -h, --help
EOF
  else
    cat <<EOF
dns-speedtest $VERSION — DNS, DoT and DoH speed test
$PROJECT_URL

Usage:  sh dnstest.sh [options]     asks questions when run in a terminal without options

  --modes LIST        dns4,dns6,dot,doh (default: all available)
  --providers SET     all | ru | global | system (default: all)
  --variants LIST     plain,malware,family,adblock (default: all)
  --domains SET       ru | global | all | custom (default: ru)
  --custom-domains L  comma-separated domains (IDN in punycode)
  --profile P         quick — 3 rounds, stability — 10 rounds
  --runs N            number of rounds, overrides the profile
  --top N             rows per mode table (0 — all)
  --timeout SEC       UDP query timeout, TLS gets +2 s (default: 1)
  --csv FILE          save the summary as CSV
  --lang ru|en        language (default: from \$LANG)
  --no-color          disable colors
  -y, --yes           never ask questions
  --list              print the catalog and exit
  --self-test         check the DNS encoder and parser
  --version, -h, --help
EOF
  fi
}

# ---------------------------------------------------------------------------
# Утилиты

have() { command -v "$1" >/dev/null 2>&1; }
die() { printf '%s: %s\n' "${M_ERROR:-error}" "$*" >&2; exit 1; }
warn() { printf '%s: %s\n' "${M_WARN:-warning}" "$*" >&2; }

color_init() {
  C_RST='' C_B='' C_DIM='' C_RED='' C_GRN='' C_YEL='' C_CYN=''
  if [ "$OPT_COLOR" = auto ]; then
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then OPT_COLOR=on; else OPT_COLOR=off; fi
  fi
  [ "$OPT_COLOR" = on ] || return 0
  local e
  e=$(printf '\033')
  C_RST="${e}[0m" C_B="${e}[1m" C_DIM="${e}[2m" C_RED="${e}[31m" C_GRN="${e}[32m" C_YEL="${e}[33m" C_CYN="${e}[36m"
}

# Таймер: NOW в микросекундах от старта. Определяется один раз, в горячем пути без fork,
# кроме запасного варианта через date.
timer_init() {
  if [ -n "${EPOCHREALTIME:-}" ]; then
    TIMER=EPOCHREALTIME
    T0S=${EPOCHREALTIME%%[.,]*}
    now_us() {
      _t=$EPOCHREALTIME
      _f=${_t#*[.,]}
      _f=${_f#"${_f%%[!0]*}"}
      NOW=$(( (${_t%%[.,]*} - T0S) * 1000000 + ${_f:-0} ))
    }
  elif { read -r _ && read -r _ && read -r _ _ _n _; } </proc/timer_list 2>/dev/null &&
    [ -n "${_n:-}" ] && [ $((2147483647 + 1)) -gt 0 ]; then
    TIMER=/proc/timer_list
    now_us() {
      { read -r _; read -r _; read -r _ _ _n _; } </proc/timer_list
      NOW=$((_n / 1000))
    }
  else
    # BusyBox без FEATURE_DATE_NANO молча выводит пустоту вместо %N: нужны ровно 9 цифр.
    case $(date +%N 2>/dev/null) in
      [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
      *) _nodate=1 ;;
    esac
    case ${_nodate:-} in
      1)
        if [ -r /proc/uptime ]; then
          TIMER="/proc/uptime ($M_TIMER_LOW)"
          now_us() {
            read -r _u _ </proc/uptime
            _f=${_u#*.}
            _f=${_f#0}
            NOW=$(( ${_u%.*} * 1000000 + ${_f:-0} * 10000 ))
          }
        else
          TIMER="date +%s ($M_TIMER_LOW)"
          now_us() { NOW=$(( $(date +%s) * 1000000 )); }
        fi
        ;;
      *)
        TIMER="date +%N"
        T0S=$(date +%s)
        now_us() { _d=$(date +%s%N); NOW=$(( (_d / 1000) - T0S * 1000000 )); }
        ;;
    esac
  fi
}

# Собственный ГПСЧ: $RANDOM есть не во всех шеллах.
rand16() {
  RNG=$(( (RNG * 1103515245 + 12345) % 2147483648 ))
  R16=$(( (RNG / 65536) % 65536 ))
}

# Сторож вместо timeout(1), которого нет в BusyBox на OpenWrt и Keenetic.
watchdog() {
  ( sleep "$2" & _s=$!
    trap 'kill $_s 2>/dev/null; exit 0' TERM
    wait $_s
    kill "$1" 2>/dev/null ) >/dev/null 2>&1 &
  WD=$!
}
cancel_watchdog() { kill "$WD" 2>/dev/null; wait "$WD" 2>/dev/null; }

# Ждём, пока фоновый процесс выполнит exec и заснёт в read(), чтобы его запуск
# не попал в замер.
wait_exec() {
  [ -r "/proc/$1/stat" ] || return 0
  local i=0 st
  while [ $i -lt 400 ]; do
    read -r st <"/proc/$1/stat" 2>/dev/null || return 0
    case $st in *"($2) S"*) return 0 ;; esac
    i=$((i + 1))
  done
}

hex_init() {
  if have hexdump; then
    hex_file() { hexdump -v -e '1/1 "%02x"' "$1" 2>/dev/null; }
  elif have od; then
    hex_file() { od -An -v -tx1 "$1" 2>/dev/null | tr -d ' \n'; }
  else
    die "hexdump/od"
  fi
}

# "73.6" мс -> US=73600
ms_to_us() {
  local i="${1%%.*}" f=''
  case $1 in *.*) f=${1#*.} ;; esac
  f="${f}000"
  f=${f%"${f#???}"}
  f=${f#"${f%%[!0]*}"}
  i=${i#"${i%%[!0]*}"}
  US=$(( ${i:-0} * 1000 + ${f:-0} ))
}

# "0.073456" с -> US=73456
sec_to_us() {
  local i="${1%%.*}" f=''
  case $1 in *.*) f=${1#*.} ;; esac
  f="${f}000000"
  f=${f%"${f#??????}"}
  f=${f#"${f%%[!0]*}"}
  i=${i#"${i%%[!0]*}"}
  US=$(( ${i:-0} * 1000000 + ${f:-0} ))
}

# ---------------------------------------------------------------------------
# DNS wire format

valid_domain() {
  case $1 in '' | *[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;; esac
  [ ${#1} -le 253 ] || return 1
  local rest="$1" l
  while [ -n "$rest" ]; do
    l=${rest%%.*}
    [ ${#l} -le 63 ] || return 1
    case $rest in *.*) rest=${rest#*.} ;; *) rest= ;; esac
  done
}

oct() { O="\\$(( $1 / 64 ))$(( $1 / 8 % 8 ))$(( $1 % 8 ))"; }

# Q — printf-формат запроса типа A с RD=1, QLEN — его длина в байтах, P — 2-байтный
# префикс длины для TCP/TLS. Без fork.
build_query() {
  local rest="$1" l
  oct $(( $2 / 256 )); Q=$O
  oct $(( $2 % 256 )); Q=$Q$O
  Q="$Q\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000"
  while [ -n "$rest" ]; do
    l=${rest%%.*}
    case $rest in *.*) rest=${rest#*.} ;; *) rest= ;; esac
    oct ${#l}; Q=$Q$O$l
  done
  Q="$Q\\000\\000\\001\\000\\001"
  QLEN=$(( ${#1} + 18 ))
  oct $(( QLEN / 256 )); P=$O
  oct $(( QLEN % 256 )); P=$P$O
}

# Разбор заголовка ответа из hex. $2 — ожидаемый TXID в hex или пусто.
# R_STATUS: ok | empty | nxdomain | servfail | refused | badresp
parse_dns() {
  local h="$1" id fl an
  R_STATUS=badresp
  [ ${#h} -ge 24 ] || return 1
  id=${h%"${h#????}"}; h=${h#????}
  fl=${h%"${h#????}"}; h=${h#????????}
  an=${h%"${h#????}"}
  [ -z "$2" ] || [ "$id" = "$2" ] || return 1
  fl=$((0x$fl)); an=$((0x$an))
  [ $((fl & 32768)) -ne 0 ] || return 1
  case $((fl & 15)) in
    0) if [ "$an" -gt 0 ]; then R_STATUS=ok; else R_STATUS=empty; fi ;;
    2) R_STATUS=servfail ;;
    3) R_STATUS=nxdomain ;;
    5) R_STATUS=refused ;;
  esac
  [ "$R_STATUS" = ok ]
}

status_from_rcode() {
  case $1 in
    NOERROR) if [ "${2:-0}" -gt 0 ] 2>/dev/null; then R_STATUS=ok; else R_STATUS=empty; fi ;;
    NXDOMAIN) R_STATUS=nxdomain ;;
    SERVFAIL) R_STATUS=servfail ;;
    REFUSED) R_STATUS=refused ;;
    *) R_STATUS=badresp ;;
  esac
}

# base64url запросов (ID=0, как советует RFC 8484) для DoH GET, по строке на домен.
doh_params() {
  awk -v list="$*" 'BEGIN {
    A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    C = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    n = split(list, D, " ")
    for (i = 1; i <= n; i++) {
      nb = split("0 0 1 0 0 1 0 0 0 0 0 0", B, " ")
      m = split(D[i], Lb, ".")
      for (j = 1; j <= m; j++) {
        B[++nb] = length(Lb[j])
        for (c = 1; c <= length(Lb[j]); c++) {
          x = index(C, substr(Lb[j], c, 1))
          B[++nb] = x == 1 ? 45 : x <= 11 ? 46 + x : x <= 37 ? 53 + x : 59 + x
        }
      }
      B[++nb] = 0; B[++nb] = 0; B[++nb] = 1; B[++nb] = 0; B[++nb] = 1
      s = ""
      for (k = 1; k <= nb; k += 3) {
        v = B[k] * 65536 + (k < nb ? B[k + 1] : 0) * 256 + (k + 1 < nb ? B[k + 2] : 0)
        s = s substr(A, int(v / 262144) % 64 + 1, 1) substr(A, int(v / 4096) % 64 + 1, 1)
        if (k < nb) s = s substr(A, int(v / 64) % 64 + 1, 1)
        if (k + 1 < nb) s = s substr(A, v % 64 + 1, 1)
      }
      print s
    }
  }'
}

# ---------------------------------------------------------------------------
# Окружение: какие транспорты доступны

detect_env() {
  if [ -n "${BASH_VERSION:-}" ]; then SHELL_NAME="bash $BASH_VERSION"
  elif [ -n "${ZSH_VERSION:-}" ]; then SHELL_NAME="zsh $ZSH_VERSION"
  else
    SHELL_NAME=$(readlink "/proc/$$/exe" 2>/dev/null)
    SHELL_NAME=${SHELL_NAME##*/}
    [ "$SHELL_NAME" = busybox ] && SHELL_NAME="BusyBox ash"
    : "${SHELL_NAME:=sh}"
  fi

  CA_FILE=
  for f in /etc/ssl/certs/ca-certificates.crt /opt/etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/cert.pem /opt/etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt /jffs/ssl/certs/ca-certificates.crt; do
    [ -r "$f" ] && { CA_FILE=$f; break; }
  done

  # Приоритет по точности: kdig (0,1 мс), bash /dev/udp (мкс), dig (часы ядра, на роутерах
  # шаг 4 мс), nslookup (время запуска процесса вычитается по калибровке).
  UDP_BACKEND=''
  # shellcheck disable=SC3025
  if have kdig; then UDP_BACKEND=kdig
  elif [ -n "${BASH_VERSION:-}" ] && (exec 5<>/dev/udp/127.0.0.1/53) 2>/dev/null; then UDP_BACKEND=bash
  elif have dig; then UDP_BACKEND=dig
  elif have nslookup; then
    UDP_BACKEND=nslookup
    NSLOOKUP_BIG=0
    case $(nslookup 2>&1) in *-type=*) NSLOOKUP_BIG=1 ;; esac
  fi

  DOT_BACKEND=
  if have kdig; then DOT_BACKEND=kdig
  elif have openssl && have mkfifo; then DOT_BACKEND=openssl
  fi

  DOH_BACKEND='' CURL_H2=''
  if have curl; then
    DOH_BACKEND=curl
    case $(curl -V 2>/dev/null) in *HTTP2*) CURL_H2=--http2 ;; esac
  elif have uclient-fetch; then DOH_BACKEND=uclient-fetch
  elif have wget; then DOH_BACKEND=wget
  fi
}

backend_label() {
  case $1 in
    dns4 | dns6) BL=$UDP_BACKEND
      [ "$BL" = nslookup ] && BL="nslookup (−$((NS_OVERHEAD / 1000)).$((NS_OVERHEAD % 1000 / 100)) $M_MS)" ;;
    dot) BL=$DOT_BACKEND ;;
    doh) BL=$DOH_BACKEND
      [ "$BL" = curl ] && { [ -n "$CURL_H2" ] && BL="curl HTTP/2" || BL="curl HTTP/1.1"; } ;;
  esac
}

mode_available() {
  case $1 in
    dns4 | dns6) [ -n "$UDP_BACKEND" ] ;;
    dot) [ -n "$DOT_BACKEND" ] ;;
    doh) [ -n "$DOH_BACKEND" ] ;;
    *) return 1 ;;
  esac
}

# Накладные расходы на запуск nslookup: вычитаются из замеров.
calibrate_nslookup() {
  NS_OVERHEAD=0
  [ "$UDP_BACKEND" = nslookup ] || return 0
  local i=0 best=999999999 t0 pid
  while [ $i -lt 5 ]; do
    now_us; t0=$NOW
    nslookup localhost 127.0.0.1 >/dev/null 2>&1 &
    pid=$!
    watchdog "$pid" 1
    wait "$pid"
    now_us
    cancel_watchdog
    [ $((NOW - t0)) -lt $best ] && best=$((NOW - t0))
    i=$((i + 1))
  done
  NS_OVERHEAD=$best
}

# ---------------------------------------------------------------------------
# UDP: R_STATUS, R_US

udp_query() {
  R_STATUS=timeout R_US=0
  case $UDP_BACKEND in
    dig) udp_dig "$1" "$2" ;;
    kdig) udp_kdig "$1" "$2" ;;
    bash) udp_bash "$1" "$2" ;;
    nslookup) udp_nslookup "$1" "$2" ;;
  esac
}

udp_dig() {
  local out st an qt
  out=$(dig +tries=1 +time="$OPT_TIMEOUT" +noall +comments +stats @"$1" "$2" A 2>&1)
  case $out in
    *"status: "*) st=${out#*status: }; st=${st%%,*} ;;
    *"refused"* | *"unreachable"*) R_STATUS=neterr; return ;;
    *) return ;;
  esac
  an=${out#*ANSWER: }; an=${an%%,*}
  qt=${out#*Query time: }; qt=${qt%% *}
  status_from_rcode "$st" "$an"
  case $qt in '' | *[!0-9]*) qt=0 ;; esac
  R_US=$((qt * 1000))
}

udp_kdig() {
  local out st an ms
  out=$(kdig @"$1" +notcp +timeout="$OPT_TIMEOUT" +retry=0 +noall +header +stats "$2" A 2>&1)
  case $out in
    *"status: "*) st=${out#*status: }; st=${st%%;*} ;;
    *"refused"* | *"unreachable"*) R_STATUS=neterr; return ;;
    *) return ;;
  esac
  an=${out#*ANSWER: }; an=${an%%;*}
  ms=${out##* in }; ms=${ms%% ms*}
  status_from_rcode "$st" "$an"
  ms_to_us "$ms"
  R_US=$US
}

udp_bash() {
  local f="$TMPD/udp.$JOB" res rc us
  rand16
  build_query "$2" "$R16"
  # В подоболочке: ошибка exec с /dev/udp не должна завершить основной шелл.
  # shellcheck disable=SC3025
  res=$(
    exec 5<>"/dev/udp/$1/53" 2>/dev/null || { echo neterr; exit 0; }
    dd bs=4096 count=1 <&5 >"$f" 2>/dev/null &
    pid=$!
    wait_exec "$pid" dd
    now_us; t0=$NOW
    printf "$Q" >&5 2>/dev/null || { kill "$pid" 2>/dev/null; echo neterr; exit 0; }
    watchdog "$pid" "$OPT_TIMEOUT"
    wait "$pid"; rc=$?
    now_us
    cancel_watchdog
    echo "$rc $((NOW - t0))"
  )
  case $res in neterr) R_STATUS=neterr; return ;; esac
  rc=${res%% *} us=${res#* }
  [ "$rc" = 0 ] || return
  parse_dns "$(hex_file "$f")" "$(printf '%04x' "$R16")"
  R_US=$us
}

udp_nslookup() {
  local f="$TMPD/ns.$JOB" pid t0 line name=0 addr=0
  now_us; t0=$NOW
  if [ "$NSLOOKUP_BIG" = 1 ]; then
    nslookup -type=a "$2" "$1" >"$f" 2>&1 &
  else
    nslookup "$2" "$1" >"$f" 2>&1 &
  fi
  pid=$!
  watchdog "$pid" "$OPT_TIMEOUT"
  wait "$pid"
  now_us
  cancel_watchdog
  R_US=$((NOW - t0 - NS_OVERHEAD))
  [ "$R_US" -lt 0 ] && R_US=0
  R_STATUS=badresp
  while IFS= read -r line; do
    case $line in
      *"NXDOMAIN"*) R_STATUS=nxdomain; return ;;
      *"SERVFAIL"*) R_STATUS=servfail; return ;;
      *"REFUSED"*) R_STATUS=refused; return ;;
      *"timed out"* | *"no servers could be reached"*) R_STATUS=timeout; return ;;
      *nreachable* | *"can't connect"* | *"connection refused"*) R_STATUS=neterr; return ;;
      Name:*) name=1 ;;
      Address*) [ "$name" = 1 ] && addr=1 ;;
    esac
  done <"$f"
  # Маленький nslookup (через libc) код ответа не показывает: только «не разрешилось».
  if [ "$addr" = 1 ]; then R_STATUS=ok; elif [ -s "$f" ]; then R_STATUS=fail; else R_STATUS=timeout; fi
}

# ---------------------------------------------------------------------------
# Сессии DoT/DoH: все домены по одному соединению. Первый запрос — cold, остальные — warm.
# Запись результата: key round domain phase status us

emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$OUT"; }

phase_of() { if [ "$1" -eq 1 ]; then PHASE=cold; else PHASE=warm; fi; }

# Запросы сессии после обрыва соединения засчитываются как потери с той же причиной.
emit_rest() { # key round status from domains...
  local key="$1" round="$2" status="$3" from="$4" i=0 d
  shift 4
  for d in "$@"; do
    i=$((i + 1))
    [ $i -lt "$from" ] && continue
    phase_of $i
    emit "$key" "$round" "$d" "$PHASE" "$status" 0
  done
}

session() { # key mode addr endpoint round domains...
  local key="$1" mode="$2" addr="$3" ep="$4" round="$5"
  shift 5
  case $mode in
    dot) case $DOT_BACKEND in kdig) dot_kdig "$key" "$addr" "$ep" "$round" "$@" ;; openssl) dot_openssl "$key" "$addr" "$ep" "$round" "$@" ;; esac ;;
    doh) case $DOH_BACKEND in curl) doh_curl "$key" "$addr" "$ep" "$round" "$@" ;; *) doh_fetch "$key" "$addr" "$ep" "$round" "$@" ;; esac ;;
  esac
}

dot_kdig() {
  local key="$1" ip="$2" host="$3" round="$4" tls out i=0 d line
  shift 4
  tls=+tls
  [ -n "$CA_FILE" ] && tls="+tls-ca=$CA_FILE"
  # kdig сам меряет время каждого запроса; +keepopen держит одно TLS-соединение.
  out=$(kdig @"$ip" "$tls" "+tls-hostname=$host" "+tls-sni=$host" +keepopen \
    +timeout=$((OPT_TIMEOUT + 2)) +retry=0 +noall +header +stats "$@" 2>&1 | awk '
    /WARNING:/ { w = w " " $0 }
    /->>HEADER<<-/ { s = $0; sub(/.*status: /, "", s); sub(/;.*/, "", s) }
    /^;; Flags:/ { a = $0; sub(/.*ANSWER: /, "", a); sub(/;.*/, "", a) }
    / in [0-9.]+ ms$/ { print "ok", (s == "" ? "NONE" : s), (a == "" ? 0 : a), $(NF - 1); s = ""; a = ""; w = "" }
    /ERROR:/ {
      r = "neterr"
      if (w ~ /certificate/) r = "cert"; else if (w ~ /timeout/) r = "timeout"
      else if (w ~ /handshake|TLS/) r = "tls"
      print "err", r; w = ""
    }')
  for d in "$@"; do
    i=$((i + 1))
    phase_of $i
    line=$(printf '%s\n' "$out" | sed -n "${i}p")
    case $line in
      ok\ *)
        # shellcheck disable=SC2086
        set -- $line
        status_from_rcode "$2" "$3"
        ms_to_us "$4"
        emit "$key" "$round" "$d" "$PHASE" "$R_STATUS" "$US" ;;
      err\ *) emit "$key" "$round" "$d" "$PHASE" "${line#err }" 0 ;;
      *) emit "$key" "$round" "$d" "$PHASE" timeout 0 ;;
    esac
  done
}

dot_openssl() {
  local key="$1" ip="$2" host="$3" round="$4" j="$TMPD/tls.$JOB" n st
  shift 4
  rm -f "$j.n" "$j.st"
  # Подоболочка: свои дескрипторы 3/4 и игнор SIGPIPE на случай, если openssl уже вышел.
  (
    trap '' PIPE
    rm -f "$j.in" "$j.out"
    mkfifo "$j.in" "$j.out" || { echo neterr >"$j.st"; exit 0; }
    ca=
    [ -n "$CA_FILE" ] && ca="-CAfile $CA_FILE"
    target="$ip:853"
    case $ip in *:*) target="[$ip]:853" ;; esac
    now_us; ts=$NOW
    # shellcheck disable=SC2086
    openssl s_client -connect "$target" -servername "$host" -verify_return_error \
      -verify_hostname "$host" $ca -quiet <"$j.in" >"$j.out" 2>"$j.err" &
    spid=$!
    watchdog "$spid" $(( (OPT_TIMEOUT + 2) * ($# + 1) ))
    swd=$WD
    exec 3>"$j.in" 4<"$j.out"
    i=0
    for d in "$@"; do
      i=$((i + 1))
      phase_of $i
      rand16
      build_query "$d" "$R16"
      # Читатель запускается до отправки запроса, его старт не попадает в замер.
      dd bs=1 count=4 <&4 >"$j.h" 2>/dev/null &
      rp=$!
      wait_exec "$rp" dd
      now_us; t0=$NOW
      [ $i -eq 1 ] && t0=$ts
      printf "$P$Q" >&3 2>/dev/null
      watchdog "$rp" $((OPT_TIMEOUT + 2))
      wait "$rp"
      now_us
      cancel_watchdog
      h=$(hex_file "$j.h")
      if [ ${#h} -ne 8 ]; then
        st=timeout
        case $(cat "$j.err" 2>/dev/null) in
          *verify* | *certificate*) st=cert ;;
          *refused* | *unreachable* | *errno*) st=neterr ;;
          *ssl* | *SSL* | *alert*) st=tls ;;
        esac
        echo "$st" >"$j.st"
        break
      fi
      len=$((0x${h%????}))
      dd bs=1 count=$((len - 2)) <&4 >"$j.b" 2>/dev/null
      parse_dns "${h#????}$(hex_file "$j.b")" "$(printf '%04x' "$R16")"
      emit "$key" "$round" "$d" "$PHASE" "$R_STATUS" $((NOW - t0))
      echo "$i" >"$j.n"
    done
    exec 3>&- 4<&-
    kill "$spid" 2>/dev/null
    WD=$swd
    cancel_watchdog
    wait "$spid" 2>/dev/null
  )
  n=$(cat "$j.n" 2>/dev/null)
  st=$(cat "$j.st" 2>/dev/null)
  [ "${n:-0}" -lt $# ] && emit_rest "$key" "$round" "${st:-timeout}" $(( ${n:-0} + 1 )) "$@"
  rm -f "$j.n" "$j.st" "$j.in" "$j.out"
}

url_host() { UH=${1#https://}; UH=${UH%%/*}; }

doh_curl() {
  local key="$1" ip="$2" url="$3" round="$4" i=0 d sep='?' line code ex tst tpre params
  shift 4
  url_host "$url"
  case $url in *\?*) sep='&' ;; esac
  params=$(doh_params "$@")
  local doms="$*" f="$TMPD/doh.$JOB"
  set --
  for p in $params; do
    i=$((i + 1))
    rm -f "$f.$i"
    set -- "$@" -o "$f.$i" "$url${sep}dns=$p"
  done
  # Один процесс curl на сессию: соединение переиспользуется, тайминги curl считает сам.
  # shellcheck disable=SC2086
  line=$(curl -s $CURL_H2 --resolve "$UH:443:$ip" --connect-timeout $((OPT_TIMEOUT + 2)) \
    -m $((OPT_TIMEOUT * 2 + 4)) -H 'accept: application/dns-message' \
    -w '%{http_code} %{exitcode} %{time_starttransfer} %{time_pretransfer}\n' "$@" 2>/dev/null)
  i=0
  for d in $doms; do
    i=$((i + 1))
    phase_of $i
    # shellcheck disable=SC2046
    set -- $(printf '%s\n' "$line" | sed -n "${i}p")
    code=${1:-000} ex=${2:-28} tst=${3:-0} tpre=${4:-0}
    if [ "$ex" != 0 ]; then
      case $ex in
        28) st=timeout ;; 35) st=tls ;; 51 | 58 | 60 | 77 | 83 | 90 | 91) st=cert ;;
        16 | 92) st=h2 ;; *) st=neterr ;;
      esac
      emit "$key" "$round" "$d" "$PHASE" "$st" 0
      continue
    fi
    if [ "$code" != 200 ]; then
      st="http$code"
      [ "$code" = 505 ] && st=h2
      emit "$key" "$round" "$d" "$PHASE" "$st" 0
      continue
    fi
    parse_dns "$(hex_file "$f.$i")" 0000
    # Первый запрос: всё вместе с TCP и TLS. Остальные: от отправки до первого байта ответа.
    sec_to_us "$tst"
    us=$US
    if [ $i -gt 1 ]; then sec_to_us "$tpre"; us=$((us - US)); fi
    emit "$key" "$round" "$d" "$PHASE" "$R_STATUS" "$us"
  done
}

# Запасной DoH через wget/uclient-fetch: без переиспользования соединения и без
# пиннинга IP, поэтому все замеры холодные.
doh_fetch() {
  local key="$1" url="$3" round="$4" i=0 d p sep='?' f pid t0 params rc
  shift 4
  case $url in *\?*) sep='&' ;; esac
  params=$(doh_params "$@")
  f="$TMPD/dohf.$JOB"
  for d in "$@"; do
    i=$((i + 1))
    p=$(printf '%s\n' "$params" | sed -n "${i}p")
    rm -f "$f"
    now_us; t0=$NOW
    "$DOH_BACKEND" -q -T $((OPT_TIMEOUT + 2)) -O "$f" --header 'accept: application/dns-message' "$url${sep}dns=$p" >/dev/null 2>&1 &
    pid=$!
    watchdog "$pid" $((OPT_TIMEOUT + 3))
    wait "$pid"
    rc=$?
    now_us
    cancel_watchdog
    if [ -s "$f" ]; then
      parse_dns "$(hex_file "$f")" 0000
      emit "$key" "$round" "$d" cold "$R_STATUS" $((NOW - t0))
    elif [ "$rc" -gt 128 ]; then
      emit "$key" "$round" "$d" cold timeout 0
    else
      emit "$key" "$round" "$d" cold neterr 0
    fi
  done
}

# ---------------------------------------------------------------------------
# Цели: key|provider|name|region|variant|mode|addr|endpoint|kind

build_targets() {
  catalog | awk -v prov="$OPT_PROVIDERS" -v modes=",$MODES," -v vars=",$OPT_VARIANTS," -F'|' '
    /^@/ { id = substr($1, 2); name = $2; region = $3; variant = $4; next }
    {
      split($0, f, " ")
      if (index(modes, "," f[1] ",") == 0) next
      if (prov == "system") next
      if (prov != "all" && prov != region) next
      if (vars != ",," && index(vars, "," variant ",") == 0) next
      print id "." f[1] "|" id "|" name "|" region "|" variant "|" f[1] "|" f[2] "|" f[3] "|public"
    }' >"$TMPD/targets"

  case $OPT_PROVIDERS in all | system) ;; *) return 0 ;; esac
  local ns n=0 m
  [ -r /etc/resolv.conf ] || return 0
  while read -r m ns _; do
    [ "$m" = nameserver ] || continue
    case $ns in *%*) continue ;; esac
    n=$((n + 1))
    case $ns in *:*) m=dns6 ;; *) m=dns4 ;; esac
    case ",$MODES," in *",$m,"*) ;; *) continue ;; esac
    printf 'system%s.%s|system%s|System %s|local|system|%s|%s||system\n' "$n" "$m" "$n" "$ns" "$m" "$ns" >>"$TMPD/targets"
  done </etc/resolv.conf
}

# ---------------------------------------------------------------------------
# Проверки сети

check_hijack() { # ip → HJ=yes|no|unknown
  udp_query "$1" ya.ru
  case $R_STATUS in
    ok) HJ=yes ;;
    timeout | neterr) HJ=unknown ;;
    *) HJ=no ;;
  esac
}

# Проверка доступности: один запрос с повтором; пишет "key status" в файл задания.
probe_target() {
  local key="$1" mode="$2" addr="$3" ep="$4" d="$5" try=0
  while [ $try -lt 2 ]; do
    try=$((try + 1))
    case $mode in
      dns4 | dns6) udp_query "$addr" "$d" ;;
      *)
        OUT="$TMPD/probe.$JOB.rec"
        : >"$OUT"
        session "$key" "$mode" "$addr" "$ep" 0 "$d"
        R_STATUS=$(cut -f5 "$OUT" | head -n 1)
        ;;
    esac
    [ "$R_STATUS" = ok ] && break
  done
  rm -f "$TMPD/probe.$JOB.rec"
  # Короткие строки с O_APPEND пишутся атомарно, общий файл для всех заданий безопасен.
  echo "$key ${R_STATUS:-timeout}" >>"$TMPD/probe"
}

# Доступность проверяется параллельно: мёртвые цели отсекаются за один таймаут, а не за сумму.
probe_all() {
  local n=0 total key mode addr ep st
  total=$(wc -l <"$TMPD/targets")
  : >"$TMPD/down"
  : >"$TMPD/probe"
  JOBS=0
  while IFS='|' read -r key _ _ _ _ mode addr ep _; do
    n=$((n + 1))
    if [ "$mode" = dns6 ] && [ "$HAVE_V6" != yes ]; then
      echo "$key noipv6" >>"$TMPD/down"
      continue
    fi
    JOB=$n
    probe_target "$key" "$mode" "$addr" "$ep" "${DOMAIN_LIST%% *}" </dev/null &
    JOBS=$((JOBS + 1))
    if [ $JOBS -ge $PAR ]; then wait; JOBS=0; fi
    progress "$M_PROBE" "$n" "$total" ""
  done <"$TMPD/targets"
  wait
  JOB=0
  while read -r key st; do
    [ "$st" = ok ] || echo "$key $st"
  done <"$TMPD/probe" >>"$TMPD/down"
}

progress() {
  [ "$PROGRESS" = 1 ] || return 0
  printf '\r\033[K%s %s/%s %s' "$1" "$2" "$3" "$4" >&2
}
progress_done() { [ "$PROGRESS" = 1 ] && printf '\r\033[K' >&2; }

run_rounds() {
  local r=1 n=0 total alive key name mode addr ep doms d k
  awk -F'|' 'FILENAME == ARGV[1] { split($0, f, " "); down[f[1]] = 1; next } !($1 in down)' \
    "$TMPD/down" "$TMPD/targets" >"$TMPD/alive"
  alive=$(wc -l <"$TMPD/alive")
  total=$((alive * ROUNDS))
  OUT=$TMPD/results
  : >"$OUT"
  while [ $r -le "$ROUNDS" ]; do
    # Каждый раунд: другой порядок целей и сдвиг списка доменов, чтобы холодный
    # первый запрос и кеш резолверов распределялись равномерно.
    doms=$DOMAIN_LIST
    k=1
    while [ "$DOMAIN_COUNT" -gt 1 ] && [ $k -lt $(( (r - 1) % DOMAIN_COUNT + 1 )) ]; do
      doms="${doms#* } ${doms%% *}"
      k=$((k + 1))
    done
    awk -v seed="$r$$" 'BEGIN { srand(seed) } { print rand() "\t" $0 }' "$TMPD/alive" | sort -n | cut -f2- >"$TMPD/order"
    while IFS='|' read -r key _ name _ _ mode addr ep _; do
      n=$((n + 1))
      progress "$M_ROUND $r/$ROUNDS" "$n" "$total" "$name"
      case $mode in
        dns4 | dns6)
          for d in $doms; do
            udp_query "$addr" "$d"
            emit "$key" "$r" "$d" single "$R_STATUS" "$R_US"
          done
          ;;
        *)
          # shellcheck disable=SC2086
          session "$key" "$mode" "$addr" "$ep" "$r" $doms
          ;;
      esac
    done <"$TMPD/order"
    r=$((r + 1))
  done
  progress_done
}

# ---------------------------------------------------------------------------
# Отчёт: статистика и таблицы считаются в awk за один проход.

report() {
  local width
  width=${COLS:-80}
  # BusyBox sort на роутерах бывает без -k/-t: сортируем целые строки, время — с нулями слева.
  awk -F'\t' '{ printf "%s\t%s\t%s\t%012d\n", $1, $4, $5, $6 }' "$TMPD/results" | sort >"$TMPD/results.sorted"
  awk -F'\t' \
    -v modes="$MODES" -v top="$OPT_TOP" -v width="$width" -v csv="$OPT_CSV" -v lossmax="$LOSS_MAX" \
    -v hj4="$HIJACK4" -v hj6="$HIJACK6" -v lang="$L" \
    -v bl_dns4="$BL_dns4" -v bl_dns6="$BL_dns6" -v bl_dot="$BL_dot" -v bl_doh="$BL_doh" \
    -v cold_only="$([ "$DOH_BACKEND" = curl ] || echo doh)" \
    -v c_rst="$C_RST" -v c_b="$C_B" -v c_dim="$C_DIM" -v c_red="$C_RED" -v c_grn="$C_GRN" -v c_yel="$C_YEL" -v c_cyn="$C_CYN" \
    -v h_num="$M_C_NUM" -v h_name="$M_C_NAME" -v h_var="$M_C_VAR" -v h_addr="$M_C_ADDR" \
    -v h_med="$M_C_MED" -v h_p90="$M_C_P90" -v h_cold="$M_C_COLD" -v h_loss="$M_C_LOSS" -v u_ms="$M_MS" \
    -v n_udp="$M_N_UDP" -v n_tls="$M_N_TLS" -v n_cold="$M_N_COLD" -v n_sys="$M_N_SYS" -v n_hj="$M_HIJACK_NOTE" \
    -v t_dns4="DNS v4 (UDP/53)" -v t_dns6="DNS v6 (UDP/53)" -v t_dot="DoT (TLS/853)" -v t_doh="DoH (HTTPS)" \
    -v m_rec="$M_REC" -v m_norec="$M_NOREC" \
    -v s_timeout="$S_timeout" -v s_refused="$S_refused" -v s_servfail="$S_servfail" -v s_nxdomain="$S_nxdomain" \
    -v s_empty="$S_empty" -v s_tls="$S_tls" -v s_cert="$S_cert" -v s_neterr="$S_neterr" -v s_badresp="$S_badresp" \
    -v s_h2="$S_h2" -v s_http="$S_http" -v s_fail="$S_fail" -v s_noipv6="IPv6: $M_NO" '
  function vlen(s,  t) { t = s; return length(s) - gsub(/[\200-\277]/, "", t) }
  function pad(s, w) { while (vlen(s) < w) s = s " "; return s }
  function lpad(s, w) { while (vlen(s) < w) s = " " s; return s }
  function cut(s, w) { return length(s) > w ? substr(s, 1, w - 2) ".." : s }
  function ms(us) { return sprintf("%.1f", us / 1000) }
  function reason(st) {
    if (st ~ /^http/) return s_http " " substr(st, 5)
    if (st == "timeout") return s_timeout; if (st == "refused") return s_refused
    if (st == "servfail") return s_servfail; if (st == "nxdomain") return s_nxdomain
    if (st == "empty") return s_empty; if (st == "tls") return s_tls; if (st == "cert") return s_cert
    if (st == "neterr") return s_neterr; if (st == "h2") return s_h2; if (st == "noipv6") return s_noipv6
    if (st == "fail") return s_fail
    return s_badresp
  }
  FILENAME == ARGV[1] {
    split($0, f, "|")
    k = f[1]; T[k] = 1; NAME[k] = f[3]; VAR[k] = f[5]; MODE[k] = f[6]; ADDR[k] = f[7]; EP[k] = f[8]; KIND[k] = f[9]
    ORDER[++nt] = k
    next
  }
  FILENAME == ARGV[2] { split($0, f, " "); DOWN[f[1]] = f[2]; next }
  {
    k = $1; ph = $2; st = $3
    TOT[k]++
    if (st != "ok") { ERR[k, st]++; if (ERR[k, st] > ERRMAX[k]) { ERRMAX[k] = ERR[k, st]; ERRTOP[k] = st }; next }
    OK[k]++
    n = ++CNT[k, ph]; S[k, ph, n] = $4 + 0; SUM[k, ph] += $4
  }
  function q(k, ph, p,  n, i) { n = CNT[k, ph]; if (!n) return -1; i = int(n * p + 0.9999); if (i < 1) i = 1; return S[k, ph, i] }
  function med(k, ph,  n) {
    n = CNT[k, ph]; if (!n) return -1
    return n % 2 ? S[k, ph, (n + 1) / 2] : (S[k, ph, n / 2] + S[k, ph, n / 2 + 1]) / 2
  }
  END {
    nm = split(modes, M, ",")
    wide = width >= 100
    for (mi = 1; mi <= nm; mi++) {
      m = M[mi]; tls = (m == "dot" || m == "doh")
      hj = (m == "dns4" && hj4 == "yes") || (m == "dns6" && hj6 == "yes")
      rows = 0
      for (i = 1; i <= nt; i++) {
        k = ORDER[i]; if (MODE[k] != m) continue
        ph = tls ? (CNT[k, "warm"] ? "warm" : "cold") : "single"
        R[++rows] = k; PH[k] = ph
        MED[k] = med(k, ph); P90[k] = q(k, ph, 0.9)
        COLD[k] = tls ? med(k, "cold") : -1
        LOSS[k] = TOT[k] ? (TOT[k] - OK[k]) * 100 / TOT[k] : 100
        # Ключ сортировки: живые без потерь, живые с потерями, системные, недоступные.
        cls = (k in DOWN || !OK[k]) ? 3 : (LOSS[k] > lossmax ? 1 : 0)
        if (KIND[k] == "system" && cls < 3) cls = 2
        KEY[k] = sprintf("%d %012d %012d", cls, MED[k] < 0 ? 0 : MED[k], P90[k] < 0 ? 0 : P90[k])
        CLS[k] = cls
      }
      if (!rows) continue
      for (i = 2; i <= rows; i++) { x = R[i]; for (j = i - 1; j >= 1 && KEY[R[j]] > KEY[x]; j--) R[j + 1] = R[j]; R[j + 1] = x }

      title = m == "dns4" ? t_dns4 : m == "dns6" ? t_dns6 : m == "dot" ? t_dot : t_doh
      bl = m == "dns4" ? bl_dns4 : m == "dns6" ? bl_dns6 : m == "dot" ? bl_dot : bl_doh
      printf "\n%s%s%s  %s%s%s\n", c_b, title, c_rst, c_dim, bl, c_rst
      if (hj) printf "%s! %s%s\n", c_red, n_hj, c_rst
      wn = wide ? 24 : 20; wa = wide ? 34 : 0
      line = lpad(h_num, 3) "  " pad(h_name, wn) pad(h_var, 9)
      if (wide) line = line pad(h_addr, wa)
      line = line lpad(h_med, 8) lpad(h_p90, 8)
      if (tls) line = line lpad(h_cold, 10)
      line = line lpad(h_loss, 8)
      printf "%s%s%s\n", c_dim, line, c_rst

      shown = 0; rank = 0; nrec = 0
      for (i = 1; i <= rows; i++) {
        k = R[i]
        addr = m == "doh" ? EP[k] : m == "dot" ? EP[k] : ADDR[k]
        if (CLS[k] == 3) {
          st = (k in DOWN) ? DOWN[k] : ERRTOP[k]
          if (top > 0 && shown >= top) continue
          line = "  -  " pad(cut(NAME[k], wn - 1), wn) pad(VAR[k], 9)
          if (wide) line = line pad(cut(addr, wa - 1), wa)
          printf "%s%s%s%s\n", c_dim, line, c_red reason(st), c_rst
          shown++
          if (csv != "") printf "%s,%s,%s,%s,%s,,,,,100,0,%s\n", m, NAME[k], VAR[k], ADDR[k], EP[k], st >> csv
          continue
        }
        if (CLS[k] < 2) rank++
        if (top > 0 && shown >= top) continue
        num = CLS[k] < 2 ? rank : "*"
        cn = (CLS[k] == 0 && rank <= 3 && !hj) ? c_grn : ""
        line = lpad(num, 3) "  " pad(cut(NAME[k], wn - 1), wn) pad(VAR[k], 9)
        if (wide) line = line pad(cut(addr, wa - 1), wa)
        cell = lpad(ms(MED[k]), 8) lpad(ms(P90[k]), 8)
        if (tls) cell = cell lpad(COLD[k] < 0 ? "-" : ms(COLD[k]), 10)
        ls = sprintf("%.0f%%", LOSS[k])
        lc = LOSS[k] > 0 ? c_yel : ""
        note = CLS[k] == 2 ? "  " c_dim n_sys c_rst : (LOSS[k] > 0 && ERRTOP[k] != "" ? "  " c_dim reason(ERRTOP[k]) c_rst : "")
        printf "%s%s%s%s%s%s%s\n", cn, line, c_rst, cell, lc lpad(ls, 8), c_rst, note
        shown++
        if (csv != "") printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%.1f,%d,ok\n", m, NAME[k], VAR[k], ADDR[k], EP[k], ms(MED[k]), ms(P90[k]), CNT[k, PH[k]] ? ms(SUM[k, PH[k]] / CNT[k, PH[k]]) : "", COLD[k] < 0 ? "" : ms(COLD[k]), LOSS[k], TOT[k] >> csv
        if (CLS[k] == 0 && KIND[k] == "public" && nrec < 3 && !hj) { nrec++; REC[m, nrec] = k }
      }
      if (rows > shown) printf "%s  ... +%d%s\n", c_dim, rows - shown, c_rst
      printf "%s%s%s\n", c_dim, tls ? (m == cold_only ? n_cold : n_tls) : n_udp, c_rst
      NREC[m] = nrec
    }

    printf "\n%s%s%s\n", c_b, m_rec, c_rst
    for (mi = 1; mi <= nm; mi++) {
      m = M[mi]
      title = m == "dns4" ? "DNS v4" : m == "dns6" ? "DNS v6" : m == "dot" ? "DoT" : "DoH"
      if (!NREC[m]) {
        hj = (m == "dns4" && hj4 == "yes") || (m == "dns6" && hj6 == "yes")
        printf "  %-7s %s%s%s\n", title, c_dim, hj ? n_hj : m_norec, c_rst
        continue
      }
      for (r = 1; r <= NREC[m]; r++) {
        k = REC[m, r]
        setup = m == "doh" ? EP[k] : m == "dot" ? EP[k] " (" ADDR[k] ")" : ADDR[k]
        printf "  %-7s %s%d. %s%s  %s%s%s  %s %s\n", r == 1 ? title : "", c_grn, r, NAME[k], c_rst, c_cyn, setup, c_rst, ms(MED[k]), u_ms
      }
    }
  }' "$TMPD/targets" "$TMPD/down" "$TMPD/results.sorted"
}

# ---------------------------------------------------------------------------
# Самопроверка: эталоны из RFC 8484 и вручную собранные ответы.

self_test() {
  local fail=0 got
  TMPD=${TMPDIR:-/tmp}/dnstest.self.$$
  mkdir -p "$TMPD" || die "tmp"
  hex_init
  check() { if [ "$2" = "$3" ]; then printf 'ok    %s\n' "$1"; else printf 'FAIL  %s: %s != %s\n' "$1" "$2" "$3"; fail=1; fi; }
  build_query www.example.com 0
  printf "$Q" >"$TMPD/q"
  check "build_query" "$(hex_file "$TMPD/q")" "00000100000100000000000003777777076578616d706c6503636f6d0000010001"
  check "query length" "$QLEN" 33
  printf "$P" >"$TMPD/p"
  check "tcp prefix" "$(hex_file "$TMPD/p")" "0021"
  check "base64url (RFC 8484)" "$(doh_params www.example.com)" "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
  check "base64url digits" "$(doh_params a-1.b2)" "AAABAAABAAAAAAAAA2EtMQJiMgAAAQAB"
  parse_dns "abcd81800001000300000000" abcd; check "parse ok" "$R_STATUS" ok
  parse_dns "abcd81830001000000000000" abcd; check "parse nxdomain" "$R_STATUS" nxdomain
  parse_dns "abcd81850001000000000000" abcd; check "parse refused" "$R_STATUS" refused
  parse_dns "abcd81820001000000000000" abcd; check "parse servfail" "$R_STATUS" servfail
  parse_dns "abcd81800001000000000000" abcd; check "parse empty" "$R_STATUS" empty
  parse_dns "abce81800001000300000000" abcd; check "parse wrong id" "$R_STATUS" badresp
  parse_dns "abcd01000001000300000000" abcd; check "parse query, not answer" "$R_STATUS" badresp
  ms_to_us 73.6; check "ms_to_us" "$US" 73600
  ms_to_us 4; check "ms_to_us int" "$US" 4000
  sec_to_us 0.073456; check "sec_to_us" "$US" 73456
  sec_to_us 1.000009; check "sec_to_us leading zeros" "$US" 1000009
  valid_domain ya.ru && got=yes || got=no; check "valid ya.ru" "$got" yes
  valid_domain "xn--80ak6aa92e.com" && got=yes || got=no; check "valid punycode" "$got" yes
  valid_domain "пример.рф" && got=yes || got=no; check "reject IDN" "$got" no
  valid_domain "a..b" && got=yes || got=no; check "reject empty label" "$got" no
  rm -rf "$TMPD"
  return $fail
}

# ---------------------------------------------------------------------------
# Аргументы и вопросы

parse_args() {
  local opt val
  while [ $# -gt 0 ]; do
    opt=$1 val=
    case $opt in
      --*=*) val=${opt#*=}; opt=${opt%%=*} ;;
      --lang | --profile | --runs | --domains | --custom-domains | --providers | --modes | --variants | --top | --timeout | --csv)
        [ $# -ge 2 ] || { USAGE_ERR="$opt"; return 0; }
        val=$2; shift ;;
    esac
    case $opt in
      --lang) OPT_LANG=$val ;;
      --profile) OPT_PROFILE=$val ;;
      --runs) OPT_RUNS=$val ;;
      --domains) OPT_DOMAINS=$val ;;
      --custom-domains) OPT_CUSTOM=$val; OPT_DOMAINS=custom ;;
      --providers) OPT_PROVIDERS=$val ;;
      --modes) OPT_MODES=$val ;;
      --variants) OPT_VARIANTS=$val ;;
      --top) OPT_TOP=$val ;;
      --timeout) OPT_TIMEOUT=$val ;;
      --csv) OPT_CSV=$val ;;
      --no-color) OPT_COLOR=off ;;
      -y | --yes) OPT_YES=1 ;;
      --list) ACTION=list ;;
      --self-test) ACTION=selftest ;;
      --version) ACTION=version ;;
      -h | --help) ACTION=help ;;
      *) USAGE_ERR=$opt; return 0 ;;
    esac
    shift
  done
}

ask() { # prompt default → A
  printf '%s [%s %s]: ' "$1" "$Q_DEFAULT" "$2" >/dev/tty
  A=
  read -r A </dev/tty || A=
  [ -n "$A" ] || A=$2
}

interactive() {
  ask "$Q_LANG" "$([ "$L" = ru ] && echo 1 || echo 2)"
  case $A in 2 | en) set_lang en ;; *) set_lang ru ;; esac
  ask "$Q_PROFILE" 1
  case $A in 2) OPT_PROFILE=stability ;; *) OPT_PROFILE=quick ;; esac
  ask "$Q_DOMAINS" 1
  case $A in 2) OPT_DOMAINS=global ;; 3) OPT_DOMAINS=all ;; 4) OPT_DOMAINS=custom ;; *) OPT_DOMAINS=ru ;; esac
  if [ "$OPT_DOMAINS" = custom ]; then ask "$Q_CUSTOM" "ya.ru"; OPT_CUSTOM=$A; fi
  ask "$Q_PROVIDERS" 1
  case $A in 2) OPT_PROVIDERS=ru ;; 3) OPT_PROVIDERS=global ;; 4) OPT_PROVIDERS=system ;; *) OPT_PROVIDERS=all ;; esac
  local def='' m
  for m in 1:dns4 2:dns6 3:dot 4:doh; do mode_available "${m#*:}" && def="$def,${m%%:*}"; done
  ask "$Q_MODES" "${def#,}"
  OPT_MODES=
  for m in $(echo "$A" | tr ',' ' '); do
    case $m in 1 | dns4) m='dns4' ;; 2 | dns6) m='dns6' ;; 3 | dot) m='dot' ;; 4 | doh) m='doh' ;; esac
    OPT_MODES="$OPT_MODES,$m"
  done
  OPT_MODES=${OPT_MODES#,}
  printf '\n' >/dev/tty
}

resolve_settings() {
  case ${OPT_PROFILE:-quick} in
    quick) ROUNDS=3 LOSS_MAX=0 ;;
    stability) ROUNDS=10 LOSS_MAX=5 ;;
    *) die "--profile quick|stability" ;;
  esac
  if [ -n "$OPT_RUNS" ]; then
    case $OPT_RUNS in '' | *[!0-9]* | 0) die "--runs N" ;; esac
    ROUNDS=$OPT_RUNS
    [ "$ROUNDS" -ge 5 ] && LOSS_MAX=5
  fi
  case $OPT_TOP in *[!0-9]* | '') die "--top N" ;; esac
  case $OPT_TIMEOUT in *[!0-9]* | '' | 0) die "--timeout SEC" ;; esac

  case ${OPT_DOMAINS:-ru} in
    ru) DOMAIN_LIST=$DOMAINS_RU ;;
    global) DOMAIN_LIST=$DOMAINS_GLOBAL ;;
    all) DOMAIN_LIST="$DOMAINS_RU $DOMAINS_GLOBAL" ;;
    custom) DOMAIN_LIST=$(echo "$OPT_CUSTOM" | tr ',' ' ') ;;
    *) die "--domains ru|global|all|custom" ;;
  esac
  local d list='' m
  for d in $DOMAIN_LIST; do
    valid_domain "$d" || die "domain: $d"
    list="$list $d"
  done
  DOMAIN_LIST=${list# }
  [ -n "$DOMAIN_LIST" ] || die "--custom-domains"
  DOMAIN_COUNT=0
  for d in $DOMAIN_LIST; do DOMAIN_COUNT=$((DOMAIN_COUNT + 1)); done

  case ${OPT_PROVIDERS:=all} in all | ru | global | system) ;; *) die "--providers all|ru|global|system" ;; esac

  MODES=
  if [ -z "$OPT_MODES" ]; then
    for m in dns4 dns6 dot doh; do mode_available "$m" && MODES="$MODES,$m"; done
  else
    for m in $(echo "$OPT_MODES" | tr ',' ' '); do
      case $m in dns4 | dns6 | dot | doh) ;; *) die "--modes dns4,dns6,dot,doh: $m" ;; esac
      if mode_available "$m"; then MODES="$MODES,$m"; else warn "$m: $M_NONE"; fi
    done
  fi
  MODES=${MODES#,}
  [ -n "$MODES" ] || die "--modes: $M_NONE"
}

print_catalog() {
  catalog | awk -F'|' '/^@/ { printf "\n%s  [%s, %s]\n", $2, $3, $4; next } { printf "  %s\n", $0 }'
}

# ---------------------------------------------------------------------------

main() {
  parse_args "$@"
  case ${OPT_LANG:-${LC_MESSAGES:-${LANG:-}}} in ru*) set_lang ru ;; *) set_lang en ;; esac
  [ -z "${USAGE_ERR:-}" ] || { usage >&2; die "$USAGE_ERR"; }
  case $ACTION in
    help) usage; exit 0 ;;
    version) echo "dns-speedtest $VERSION"; exit 0 ;;
    list) print_catalog; exit 0 ;;
    selftest) self_test; exit $? ;;
  esac

  TMPD=$(mktemp -d "${TMPDIR:-/tmp}/dnstest.XXXXXX" 2>/dev/null) || {
    TMPD=${TMPDIR:-/tmp}/dnstest.$$
    mkdir "$TMPD" || die "tmp"
  }
  trap 'rm -rf "$TMPD"' EXIT
  trap 'progress_done; exit 130' INT TERM
  JOB=0

  timer_init
  now_us
  RNG=$(( ($$ * 7919 + NOW) % 2147483647 ))
  hex_init
  have awk || die "awk"
  have sort || die "sort"
  detect_env

  if [ $# -eq 0 ] && [ "$OPT_YES" = 0 ] && (: </dev/tty) 2>/dev/null; then
    interactive
  fi
  color_init
  resolve_settings
  calibrate_nslookup

  COLS=${COLUMNS:-}
  [ -z "$COLS" ] && COLS=$({ stty size </dev/tty; } 2>/dev/null | cut -d' ' -f2)
  case $COLS in '' | *[!0-9]*) COLS=80 ;; esac
  PROGRESS=0
  [ -t 2 ] && PROGRESS=1

  build_targets
  [ -s "$TMPD/targets" ] || die "$M_TARGETS: 0"

  local m v line=''
  for m in dns4 dns6 dot doh; do
    backend_label "$m"
    line="$line · $m ${BL:-$M_NONE}"
  done
  backend_label dns4; BL_dns4=$BL
  backend_label dns6; BL_dns6=$BL
  backend_label dot; BL_dot=$BL
  backend_label doh; BL_doh=$BL

  printf '%sdns-speedtest %s%s  %s%s%s\n' "$C_B" "$VERSION" "$C_RST" "$C_DIM" "$PROJECT_URL" "$C_RST"
  printf '  %s: %s · %s: %s\n' "$M_SHELL" "$SHELL_NAME" "$M_TIMER" "$TIMER"
  printf '  %s: %s\n' "$M_TRANSPORT" "${line# · }"
  printf '  %s: %s\n' "$M_DOMAINS" "$DOMAIN_LIST"

  HIJACK4=no HIJACK6=no HAVE_V6=no
  case ",$MODES," in *,dns4,*)
    check_hijack "$ROOT4"; HIJACK4=$HJ
    case $HJ in yes) v=$C_RED$M_YES$C_RST ;; no) v=$M_NO ;; *) v=$M_UNKNOWN ;; esac
    printf '  DNS v4: %s — %s\n' "$M_HIJACK" "$v" ;;
  esac
  case ",$MODES," in *,dns6,*)
    udp_query "$V6_PROBE" ya.ru
    # IPv6 есть, только если пришёл настоящий DNS-ответ.
    case $R_STATUS in ok | empty | nxdomain | servfail | refused) HAVE_V6=yes ;; *) HAVE_V6=no ;; esac
    if [ "$HAVE_V6" = yes ]; then
      check_hijack "$ROOT6"; HIJACK6=$HJ
      case $HJ in yes) v=$C_RED$M_YES$C_RST ;; no) v=$M_NO ;; *) v=$M_UNKNOWN ;; esac
      printf '  DNS v6: %s — %s\n' "$M_HIJACK" "$v"
    else
      # Без IPv6 режим dns6 убираем целиком, чтобы не печатать таблицу из одних ошибок.
      printf '  DNS v6: %s — %s\n' "$M_IPV6" "$M_NO"
      MODES=$(echo ",$MODES," | sed 's/,dns6,/,/; s/^,//; s/,$//')
      awk -F'|' '$6 != "dns6"' "$TMPD/targets" >"$TMPD/targets.v4" && mv "$TMPD/targets.v4" "$TMPD/targets"
    fi ;;
  esac
  [ -n "$MODES" ] || die "--modes: $M_NONE"
  printf '  %s: %s · %s: %s\n' "$M_ROUNDS" "$ROUNDS" "$M_TARGETS" "$(wc -l <"$TMPD/targets" | tr -d ' ')"
  [ "$HIJACK4" = yes ] || [ "$HIJACK6" = yes ] && printf '\n%s%s%s\n' "$C_RED" "$M_HIJACK_WARN" "$C_RST"

  now_us
  START=$NOW
  probe_all
  run_rounds
  [ -n "$OPT_CSV" ] && echo "mode,provider,variant,address,endpoint,median_ms,p90_ms,avg_ms,cold_ms,loss_pct,samples,status" >"$OPT_CSV"
  report
  now_us
  printf '\n%s%s %s %s%s\n' "$C_DIM" "$M_DONE" "$(( (NOW - START) / 1000000 ))" "$M_SEC" "$C_RST"
  [ -n "$OPT_CSV" ] && printf '%s: %s\n' "$M_CSV_SAVED" "$OPT_CSV"
  return 0
}

main "$@"
