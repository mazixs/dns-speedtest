# dns-speedtest

[English](README.en.md) · [Релизы](https://github.com/mazixs/dns-speedtest/releases) · GPL-3.0

Тест скорости DNS-серверов по обычному DNS (UDP), DNS over TLS (DoT) и DNS over HTTPS (DoH). Показывает, какой публичный DNS быстрее и стабильнее из вашей сети, и что вписать в настройки роутера.

Работает одним файлом, без установки пакетов:

- `dnstest.sh` — роутеры (OpenWrt, Keenetic с Entware, ASUSWRT-Merlin), Linux, Docker. POSIX sh: BusyBox ash, dash, bash, zsh;
- `dnstest.ps1` — Windows: PowerShell 5.1 из коробки или PowerShell 7.

## Быстрый старт

### Роутер или Linux

Подключитесь к роутеру по SSH и выполните:

```sh
wget -qO /tmp/dnstest.sh https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.sh && sh /tmp/dnstest.sh
```

Если вместо `wget` есть `curl`:

```sh
curl -fsSLo /tmp/dnstest.sh https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.sh && sh /tmp/dnstest.sh
```

Без параметров скрипт задаёт пять вопросов: язык, профиль, домены, провайдеры и режимы. Чтобы запустить без вопросов, добавьте `-y` и нужные параметры:

```sh
sh /tmp/dnstest.sh -y --modes dot,doh --providers ru
```

Если роутер не умеет скачивать по HTTPS, скачайте `dnstest.sh` на компьютер и скопируйте на роутер:

```sh
scp -O dnstest.sh root@192.168.1.1:/tmp/
```

Ключ `-O` нужен для Dropbear, SSH-сервера OpenWrt.

### Windows

Откройте PowerShell и выполните:

```powershell
irm https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.ps1 | iex
```

С параметрами:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/mazixs/dns-speedtest/master/dnstest.ps1))) -Modes dot,doh -Yes
```

Скачанный файл запускается так:

```powershell
powershell -ExecutionPolicy Bypass -File .\dnstest.ps1 -Yes
```

Для DoH лучше PowerShell 7 (`pwsh`): Windows PowerShell 5.1 умеет только HTTP/1.1, и серверы, которые требуют HTTP/2, получат статус «нужен HTTP/2».

### Docker

```sh
docker build -t dns-speedtest .
docker run --rm -it dns-speedtest
```

## Что и как измеряется

| Режим | Протокол | Что считается временем |
|---|---|---|
| DNS v4, DNS v6 | UDP/53 | от отправки запроса до ответа |
| DoT | TLS, порт 853 | запрос по уже открытому TLS-соединению |
| DoH | HTTPS, RFC 8484 (GET) | запрос по уже открытому HTTPS-соединению |

Каждый ответ проверяется: совпадение ID запроса, флаг ответа, код RCODE и наличие записей. NXDOMAIN, SERVFAIL, REFUSED и пустой ответ считаются потерей, а не быстрым ответом.

DoT и DoH в каждом раунде открывают одну TLS-сессию и отправляют по ней все домены. Первый запрос — холодный: TCP, TLS-рукопожатие и сам запрос. Остальные — тёплые. Рейтинг строится по тёплым запросам, потому что DoT/DoH-клиент роутера держит соединение открытым. Холодное время показано отдельной колонкой.

Скрипт подключается к IP-адресу из каталога напрямую и проверяет сертификат по имени сервера. Системный DNS в этом не участвует и не может подменить адрес.

Перед замерами скрипт:

1. Проверяет перехват порта 53. Корневой сервер a.root-servers.net не выполняет рекурсию, поэтому готовый ответ на запрос `ya.ru` означает, что запрос перехватил роутер, VPN или провайдер. В этом случае рейтинг обычного DNS не строится: замер показывает перехватчик.
2. Проверяет доступность всех серверов. Недоступные серверы попадают в конец таблицы с причиной и не тратят время в раундах.

Каждый раунд идёт в случайном порядке серверов, а список доменов сдвигается. Так холодный первый запрос и кеш резолверов распределяются равномерно.

## Как читать отчёт

Фрагмент запуска на Keenetic:

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

- **Медиана** — типичное время ответа, мс. По ней идёт сортировка.
- **p90** — 90 % ответов быстрее этого значения. Большой разрыв между медианой и p90 значит нестабильный сервер.
- **Холодный** — новое соединение и первый запрос.
- **Потери** — доля запросов без корректного ответа.
- Строка со `*` — системный резолвер, он не попадает в рекомендации.
- Строка с `-` — сервер недоступен, справа причина.

Блок «Что поставить» — три лучших сервера без потерь в каждом режиме. Для DoT указаны имя сервера и IP, для DoH — URL.

## Параметры

| sh | PowerShell | Значение |
|---|---|---|
| `--modes LIST` | `-Modes` | `dns4,dns6,dot,doh`, по умолчанию все доступные |
| `--providers SET` | `-Providers` | `all`, `ru`, `global` или `system` |
| `--variants LIST` | `-Variants` | `plain`, `malware`, `family`, `adblock` |
| `--domains SET` | `-Domains` | `ru`, `global`, `all` или `custom`, по умолчанию `ru` |
| `--custom-domains L` | `-CustomDomains` | свои домены через запятую, IDN — в punycode |
| `--profile P` | `-Profile` | `quick` — 3 раунда, `stability` — 10 раундов |
| `--runs N` | `-Runs` | число раундов вместо профиля |
| `--top N` | `-Top` | строк в таблице каждого режима, 0 — все |
| `--timeout SEC` | `-Timeout` | таймаут UDP-запроса, для TLS +2 с, по умолчанию 1 |
| `--csv FILE` | `-Csv` | сохранить сводку в CSV |
| `--lang ru\|en` | `-Lang` | язык, по умолчанию из системы |
| `--no-color` | `-NoColor` | без цвета |
| `-y`, `--yes` | `-Yes` | не задавать вопросов |
| `--list` | `-List` | показать каталог серверов |
| `--self-test` | `-SelfTest` | проверить кодировщик и парсер DNS |
| `--version`, `--help` | `-Version`, `-Help` | версия и справка |

Профиль `quick` считает сервер стабильным только без потерь. Профиль `stability` допускает до 5 % потерь.

## Чем скрипт пользуется

Скрипт сам выбирает лучший доступный инструмент для каждого режима. Если инструмента нет, режим пропускается.

| Режим | Инструменты по приоритету |
|---|---|
| UDP | `kdig`, bash `/dev/udp`, `dig`, `nslookup` |
| DoT | `kdig`, `openssl s_client` |
| DoH | `curl` (HTTP/2, тёплые и холодные запросы), `uclient-fetch` или `wget` (только холодные) |

Что проверено:

| Система | UDP | DoT | DoH |
|---|---|---|---|
| Keenetic, Entware | kdig | kdig | curl, HTTP/2 |
| OpenWrt 24.10 | nslookup | нужен пакет | uclient-fetch |
| Debian, dash | bash | openssl | curl |
| Alpine, BusyBox | nslookup | openssl | curl |
| Windows, PowerShell 7 | встроено | встроено | встроено, HTTP/2 |
| Windows PowerShell 5.1 | встроено | встроено | встроено, HTTP/1.1 |

Чтобы на OpenWrt появился DoT, установите `openssl-util` или `knot-dig`. Для тёплых замеров DoH нужен `curl`.

Скрипт не меняет настройки системы. Временные файлы лежат в `/tmp` и удаляются после завершения.

## Каталог

49 провайдеров: Cloudflare, Google, Quad9, AdGuard, CleanBrowsing, ControlD, DNS.SB, Mullvad, Gcore, OpenDNS, NextDNS, Яндекс, Comss.one, НСДИ, DNS провайдеров и другие. Полный список с адресами:

```sh
sh /tmp/dnstest.sh --list
```

Каталог встроен в оба скрипта и совпадает символ в символ, это проверяет CI. Формат записи:

```
@id|Название|регион|вариант|теги
dns4 1.1.1.1
dot 1.1.1.1 one.one.one.one
doh 1.1.1.1 https://cloudflare-dns.com/dns-query
```

## Вопросы

**Почему тест на компьютере и на роутере даёт разные цифры?**
С компьютера запрос идёт через Wi-Fi и роутер, добавляя их задержку. Кроме того, роутер может перехватывать порт 53. Чтобы выбрать сервер для роутера, запускайте тест на роутере.

**Что делать, если найден перехват UDP/53?**
Обычный DNS в такой сети замерить нельзя: отвечает перехватчик. Смотрите на DoT и DoH, их перехватить без ошибки сертификата нельзя.

**Почему DoT и DoH в таблице почти так же быстры, как обычный DNS?**
В таблице тёплые запросы по открытому соединению, без рукопожатия. Цена нового соединения видна в колонке «Холодный».

**Сколько идёт тест?**
Быстрый профиль на Keenetic со всеми провайдерами и режимами занял 141 с, на Windows в PowerShell 5.1 — 204 с. Ограничьте режимы или провайдеров, чтобы ускорить.

**Как добавить свой сервер?**
Добавьте запись в каталог в обоих файлах и пришлите пул-реквест.
