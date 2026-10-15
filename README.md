<div align="center">

# 🩸 HunterA 2

**Мобильный пентест-фреймворк для Termux без root**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red)](LICENSE)
[![Termux](https://img.shields.io/badge/platform-Termux-black)](https://termux.com/)

by [@heyscally](https://t.me/heyscally)

</div>

---

## Что это

HunterA 2 — переписанный с нуля мультитул для пентеста в Termux. Работает **без root**, использует TUI (Textual) и поддерживает плагины через entry points.

## Возможности

| Плагин | Категория | Что делает |
|---|---|---|
| 🛰 `dns` | Recon | DNS-разведка: A/AAAA/MX/NS/TXT/CNAME/SOA/PTR/SRV/CAA |
| 🔍 `whois` | Recon | WHOIS/RDAP: регистратор, EPP-статусы, DNSSEC, контакты |
| 🔄 `reverse_ip` | Recon | Обратный IP: домены на IP, CIDR, кэш |
| 🔎 `subdomain` | Recon | Перебор поддоменов: brute + crt.sh, wildcard, CNAME |
| 🌍 `geoip` | Recon | Геолокация: страна, ISP, ASN, Tor, CDN |
| ☁ `cloudflair` | Recon | Поиск origin-IP за Cloudflare: CT-логи, DNS, MX/SPF, favicon |
| 🛡 `waf_detect` | Recon | Детект и фингерпринт WAF: заголовки, cookies, тело, активные пробы |
| 🤖 `robots` | Recon | Анализ robots.txt/sitemap.xml: скрытые пути, live-check, security.txt |
| 🌐 `http_probe` | Web | Аудит HTTP: security-заголовки, CORS, cookie, оценка A+–F |
| 📂 `dir_brute` | Web | Перебор директорий и файлов |
| 🕷 `crawl` | Web | Веб-краулер: sitemap, JSON-LD, WAF, формы, email |
| 📡 `portscan` | Network | Асинхронный сканер портов: баннеры, профили, CIDR |
| 🔒 `ssl` | TLS | Аудит SSL/TLS: цепочка, шифры, HSTS, уязвимости |
| 🔐 `hash` | Utils | Хеши, Base64, URL, Hex, HMAC, PBKDF2, JWT, identify |

**14 плагинов** в 5 категориях (Recon, Web, Network, TLS, Utils).

## Ключевые фишки

- **TUI с категориями** — фильтр по `1`–`6`, счётчики плагинов, кровавая подсветка выбора
- **Потоковый вывод** — результаты `portscan` появляются в реальном времени
- **Графики** — после `portscan` автоматически строится bar chart сервисов
- **Кэширование** — повторные `whois`, `dns`, `geoip`, `ssl`, `cloudflair`, `subdomain` мгновенны
- **Цветные уровни угроз** — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` в бейджах с фоном
- **Плагины через entry points** — можно публиковать свои на PyPI
- **Live-проверка** — `robots check=1` показывает, реально ли закрыт путь

## Установка

### Требования

- Android с [Termux](https://f-droid.org/en/packages/com.termux/) (из F-Droid, **не** из Google Play)
- ~500 МБ свободного места
- Python 3.11+

### Быстрая установка

```bash
# 1. Клонировать
git clone https://github.com/nitkinov/HunterA2.git

# 2. Перейти в директорию
cd HunterA2

# 3. Запустить установщик
bash install.sh

# 4. Запустить
huntera2
