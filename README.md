<div align="center">

# 🩸 HunterA 2

**Мобильный пентест-фреймворк для Termux без root**

[![Version](https://img.shields.io/badge/version-2.0.0-red)](https://github.com/nitkinov/HunterA2/releases)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Termux](https://img.shields.io/badge/platform-Termux-black)](https://termux.com/)

by [@heyscally](https://t.me/heyscally)

</div>

---

## Что это

HunterA 2 — это не просто набор скриптов, а полноценная платформа для пентеста в Termux. Работает **без root**, имеет мощный TUI (Textual), систему плагинов, кэширование, поддержку прокси и геймификацию.

## 🚀 Что нового в v2.0

*   **Auto-Chain (Автопилот)** — запуск цепочки плагинов одной командой (`chain=recon target=site.com`).
*   **Система тем** — 4 встроенные темы (blood, matrix, cyberpunk, mono), переключение по клавише `t`.
*   **Экран справки** — нажми `?` для вызова модального окна со всеми горячими клавишами.
*   **Менеджер словарей** — используй `wordlist=@common` или `@subdomains`, базы скачаются автоматически.
*   **Глобальные API-ключи** — храни ключи от Shodan/SecurityTrails в `~/.config/huntera2/config.toml`.
*   **Прокси-поддержка** — пускай весь трафик (HTTP/HTTPS) через SOCKS5 или HTTP-прокси (например, Tor).
*   **Прогресс-бар** — визуальное отображение прогресса сканирования портов.

## 📦 Плагины (15 встроенных)

| Плагин | Категория | Что делает |
|---|---|---|
| 🛰 `dns` | Recon | DNS-разведка: A/AAAA/MX/NS/TXT/CNAME/SOA/PTR/SRV/CAA |
| 🔍 `whois` | Recon | WHOIS/RDAP: регистратор, EPP-статусы, DNSSEC, контакты |
| 🔄 `reverse_ip` | Recon | Обратный IP: домены на IP, CIDR, кэш |
| 🔎 `subdomain` | Recon | Перебор поддоменов: brute + crt.sh, wildcard, CNAME |
| 🌍 `geoip` | Recon | Геолокация: страна, ISP, ASN, Tor, CDN |
| ☁ `cloudflair` | Recon | Поиск origin-IP за Cloudflare: CT-логи, DNS, MX/SPF, favicon |
| 🛡 `waf_detect` | Recon | Детект и фингерпринт WAF (Cloudflare, AWS, Akamai и др.) |
| 🤖 `robots` | Recon | Анализ robots.txt/sitemap.xml: скрытые пути, live-check, security.txt |
| 🌐 `http_probe` | Web | Аудит HTTP: security-заголовки, CORS, cookie, оценка A+–F |
| 📂 `dir_brute` | Web | Перебор директорий и файлов |
| 🕷 `crawl` | Web | Веб-краулер: sitemap, JSON-LD, WAF, формы, email |
| 📡 `portscan` | Network | Асинхронный сканер портов: баннеры, профили, CIDR |
| 🔒 `ssl` | TLS | Аудит SSL/TLS: цепочка, шифры, HSTS, уязвимости |
| 🔐 `hash` | Utils | Хеши, Base64, URL, Hex, HMAC, PBKDF2, JWT, identify |
| ⛓ `chain` | Utils | Запуск цепочек плагинов (recon, web, full) |

## ⚙️ Установка

### Требования
- Android с [Termux](https://f-droid.org/en/packages/com.termux/) (из F-Droid, **не** из Google Play).
- Python 3.11+
- ~500 МБ свободного места

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
