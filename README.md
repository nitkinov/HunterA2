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
| 🔎 `subdomain` | Recon | Перебор поддоменов: brute + crt.sh, wildcard |
| 🌍 `geoip` | Recon | Геолокация: страна, ISP, ASN, Tor, CDN |
| 🌐 `http_probe` | Web | Аудит HTTP: security-заголовки, CORS, cookie, оценка A+–F |
| 📂 `dir_brute` | Web | Перебор директорий и файлов |
| 🕷 `crawl` | Web | Веб-краулер: sitemap, JSON-LD, WAF, формы, email |
| 📡 `portscan` | Network | Асинхронный сканер портов: баннеры, профили, CIDR |
| 🔒 `ssl` | TLS | Аудит SSL/TLS: цепочка, шифры, HSTS, уязвимости |
| 🔐 `hash` | Utils | Хеши, Base64, URL, Hex, HMAC, PBKDF2, JWT, identify |

## Установка

```bash
# 1. Клонировать
git clone https://github.com/heyscally/huntera2.git
cd huntera2

# 2. Установить (всё автоматически)
bash install.sh

# 3. Запустить
huntera2

