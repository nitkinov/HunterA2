import asyncio
import concurrent.futures
import hashlib
import json
import re
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from urllib.parse import urljoin, urlparse

from huntera2.sdk import Plugin

try:
    import httpx
    from bs4 import BeautifulSoup
    DEPS_AVAILABLE = True
except ImportError:
    DEPS_AVAILABLE = False

# --- Regex ---
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_REGEX = re.compile(r"\+?\d[\d\s\-().]{7,}\d")

# --- Технологии ---
TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes"],
    "React": [r"_next/static", r"react\.js"],
    "Vue.js": [r"vue\.js", r"vue\.min\.js", r"__vue__"],
    "Angular": [r"ng-app", r"angular\.js", r"ng-version"],
    "Bootstrap": [r"bootstrap\.css", r"bootstrap\.min\.css"],
    "jQuery": [r"jquery"],
    "Cloudflare": [r"cloudflare"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Nuxt": [r"__NUXT__", r"_nuxt/"],
    "Tailwind": [r"tailwind"],
    "Google Analytics": [r"google-analytics\.com", r"gtag/"],
    "Google Tag Manager": [r"googletagmanager\.com"],
    "Facebook Pixel": [r"connect\.facebook\.net"],
    "Font Awesome": [r"font-awesome", r"fontawesome"],
}

# --- WAF / CAPTCHA ---
WAF_SIGNATURES = {
    "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cf-chl-"],
    "AWS WAF": [r"awselb", r"x-amzn-requestid"],
    "Akamai": [r"akamai", r"ak-bmsc"],
    "Sucuri": [r"sucuri", r"x-sucuri-id"],
    "Imperva": [r"imperva", r"incap_ses"],
    "ModSecurity": [r"mod_security", r"modsecurity"],
}

CAPTCHA_SIGNATURES = {
    "reCAPTCHA v2": [r"g-recaptcha", r"recaptcha/api"],
    "reCAPTCHA v3": [r"recaptcha/api\.js\?render"],
    "hCaptcha": [r"hcaptcha\.com"],
    "Cloudflare Turnstile": [r"challenges\.cloudflare\.com/turnstile"],
    "Cloudflare Challenge": [r"cf-chl-", r"jschl-answer"],
}

# --- Пропускаемые расширения ---
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".rar", ".tar", ".gz",
    ".exe", ".dmg", ".iso", ".apk",
}

# --- Максимум попыток ---
MAX_RETRIES = 3
RETRY_BACKOFF = 1.5  # секунды * (attempt ** 2)


def _normalize_url(url: str, base: str) -> str | None:
    try:
        absolute = urljoin(base, url)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return None
        clean = parsed._replace(fragment="").geturl()
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return None
        return clean
    except Exception:
        return None


def _same_domain(url: str, base_netloc: str) -> bool:
    try:
        return urlparse(url).netloc == base_netloc
    except Exception:
        return False


def _detect_waf(html: str, headers: dict) -> list[str]:
    found = set()
    html_lower = html.lower()
    headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    for waf, patterns in WAF_SIGNATURES.items():
        for p in patterns:
            if re.search(p, html_lower) or re.search(p, headers_str):
                found.add(waf)
                break
    return sorted(found)


def _detect_captcha(html: str) -> list[str]:
    found = set()
    html_lower = html.lower()
    for captcha, patterns in CAPTCHA_SIGNATURES.items():
        for p in patterns:
            if re.search(p, html_lower):
                found.add(captcha)
                break
    return sorted(found)


def _detect_techs(html: str, headers: dict) -> list[str]:
    found = set()
    html_lower = html.lower()
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, html_lower):
                found.add(tech)
                break
    server = headers.get("server", "").lower()
    if "nginx" in server:
        found.add("Nginx")
    if "apache" in server:
        found.add("Apache")
    if "cloudflare" in server:
        found.add("Cloudflare")
    return sorted(found)


def _extract_structured_data(soup) -> list[dict]:
    """Извлекает JSON-LD, microdata, RDFa."""
    results = []
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(script.string or "")
            results.append({"type": "json-ld", "data": data})
        except Exception:
            pass
    return results


def _extract_tables(soup) -> list[dict]:
    tables = []
    for table in soup.find_all("table"):
        headers = [th.get_text(strip=True) for th in table.find_all("th")]
        rows = []
        for tr in table.find_all("tr"):
            cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
            if cells:
                rows.append(cells)
        if rows:
            tables.append({"headers": headers, "rows": rows[:20], "total_rows": len(rows)})
    return tables


def _detect_language(soup, headers: dict) -> str:
    html_tag = soup.find("html")
    if html_tag and html_tag.get("lang"):
        return html_tag["lang"]
    meta = soup.find("meta", attrs={"http-equiv": re.compile("content-language", re.I)})
    if meta and meta.get("content"):
        return meta["content"]
    return headers.get("content-language", "")


def _parse_page(url: str, html: str, headers: dict):
    soup = BeautifulSoup(html, "html.parser")

    # Ссылки
    links = set()
    for a in soup.find_all("a", href=True):
        norm = _normalize_url(a["href"], url)
        if norm:
            links.add(norm)

    # Email
    emails = set(EMAIL_REGEX.findall(html))
    for a in soup.find_all("a", href=True):
        if a["href"].lower().startswith("mailto:"):
            email = a["href"][7:].split("?")[0].strip()
            if email:
                emails.add(email)

    # Телефоны
    phones = set()
    for a in soup.find_all("a", href=True):
        if a["href"].lower().startswith("tel:"):
            phones.add(a["href"][4:].strip())
    for m in PHONE_REGEX.finditer(soup.get_text()[:5000]):
        phones.add(m.group().strip())

    # Формы
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                fields.append({"name": name, "type": inp.get("type", "text")})
        has_csrf = any("csrf" in f["name"].lower() or "token" in f["name"].lower() for f in fields)
        has_captcha = any("captcha" in f["name"].lower() for f in fields)
        forms.append({
            "action": urljoin(url, action) if action else url,
            "method": method,
            "fields": fields,
            "has_csrf": has_csrf,
            "has_captcha": has_captcha,
        })

    # Meta
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    description = ""
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        description = meta_desc.get("content", "").strip()

    return {
        "links": sorted(links),
        "emails": sorted(emails),
        "phones": sorted(phones),
        "forms": forms,
        "title": title,
        "description": description,
        "technologies": _detect_techs(html, headers),
        "waf": _detect_waf(html, headers),
        "captcha": _detect_captcha(html),
        "structured_data": _extract_structured_data(soup),
        "tables": _extract_tables(soup),
        "language": _detect_language(soup, headers),
    }


async def _fetch_with_retry(client, url: str, timeout: float) -> tuple[str, str, dict] | None:
    """Загружает страницу с ретраями и exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            r = await client.get(url, timeout=timeout, follow_redirects=True)
            if r.status_code == 429 or r.status_code == 503:
                retry_after = r.headers.get("retry-after")
                wait = float(retry_after) if retry_after and retry_after.isdigit() else RETRY_BACKOFF * (attempt + 1) ** 2
                await asyncio.sleep(wait)
                continue
            if r.status_code >= 500:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1) ** 2)
                continue
            if r.status_code >= 400:
                return None
            return url, r.text, dict(r.headers)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ConnectError):
            if attempt == MAX_RETRIES - 1:
                return None
            await asyncio.sleep(RETRY_BACKOFF * (attempt + 1) ** 2)
        except Exception:
            return None
    return None


async def _fetch_sitemap(client, base_origin: str, timeout: float) -> list[str]:
    """Парсит sitemap.xml и возвращает список URL."""
    urls = set()
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml"):
        try:
            r = await client.get(urljoin(base_origin, path), timeout=timeout)
            if r.status_code != 200:
                continue
            text = r.text
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.IGNORECASE)
            for loc in locs:
                loc = loc.strip()
                if loc.endswith(".xml") and "sitemap" in loc.lower():
                    # sitemap index — рекурсивно
                    try:
                        r2 = await client.get(loc, timeout=timeout)
                        if r2.status_code == 200:
                            for sub in re.findall(r"<loc>\s*(.*?)\s*</loc>", r2.text, re.IGNORECASE):
                                urls.add(sub.strip())
                    except Exception:
                        pass
                elif loc.startswith("http"):
                    urls.add(loc)
            if urls:
                break
        except Exception:
            continue
    return sorted(urls)


async def _crawl_async(start_url: str, max_depth: int, max_pages: int,
                       concurrency: int, delay: float, timeout: float,
                       respect_robots: bool, user_agent: str,
                       use_sitemap: bool):
    parsed = urlparse(start_url)
    base_netloc = parsed.netloc
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # Robots
    rp = None
    if respect_robots:
        try:
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(urljoin(base_origin, "/robots.txt"))
            rp.read()
        except Exception:
            rp = None

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    headers = {"User-Agent": user_agent}
    sem = asyncio.Semaphore(concurrency)

    visited: set[str] = set()
    seen_hashes: set[str] = set()
    pages: dict[str, dict] = {}
    all_emails: set[str] = set()
    all_phones: set[str] = set()
    all_technologies: set[str] = set()
    all_waf: set[str] = set()
    all_captcha: set[str] = set()
    all_forms: list[dict] = []
    all_structured: list[dict] = []
    all_tables: list[dict] = []
    languages: set[str] = set()

    queue: deque = deque([(start_url, 0)])

    async with httpx.AsyncClient(limits=limits, headers=headers, verify=False) as client:
        # Sitemap
        sitemap_count = 0
        if use_sitemap:
            sitemap_urls = await _fetch_sitemap(client, base_origin, timeout)
            for u in sitemap_urls:
                if _same_domain(u, base_netloc) and u not in visited:
                    queue.append((u, 1))
            sitemap_count = len(sitemap_urls)

        while queue and len(pages) < max_pages:
            batch = []
            while queue and len(batch) < concurrency and len(pages) + len(batch) < max_pages:
                url, depth = queue.popleft()
                if url in visited or depth > max_depth:
                    continue
                if respect_robots and rp and not rp.can_fetch(user_agent, url):
                    continue
                visited.add(url)
                batch.append((url, depth))

            if not batch:
                break

            async def _bounded(u, d):
                async with sem:
                    if delay > 0:
                        await asyncio.sleep(delay)
                    return await _fetch_with_retry(client, u, timeout)

            tasks = [asyncio.create_task(_bounded(u, d)) for u, d in batch]
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if not result:
                    continue
                url, html, headers = result
                depth = next((d for u, d in batch if u == url), 0)

                # Дедупликация по контенту
                content_hash = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)

                parsed_page = _parse_page(url, html, headers)
                pages[url] = {
                    "title": parsed_page["title"],
                    "description": parsed_page["description"],
                    "language": parsed_page["language"],
                    "emails": parsed_page["emails"],
                    "phones": parsed_page["phones"],
                    "forms": parsed_page["forms"],
                    "technologies": parsed_page["technologies"],
                    "waf": parsed_page["waf"],
                    "captcha": parsed_page["captcha"],
                    "structured_data_count": len(parsed_page["structured_data"]),
                    "tables_count": len(parsed_page["tables"]),
                    "links_count": len(parsed_page["links"]),
                }
                all_emails.update(parsed_page["emails"])
                all_phones.update(parsed_page["phones"])
                all_technologies.update(parsed_page["technologies"])
                all_waf.update(parsed_page["waf"])
                all_captcha.update(parsed_page["captcha"])
                all_forms.extend(parsed_page["forms"])
                all_structured.extend(parsed_page["structured_data"])
                all_tables.extend(parsed_page["tables"])
                if parsed_page["language"]:
                    languages.add(parsed_page["language"])

                if depth < max_depth:
                    for link in parsed_page["links"]:
                        if link not in visited and _same_domain(link, base_netloc):
                            queue.append((link, depth + 1))

    return {
        "start_url": start_url,
        "base_domain": base_netloc,
        "pages_crawled": len(pages),
        "sitemap_urls": sitemap_count,
        "pages": pages,
        "emails": sorted(all_emails),
        "phones": sorted(all_phones),
        "forms": all_forms,
        "technologies": sorted(all_technologies),
        "waf": sorted(all_waf),
        "captcha": sorted(all_captcha),
        "structured_data": all_structured,
        "tables": all_tables,
        "languages": sorted(languages),
    }


def _run_crawl_in_thread(**kwargs):
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_crawl_async(**kwargs))
        finally:
            loop.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


class Crawl(Plugin):
    name = "crawl"
    description = "Advanced async crawler: sitemap, retries, dedup, WAF/CAPTCHA, structured data, tables"
    usage = "url=https://example.com [depth=3] [max_pages=50] [concurrency=5] [delay=0.5] [no-sitemap=1] [no-robots=1] [json=1]"
    icon = "🕷"
    category = "Web"
    needs_network = True

    def run(self, args: dict) -> str:
        if not DEPS_AVAILABLE:
            return "[#e63946]Нужны библиотеки.[/#e63946] Установи: pip install httpx beautifulsoup4 lxml"

        url = args.get("url")
        if not url:
            return "Error: pass url=<https://example.com>"
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        max_depth = int(args.get("depth", "3"))
        max_pages = int(args.get("max_pages", "50"))
        concurrency = int(args.get("concurrency", "5"))
        delay = float(args.get("delay", "0.5"))
        timeout = float(args.get("timeout", "10.0"))
        respect_robots = args.get("no-robots") not in ("1", "true", "yes")
        use_sitemap = args.get("no-sitemap") not in ("1", "true", "yes")
        user_agent = args.get("ua", "HunterA2/0.1 (+https://github.com/heyscally/huntera2)")
        json_out = args.get("json") in ("1", "true", "yes")

        try:
            result = _run_crawl_in_thread(
                start_url=url, max_depth=max_depth, max_pages=max_pages,
                concurrency=concurrency, delay=delay, timeout=timeout,
                respect_robots=respect_robots, user_agent=user_agent,
                use_sitemap=use_sitemap,
            )
        except Exception as e:
            return f"[#e63946]Crawl error:[/#e63946] {e}"

        if json_out:
            return json.dumps(result, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        lines = []
        lines.append(f"[b]Start:[/b]       {result['start_url']}")
        lines.append(f"[b]Domain:[/b]      {result['base_domain']}")
        lines.append(f"[b]Depth:[/b]       {max_depth}  [#555555]max_pages={max_pages}, conc={concurrency}, delay={delay}s[/#555555]")
        lines.append(f"[b]Robots:[/b]      {'[#7fb069]respect[/#7fb069]' if respect_robots else '[#e6b800]ignore[/#e6b800]'}")
        if use_sitemap and result["sitemap_urls"]:
            lines.append(f"[b]Sitemap:[/b]     [#7fb069]+{result['sitemap_urls']}[/#7fb069] URL(s)")
        lines.append(f"[b]Pages:[/b]       [#7fb069]{result['pages_crawled']}[/#7fb069]")
        lines.append("")

        if result["technologies"]:
            lines.append(f"[b #7fb069]◆ Technologies:[/b #7fb069] {', '.join(result['technologies'])}")
        if result["waf"]:
            lines.append(f"[b #e6b800]◆ WAF:[/b #e6b800] {', '.join(result['waf'])}")
        if result["captcha"]:
            lines.append(f"[b #e63946]◆ CAPTCHA:[/b #e63946] {', '.join(result['captcha'])}")
        if result["languages"]:
            lines.append(f"[b #7fb069]◆ Languages:[/b #7fb069] {', '.join(result['languages'])}")
        if result["technologies"] or result["waf"] or result["captcha"] or result["languages"]:
            lines.append("")

        if result["emails"]:
            lines.append(f"[b #e6b800]◆ Emails:[/b #e6b800] [#555555]({len(result['emails'])})[/#555555]")
            for e in result["emails"][:15]:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {e}")
            lines.append("")

        if result["phones"]:
            lines.append(f"[b #e6b800]◆ Phones:[/b #e6b800] [#555555]({len(result['phones'])})[/#555555]")
            for p in result["phones"][:10]:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {p}")
            lines.append("")

        if result["forms"]:
            lines.append(f"[b #e63946]◆ Forms:[/b #e63946] [#555555]({len(result['forms'])})[/#555555]")
            for f in result["forms"][:10]:
                flags = []
                if f.get("has_csrf"):
                    flags.append("CSRF")
                if f.get("has_captcha"):
                    flags.append("CAPTCHA")
                flag_str = f"  [#555555]({','.join(flags)})[/#555555]" if flags else ""
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {f['method']} {f['action'][:60]}{flag_str}")
            lines.append("")

        if result["structured_data"]:
            lines.append(f"[b #7fb069]◆ Structured Data:[/b #7fb069] [#555555]({len(result['structured_data'])} blocks)[/#555555]")
            for sd in result["structured_data"][:5]:
                dtype = sd.get("data", {}).get("@type", "?") if isinstance(sd.get("data"), dict) else "?"
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {sd['type']}: {dtype}")
            lines.append("")

        if result["tables"]:
            lines.append(f"[b #7fb069]◆ Tables:[/b #7fb069] [#555555]({len(result['tables'])})[/#555555]")
            for t in result["tables"][:5]:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {t['total_rows']} rows, headers: {', '.join(t['headers'][:5])}")
            lines.append("")

        lines.append("[b #7fb069]◆ Pages:[/b #7fb069]")
        for page_url, info in list(result["pages"].items())[:15]:
            title = info["title"][:50] if info["title"] else "[#555555]—[/#555555]"
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] {page_url}")
            lines.append(f"    [#555555]title: {title}  links: {info['links_count']}[/#555555]")
        if len(result["pages"]) > 15:
            lines.append(f"  [#555555]... и ещё {len(result['pages']) - 15} страниц[/#555555]")

        return "\n".join(lines)


PLUGIN = Crawl()
