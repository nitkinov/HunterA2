import asyncio
import concurrent.futures
import json
import random
from huntera2.sdk import Plugin
from huntera2.core.wordlists import resolve_wordlist

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Встроенный словарь частых путей
BUILTIN_WORDLIST = [
    "admin", "api", "login", "logout", "register", "dashboard", "config",
    "backup", "backups", "old", "test", "tests", "dev", "development",
    "staging", "prod", "production", "private", "secret", "hidden", "tmp",
    "temp", "cache", "logs", "log", "db", "database", "sql", "mysql",
    "dump", "dumps", "export", "import", "upload", "uploads", "download",
    "downloads", "files", "file", "media", "images", "img", "css", "js",
    "static", "assets", "public", "includes", "include", "lib", "library",
    "vendor", "node_modules", "src", "source", "app", "apps", "application",
    "system", "core", "common", "shared", "user", "users", "account",
    "accounts", "profile", "settings", "preferences", "help", "support",
    "docs", "documentation", "readme", "changelog", "license", "robots.txt",
    "sitemap.xml", "sitemap", "crossdomain.xml", "clientaccesspolicy.xml",
    ".git", ".svn", ".hg", ".env", ".htaccess", ".htpasswd", ".DS_Store",
    "web.config", "wp-admin", "wp-login.php", "administrator", "phpmyadmin",
    "pma", "mysql", "cpanel", "whm", "webmail", "mail", "email", "news",
    "blog", "forum", "community", "shop", "store", "cart", "checkout",
    "order", "orders", "payment", "payments", "invoice", "invoices",
    "report", "reports", "analytics", "stats", "statistics", "metrics",
    "health", "healthcheck", "status", "ping", "version", "info",
    "about", "contact", "faq", "terms", "privacy", "security", "auth",
    "oauth", "sso", "saml", "ldap", "actuator", "swagger", "swagger-ui",
    "api-docs", "graphql", "console", "manager", "management", "monitor",
    "debug", "trace", "test.php", "info.php", "phpinfo.php", "shell.php",
    "cmd.php", "upload.php", "index.php", "index.html", "index.htm",
    "default.html", "home.html", "main.html", "error", "errors", "404",
    "403", "500", "access-denied", "forbidden", "unauthorized",
]

INTERESTING_STATUS = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500}


def _normalize_base(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _load_wordlist(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


async def _probe(client: httpx.AsyncClient, base: str, path: str, extensions: list[str]) -> list[dict]:
    """Проверяет один путь и его расширения."""
    results = []
    candidates = [path]
    if extensions:
        for ext in extensions:
            candidates.append(f"{path}.{ext}")

    for candidate in candidates:
        url = f"{base}/{candidate}"
        try:
            r = await client.get(url, follow_redirects=False, timeout=8.0)
        except Exception:
            continue
        if r.status_code in INTERESTING_STATUS:
            results.append({
                "url": url,
                "path": candidate,
                "status": r.status_code,
                "length": len(r.content),
                "redirect": r.headers.get("location", ""),
            })
    return results


async def _scan(base: str, words: list[str], extensions: list[str],
                concurrency: int, delay: float, timeout: float) -> tuple[list[dict], int]:
    """Запускает сканирование, возвращает результаты и длину базового 404."""
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    headers = {"User-Agent": "HunterA2/0.1 (dir-brute)"}

    async with httpx.AsyncClient(limits=limits, headers=headers, verify=False) as client:
        # Базовый 404 для фильтрации кастомных страниц ошибок
        try:
            base_resp = await client.get(f"{base}/__huntera_nonexistent__{random.randint(1000,9999)}", timeout=timeout)
            base_404_len = len(base_resp.content)
        except Exception:
            base_404_len = -1

        sem = asyncio.Semaphore(concurrency)
        results: list[dict] = []

        async def _bounded(word: str):
            async with sem:
                if delay > 0:
                    await asyncio.sleep(delay + random.uniform(0, delay / 2))
                return await _probe(client, base, word, extensions)

        tasks = [asyncio.create_task(_bounded(w)) for w in words]
        for coro in asyncio.as_completed(tasks):
            try:
                res = await coro
                results.extend(res)
            except Exception:
                pass

    # Фильтрация: отсеиваем ответы, чья длина совпадает с базовым 404
    filtered = [r for r in results if r["length"] != base_404_len or r["status"] != 404]
    filtered.sort(key=lambda r: (r["status"], r["path"]))
    return filtered, base_404_len


def _run_scan_in_thread(base, words, extensions, concurrency, delay, timeout):
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_scan(base, words, extensions, concurrency, delay, timeout))
        finally:
            loop.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


class DirBrute(Plugin):
    name = "dir_brute"
    description = "Directory & file brute-force (async, built-in wordlist, extensions, custom list)"
    usage = "url=http://example.com [wordlist=@common | /path] [ext=php,html] [json=1]"
    icon = "📂"
    category = "Web"
    needs_network = True

    def run(self, args: dict) -> str:
        if not HTTPX_AVAILABLE:
            return "[#e63946]httpx not installed.[/#e63946]"

        url = args.get("url")
        if not url:
            return "Error: pass url=<http://example.com>"

        base = _normalize_base(url)

        # Словарь
        wordlist_arg = args.get("wordlist")
        if wordlist_arg:
            try:
                words = resolve_wordlist(wordlist_arg)
            except Exception as e:
                return f"[#e63946]Wordlist error:[/#e63946] {e}"
        else:
            words = BUILTIN_WORDLIST

        # Расширения
        extensions = []
        if args.get("ext"):
            extensions = [e.strip().lstrip(".") for e in args["ext"].split(",") if e.strip()]

        concurrency = int(args.get("concurrency", "50"))
        delay = float(args.get("delay", "0"))
        timeout = float(args.get("timeout", "8.0"))
        json_out = args.get("json") in ("1", "true", "yes")

        try:
            results, base_404_len = _run_scan_in_thread(base, words, extensions, concurrency, delay, timeout)
        except Exception as e:
            return f"[#e63946]Scan error:[/#e63946] {e}"

        if json_out:
            return json.dumps({
                "target": base,
                "words": len(words),
                "extensions": extensions,
                "base_404_length": base_404_len,
                "found": results,
            }, indent=2, ensure_ascii=False)

        lines = []
        lines.append(f"[b]Target:[/b]       {base}")
        lines.append(f"[b]Words:[/b]        {len(words)}  [#555555]({'custom' if wordlist_path else 'built-in'})[/#555555]")
        if extensions:
            lines.append(f"[b]Extensions:[/b]   {', '.join(extensions)}")
        lines.append(f"[b]Concurrency:[/b]  {concurrency}")
        lines.append(f"[b]Base 404 len:[/b] {base_404_len} bytes  [#555555](используется для фильтрации)[/#555555]")
        lines.append(f"[b]Found:[/b]        [#7fb069]{len(results)}[/#7fb069]")
        lines.append("")

        if not results:
            lines.append("[#e6b800]Ничего не найдено.[/#e6b800]")
            return "\n".join(lines)

        # Группировка по статусу
        by_status: dict[int, list[dict]] = {}
        for r in results:
            by_status.setdefault(r["status"], []).append(r)

        status_colors = {
            200: "#7fb069", 201: "#7fb069", 202: "#7fb069", 204: "#7fb069",
            301: "#e6b800", 302: "#e6b800", 303: "#e6b800", 307: "#e6b800", 308: "#e6b800",
            401: "#e63946", 403: "#e63946", 405: "#e63946", 500: "#e63946",
        }

        for status in sorted(by_status.keys()):
            color = status_colors.get(status, "#8a8a8a")
            items = by_status[status]
            lines.append(f"[b {color}]◆ {status}[/b {color}]  [#555555]({len(items)})[/#555555]")
            for r in items:
                redirect = f"  [#555555]→ {r['redirect'][:50]}[/#555555]" if r["redirect"] else ""
                lines.append(f"  {r['url']}  [#555555]({r['length']}B)[/#555555]{redirect}")
            lines.append("")

        return "\n".join(lines)


PLUGIN = DirBrute()
