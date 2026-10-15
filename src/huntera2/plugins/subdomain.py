import asyncio
import concurrent.futures
import json
import random
import string
import urllib.request
from huntera2.sdk import Plugin
from huntera2.core.config import DEFAULT_DNS_SERVERS

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# --- Встроенный словарь популярных префиксов ---
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "dev", "staging", "api", "blog", "vpn", "test",
    "admin", "ns1", "ns2", "cdn", "shop", "m", "portal", "secure",
    "autodiscover", "webmail", "smtp", "pop", "imap", "remote", "office",
    "app", "apps", "mobile", "beta", "alpha", "demo", "support", "help",
    "status", "monitor", "stats", "analytics", "dashboard", "panel",
    "cpanel", "whm", "manage", "manager", "git", "gitlab", "github",
    "jenkins", "ci", "cd", "deploy", "build", "test2", "stage", "stg",
    "prod", "production", "int", "internal", "ext", "external", "public",
    "private", "secure2", "ssl", "tls", "dns", "dns1", "dns2", "db",
    "database", "mysql", "postgres", "redis", "mongo", "elastic", "kibana",
    "grafana", "prometheus", "sentry", "logs", "log", "metrics", "health",
    "healthcheck", "ping", "info", "about", "contact", "faq", "terms",
    "privacy", "security", "auth", "oauth", "sso", "ldap", "vpn2", "proxy",
    "gateway", "gw", "router", "switch", "firewall", "ids", "ips", "mail2",
    "news", "forum", "community", "wiki", "docs", "doc", "documentation",
    "media", "images", "img", "static", "assets", "css", "js", "files",
    "file", "upload", "uploads", "download", "downloads", "backup",
    "backups", "old", "new", "v2", "v3", "api2", "api-v2", "rest", "graphql",
    "ws", "websocket", "socket", "stream", "live", "video", "audio", "chat",
    "talk", "meet", "conference", "calendar", "cal", "drive", "cloud",
    "storage", "share", "box", "drop", "sync", "backup2", "archive",
    "temp", "tmp", "cache", "private2", "internal2", "dev2", "test3",
]

# --- Пул публичных DNS-резолверов ---
DNS_RESOLVERS = DEFAULT_DNS_SERVERS


def _random_label(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


_global_resolver = None


def _get_resolver(timeout: float) -> "dns.resolver.Resolver":
    """Один Resolver на все запросы — не создаём новый каждый раз."""
    global _global_resolver
    if _global_resolver is None:
        _global_resolver = dns.resolver.Resolver(configure=False)
        _global_resolver.nameservers = list(DNS_RESOLVERS)
        _global_resolver.timeout = timeout
        _global_resolver.lifetime = timeout * 2
    return _global_resolver


def _resolve_sync(fqdn: str, timeout: float, record_type: str = "A") -> tuple[list[str], str]:
    """Возвращает (список IP, CNAME-цель). Если ничего не найдено — ([], '')."""
    try:
        resolver = _get_resolver(timeout)
        answers = resolver.resolve(fqdn, record_type)
        ips = sorted({str(r) for r in answers}) if record_type == "A" else []
        cname = ""
        # Пробуем получить CNAME (может отсутствовать)
        try:
            cname_answers = resolver.resolve(fqdn, "CNAME")
            cname = str(cname_answers[0].target).rstrip(".")
        except Exception:
            pass
        return ips, cname
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return [], ""
    except Exception:
        return [], ""


def _fetch_crt_sh(domain: str, timeout: float = 10.0) -> list[str]:
    """Пассивный поиск поддоменов через crt.sh (Certificate Transparency)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return []

    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") and name != domain:
                subs.add(name[: -len(domain) - 1])
    return sorted(subs)


async def _resolve_async(fqdn: str, timeout: float, sem: asyncio.Semaphore):
    async with sem:
        ips, cname = await asyncio.to_thread(_resolve_sync, fqdn, timeout)
        return fqdn, ips, cname


async def _detect_wildcard(domain: str, timeout: float, sem: asyncio.Semaphore) -> set[str]:
    """Улучшенная детекция wildcard: 3 случайных канарейки."""
    canary_tasks = [
        asyncio.create_task(_resolve_async(f"{_random_label()}.{domain}", timeout, sem))
        for _ in range(3)
    ]
    wildcard_ips = set()
    for coro in asyncio.as_completed(canary_tasks):
        _, ips, _ = await coro
        wildcard_ips.update(ips)
    return wildcard_ips


async def _scan_async(domain: str, words: list[str], concurrency: int,
                      timeout: float, use_passive: bool):
    sem = asyncio.Semaphore(concurrency)

    # --- Wildcard ---
    wildcard_ips = await _detect_wildcard(domain, timeout, sem)
    wildcard_detected = bool(wildcard_ips)

    # --- Пассивный источник ---
    passive_subs = []
    if use_passive:
        passive_subs = await asyncio.to_thread(_fetch_crt_sh, domain)

    # --- Merge: brute + passive ---
    all_words = sorted(set(words) | set(passive_subs))
    passive_set = set(passive_subs)
    brute_set = set(words)

    # --- Резолвинг ---
    tasks = [
        asyncio.create_task(_resolve_async(f"{w}.{domain}", timeout, sem))
        for w in all_words
    ]
    results = []
    for coro in asyncio.as_completed(tasks):
        fqdn, ips, cname = await coro
        if not ips and not cname:
            continue
        if wildcard_detected and set(ips).issubset(wildcard_ips) and not cname:
            continue
        sub = fqdn[: -len(domain) - 1]
        sources = []
        if sub in brute_set:
            sources.append("brute")
        if sub in passive_set:
            sources.append("crt.sh")
        results.append({
            "subdomain": sub,
            "ips": ips,
            "cname": cname,
            "sources": sources,
        })

    results.sort(key=lambda r: r["subdomain"])
    return results, sorted(wildcard_ips), wildcard_detected, len(passive_subs)


def _run_scan_in_thread(domain, words, concurrency, timeout, use_passive):
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                _scan_async(domain, words, concurrency, timeout, use_passive)
            )
        finally:
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


class SubdomainEnum(Plugin):
    name = "subdomain"
    description = "Subdomain enumeration: DNS brute-force + crt.sh, wildcard detection, CNAME"
    usage = "domain=example.com [wordlist=/path] [concurrency=100] [timeout=3.0] [passive=0] [json=1]"
    icon = "🔎"
    cache_ttl = 3600
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        if not DNS_AVAILABLE:
            return "[#e63946]dnspython not installed.[/#e63946] Run: pip install dnspython"

        domain = args.get("domain")
        if not domain:
            return "Error: pass domain=<example.com>"

        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]

        # --- Словарь ---
        wordlist_path = args.get("wordlist")
        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception as e:
                return f"[#e63946]Wordlist error:[/#e63946] {e}"
        else:
            words = BUILTIN_WORDLIST

        concurrency = int(args.get("concurrency", "100"))
        timeout = float(args.get("timeout", "3.0"))
        use_passive = args.get("passive", "1") not in ("0", "false", "no")
        json_out = args.get("json") in ("1", "true", "yes")

        try:
            results, wildcard_ips, wildcard_detected, passive_count = _run_scan_in_thread(
                domain, words, concurrency, timeout, use_passive
            )
        except Exception as e:
            return f"[#e63946]Scan error:[/#e63946] {e}"

        # --- JSON ---
        if json_out:
            return json.dumps({
                "domain": domain,
                "words": len(words),
                "passive_subs": passive_count,
                "wildcard": wildcard_detected,
                "wildcard_ips": wildcard_ips,
                "found": results,
            }, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        lines = []
        lines.append(f"[b]Domain:[/b]      {domain}")
        lines.append(f"[b]Words:[/b]       {len(words)}  [#555555]({'custom' if wordlist_path else 'built-in'})[/#555555]")
        if use_passive:
            lines.append(f"[b]crt.sh:[/b]      [#7fb069]+{passive_count}[/#7fb069] поддоменов из CT-логов")
        lines.append(f"[b]Resolvers:[/b]   {', '.join(DNS_RESOLVERS)}")
        if wildcard_detected:
            lines.append(f"[#e6b800]⚠ Wildcard DNS:[/#e6b800] {', '.join(wildcard_ips)} — результаты отфильтрованы")
        lines.append(f"[b]Found:[/b]       [#7fb069]{len(results)}[/#7fb069]")
        lines.append("")

        if not results:
            lines.append("[#e6b800]Поддомены не найдены.[/#e6b800]")
            return "\n".join(lines)

        # --- Группировка по IP ---
        by_ip: dict[str, list[dict]] = {}
        no_ip = []
        for r in results:
            if r["ips"]:
                for ip in r["ips"]:
                    by_ip.setdefault(ip, []).append(r)
            else:
                no_ip.append(r)

        lines.append("[b #7fb069]◆ Поддомены (по IP):[/b #7fb069]")
        for ip in sorted(by_ip.keys()):
            lines.append(f"  [#e63946]{ip}[/#e63946]")
            for r in by_ip[ip]:
                src = f" [#555555]({','.join(r['sources'])})[/#555555]" if r["sources"] else ""
                cname = f"  → CNAME: {r['cname']}" if r["cname"] else ""
                lines.append(f"    [#8a8a8a]•[/#8a8a8a] {r['subdomain']}{src}{cname}")
            lines.append("")

        if no_ip:
            lines.append("[b #e6b800]◆ Только CNAME (без A-записи):[/b #e6b800]")
            for r in no_ip:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {r['subdomain']}  → {r['cname']}")

        return "\n".join(lines)


PLUGIN = SubdomainEnum()
