import asyncio
import concurrent.futures
import json
import socket
import time
import urllib.parse
import urllib.request
from pathlib import Path

from huntera2.sdk import Plugin

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


CACHE_DIR = Path.home() / ".cache" / "huntera2" / "cloudflair"
CACHE_TTL = 86400

# --- IP-диапазоны Cloudflare (топ-10, для проверки) ---
CF_RANGES_SAMPLE = [
    "103.21.244.0/22", "103.22.200.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
    "198.41.128.0/17",
]

# --- Поддомены, часто не проксированные ---
DIRECT_SUBDOMAINS = [
    "direct", "origin", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "vpn", "dev", "staging", "test", "old", "backup", "ssh", "api",
    "admin", "cpanel", "whm", "webmail", "ns1", "ns2", "dns",
]


# ---------------- Кэш ----------------

def _cache_get(key: str):
    p = CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    if time.time() - p.stat().st_mtime > CACHE_TTL:
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _cache_set(key: str, value):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        (CACHE_DIR / f"{key}.json").write_text(json.dumps(value))
    except Exception:
        pass


# ---------------- HTTP helper ----------------

def _http_get(url: str, timeout: float = 15.0, headers: dict = None) -> str:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "HunterA2/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


# ---------------- Метод 1: crt.sh ----------------

def _crtsh(domain: str) -> list[str]:
    """Ищем IP в CT-логах. crt.sh отдаёт только имена, но имена → резолв."""
    try:
        data = json.loads(_http_get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30
        ))
    except Exception:
        return []

    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") and name != domain:
                subs.add(name)

    # Резолвим каждый поддомен — если попадёт не в CF-диапазон, это origin
    ips = set()
    for sub in subs:
        try:
            for ip in socket.gethostbyname_ex(sub)[2]:
                ips.add((ip, sub))
        except Exception:
            continue
    return list(ips)


# ---------------- Метод 2: HackerTarget hostsearch ----------------

def _hackertarget(domain: str) -> list[str]:
    """Исторический DNS через публичный API HackerTarget."""
    try:
        text = _http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15).strip()
    except Exception:
        return []
    if "error" in text.lower() or "API count exceeded" in text:
        return []
    results = []
    for line in text.splitlines():
        if "," in line:
            name, ip = line.split(",", 1)
            results.append((ip.strip(), name.strip()))
    return results


# ---------------- Метод 3: поддомены и MX/SPF ----------------

def _direct_subdomains(domain: str) -> list[str]:
    ips = set()
    for sub in DIRECT_SUBDOMAINS:
        try:
            for ip in socket.gethostbyname_ex(f"{sub}.{domain}")[2]:
                ips.add((ip, f"{sub}.{domain}"))
        except Exception:
            continue
    return list(ips)


def _mx_ips(domain: str) -> list[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 3.0
        resolver.lifetime = 5.0
        mx_answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        return []

    ips = set()
    for mx in mx_hosts:
        try:
            for ip in socket.gethostbyname_ex(mx)[2]:
                ips.add((ip, f"MX:{mx}"))
        except Exception:
            continue
    return list(ips)


def _spf_ips(domain: str) -> list[str]:
    """Извлекаем IP из SPF-записи (TXT)."""
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        txt_answers = resolver.resolve(domain, "TXT")
    except Exception:
        return []

    spf = ""
    for r in txt_answers:
        s = str(r).strip('"')
        if s.startswith("v=spf1"):
            spf = s
            break
    if not spf:
        return []

    ips = set()
    for token in spf.split():
        if token.startswith("ip4:") or token.startswith("ip6:"):
            candidate = token.split(":", 1)[1]
            ip = candidate.split("/")[0]
            ips.add((ip, "SPF"))
    return list(ips)


# ---------------- Метод 4: favicon hash ----------------

def _favicon_hash(domain: str) -> str | None:
    """Считаем mmh3-подобный hash favicon (для Shodan-поиска)."""
    try:
        import codecs
        favicon_url = f"https://{domain}/favicon.ico"
        req = urllib.request.Request(favicon_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
        # Shodan использует mmh3 base64(favicon)
        encoded = codecs.encode(data, "base64").replace(b"\n", b"")
        try:
            import mmh3
            return str(mmh3.hash(encoded))
        except ImportError:
            # fallback: sha256 hex
            import hashlib
            return "sha256:" + hashlib.sha256(data).hexdigest()[:16]
    except Exception:
        return None


def _shodan_search(favicon_hash: str, api_key: str) -> list[str]:
    if not favicon_hash or favicon_hash.startswith("sha256:") or not api_key:
        return []
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=http.favicon.hash:{favicon_hash}"
        data = json.loads(_http_get(url, timeout=15))
        return [m.get("ip_str") for m in data.get("matches", []) if m.get("ip_str")]
    except Exception:
        return []


# ---------------- Проверка: за Cloudflare ли домен ----------------

def _is_cloudflare(domain: str) -> bool:
    import ipaddress
    try:
        ips = socket.gethostbyname_ex(domain)[2]
    except Exception:
        return False
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for cidr in CF_RANGES_SAMPLE:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    return False


def _in_cf_ranges(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in CF_RANGES_SAMPLE:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------- Валидация: ip отдаёт тот же сайт ----------------

async def _validate_origin(client: httpx.AsyncClient, ip: str, domain: str) -> dict | None:
    try:
        r = await client.get(
            f"https://{ip}/",
            headers={"Host": domain, "User-Agent": "HunterA2/0.1"},
            timeout=8.0,
            verify=False,
        )
        server = r.headers.get("server", "").lower()
        # Признак того, что это origin (не Cloudflare)
        if "cloudflare" in server:
            return None
        title = ""
        if "<title>" in r.text.lower():
            start = r.text.lower().find("<title>") + 7
            end = r.text.lower().find("</title>", start)
            if end > start:
                title = r.text[start:end].strip()[:80]
        return {"ip": ip, "status": r.status_code, "server": server, "title": title}
    except Exception:
        return None


async def _validate_all(candidates: list[tuple[str, str]], domain: str) -> list[dict]:
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, verify=False) as client:
        tasks = [_validate_origin(client, ip, domain) for ip, _ in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# ---------------- Основная логика ----------------

async def _scan(domain: str, shodan_key: str):
    candidates: dict[str, set] = {}  # ip -> set(sources)

    def add(ip: str, src: str):
        candidates.setdefault(ip, set()).add(src)

    # Метод 1: crt.sh
    for ip, sub in _crtsh(domain):
        if not _in_cf_ranges(ip):
            add(ip, f"crt.sh:{sub}")

    # Метод 2: HackerTarget
    for ip, sub in _hackertarget(domain):
        if not _in_cf_ranges(ip):
            add(ip, f"ht:{sub}")

    # Метод 3: прямые поддомены
    for ip, sub in _direct_subdomains(domain):
        if not _in_cf_ranges(ip):
            add(ip, f"sub:{sub}")

    # Метод 4: MX
    for ip, sub in _mx_ips(domain):
        if not _in_cf_ranges(ip):
            add(ip, f"mx:{sub}")

    # Метод 5: SPF
    for ip, src in _spf_ips(domain):
        if not _in_cf_ranges(ip):
            add(ip, f"spf:{src}")

    # Метод 6: Shodan по favicon
    favicon_hash = _favicon_hash(domain)
    if favicon_hash and shodan_key:
        for ip in _shodan_search(favicon_hash, shodan_key):
            if not _in_cf_ranges(ip):
                add(ip, "shodan:favicon")

    # Валидация кандидатов
    cand_list = [(ip, ",".join(sorted(sources))) for ip, sources in candidates.items()]
    validated = await _validate_all(cand_list, domain) if HTTPX_AVAILABLE and cand_list else []

    # Добавим источники к валидированным
    for v in validated:
        v["sources"] = sorted(candidates.get(v["ip"], []))

    return {
        "domain": domain,
        "behind_cloudflare": _is_cloudflare(domain),
        "candidates_total": len(candidates),
        "validated": validated,
        "favicon_hash": favicon_hash,
    }


def _run_scan_thread(domain, shodan_key):
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_scan(domain, shodan_key))
        finally:
            loop.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


# ---------------- Плагин ----------------

class Cloudflair(Plugin):
    name = "cloudflair"
    description = "Find origin IP behind Cloudflare: CT logs, historical DNS, subdomains, MX/SPF, favicon"
    usage = "domain=example.com [shodan_key=KEY] [no-cache=1] [json=1]"
    icon = "☁"
    cache_ttl = 3600
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        if not HTTPX_AVAILABLE:
            return "[#e63946]httpx not installed.[/#e63946]"

        domain = args.get("domain")
        if not domain:
            return "Error: pass domain=<example.com>"

        domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
        shodan_key = args.get("shodan_key", "").strip()
        use_cache = args.get("no-cache") not in ("1", "true", "yes")
        json_out = args.get("json") in ("1", "true", "yes")

        cache_key = f"{domain}_{shodan_key[:8]}"
        if use_cache:
            cached = _cache_get(cache_key)
            if cached:
                if json_out:
                    cached["_cached"] = True
                    return json.dumps(cached, indent=2, ensure_ascii=False)
                return self._render(cached, cached=True)

        try:
            result = _run_scan_thread(domain, shodan_key)
        except Exception as e:
            return f"[#e63946]Scan error:[/#e63946] {e}"

        if use_cache:
            _cache_set(cache_key, result)

        if json_out:
            result["_cached"] = False
            return json.dumps(result, indent=2, ensure_ascii=False)

        return self._render(result)

    def _render(self, data: dict, cached: bool = False) -> str:
        lines = []
        lines.append(f"[b]Domain:[/b]      {data['domain']}")

        if data["behind_cloudflare"]:
            lines.append("[b]Behind CF:[/b]   [#e6b800]да[/#e6b800]")
        else:
            lines.append("[b]Behind CF:[/b]   [#7fb069]нет[/#7fb069] — возможно, origin не защищён")

        lines.append(f"[b]Candidates:[/b]  {data['candidates_total']}")
        lines.append(f"[b]Validated:[/b]   [#7fb069]{len(data['validated'])}[/#7fb069]")
        if data.get("favicon_hash"):
            lines.append(f"[b]Favicon:[/b]     {data['favicon_hash']}")
        if cached:
            lines.append("[#e6b800]⚡ из кэша (24ч)[/#e6b800]")
        lines.append("")

        if not data["validated"]:
            lines.append("[#e6b800]Origin IP не найдены.[/#e6b800]")
            lines.append("[#555555]Попробуй указать shodan_key=KEY для поиска по favicon.[/#555555]")
            return "\n".join(lines)

        lines.append("[b #e63946]◆ Origin candidates:[/b #e63946]")
        for v in data["validated"]:
            lines.append(
                f"  [#e63946]{v['ip']}[/#e63946]  "
                f"[#8a8a8a]{v['status']}  {v['server']}[/#8a8a8a]"
            )
            if v.get("title"):
                lines.append(f"    [#555555]title: {v['title']}[/#555555]")
            lines.append(f"    [#555555]sources: {', '.join(v.get('sources', []))}[/#555555]")

        return "\n".join(lines)


PLUGIN = Cloudflair()
