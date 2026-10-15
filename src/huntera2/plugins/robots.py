"""Максимальный анализ robots.txt, sitemap.xml, security.txt и .well-known."""
import json as _json
import re
import socket
import urllib.parse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from collections import defaultdict

from huntera2.sdk import Plugin


TIMEOUT = 10.0
MAX_SITEMAP_URLS = 500
MAX_CHECK_PATHS = 30

# --- Категории интересных путей ---
PATH_CATEGORIES = {
    "backup":  ["backup", "backups", "bak", "old", "save", "archive", "dump", "sql", "db"],
    "admin":   ["admin", "administrator", "manage", "manager", "cpanel", "whm", "phpmyadmin", "pma"],
    "config":  ["config", "conf", "setup", "install", ".env", "env", "settings", "wp-config"],
    "auth":    ["login", "auth", "sso", "oauth", "token", "session", "jwt"],
    "api":     ["api", "graphql", "rest", "soap", "swagger", "openapi", "docs"],
    "test":    ["test", "dev", "staging", "beta", "alpha", "demo", "sandbox", "qa"],
    "debug":   ["debug", "trace", "log", "logs", "error", "console", "shell", "cmd"],
    "private": ["private", "secret", "hidden", "internal", "restricted"],
    "upload":  ["upload", "uploads", "files", "media", "tmp", "temp"],
}

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
]

EXTRA_FILES = [
    "/humans.txt",
    "/ads.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

STATUS_COLORS = {
    200: "#7fb069",
    301: "#e6b800", 302: "#e6b800", 307: "#e6b800", 308: "#e6b800",
    401: "#e63946", 403: "#e63946",
    404: "#555555", 410: "#555555",
    500: "#e63946",
}


# ---------------- HTTP ----------------

def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _fetch(url: str, timeout: float = TIMEOUT) -> tuple[int, str | None]:
    """Возвращает (status_code, body). При ошибке — (0, None)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def _check_status(url: str, timeout: float = 5.0) -> int:
    """Быстрая проверка: возвращает только статус."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# ---------------- Разбор robots.txt ----------------

def _parse_robots(text: str) -> dict:
    agents: dict[str, dict] = {}
    current_agents: list[str] = []
    sitemaps: list[str] = []
    host = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_agents.append(value)
            agents.setdefault(value, {"disallow": [], "allow": [], "crawl_delay": None})
        elif key == "disallow":
            for a in current_agents:
                agents[a]["disallow"].append(value)
        elif key == "allow":
            for a in current_agents:
                agents[a]["allow"].append(value)
        elif key == "crawl-delay":
            for a in current_agents:
                try:
                    agents[a]["crawl_delay"] = float(value)
                except ValueError:
                    pass
        elif key == "sitemap":
            sitemaps.append(value)
        elif key == "host":
            host = value

    return {"agents": agents, "sitemaps": sitemaps, "host": host}


# ---------------- Sitemap ----------------

def _parse_sitemap(url: str, depth: int = 0) -> list[dict]:
    """Парсит sitemap.xml рекурсивно. Возвращает [{loc, lastmod, priority}]."""
    if depth > 2:
        return []
    status, text = _fetch(url)
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.IGNORECASE)
        return [{"loc": loc.strip()} for loc in locs]

    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    results = []

    # sitemap index — рекурсивно
    for sm in root.findall(".//sm:sitemap", ns) + root.findall(".//sitemap"):
        loc_el = sm.find("sm:loc", ns) or sm.find("loc")
        if loc_el is not None and loc_el.text:
            results.extend(_parse_sitemap(loc_el.text.strip(), depth + 1))

    # обычный sitemap
    for url_el in root.findall(".//sm:url", ns) + root.findall(".//url"):
        loc_el = url_el.find("sm:loc", ns) or url_el.find("loc")
        if loc_el is None or not loc_el.text:
            continue
        entry = {"loc": loc_el.text.strip()}
        lm = url_el.find("sm:lastmod", ns) or url_el.find("lastmod")
        if lm is not None and lm.text:
            entry["lastmod"] = lm.text.strip()
        pr = url_el.find("sm:priority", ns) or url_el.find("priority")
        if pr is not None and pr.text:
            entry["priority"] = pr.text.strip()
        results.append(entry)

    return results


# ---------------- Категоризация ----------------

def _categorize(path: str) -> list[str]:
    low = path.lower()
    cats = []
    for cat, keywords in PATH_CATEGORIES.items():
        if any(kw in low for kw in keywords):
            cats.append(cat)
    return cats


def _is_wildcard(base: str) -> bool:
    """Проверяет wildcard: возвращает True, если любой URL даёт 200."""
    import random
    import string
    rand = "".join(random.choices(string.ascii_lowercase, k=12))
    status = _check_status(f"{base}/{rand}-huntera2-nonexistent")
    return status == 200


# ---------------- Основной плагин ----------------

class Robots(Plugin):
    name = "robots"
    description = "Parse robots.txt/sitemap.xml/.well-known: hidden paths, security.txt, live check"
    usage = "url=https://example.com [check=1] [sitemap=1] [extra=1] [json=1]"
    icon = "🤖"
    category = "Recon"
    needs_network = True
    cache_ttl = 3600

    def run(self, args: dict) -> str:
        url = args.get("url")
        if not url:
            return "Error: pass url=<https://example.com>"

        base = _normalize(url)
        do_check = args.get("check") in ("1", "true", "yes")
        do_sitemap = args.get("sitemap") in ("1", "true", "yes")
        do_extra = args.get("extra") in ("1", "true", "yes")
        json_out = args.get("json") in ("1", "true", "yes")

        # --- robots.txt ---
        robots_url = f"{base}/robots.txt"
        status, robots_text = _fetch(robots_url)
        if status != 200 or not robots_text:
            return (
                f"[b]Robots:[/b]  [#e6b800]not found[/#e6b800]  "
                f"[#555555](HTTP {status}, {robots_url})[/#555555]"
            )

        parsed = _parse_robots(robots_text)
        agents = parsed["agents"]
        sitemaps = parsed["sitemaps"]

        # Собираем все Disallow-пути
        all_disallow = set()
        all_allow = set()
        for data in agents.values():
            all_disallow.update(p for p in data["disallow"] if p)
            all_allow.update(p for p in data["allow"] if p)

        # Категоризация
        by_cat: dict[str, list[str]] = defaultdict(list)
        uncategorized: list[str] = []
        for p in sorted(all_disallow):
            cats = _categorize(p)
            if cats:
                for c in cats:
                    by_cat[c].append(p)
            else:
                uncategorized.append(p)

        # --- Проверка live-статусов ---
        check_results: dict[str, int] = {}
        if do_check and all_disallow:
            wildcard = _is_wildcard(base)
            paths_to_check = sorted(all_disallow)[:MAX_CHECK_PATHS]
            for p in paths_to_check:
                if not p.startswith("/"):
                    continue
                check_results[p] = _check_status(f"{base}{p}")
        else:
            wildcard = None

        # --- security.txt и .well-known ---
        well_known: dict[str, tuple[int, str]] = {}
        if do_extra:
            for path in WELL_KNOWN_PATHS + EXTRA_FILES:
                st, body = _fetch(f"{base}{path}", timeout=5.0)
                if st in (200, 301, 302):
                    well_known[path] = (st, (body or "")[:500])

        # --- Sitemap ---
        sitemap_entries: list[dict] = []
        if do_sitemap or sitemaps:
            targets = sitemaps[:3] if sitemaps else [f"{base}/sitemap.xml"]
            for sm in targets:
                sitemap_entries.extend(_parse_sitemap(sm))
                if len(sitemap_entries) > MAX_SITEMAP_URLS:
                    break
            sitemap_entries = sitemap_entries[:MAX_SITEMAP_URLS]

        # --- JSON ---
        if json_out:
            return _json.dumps({
                "robots_url": robots_url,
                "robots_size": len(robots_text),
                "agents": agents,
                "sitemaps": sitemaps,
                "host": parsed.get("host"),
                "disallow_count": len(all_disallow),
                "by_category": {k: v for k, v in by_cat.items()},
                "uncategorized": uncategorized,
                "live_status": check_results,
                "wildcard": wildcard,
                "well_known": {k: {"status": v[0]} for k, v in well_known.items()},
                "sitemap_total": len(sitemap_entries),
                "sitemap_urls": [e["loc"] for e in sitemap_entries],
            }, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        lines = []
        lines.append(f"[b]Robots:[/b]     {robots_url}")
        lines.append(f"[b]Size:[/b]       {len(robots_text)} bytes")
        lines.append(f"[b]User-agents:[/b] {len(agents)}")
        if parsed.get("host"):
            lines.append(f"[b]Host:[/b]       {parsed['host']}")
        if wildcard is not None:
            if wildcard:
                lines.append("[#e6b800]⚠ Wildcard: любой URL → 200 (проверка статусов ненадёжна)[/#e6b800]")
            else:
                lines.append("[#7fb069]✓ Wildcard: нет[/#7fb069]")
        lines.append("")

        # --- Disallow по категориям ---
        if by_cat:
            lines.append(f"[b #e63946]◆ Интересные Disallow-пути:[/b #e63946]")
            for cat in ["backup", "config", "db", "admin", "private", "api", "test", "debug", "auth", "upload"]:
                if cat not in by_cat:
                    continue
                items = by_cat[cat]
                lines.append(f"  [b #e63946]{cat.upper()}[/b #e63946]  [#555555]({len(items)})[/#555555]")
                for p in items[:8]:
                    line = f"    [#e63946]✗[/#e63946] {p}"
                    if p in check_results:
                        st = check_results[p]
                        color = STATUS_COLORS.get(st, "#8a8a8a")
                        line += f"   [{color}]→ HTTP {st}[/{color}]"
                    lines.append(line)
                if len(items) > 8:
                    lines.append(f"    [#555555]... и ещё {len(items) - 8}[/#555555]")
            lines.append("")

        if uncategorized:
            lines.append(f"[b]◆ Прочие запреты ({len(uncategorized)}):[/b]")
            for p in uncategorized[:15]:
                line = f"  [#8a8a8a]·[/#8a8a8a] {p}"
                if p in check_results:
                    st = check_results[p]
                    color = STATUS_COLORS.get(st, "#8a8a8a")
                    line += f"   [{color}]→ HTTP {st}[/{color}]"
                lines.append(line)
            if len(uncategorized) > 15:
                lines.append(f"  [#555555]... и ещё {len(uncategorized) - 15}[/#555555]")
            lines.append("")

        # --- Live-проверка: доступные Disallow ---
        if check_results:
            accessible = {p: st for p, st in check_results.items() if st in (200, 301, 302)}
            forbidden = {p: st for p, st in check_results.items() if st in (401, 403)}
            not_found = {p: st for p, st in check_results.items() if st in (404, 410)}

            if accessible:
                lines.append(f"[b #e63946]◆ ДОСТУПНЫ, хотя запрещены в robots ({len(accessible)}):[/b #e63946]")
                for p, st in sorted(accessible.items()):
                    lines.append(f"  [#e63946]⚠[/#e63946] {p}  [#555555](HTTP {st})[/#555555]")
                lines.append("")

            if forbidden:
                lines.append(f"[b #7fb069]◆ Реально защищены ({len(forbidden)}):[/b #7fb069]")
                for p, st in sorted(forbidden.items())[:10]:
                    lines.append(f"  [#7fb069]✓[/#7fb069] {p}  [#555555](HTTP {st})[/#555555]")
                if len(forbidden) > 10:
                    lines.append(f"  [#555555]... и ещё {len(forbidden) - 10}[/#555555]")
                lines.append("")

            if not_found:
                lines.append(f"[#555555]◆ Не существуют ({len(not_found)}): {', '.join(list(not_found)[:8])}[/#555555]")
                lines.append("")

        # --- Crawl-delay ---
        delays = {a: d["crawl_delay"] for a, d in agents.items() if d["crawl_delay"]}
        if delays:
            lines.append("[b]◆ Crawl-delay:[/b]")
            for a, d in delays.items():
                color = "#e6b800" if d >= 5 else "#7fb069"
                lines.append(f"  [#8a8a8a]{a}:[/#8a8a8a] [{color}]{d}s[/{color}]")
            lines.append("")

        # --- security.txt и .well-known ---
        if well_known:
            lines.append(f"[b #7fb069]◆ .well-known и служебные файлы ({len(well_known)}):[/b #7fb069]")
            for path, (st, body) in well_known.items():
                lines.append(f"  [#7fb069]✓[/#7fb069] {path}  [#555555](HTTP {st})[/#555555]")
                # Если security.txt — показываем контакт
                if "security.txt" in path and body:
                    for line in body.splitlines():
                        if line.lower().startswith(("contact:", "expires:", "policy:")):
                            lines.append(f"    [#8a8a8a]{line.strip()}[/#8a8a8a]")
            lines.append("")

        # --- Sitemap ---
        if sitemaps:
            lines.append(f"[b #7fb069]◆ Sitemaps ({len(sitemaps)}):[/b #7fb069]")
            for sm in sitemaps[:5]:
                lines.append(f"  [#7fb069]✓[/#7fb069] {sm}")
            lines.append("")

        if sitemap_entries:
            lines.append(f"[b #7fb069]◆ URL из sitemap:[/b #7fb069] [#7fb069]{len(sitemap_entries)}[/#7fb069]")

            # Интересные URL
            interesting = [e for e in sitemap_entries if _categorize(e["loc"])][:15]
            if interesting:
                for e in interesting:
                    cats = ",".join(_categorize(e["loc"]))
                    lines.append(f"  [#e6b800]⚠[/#e6b800] {e['loc']}  [#555555]({cats})[/#555555]")
            else:
                for e in sitemap_entries[:10]:
                    lastmod = f"  [#555555]{e.get('lastmod', '')}[/#555555]" if e.get("lastmod") else ""
                    lines.append(f"  [#8a8a8a]·[/#8a8a8a] {e['loc']}{lastmod}")
                if len(sitemap_entries) > 10:
                    lines.append(f"  [#555555]... и ещё {len(sitemap_entries) - 10}[/#555555]")

            # Самые свежие
            with_dates = [e for e in sitemap_entries if e.get("lastmod")]
            if with_dates:
                with_dates.sort(key=lambda x: x["lastmod"], reverse=True)
                lines.append("")
                lines.append("[b]◆ Недавно обновлённые (топ-5):[/b]")
                for e in with_dates[:5]:
                    lines.append(f"  [#8a8a8a]{e['lastmod']}[/#8a8a8a]  {e['loc']}")

            # Готовый wordlist для dir_brute
            if sitemap_entries:
                lines.append("")
                lines.append("[#555555]→ Для dir_brute: сохрани URL из sitemap в файл и используй wordlist=/path[/#555555]")

        return "\n".join(lines)


PLUGIN = Robots()
