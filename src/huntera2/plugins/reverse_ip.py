import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
from huntera2.sdk import Plugin

CACHE_DIR = Path.home() / ".cache" / "huntera2" / "reverse_ip"
CACHE_TTL = 86400

HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/?q={query}"
ROBTEX_URL = "https://freeapi.robtex.com/ipquery/{ip}"
VIEWDNS_URL = "https://api.viewdns.info/reverseip/?host={query}&apikey={apikey}&output=json"
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/search/list?ipv4={ip}"
CRTSH_URL = "https://crt.sh/?q={query}&output=json"
DEFAULT_TIMEOUT = 15.0


def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = key.replace("/", "_").replace(":", "_")
    return CACHE_DIR / f"{safe}.json"


def _cache_get(key: str) -> dict | None:
    p = _cache_path(key)
    if not p.exists():
        return None
    try:
        if time.time() - p.stat().st_mtime > CACHE_TTL:
            return None
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _cache_set(key: str, value: dict) -> None:
    try:
        with _cache_path(key).open("w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False)
    except Exception:
        pass


def _resolve(query: str) -> tuple[str, str]:
    original = query
    try:
        ipaddress.ip_address(query)
        return original, query
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(query)
        return original, ip
    except socket.gaierror as e:
        raise ValueError(f"Не удалось разрешить {query}: {e}")


def _http_get(url: str, timeout: float, headers: dict | None = None) -> str:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "HunterA2/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _lookup_hackertarget(ip: str, timeout: float) -> list[str]:
    text = _http_get(HACKERTARGET_URL.format(query=urllib.parse.quote(ip)), timeout).strip()
    if not text or "error" in text.lower() or "API count exceeded" in text:
        raise ValueError(text or "empty response")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _lookup_robtex(ip: str, timeout: float) -> list[str]:
    data = json.loads(_http_get(ROBTEX_URL.format(ip=urllib.parse.quote(ip)), timeout))
    domains = set()
    for key in ("active", "passive"):
        for entry in data.get(key, []) or []:
            if isinstance(entry, dict):
                name = entry.get("o") or entry.get("rrname")
                if name:
                    domains.add(str(name).rstrip("."))
    return sorted(domains)


def _lookup_securitytrails(ip: str, apikey: str, timeout: float) -> list[str]:
    headers = {"apikey": apikey, "User-Agent": "HunterA2/0.1"}
    data = json.loads(_http_get(SECURITYTRAILS_URL.format(ip=urllib.parse.quote(ip)), timeout, headers))
    return [r.get("hostname", "") for r in data.get("records", []) if r.get("hostname")]


def _lookup_viewdns(ip: str, apikey: str, timeout: float) -> list[str]:
    url = VIEWDNS_URL.format(query=urllib.parse.quote(ip), apikey=urllib.parse.quote(apikey))
    data = json.loads(_http_get(url, timeout))
    if data.get("response", {}).get("status") != "ok":
        raise ValueError("ViewDNS error")
    return [r.get("name", "") for r in data.get("response", {}).get("domains", []) if r.get("name")]


def _lookup_crtsh(ip: str, timeout: float) -> list[str]:
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        return []
    try:
        url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{ptr}"))
        data = json.loads(_http_get(url, timeout))
    except Exception:
        return []
    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name:
                subs.add(name)
    return sorted(subs)


def _group_by_base(domains: list[str]) -> dict:
    groups = defaultdict(list)
    for d in domains:
        parts = d.split(".")
        if len(parts) >= 2:
            groups[".".join(parts[-2:])].append(d)
        else:
            groups[d].append(d)
    return dict(groups)


class ReverseIp(Plugin):
    name = "reverse_ip"
    description = "Reverse IP lookup: HackerTarget + Robtex + SecurityTrails + crt.sh, CIDR, cache"
    usage = "query=8.8.8.8 | query=1.1.1.0/24 [st=KEY] [apikey=VIEWDNS_KEY] [no-cache=1] [json=1]"
    icon = "🔄"
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        query = args.get("query") or args.get("ip") or args.get("host")
        if not query:
            return "Error: pass query=<IP or CIDR>"

        st_key = args.get("st", "").strip()
        viewdns_key = args.get("apikey", "").strip()
        use_cache = args.get("no-cache") not in ("1", "true", "yes")
        json_out = args.get("json") in ("1", "true", "yes")

        is_cidr = "/" in query
        ips: list[str] = []
        original = query

        if is_cidr:
            try:
                net = ipaddress.ip_network(query, strict=False)
                if net.num_addresses > 256:
                    return "[#e63946]CIDR too large (max /24 = 256 IPs)[/#e63946]"
                ips = [str(ip) for ip in net.hosts()]
            except ValueError as e:
                return f"[#e63946]Invalid CIDR:[/#e63946] {e}"
        else:
            try:
                original, ip = _resolve(query)
                ips = [ip]
            except ValueError as e:
                return f"[#e63946]Resolution error:[/#e63946] {e}"

        cache_key = f"{query}_{st_key[:8]}_{viewdns_key[:8]}"
        if use_cache:
            cached = _cache_get(cache_key)
            if cached:
                if json_out:
                    cached["_cached"] = True
                    return json.dumps(cached, indent=2, ensure_ascii=False)
                return self._render_human(cached, cached=True)

        all_domains: set[str] = set()
        per_source = {"hackertarget": 0, "robtex": 0, "securitytrails": 0, "viewdns": 0, "crtsh": 0}
        errors: list[str] = []
        ptr_records: dict[str, str] = {}

        for ip in ips:
            try:
                ptr_records[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            try:
                found = _lookup_hackertarget(ip, DEFAULT_TIMEOUT)
                all_domains.update(found)
                per_source["hackertarget"] += len(found)
            except Exception as e:
                errors.append(f"HackerTarget({ip}): {e}")

            try:
                found = _lookup_robtex(ip, DEFAULT_TIMEOUT)
                all_domains.update(found)
                per_source["robtex"] += len(found)
            except Exception as e:
                errors.append(f"Robtex({ip}): {e}")

            if st_key:
                try:
                    found = _lookup_securitytrails(ip, st_key, DEFAULT_TIMEOUT)
                    all_domains.update(found)
                    per_source["securitytrails"] += len(found)
                except Exception as e:
                    errors.append(f"SecurityTrails({ip}): {e}")

            if viewdns_key:
                try:
                    found = _lookup_viewdns(ip, viewdns_key, DEFAULT_TIMEOUT)
                    all_domains.update(found)
                    per_source["viewdns"] += len(found)
                except Exception as e:
                    errors.append(f"ViewDNS({ip}): {e}")

            try:
                found = _lookup_crtsh(ip, DEFAULT_TIMEOUT)
                all_domains.update(found)
                per_source["crtsh"] += len(found)
            except Exception as e:
                errors.append(f"crt.sh({ip}): {e}")

        all_domains = sorted(all_domains)
        groups = _group_by_base(all_domains)
        result = {
            "query": query,
            "ips": ips,
            "ptr": ptr_records,
            "sources": per_source,
            "errors": errors,
            "total": len(all_domains),
            "domains": all_domains,
            "groups": groups,
        }

        if use_cache:
            _cache_set(cache_key, result)

        if json_out:
            result["_cached"] = False
            return json.dumps(result, indent=2, ensure_ascii=False)

        return self._render_human(result)

    def _render_human(self, data: dict, cached: bool = False) -> str:
        lines = []
        ip_display = ", ".join(data["ips"]) if len(data["ips"]) <= 3 else f"{len(data['ips'])} IPs"
        lines.append(f"[b]Query:[/b]   {data['query']}")
        lines.append(f"[b]IP(s):[/b]   {ip_display}")
        if data.get("ptr"):
            for ip, ptr in data["ptr"].items():
                lines.append(f"[b]PTR:[/b]     {ip} → {ptr}")
        if cached:
            lines.append("[#e6b800]⚡ из кэша (24ч)[/#e6b800]")

        src = data.get("sources", {})
        src_str = "  ".join(f"{k}={v}" for k, v in src.items() if v > 0)
        lines.append(f"[b]Sources:[/b] {src_str or '[#e63946]—[/#e63946]'}")
        lines.append(f"[b]Found:[/b]   [#7fb069]{data['total']}[/#7fb069] доменов")
        lines.append("")

        if data.get("errors"):
            lines.append("[b #e6b800]⚠ Ошибки:[/b #e6b800]")
            for e in data["errors"][:5]:
                lines.append(f"  [#e6b800]•[/#e6b800] {e}")
            lines.append("")

        if not data.get("domains"):
            lines.append("[#e6b800]Домены не найдены.[/#e6b800]")
            return "\n".join(lines)

        groups = data.get("groups", {})
        if len(groups) > 1:
            lines.append("[b #7fb069]◆ По базовым доменам:[/b #7fb069]")
            for suffix in sorted(groups.keys()):
                items = groups[suffix]
                lines.append(f"  [#e63946]{suffix}[/#e63946]  [#555555]({len(items)})[/#555555]")
                for d in items[:8]:
                    lines.append(f"    [#8a8a8a]•[/#8a8a8a] {d}")
                if len(items) > 8:
                    lines.append(f"    [#555555]... и ещё {len(items) - 8}[/#555555]")
                lines.append("")
        else:
            lines.append("[b #7fb069]◆ Домены:[/b #7fb069]")
            for d in data["domains"][:50]:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {d}")
            if len(data["domains"]) > 50:
                lines.append(f"  [#555555]... и ещё {len(data['domains']) - 50}[/#555555]")

        return "\n".join(lines)


PLUGIN = ReverseIp()
