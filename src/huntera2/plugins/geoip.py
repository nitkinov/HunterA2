import ipaddress
import json
import socket
import urllib.parse
import urllib.request
import urllib.error
from huntera2.sdk import Plugin

# --- API endpoints (fallback chain) ---
API_PRIMARY = "http://ip-api.com/json/{query}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
API_FALLBACK = "https://getmyip.pro/api/v1/{query}"

# --- CDN IP ranges (упрощённые, самые популярные) ---
CDN_RANGES = {
    "Cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.224.0.0/14", "13.249.0.0/16",
        "18.238.0.0/15", "52.84.0.0/15", "54.182.0.0/16",
        "54.192.0.0/16", "54.230.0.0/16", "99.84.0.0/16",
        "143.204.0.0/16", "204.246.164.0/22",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "185.31.16.0/22", "199.27.72.0/21",
    ],
    "Akamai": [
        "23.0.0.0/12", "104.64.0.0/10", "184.24.0.0/13",
    ],
}

# --- Security flag descriptions ---
SECURITY_FLAGS = {
    "proxy": ("Прокси / VPN", "#e6b800"),
    "hosting": ("Хостинг / датацентр", "#e6b800"),
    "mobile": ("Мобильный оператор", "#7fb069"),
}


def _lookup_primary(query: str, timeout: float) -> dict:
    """Основной API: ip-api.com (HTTP, 45 req/min)."""
    url = API_PRIMARY.format(query=urllib.parse.quote(query))
    req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("status") == "fail":
        raise ValueError(data.get("message", "lookup failed"))
    data["_source"] = "ip-api.com"
    return data


def _lookup_fallback(query: str, timeout: float) -> dict:
    """Резервный API: getmyip.pro (HTTPS, 60 req/min, без ключа)."""
    url = API_FALLBACK.format(query=urllib.parse.quote(query))
    req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ip"):
        raise ValueError("fallback lookup failed")
    # Нормализация под формат ip-api
    return {
        "status": "success",
        "query": data.get("ip"),
        "country": data.get("country"),
        "countryCode": data.get("country_code"),
        "regionName": data.get("region"),
        "city": data.get("city"),
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "timezone": data.get("timezone"),
        "isp": data.get("org") or data.get("isp"),
        "org": data.get("org"),
        "as": data.get("asn"),
        "reverse": data.get("reverse"),
        "proxy": data.get("is_proxy", False),
        "hosting": data.get("is_hosting", False),
        "_source": "getmyip.pro",
    }


def _is_tor_exit(ip: str, timeout: float = 5.0) -> bool:
    """Проверяет, является ли IP Tor exit-нодой."""
    try:
        with urllib.request.urlopen("https://check.torproject.org/torbulkexitlist", timeout=timeout) as resp:
            content = resp.read().decode("utf-8")
        return ip in content.splitlines()
    except Exception:
        return False


def _detect_cdn(ip: str) -> list[str]:
    """Определяет CDN по диапазонам IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    found = []
    for cdn_name, ranges in CDN_RANGES.items():
        for cidr in ranges:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    found.append(cdn_name)
                    break
            except ValueError:
                continue
    return found


def _resolve(query: str) -> tuple[str, str]:
    """Если query — домен, резолвит в IP. Возвращает (original, ip)."""
    original = query
    try:
        ipaddress.ip_address(query)
        return original, query
    except ValueError:
        pass
    try:
        # getaddrinfo поддерживает IPv4 и IPv6
        infos = socket.getaddrinfo(query, None)
        ip = infos[0][4][0]
        return original, ip
    except socket.gaierror as e:
        raise ValueError(f"Не удалось разрешить {query}: {e}")


class GeoIp(Plugin):
    name = "geoip"
    description = "IP geolocation: country, city, ISP, ASN, CDN, Tor, security flags, fallback API"
    usage = "query=8.8.8.8 | query=example.com [json=1]"
    icon = "🌍"
    cache_ttl = 86400
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        query = args.get("query") or args.get("ip") or args.get("host")
        if not query:
            return "Error: pass query=<IP or domain>"

        json_out = args.get("json") in ("1", "true", "yes")

        # --- Resolve ---
        try:
            original, ip = _resolve(query)
        except ValueError as e:
            return f"[#e63946]Resolution error:[/#e63946] {e}"

        # --- Lookup with fallback ---
        data = None
        errors = []
        for fn, name in [(_lookup_primary, "ip-api.com"), (_lookup_fallback, "getmyip.pro")]:
            try:
                data = fn(ip, timeout=10.0)
                break
            except Exception as e:
                errors.append(f"{name}: {e}")
        if data is None:
            return f"[#e63946]All APIs failed:[/#e63946] {'; '.join(errors)}"

        # --- Enrichment ---
        is_tor = _is_tor_exit(ip)
        cdns = _detect_cdn(ip)

        # --- JSON ---
        if json_out:
            out = dict(data)
            out["resolved_ip"] = ip
            if original != ip:
                out["resolved_from"] = original
            out["is_tor_exit"] = is_tor
            out["cdn"] = cdns
            return json.dumps(out, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        lines = []
        if original != ip:
            lines.append(f"[b]Query:[/b]   {original}  [#555555]→ {ip}[/#555555]")
        else:
            lines.append(f"[b]IP:[/b]      {ip}")
        lines.append(f"[#555555]source: {data.get('_source', '?')}[/#555555]")
        lines.append("")

        # Location
        lines.append("[b #7fb069]◆ Location:[/b #7fb069]")
        parts = [data.get("city"), data.get("regionName"), data.get("country")]
        location = ", ".join(p for p in parts if p)
        if location:
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] {location}  [#555555]({data.get('countryCode', '')})[/#555555]")
        if data.get("continent"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Континент: {data['continent']}")
        if data.get("district"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Район: {data['district']}")
        if data.get("zip"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Индекс: {data['zip']}")
        lines.append("")

        # Coordinates
        if data.get("lat") is not None and data.get("lon") is not None:
            lat, lon = data["lat"], data["lon"]
            lines.append("[b #7fb069]◆ Coordinates:[/b #7fb069]")
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] {lat}, {lon}")
            lines.append(f"  [#555555]https://www.google.com/maps?q={lat},{lon}[/#555555]")
            lines.append("")

        # Network
        lines.append("[b #7fb069]◆ Network:[/b #7fb069]")
        if data.get("isp"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Провайдер: {data['isp']}")
        if data.get("org"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Организация: {data['org']}")
        if data.get("as"):
            asn = data["as"].split()[0] if data["as"] else ""
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] ASN: {asn}")
        if data.get("reverse"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] PTR: {data['reverse']}")
        lines.append("")

        # Time & Currency
        lines.append("[b #7fb069]◆ Time & Currency:[/b #7fb069]")
        if data.get("timezone"):
            offset = data.get("offset", 0) or 0
            sign = "+" if offset >= 0 else "-"
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] {data['timezone']}  [#555555](UTC{sign}{abs(offset) // 3600})[/#555555]")
        if data.get("currency"):
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] Валюта: {data['currency']}")
        lines.append("")

        # Security & flags
        lines.append("[b #e6b800]◆ Security & Flags:[/b #e6b800]")
        if is_tor:
            lines.append("  [#e63946]✗ Tor exit node[/#e63946]  [#555555](анонимный трафик)[/#555555]")
        if cdns:
            for cdn in cdns:
                lines.append(f"  [#e6b800]• CDN:[/#e6b800] {cdn}")
        for key, (label, color) in SECURITY_FLAGS.items():
            if data.get(key):
                lines.append(f"  [{color}]• {label}[/{color}]")
        if not is_tor and not cdns and not any(data.get(k) for k in SECURITY_FLAGS):
            lines.append("  [#7fb069]✓ чисто[/#7fb069]")

        return "\n".join(lines)


PLUGIN = GeoIp()
