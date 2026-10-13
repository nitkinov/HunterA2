import json
import re
import httpx
from huntera2.sdk import Plugin
from huntera2.core import severity

# --- Security Header Rules (OWASP-based) ---
SECURITY_RULES = {
    "strict-transport-security": {
        "risk": "Critical",
        "recommendation": "max-age=63072000; includeSubDomains; preload",
        "attack": "SSL stripping / MITM"
    },
    "content-security-policy": {
        "risk": "Critical",
        "recommendation": "default-src 'self'; ... (see OWASP)",
        "attack": "XSS / data injection"
    },
    "x-frame-options": {
        "risk": "High",
        "recommendation": "DENY or SAMEORIGIN",
        "attack": "Clickjacking"
    },
    "x-content-type-options": {
        "risk": "High",
        "recommendation": "nosniff",
        "attack": "MIME sniffing"
    },
    "referrer-policy": {
        "risk": "Medium",
        "recommendation": "strict-origin-when-cross-origin",
        "attack": "URL data leakage"
    },
    "permissions-policy": {
        "risk": "Medium",
        "recommendation": "geolocation=(), microphone=(), camera=()",
        "attack": "Feature abuse"
    },
    "access-control-allow-origin": {
        "risk": "Critical",
        "recommendation": "Avoid '*' with credentials",
        "attack": "CORS data theft"
    },
    "cache-control": {
        "risk": "Medium",
        "recommendation": "no-store, no-cache, must-revalidate",
        "attack": "Sensitive data caching"
    },
    "x-xss-protection": {
        "risk": "Low",
        "recommendation": "1; mode=block (deprecated, use CSP)",
        "attack": "Reflected XSS"
    },
}

# --- Info Leak Headers ---
LEAKY_HEADERS = {
    "server": "Server version",
    "x-powered-by": "Technology & version",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "Content generator",
    "x-runtime": "Runtime version",
    "via": "Proxy information",
    "x-varnish": "Varnish cache",
}

# --- Technology Fingerprints ---
TECH_FINGERPRINTS = {
    "server": {
        "nginx": "Nginx",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "iis": "Microsoft IIS",
        "gunicorn": "Gunicorn",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
    },
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure",
}

MAX_VALUE_LEN = 90

def _truncate(value: str, limit: int = MAX_VALUE_LEN) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."

def _color_status(code: int) -> str:
    if 200 <= code < 300:
        return f"[#7fb069]{code}[/#7fb069]"
    if 300 <= code < 400:
        return f"[#e6b800]{code}[/#e6b800]"
    return f"[#e63946]{code}[/#e63946]"

def _grade(score: int) -> str:
    if score >= 95: return "[#7fb069]A+[/#7fb069]"
    if score >= 90: return "[#7fb069]A[/#7fb069]"
    if score >= 80: return "[#a3c94b]B[/#a3c94b]"
    if score >= 70: return "[#e6b800]C[/#e6b800]"
    if score >= 60: return "[#e68a00]D[/#e68a00]"
    return "[#e63946]F[/#e63946]"

def _analyze_cors(headers: dict) -> list:
    """Check for CORS misconfigurations."""
    issues = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        issues.append("CRITICAL: CORS allows '*' with credentials")
    if acao and acao != "*" and acac.lower() == "true":
        issues.append("CORS reflects origin with credentials — verify trust")
    return issues

def _analyze_cookies(headers: httpx.Headers) -> list:
    """Audit Set-Cookie flags."""
    issues = []
    for cookie in headers.get_list("set-cookie"):
        name = cookie.split("=")[0].strip()
        if "secure" not in cookie.lower():
            issues.append(f"Cookie '{name}' missing Secure flag")
        if "httponly" not in cookie.lower():
            issues.append(f"Cookie '{name}' missing HttpOnly flag")
        if "samesite" not in cookie.lower():
            issues.append(f"Cookie '{name}' missing SameSite flag")
    return issues

def _fingerprint(headers: dict) -> list:
    """Passive technology fingerprinting."""
    techs = []
    for header, mapping in TECH_FINGERPRINTS.items():
        if isinstance(mapping, dict):
            value = headers.get(header, "").lower()
            for keyword, name in mapping.items():
                if keyword in value:
                    techs.append(name)
        elif header in headers:
            techs.append(mapping)
    return sorted(set(techs))

class HttpProbe(Plugin):
    name = "http_probe"
    description = "Probe a URL: headers, security audit, CORS, cookies, fingerprint"
    usage = "url=https://example.com [full=1] [audit=1] [json=1]"
    icon = "🌐"
    cache_ttl = 600
    category = "Web"
    needs_network = True

    def run(self, args: dict) -> str:
        url = args.get("url")
        if not url:
            return "Error: pass url=<https://example.com>"

        full = args.get("full") in ("1", "true", "yes")
        no_cookie = args.get("no-cookie") in ("1", "true", "yes")
        audit_only = args.get("audit") in ("1", "true", "yes")
        json_out = args.get("json") in ("1", "true", "yes")

        try:
            r = httpx.get(
                url,
                follow_redirects=True,
                timeout=10,
                headers={"User-Agent": "HunterA2/0.1"},
            )
        except httpx.HTTPError as e:
            return f"[#e63946]HTTP error:[/#e63946] {e}"

        headers = {k.lower(): v for k, v in r.headers.items()}
        raw_headers = r.headers

        # --- Audit ---
        issues = []
        present = []
        for h, rule in SECURITY_RULES.items():
            if h in headers:
                present.append((h, headers[h], rule))
            else:
                issues.append((h, rule))

        # Score calculation
        score = max(0, 100 - sum(
            25 if rule["risk"] == "Critical" else
            15 if rule["risk"] == "High" else
            5 if rule["risk"] == "Medium" else 2
            for _, rule in issues
        ))
        grade = _grade(score)

        # CORS & Cookie analysis
        cors_issues = _analyze_cors(headers)
        cookie_issues = _analyze_cookies(raw_headers) if not no_cookie else []

        # Fingerprint
        techs = _fingerprint(headers)

        # --- JSON Output ---
        if json_out:
            return json.dumps({
                "url": str(r.url),
                "status": r.status_code,
                "score": score,
                "grade": re.sub(r"\[.*?\]", "", grade),
                "present": [{"header": h, "value": v} for h, v, _ in present],
                "missing": [{"header": h, "risk": rule["risk"], "attack": rule["attack"]}
                           for h, rule in issues],
                "cors_issues": cors_issues,
                "cookie_issues": cookie_issues,
                "technologies": techs,
                "headers": dict(r.headers),
            }, indent=2, ensure_ascii=False)

        # --- Human-Readable Output ---
        lines = []
        lines.append(f"[b]URL:[/b]    {r.url}")
        lines.append(f"[b]Status:[/b] {_color_status(r.status_code)} {r.reason_phrase}")
        lines.append(f"[b]Score:[/b]  {score}/100  {severity.grade(score)}")
        lines.append("")

        # Technologies
        if techs:
            lines.append(f"[b #7fb069]◆ Technologies:[/b #7fb069] {', '.join(techs)}")
            lines.append("")

        # Missing headers
        if issues:
            lines.append("[b #e63946]⚠ Missing / Weak Headers:[/b #e63946]")
            for h, rule in issues:
                lvl = rule["risk"].lower()
                lines.append(f"  {severity.tag(lvl)} [b]{h}[/b]")
                lines.append(f"    [#555555]→ {rule['recommendation']}[/#555555]")
                lines.append(f"    [#555555]⚔ {rule['attack']}[/#555555]")
            lines.append("")

        # Present headers
        if present and not audit_only:
            lines.append("[b #7fb069]✓ Present Headers:[/b #7fb069]")
            for h, v, _ in present:
                lines.append(f"  [#8a8a8a]{h}:[/#8a8a8a] {_truncate(v)}")
            lines.append("")

        # CORS issues
        if cors_issues:
            lines.append("[b #e63946]✗ CORS Misconfigurations:[/b #e63946]")
            for issue in cors_issues:
                lines.append(f"  [#e63946]•[/#e63946] {issue}")
            lines.append("")

        # Cookie issues
        if cookie_issues:
            lines.append("[b #e6b800]ℹ Cookie Issues:[/b #e6b800]")
            for issue in cookie_issues:
                lines.append(f"  [#e6b800]•[/#e6b800] {issue}")
            lines.append("")

        # Info leaks
        leaked = {k: v for k, v in headers.items() if k in LEAKY_HEADERS}
        if leaked:
            lines.append("[b #e6b800]ℹ Information Leaks:[/b #e6b800]")
            for k, v in leaked.items():
                lines.append(f"  [#8a8a8a]{k}:[/#8a8a8a] {v}  [#555555]({LEAKY_HEADERS[k]})[/#555555]")
            lines.append("")

        # Full headers
        if full and not audit_only:
            lines.append(f"[b]All Headers:[/b] ({len(headers)})")
            for k, v in headers.items():
                if no_cookie and k == "set-cookie":
                    continue
                lines.append(f"  [#8a8a8a]{k}:[/#8a8a8a] {_truncate(v)}")

        return "\n".join(lines)

PLUGIN = HttpProbe()
