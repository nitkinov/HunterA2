import json
import whois
from datetime import datetime, timezone
from huntera2.sdk import Plugin


EPP_STATUS_INFO = {
    "clientTransferProhibited": ("Locked: Transfer prohibited by registrar", "info"),
    "serverTransferProhibited": ("Locked: Transfer prohibited by registry", "info"),
    "clientDeleteProhibited": ("Locked: Delete prohibited by registrar", "info"),
    "serverDeleteProhibited": ("Locked: Delete prohibited by registry", "info"),
    "clientUpdateProhibited": ("Locked: Update prohibited by registrar", "info"),
    "serverUpdateProhibited": ("Locked: Update prohibited by registry", "info"),
    "clientHold": ("SUSPENDED: Domain not published in DNS", "critical"),
    "serverHold": ("SUSPENDED: Domain removed from DNS by registry", "critical"),
    "pendingDelete": ("Pending deletion", "warning"),
    "redemptionPeriod": ("In redemption period after expiry", "warning"),
    "autoRenewPeriod": ("Auto-renew grace period", "info"),
    "renewPeriod": ("Explicitly renewed by registrant", "info"),
    "transferPeriod": ("Transfer grace period", "info"),
    "addPeriod": ("Initial registration grace period", "info"),
    "ok": ("Active: No pending operations", "success"),
    "active": ("Active", "success"),
    "inactive": ("Inactive: No nameservers", "warning"),
}


def _rdap_lookup(domain: str, timeout: float = 10.0) -> dict | None:
    """Fallback через RDAP (современный протокол, работает со всеми TLD)."""
    import urllib.request
    import urllib.error
    url = f"https://rdap.org/domain/{domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1", "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data
    except Exception:
        return None


def _parse_rdap(data: dict) -> dict:
    """Извлекает ключевые поля из RDAP-ответа."""
    out = {
        "domain_name": data.get("ldhName", "").lower(),
        "status": data.get("status", []),
        "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])],
        "events": {},
        "entities": [],
        "registrar": None,
        "dnssec": None,
    }
    for ev in data.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        out["events"][action] = date

    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [None, []])
        name = ""
        if len(vcard) > 1:
            for item in vcard[1]:
                if item[0] == "fn":
                    name = item[3]
                elif item[0] == "org":
                    name = item[3]
        if "registrar" in roles:
            out["registrar"] = name
        out["entities"].append({"roles": roles, "name": name})

    # DNSSEC
    secure_dns = data.get("secureDNS", {})
    if secure_dns:
        out["dnssec"] = "signed" if secure_dns.get("delegationSigned") else "unsigned"

    return out


def _whois_with_fallback(domain: str):
    """Пробует python-whois, при провале — RDAP. Возвращает (source, data)."""
    # 1. python-whois
    try:
        w = whois.whois(domain)
        if w and w.domain_name:
            return "whois", w
    except Exception:
        pass
    # 2. RDAP
    rdap = _rdap_lookup(domain)
    if rdap:
        return "rdap", _parse_rdap(rdap)
    return None, None


def _fmt_date(value) -> str:
    if not value:
        return "[#555555]—[/#555555]"
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _to_dt(value):
    if not value:
        return None
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return None


def _fmt_list(value) -> str:
    if not value:
        return "[#555555]—[/#555555]"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _truncate(value: str, limit: int = 80) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _days_between(dt) -> int:
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    delta = dt - now
    return delta.days


def _age_days(dt) -> int:
    if not dt:
        return 0
    now = datetime.now(timezone.utc)
    return (now - dt).days


def _risk_color(level: str) -> str:
    return {
        "critical": "#e63946",
        "warning": "#e6b800",
        "info": "#8a8a8a",
        "success": "#7fb069",
    }.get(level, "#8a8a8a")


class WhoisLookup(Plugin):
    name = "whois"
    description = "WHOIS lookup: registrar, dates, EPP status, DNSSEC, contacts"
    usage = "domain=example.com [raw=1] [json=1]"
    icon = "🔍"
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        domain = args.get("domain")
        if not domain:
            return "Error: pass domain=<example.com>"

        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0].split("?")[0]

        source, w = _whois_with_fallback(domain)
        if not w:
            return f"[#e6b800]No WHOIS/RDAP data for[/#e6b800] {domain}"

        # Нормализация: RDAP возвращает dict, WHOIS — объект
        if source == "rdap":
            class _RDAPWrap:
                def __init__(self, d):
                    self._d = d
                    self.domain_name = d.get("domain_name", domain)
                    self.registrar = d.get("registrar")
                    self.creation_date = d.get("events", {}).get("registration")
                    self.expiration_date = d.get("events", {}).get("expiration")
                    self.updated_date = d.get("events", {}).get("last changed")
                    self.status = d.get("status", [])
                    self.name_servers = d.get("nameservers", [])
                    self.emails = []
                    self.org = None
                    self.country = None
                    self.dnssec = d.get("dnssec")
                    self.registrant_name = None
                    self.text = None
            w = _RDAPWrap(w)

        # --- Dates ---
        created = _to_dt(w.creation_date)
        expires = _to_dt(w.expiration_date)
        updated = _to_dt(w.updated_date)
        age = _age_days(created)
        days_left = _days_between(expires)

        # --- EPP statuses ---
        statuses = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        status_lines = []
        has_hold = False
        for s in statuses:
            s_clean = str(s).replace("https://icann.org/epp#", "").strip()
            desc, level = EPP_STATUS_INFO.get(s_clean, ("Unknown status", "info"))
            if level == "critical":
                has_hold = True
            color = _risk_color(level)
            status_lines.append(f"  [{color}]●[/{color}] [#8a8a8a]{s_clean}[/#8a8a8a]  [{color}]{desc}[/{color}]")

        # --- DNSSEC ---
        dnssec = getattr(w, "dnssec", None)
        if isinstance(dnssec, list):
            dnssec = dnssec[0] if dnssec else None

        # --- JSON mode ---
        if args.get("json") in ("1", "true", "yes"):
            return json.dumps({
                "domain": str(w.domain_name) if not isinstance(w.domain_name, list) else w.domain_name[0],
                "registrar": str(w.registrar) if w.registrar else None,
                "created": created.isoformat() if created else None,
                "expires": expires.isoformat() if expires else None,
                "updated": updated.isoformat() if updated else None,
                "age_days": age,
                "days_to_expiry": days_left,
                "statuses": [str(s).replace("https://icann.org/epp#", "").strip() for s in statuses],
                "name_servers": [str(ns) for ns in (w.name_servers or [])],
                "dnssec": str(dnssec) if dnssec else None,
                "emails": [str(e) for e in (w.emails if isinstance(w.emails, list) else [w.emails])] if w.emails else [],
                "org": str(w.org) if w.org else None,
                "country": str(w.country) if w.country else None,
            }, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        lines = []
        domain_display = w.domain_name if not isinstance(w.domain_name, list) else w.domain_name[0]
        lines.append(f"[b #e63946]Domain:[/b #e63946]     {domain_display}")
        if w.registrar:
            lines.append(f"[b]Registrar:[/b]   {_truncate(str(w.registrar))}")

        # Age + expiry
        if age > 0:
            lines.append(f"[b]Age:[/b]         {age} days  [#555555]({age // 365} years)[/#555555]")
        if days_left != 0:
            color = "#7fb069" if days_left > 60 else "#e6b800" if days_left > 0 else "#e63946"
            lines.append(f"[b]Expires in:[/b]  [{color}]{days_left} days[/{color}]")
            if days_left < 30:
                lines.append(f"  [#e63946]⚠ Domain expires soon![/#e63946]")

        lines.append("")
        lines.append("[b]Dates:[/b]")
        lines.append(f"  [#8a8a8a]Created:[/#8a8a8a]  {_fmt_date(created)}")
        lines.append(f"  [#8a8a8a]Updated:[/#8a8a8a]  {_fmt_date(updated)}")
        lines.append(f"  [#8a8a8a]Expires:[/#8a8a8a]  {_fmt_date(expires)}")

        # Statuses
        if status_lines:
            lines.append("")
            lines.append("[b]Status:[/b]")
            lines.extend(status_lines)

        # DNSSEC
        lines.append("")
        if dnssec and str(dnssec).lower() not in ("unsigned", "no", "false"):
            lines.append(f"[#7fb069]✓ DNSSEC:[/#7fb069] {dnssec}")
        else:
            lines.append("[#e6b800]⚠ DNSSEC:[/#e6b800] not signed — vulnerable to DNS spoofing")

        # Nameservers
        if w.name_servers:
            lines.append("")
            lines.append("[b #7fb069]◆ Name Servers:[/b #7fb069]")
            for ns in w.name_servers:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {ns}")

        # Contacts
        contacts = []
        if w.emails:
            contacts.append(("Emails", _fmt_list(w.emails)))
        if w.org:
            contacts.append(("Org", _truncate(str(w.org))))
        if w.country:
            contacts.append(("Country", str(w.country)))
        if getattr(w, "registrant_name", None):
            contacts.append(("Registrant", _truncate(str(w.registrant_name))))

        if contacts:
            lines.append("")
            lines.append("[b #7fb069]◆ Contacts:[/b #7fb069]")
            for key, val in contacts:
                lines.append(f"  [#8a8a8a]{key}:[/#8a8a8a] {val}")

        # Security insights
        insights = []
        if has_hold:
            insights.append("[#e63946]✗ Domain is on HOLD — not resolving in DNS[/#e63946]")
        if days_left > 0 and days_left < 30:
            insights.append(f"[#e6b800]⚠ Expires in {days_left} days — renew soon[/#e6b800]")
        if not dnssec or str(dnssec).lower() in ("unsigned", "no", "false"):
            insights.append("[#e6b800]⚠ No DNSSEC — consider enabling it[/#e6b800]")
        if age < 365:
            insights.append("[#e6b800]⚠ Domain is less than a year old — verify trust[/#e6b800]")

        if insights:
            lines.append("")
            lines.append("[b #e63946]⚠ Security Insights:[/b #e63946]")
            for ins in insights:
                lines.append(f"  {ins}")

        # Raw
        if args.get("raw") in ("1", "true", "yes") and w.text:
            lines.append("")
            lines.append("[b]Raw WHOIS:[/b]")
            for line in w.text.splitlines()[:40]:
                if line.strip():
                    lines.append(f"  [#555555]{line.strip()}[/#555555]")

        return "\n".join(lines)


PLUGIN = WhoisLookup()
