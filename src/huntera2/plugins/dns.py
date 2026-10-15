import json
import socket
import time
from huntera2.sdk import Plugin
from huntera2.core.config import DEFAULT_DNS_SERVERS

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


DEFAULT_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
ALL_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

PUBLIC_RESOLVERS = {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}


def _fmt_rdata(rtype: str, rdata) -> str:
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if rtype == "SOA":
        return f"{rdata.mname} {rdata.rname} serial={rdata.serial}"
    return str(rdata)


class DnsLookup(Plugin):
    name = "dns"
    description = "DNS lookup: A/AAAA/MX/NS/TXT/CNAME/SOA/PTR/SRV/CAA, reverse, custom resolver"
    usage = "host=example.com [types=A,MX,NS] [server=8.8.8.8] [reverse=1] [all=1] [json=1]"
    icon = "🛰"
    cache_ttl = 3600
    category = "Recon"
    needs_network = True

    def run(self, args: dict) -> str:
        if not DNS_AVAILABLE:
            return "[#e63946]dnspython not installed.[/#e63946] Run: pip install dnspython"

        host = args.get("host")
        if not host:
            return "Error: pass host=<example.com>"

        host = host.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]

        # --- Режим обратного резолвинга ---
        if args.get("reverse") in ("1", "true", "yes"):
            return self._reverse(host)

        # --- Типы записей ---
        if args.get("all") in ("1", "true", "yes"):
            types = ALL_TYPES
        elif args.get("types"):
            types = [t.strip().upper() for t in args["types"].split(",") if t.strip()]
        else:
            types = DEFAULT_TYPES

        # --- Резолвер ---
        server = args.get("server")
        # Termux не имеет /etc/resolv.conf, поэтому всегда задаём nameservers явно
        public_resolvers = DEFAULT_DNS_SERVERS
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server] if server else public_resolvers
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        json_out = args.get("json") in ("1", "true", "yes")
        results = {}
        errors = []

        for rtype in types:
            start = time.monotonic()
            try:
                answers = resolver.resolve(host, rtype)
                rtt = (time.monotonic() - start) * 1000
                records = [_fmt_rdata(rtype, r) for r in answers]
                results[rtype] = {"records": records, "rtt_ms": round(rtt, 1)}
            except dns.resolver.NXDOMAIN:
                errors.append(f"NXDOMAIN: {host} does not exist")
                break
            except dns.resolver.NoAnswer:
                results[rtype] = {"records": [], "rtt_ms": None}
            except dns.exception.Timeout:
                results[rtype] = {"records": [], "rtt_ms": None, "error": "timeout"}
            except Exception as e:
                results[rtype] = {"records": [], "rtt_ms": None, "error": str(e)}

        if errors:
            return f"[#e63946]{errors[0]}[/#e63946]"

        # --- JSON ---
        if json_out:
            return json.dumps({
                "host": host,
                "resolver": server or "system",
                "records": results,
            }, indent=2, ensure_ascii=False)

        # --- Вывод ---
        lines = []
        lines.append(f"[b]Host:[/b]     {host}")
        lines.append(f"[b]Resolver:[/b] {server or 'system'}")
        lines.append(f"[b]Types:[/b]    {', '.join(types)}")
        lines.append("")

        any_found = False
        for rtype in types:
            data = results.get(rtype, {})
            records = data.get("records", [])
            rtt = data.get("rtt_ms")
            if records:
                any_found = True
                rtt_str = f" [#555555]({rtt}ms)[/#555555]" if rtt else ""
                lines.append(f"[b #7fb069]◆ {rtype}[/b #7fb069]{rtt_str}")
                for r in records:
                    lines.append(f"  [#8a8a8a]•[/#8a8a8a] {r}")
                lines.append("")
            elif data.get("error"):
                lines.append(f"[b #e63946]✗ {rtype}[/b #e63946]  [#e63946]{data['error']}[/#e63946]")
                lines.append("")

        if not any_found:
            lines.append("[#e6b800]No records found.[/#e6b800]")

        return "\n".join(lines)

    def _reverse(self, ip: str) -> str:
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            records = [str(r) for r in answers]
        except Exception as e:
            return f"[#e63946]Reverse DNS error:[/#e63946] {e}"

        lines = [f"[b]IP:[/b] {ip}", ""]
        lines.append("[b #7fb069]◆ PTR Records:[/b #7fb069]")
        for r in records:
            lines.append(f"  [#8a8a8a]•[/#8a8a8a] {r}")
        return "\n".join(lines)


PLUGIN = DnsLookup()
