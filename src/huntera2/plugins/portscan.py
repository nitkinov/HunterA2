import asyncio
import concurrent.futures
import ipaddress
import json
import random
import re
from huntera2.sdk import Plugin


PORT_PRESETS = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top100": [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157],
    "top1000": list(range(1, 1025)),
    "web": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
    "db": [3306, 5432, 27017, 6379, 1433, 1521, 5984, 9042, 11211, 9200, 9300],
    "mail": [25, 110, 143, 993, 995, 587, 465, 2525],
    "windows": [135, 139, 445, 3389, 5985, 5986, 47001],
    "dangerous": [4444, 5555, 6666, 6667, 31337, 12345, 27374, 1234, 1235, 1236, 1080, 3128, 8080, 8888, 9001, 9050, 9150],
}

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
}

BANNER_PATTERNS = [
    (re.compile(r"SSH-2\.0-([^\s]+)"), "SSH ({})"),
    (re.compile(r"Server: ([^\r\n]+)"), "HTTP Server: {}"),
    (re.compile(r"220 ([^\s]+) (?:FTP|SMTP)"), "{}"),
    (re.compile(r"MySQL"), "MySQL"),
    (re.compile(r"PostgreSQL"), "PostgreSQL"),
    (re.compile(r"Redis"), "Redis"),
    (re.compile(r"HTTP/1\.[01] (\d{3})"), "HTTP"),
]

_GLOBAL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1)


SCAN_PROFILES = {
    "stealth": {"concurrency": 10, "timeout": 5.0, "delay": 1.0, "jitter": 0.5, "grab": False},
    "aggressive": {"concurrency": 500, "timeout": 1.0, "delay": 0.0, "jitter": 0.0, "grab": True},
    "intense": {"concurrency": 200, "timeout": 2.0, "delay": 0.0, "jitter": 0.0, "grab": True},
    "paranoid": {"concurrency": 5, "timeout": 8.0, "delay": 2.0, "jitter": 2.0, "grab": True},
    "normal": {"concurrency": 200, "timeout": 2.0, "delay": 0.0, "jitter": 0.0, "grab": True},
}


def _parse_ports(spec: str) -> list[int]:
    spec = spec.strip().lower()
    if spec in PORT_PRESETS:
        return PORT_PRESETS[spec]
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _expand_targets(target: str) -> list[str]:
    target = target.strip()
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return [target]
    return [target]


def _detect_service(port: int, banner: str) -> str:
    if banner:
        for pattern, name in BANNER_PATTERNS:
            m = pattern.search(banner)
            if m:
                if "{}" in name and m.groups():
                    return name.format(m.group(1))
                return name
    return SERVICE_MAP.get(port, "unknown")


def _protocol_probe(port: int) -> bytes:
    if port == 3306:
        return b"\x0a\x00\x00\x00\x03SELECT VERSION()\x00"
    if port == 6379:
        return b"PING\r\n"
    if port == 21:
        return b"\r\n"
    if port == 25:
        return b"EHLO hunter\r\n"
    if port in (80, 8080, 8000, 8888):
        return b"HEAD / HTTP/1.0\r\n\r\n"
    return b"\r\n"


async def _check_host_alive(host: str, timeout: float = 2.0) -> bool:
    for port in (80, 443, 22):
        try:
            fut = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, OSError):
            continue
    return False


async def _scan_port(host: str, port: int, timeout: float, grab: bool, delay: float) -> dict | None:
    if delay > 0:
        await asyncio.sleep(delay)
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None

    banner = ""
    try:
        if grab:
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=1.0)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()
            except asyncio.TimeoutError:
                pass
            if not banner:
                try:
                    writer.write(_protocol_probe(port))
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(256), timeout=1.5)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return {"port": port, "service": _detect_service(port, banner), "banner": banner[:80]}


async def _scan_stream(host: str, ports: list[int], concurrency: int, timeout: float,
                       grab: bool, delay: float, jitter: float, emit) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _bounded(p):
        async with sem:
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            return await _scan_port(host, p, timeout, grab, delay)

    tasks = [asyncio.create_task(_bounded(p)) for p in ports]
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            results.append(res)
            if emit:
                banner = res["banner"][:60] if res["banner"] else "[#555555]—[/#555555]"
                emit(
                    f"  [#e63946]:{res['port']}[/#e63946]  "
                    f"[#8a8a8a]{res['service']:<16}[/#8a8a8a]  {banner}\n"
                )
    results.sort(key=lambda r: r["port"])
    return results


def _run_stream_in_thread(host, ports, concurrency, timeout, grab, delay, jitter, emit):
    """Переиспользует глобальный executor вместо создания нового."""
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                _scan_stream(host, ports, concurrency, timeout, grab, delay, jitter, emit)
            )
        finally:
            loop.close()
    return _GLOBAL_EXECUTOR.submit(_worker).result()


class PortScan(Plugin):
    name = "portscan"
    description = "Async TCP port scanner with streaming output, host discovery, banner grabbing"
    usage = "host=example.com [ports=top100] [profile=normal] [json=1]"
    icon = "📡"
    category = "Network"
    needs_network = True
    supports_stream = True

    def run(self, args: dict) -> str:
        return self._run(args, emit=None)

    def run_stream(self, args: dict, emit) -> str:
        return self._run(args, emit=emit)

    def _run(self, args: dict, emit) -> str:
        host = args.get("host")
        if not host:
            return "Error: pass host=<example.com>"

        host = host.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]

        profile_name = args.get("profile", "normal").lower()
        profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["normal"])

        concurrency = int(args.get("concurrency", str(profile["concurrency"])))
        timeout = float(args.get("timeout", str(profile["timeout"])))
        delay = float(args.get("delay", str(profile["delay"])))
        jitter = float(args.get("jitter", str(profile["jitter"])))
        grab = args.get("no-banner") not in ("1", "true", "yes") and profile["grab"]
        json_out = args.get("json") in ("1", "true", "yes")

        targets = _expand_targets(host)
        ports_spec = args.get("ports", "top100")
        try:
            ports = _parse_ports(ports_spec)
        except Exception as e:
            return f"[#e63946]Invalid ports:[/#e63946] {e}"

        if not ports:
            return "[#e63946]No valid ports to scan[/#e63946]"

        header = (
            f"[b #e63946]▸ Scanning[/b #e63946] [b]{host}[/b]\n"
            f"[#555555]ports={len(ports)} ({ports_spec}) · profile={profile_name} · "
            f"conc={concurrency} · timeout={timeout}s[/#555555]\n"
        )
        if emit:
            emit(header)
        lines = [header]

        all_results = []
        for t in targets:
            if not _run_stream_in_thread(t, [80], 1, 2.0, False, 0, 0, lambda _: None):
                continue

            host_header = f"\n[b]{t}[/b]\n"
            if emit:
                emit(host_header)
            lines.append(host_header)

            try:
                res = _run_stream_in_thread(
                    t, ports, concurrency, timeout, grab, delay, jitter,
                    emit if emit else lambda _: None,
                )
                all_results.append((t, res))
            except Exception as e:
                err = f"[#e63946]✗ {e}[/#e63946]\n"
                if emit:
                    emit(err)
                lines.append(err)
                all_results.append((t, []))

        total = sum(len(r) for _, r in all_results)
        summary = (
            f"\n[#7fb069]✓ Found:[/#7fb069] [b]{total}[/b] open port(s) "
            f"across {len(targets)} target(s)\n"
        )
        if emit:
            emit(summary)

        self._last_results = all_results
        return "".join(lines) + summary


PLUGIN = PortScan()
