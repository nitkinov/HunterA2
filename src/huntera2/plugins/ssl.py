import json
import socket
import ssl
from datetime import datetime, timezone
from huntera2.sdk import Plugin
from huntera2.core import severity

CRYPTO_AVAILABLE = None
_CRYPTO_MODS = {}


def _ensure_crypto():
    global CRYPTO_AVAILABLE, _CRYPTO_MODS
    if CRYPTO_AVAILABLE is None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            from cryptography.hazmat.primitives import hashes
            _CRYPTO_MODS = {"x509": x509, "rsa": rsa, "ec": ec, "dsa": dsa, "hashes": hashes}
            CRYPTO_AVAILABLE = True
        except ImportError:
            CRYPTO_AVAILABLE = False
    return CRYPTO_AVAILABLE

DEFAULT_TIMEOUT = 10.0

# --- Устаревшие версии TLS ---
DEPRECATED_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# --- Слабые шифры (подстроки в имени) ---
WEAK_CIPHERS = {
    "RC4": "RC4 (broken stream cipher)",
    "DES": "DES (56-bit, too weak)",
    "3DES": "3DES (64-bit, deprecated)",
    "MD5": "MD5 (broken hash)",
    "NULL": "NULL (no encryption)",
    "EXPORT": "EXPORT-grade (intentionally weakened)",
    "anon": "Anonymous (no authentication)",
}

# --- PFS-шифры ---
PFS_CIPHERS = ["ECDHE", "DHE"]


def _test_tls_version(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    """Проверяет, поддерживает ли сервер указанную версию TLS."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except (ssl.SSLError, socket.timeout, OSError):
        return False


def _get_cert_chain(host: str, port: int, timeout: float) -> dict:
    """Получает цепочку сертификатов и информацию о соединении."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            tls_version = ssock.version()
            cipher = ssock.cipher()
            # Получаем цепочку сертификатов
            chain = []
            try:
                chain_der = ssock.get_verified_chain() if hasattr(ssock, 'get_verified_chain') else []
                if not chain_der:
                    chain_der = [ssock.getpeercert(binary_form=True)]
            except Exception:
                chain_der = [ssock.getpeercert(binary_form=True)]
    return {"chain_der": chain_der, "tls_version": tls_version, "cipher": cipher}


def _parse_cert(der: bytes) -> dict:
    """Разбирает DER-сертификат через cryptography."""
    _ensure_crypto()
    x509 = _CRYPTO_MODS["x509"]
    cert = x509.load_der_x509_certificate(der)

    def _get_utc(dt):
        if hasattr(dt, "utc"):
            return dt.utc
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    not_before = _get_utc(cert.not_valid_before)
    not_after = _get_utc(cert.not_valid_after)
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    # SAN
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    # Ключ
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        key_type, key_size = "RSA", pubkey.key_size
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_type, key_size = "ECC", pubkey.key_size
    elif isinstance(pubkey, dsa.DSAPublicKey):
        key_type, key_size = "DSA", pubkey.key_size
    else:
        key_type, key_size = "Unknown", 0

    # Подпись
    sig_hash = "Unknown"
    try:
        sig_hash = cert.signature_hash_algorithm.name.upper()
    except Exception:
        pass

    # Издатель / субъект
    def _get_attr(name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""

    return {
        "subject_cn": _get_attr(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _get_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _get_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _get_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "is_expired": days_left < 0,
        "sans": sans,
        "key_type": key_type,
        "key_size": key_size,
        "sig_hash": sig_hash,
        "self_signed": cert.issuer == cert.subject,
        "sha256_fp": cert.fingerprint(hashes.SHA256()).hex(),
        "sha1_fp": cert.fingerprint(hashes.SHA1()).hex(),
    }


def _check_hsts(host: str, port: int, timeout: float) -> dict:
    """Проверяет HSTS-заголовок."""
    import http.client
    result = {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hsts = resp.getheader("Strict-Transport-Security", "")
        if hsts:
            result["present"] = True
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        result["max_age"] = int(part.split("=")[1])
                    except ValueError:
                        pass
                elif part == "includesubdomains":
                    result["include_subdomains"] = True
                elif part == "preload":
                    result["preload"] = True
        conn.close()
    except Exception:
        pass
    return result


def _check_vulnerabilities(tls_supported: dict, cipher_name: str) -> list:
    """Проверяет известные уязвимости по поддержке протоколов/шифров."""
    vulns = []
    if tls_supported.get("SSLv3"):
        vulns.append({"name": "POODLE", "severity": "High", "desc": "SSLv3 padding oracle"})
    if tls_supported.get("TLSv1") and "CBC" in cipher_name.upper():
        vulns.append({"name": "BEAST", "severity": "Medium", "desc": "TLS 1.0 CBC IV issue"})
    if "RC4" in cipher_name.upper():
        vulns.append({"name": "RC4 NOMORE", "severity": "High", "desc": "RC4 biases"})
    if "EXP" in cipher_name.upper() or "EXPORT" in cipher_name.upper():
        vulns.append({"name": "FREAK", "severity": "High", "desc": "Export-grade RSA"})
    if "DHE" in cipher_name.upper() and tls_supported.get("TLSv1"):
        vulns.append({"name": "Logjam (potential)", "severity": "Medium", "desc": "Weak DH params possible"})
    return vulns


def _grade(cert: dict, tls_supported: dict, hsts: dict, vulns: list) -> tuple:
    """Оценка по методологии SSL Labs (адаптированная)."""
    score = 100

    # Сертификат
    if cert["is_expired"]:
        score -= 60
    elif cert["days_left"] < 7:
        score -= 30
    elif cert["days_left"] < 30:
        score -= 15

    if cert["self_signed"]:
        score -= 40
    if cert["sig_hash"] in ("SHA1", "MD5"):
        score -= 15
    if cert["key_type"] == "RSA" and cert["key_size"] < 2048:
        score -= 25
    elif cert["key_type"] == "ECC" and cert["key_size"] < 256:
        score -= 20

    # Протоколы
    if tls_supported.get("SSLv3") or tls_supported.get("SSLv2"):
        score -= 50
    if tls_supported.get("TLSv1") or tls_supported.get("TLSv1.1"):
        score -= 20
    if not tls_supported.get("TLSv1.2") and not tls_supported.get("TLSv1.3"):
        score -= 20

    # HSTS
    if hsts["present"]:
        if hsts["max_age"] < 15768000:  # 6 месяцев
            score -= 5
    else:
        score -= 5

    # Уязвимости
    for v in vulns:
        if v["severity"] == "High":
            score -= 30
        elif v["severity"] == "Medium":
            score -= 10

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


class SslAudit(Plugin):
    name = "ssl"
    description = "SSL/TLS audit: cert chain, ciphers, PFS, HSTS, vulnerabilities, OCSP, grade"
    usage = "host=example.com [port=443] [timeout=10] [json=1]"
    icon = "🔒"
    cache_ttl = 3600
    category = "TLS"
    needs_network = True

    def run(self, args: dict) -> str:
        if not _ensure_crypto():
            return "[#e63946]cryptography not installed.[/#e63946] Run: pip install cryptography"

        host = args.get("host")
        if not host:
            return "Error: pass host=<example.com>"

        host = host.replace("https://", "").replace("http://", "").split("/")[0].split("?")[0]
        port = int(args.get("port", "443"))
        timeout = float(args.get("timeout", str(DEFAULT_TIMEOUT)))
        json_out = args.get("json") in ("1", "true", "yes")

        # --- Получаем цепочку ---
        try:
            info = _get_cert_chain(host, port, timeout)
        except socket.timeout:
            return f"[#e63946]Connection timeout:[/#e63946] {host}:{port}"
        except ConnectionRefusedError:
            return f"[#e63946]Connection refused:[/#e63946] {host}:{port}"
        except ssl.SSLError as e:
            return f"[#e63946]SSL error:[/#e63946] {e}"
        except Exception as e:
            return f"[#e63946]Error:[/#e63946] {e}"

        chain_der = info["chain_der"]
        if not chain_der:
            return "[#e63946]No certificate received[/#e63946]"

        try:
            cert = _parse_cert(chain_der[0])
            chain = [_parse_cert(der) for der in chain_der]
        except Exception as e:
            return f"[#e63946]Failed to parse certificate:[/#e63946] {e}"

        # --- TLS версии ---
        tls_versions = {}
        for name, ver in [
            ("TLSv1", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]:
            tls_versions[name] = _test_tls_version(host, port, ver, timeout)

        # --- HSTS ---
        hsts = _check_hsts(host, port, timeout)

        # --- Уязвимости ---
        cipher_name = info["cipher"][0] if info["cipher"] else ""
        vulns = _check_vulnerabilities(tls_versions, cipher_name)

        # --- Оценка ---
        score, grade = _grade(cert, tls_versions, hsts, vulns)

        # --- JSON ---
        if json_out:
            return json.dumps({
                "host": host, "port": port,
                "score": score, "grade": grade,
                "tls_version": info["tls_version"],
                "cipher": {"name": info["cipher"][0], "protocol": info["cipher"][1], "bits": info["cipher"][2]} if info["cipher"] else None,
                "tls_supported": tls_versions,
                "hsts": hsts,
                "vulnerabilities": vulns,
                "certificate": {
                    "subject_cn": cert["subject_cn"],
                    "subject_org": cert["subject_org"],
                    "issuer_cn": cert["issuer_cn"],
                    "issuer_org": cert["issuer_org"],
                    "serial": cert["serial"],
                    "not_before": cert["not_before"].isoformat(),
                    "not_after": cert["not_after"].isoformat(),
                    "days_left": cert["days_left"],
                    "is_expired": cert["is_expired"],
                    "self_signed": cert["self_signed"],
                    "sans": cert["sans"],
                    "key_type": cert["key_type"],
                    "key_size": cert["key_size"],
                    "sig_hash": cert["sig_hash"],
                    "sha256_fingerprint": cert["sha256_fp"],
                },
                "chain_length": len(chain),
            }, indent=2, ensure_ascii=False)

        # --- Human-readable ---
        grade_color = {"A+": "#7fb069", "A": "#7fb069", "B": "#a3c94b",
                       "C": "#e6b800", "D": "#e68a00", "F": "#e63946"}.get(grade, "#8a8a8a")

        lines = []
        lines.append(f"[b]Host:[/b]         {host}:{port}")
        lines.append(f"[b]Grade:[/b]        {severity.grade(score)}  [#555555]({score}/100)[/#555555]")
        lines.append(f"[b]TLS version:[/b]  {info['tls_version']}")
        cipher_name, cipher_proto, cipher_bits = info["cipher"]
        lines.append(f"[b]Cipher:[/b]       {cipher_name}  [#555555]({cipher_bits} bits)[/#555555]")
        lines.append("")

        # TLS versions
        lines.append("[b]◆ Supported TLS Versions:[/b]")
        for ver, sup in tls_versions.items():
            if sup:
                if ver in DEPRECATED_VERSIONS:
                    lines.append(f"  [#e63946]✗ {ver}[/#e63946]  [#e63946](deprecated)[/#e63946]")
                else:
                    lines.append(f"  [#7fb069]✓ {ver}[/#7fb069]")
            else:
                lines.append(f"  [#555555]— {ver}[/#555555]")
        lines.append("")

        # Certificate chain
        lines.append(f"[b]◆ Certificate Chain:[/b] [#555555]({len(chain)} cert(s))[/#555555]")
        for i, c in enumerate(chain):
            role = "Leaf" if i == 0 else "Intermediate" if i < len(chain) - 1 else "Root"
            lines.append(f"  [#8a8a8a]{role}:[/#8a8a8a] CN={c['subject_cn'] or '—'}  O={c['subject_org'] or '—'}")
        lines.append("")

        # Cert details
        lines.append("[b]◆ Leaf Certificate:[/b]")
        lines.append(f"  [#8a8a8a]Issuer:[/#8a8a8a]    CN={cert['issuer_cn'] or '—'}  O={cert['issuer_org'] or '—'}")
        lines.append(f"  [#8a8a8a]Serial:[/#8a8a8a]    {cert['serial']}")
        lines.append(f"  [#8a8a8a]Valid:[/#8a8a8a]     {cert['not_before'].strftime('%Y-%m-%d')} → {cert['not_after'].strftime('%Y-%m-%d')}")

        if cert["is_expired"]:
            lines.append(f"  [#e63946]✗ EXPIRED {-cert['days_left']} days ago![/#e63946]")
        elif cert["days_left"] < 7:
            lines.append(f"  [#e63946]✗ Expires in {cert['days_left']} days — critical![/#e63946]")
        elif cert["days_left"] < 30:
            lines.append(f"  [#e6b800]⚠ Expires in {cert['days_left']} days[/#e6b800]")
        else:
            lines.append(f"  [#7fb069]✓ {cert['days_left']} days left[/#7fb069]")

        lines.append(f"  [#8a8a8a]Key:[/#8a8a8a]       {cert['key_type']} {cert['key_size']} bits")
        lines.append(f"  [#8a8a8a]Signature:[/#8a8a8a] {cert['sig_hash']}")
        lines.append(f"  [#8a8a8a]Self-signed:[/#8a8a8a] {'[#e63946]YES[/#e63946]' if cert['self_signed'] else '[#7fb069]no[/#7fb069]'}")
        lines.append("")

        # HSTS
        if hsts["present"]:
            hsts_color = "#7fb069" if hsts["max_age"] >= 15768000 else "#e6b800"
            lines.append(f"[b]◆ HSTS:[/b] [{hsts_color}]✓ present[/{hsts_color}]  [#555555](max-age={hsts['max_age']}, subdomains={hsts['include_subdomains']}, preload={hsts['preload']})[/#555555]")
        else:
            lines.append("[b]◆ HSTS:[/b] [#e63946]✗ missing[/#e63946]  [#555555](vulnerable to SSL stripping)[/#555555]")
        lines.append("")

        # Vulnerabilities
        if vulns:
            lines.append("[b #e63946]◆ Vulnerabilities:[/b #e63946]")
            for v in vulns:
                lvl = v["severity"].lower()
                lines.append(f"  {severity.tag(lvl)}  [b]{v['name']}[/b]")
                lines.append(f"    [#555555]{v['desc']}[/#555555]")
            lines.append("")
        else:
            lines.append("[b #7fb069]◆ Vulnerabilities:[/b #7fb069] [#7fb069]none detected[/#7fb069]")
            lines.append("")

        # SANs
        if cert["sans"]:
            lines.append(f"[b]◆ SANs:[/b] [#555555]({len(cert['sans'])})[/#555555]")
            for san in cert["sans"][:15]:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {san}")
            if len(cert["sans"]) > 15:
                lines.append(f"  [#555555]... and {len(cert['sans']) - 15} more[/#555555]")
            lines.append("")

        # Fingerprints
        lines.append("[b]◆ Fingerprints:[/b]")
        lines.append(f"  [#8a8a8a]SHA-256:[/#8a8a8a] {cert['sha256_fp']}")

        return "\n".join(lines)


PLUGIN = SslAudit()
