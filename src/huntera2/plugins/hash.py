import base64
import hashlib
import hmac
import json
import re
import secrets
import urllib.parse
from pathlib import Path

from huntera2.sdk import Plugin


HASH_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

# --- Эвристика идентификации хешей по длине и формату ---
HASH_PATTERNS = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    (re.compile(r"^\$argon2[id]{0,2}\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"), "argon2"),
    (re.compile(r"^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"), "pbkdf2_sha256"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$"), "md5crypt"),
    (re.compile(r"^\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43}$"), "sha256crypt"),
    (re.compile(r"^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}$"), "sha512crypt"),
    (re.compile(r"^[0-9a-fA-F]{32}$"), "MD5 / NTLM / LM"),
    (re.compile(r"^[0-9a-fA-F]{40}$"), "SHA1"),
    (re.compile(r"^[0-9a-fA-F]{56}$"), "SHA224"),
    (re.compile(r"^[0-9a-fA-F]{64}$"), "SHA256"),
    (re.compile(r"^[0-9a-fA-F]{96}$"), "SHA384"),
    (re.compile(r"^[0-9a-fA-F]{128}$"), "SHA512"),
    (re.compile(r"^[A-Za-z0-9+/]{22}==$"), "Base64 (16 bytes)"),
    (re.compile(r"^[A-Za-z0-9+/]{43}=$"), "Base64 (32 bytes)"),
]

B64_ALPHABET = re.compile(r"^[A-Za-z0-9+/=]+$")
B64_URLSAFE_ALPHABET = re.compile(r"^[A-Za-z0-9\-_=]+$")
HEX_ALPHABET = re.compile(r"^[0-9a-fA-F]+$")


def _hash_bytes(data: bytes, algos: list[str]) -> dict:
    result = {}
    for algo in algos:
        h = HASH_ALGOS[algo]()
        h.update(data)
        result[algo] = h.hexdigest()
    return result


def _hash_file(path: str, algos: list[str], chunk_size: int = 1048576) -> dict:
    result = {a: HASH_ALGOS[a]() for a in algos}
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            for h in result.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in result.items()}


def _identify(value: str) -> list[str]:
    matches = []
    for pattern, name in HASH_PATTERNS:
        if pattern.match(value):
            matches.append(name)
    return matches


def _b64_decode_safe(value: str, urlsafe: bool = False) -> bytes:
    alphabet = B64_URLSAFE_ALPHABET if urlsafe else B64_ALPHABET
    if not alphabet.match(value):
        raise ValueError("invalid base64 alphabet")
    return base64.urlsafe_b64decode(value) if urlsafe else base64.b64decode(value)


class HashTool(Plugin):
    name = "hash"
    description = "Hash: md5/sha1/sha224/sha256/sha384/sha512/sha3/blake2, Base64, URL, Hex, HMAC, PBKDF2, JWT, identify"
    usage = "text=hello | file=/path | identify=5d414... | b64=hello | b64d=... | hex=hello | hexd=... | url=hello | urld=... | hmac=key | pbkdf2=salt:100000 | jwt=... [type=sha256] [check=<hash>] [json=1]"
    icon = "🔐"
    category = "Utils"
    needs_network = False

    def run(self, args: dict) -> str:
        text = args.get("text")
        file_path = args.get("file")
        identify = args.get("identify")
        b64 = args.get("b64")
        b64d = args.get("b64d")
        hex_in = args.get("hex")
        hexd = args.get("hexd")
        url = args.get("url")
        urld = args.get("urld")
        hmac_key = args.get("hmac")
        pbkdf2 = args.get("pbkdf2")
        jwt_token = args.get("jwt")
        algo = args.get("type")
        check = args.get("check")
        json_out = args.get("json") in ("1", "true", "yes")

        algos = [algo] if algo in HASH_ALGOS else list(HASH_ALGOS.keys())

        # --- Identify hash ---
        if identify:
            matches = _identify(identify.strip())
            if json_out:
                return json.dumps({"input": identify, "matches": matches}, indent=2)
            if not matches:
                return f"[#e6b800]Не удалось определить тип хеша.[/#e6b800]\nВход: {identify}\nДлина: {len(identify)}"
            lines = [f"[b]Input:[/b] {identify}", f"[b]Length:[/b] {len(identify)}", "", "[b #7fb069]◆ Возможные типы:[/b #7fb069]"]
            for m in matches:
                lines.append(f"  [#8a8a8a]•[/#8a8a8a] {m}")
            return "\n".join(lines)

        # --- JWT decoder ---
        if jwt_token:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return "[#e63946]Неверный формат JWT (нужно 3 части через точку).[/#e63946]"
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==="))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==="))
            except Exception as e:
                return f"[#e63946]JWT decode error:[/#e63946] {e}"
            if json_out:
                return json.dumps({"header": header, "payload": payload, "signature": parts[2]}, indent=2, ensure_ascii=False)
            lines = ["[b #7fb069]◆ JWT Header:[/b #7fb069]"]
            for k, v in header.items():
                lines.append(f"  [#8a8a8a]{k}:[/#8a8a8a] {v}")
            lines.append("")
            lines.append("[b #7fb069]◆ JWT Payload:[/b #7fb069]")
            for k, v in payload.items():
                lines.append(f"  [#8a8a8a]{k}:[/#8a8a8a] {v}")
            lines.append("")
            lines.append(f"[#e6b800]⚠ Signature:[/#e6b800] {parts[2][:32]}... [#555555](не проверена)[/#555555]")
            if "alg" in header and header["alg"].lower() == "none":
                lines.append("[#e63946]✗ ALGORITHM 'none' — критическая уязвимость![/#e63946]")
            return "\n".join(lines)

        # --- PBKDF2 password hash ---
        if pbkdf2:
            if ":" in pbkdf2:
                salt_str, iters_str = pbkdf2.split(":", 1)
                salt = salt_str.encode("utf-8")
                iterations = int(iters_str)
            else:
                salt = secrets.token_bytes(16)
                iterations = 100000
            if not text:
                return "Error: pass text=<password> pbkdf2=[salt:iterations]"
            derived = hashlib.pbkdf2_hmac("sha256", text.encode("utf-8"), salt, iterations)
            salt_b64 = base64.b64encode(salt).decode()
            if json_out:
                return json.dumps({"algorithm": "pbkdf2-hmac-sha256", "iterations": iterations, "salt_b64": salt_b64, "hash_hex": derived.hex()}, indent=2)
            return (f"[b]PBKDF2-HMAC-SHA256:[/b]\n"
                    f"  [#8a8a8a]salt (b64):[/#8a8a8a] {salt_b64}\n"
                    f"  [#8a8a8a]iterations:[/#8a8a8a] {iterations}\n"
                    f"  [#7fb069]hash (hex):[/#7fb069] {derived.hex()}")

        # --- HMAC ---
        if hmac_key and text:
            sig = hmac.new(hmac_key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()
            if json_out:
                return json.dumps({"mode": "hmac-sha256", "key": hmac_key, "text": text, "hmac": sig}, indent=2)
            return f"[b]HMAC-SHA256:[/b]\n  [#8a8a8a]key:[/#8a8a8a]  {hmac_key}\n  [#8a8a8a]text:[/#8a8a8a] {text}\n  [#7fb069]hmac:[/#7fb069] {sig}"

        # --- Hash file ---
        if file_path:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return f"[#e63946]File not found:[/#e63946] {file_path}"
            try:
                digests = _hash_file(str(p), algos)
            except Exception as e:
                return f"[#e63946]Error hashing file:[/#e63946] {e}"
            if json_out:
                return json.dumps({"file": str(p), "size": p.stat().st_size, "hashes": digests}, indent=2)
            lines = [f"[b]File:[/b]  {p}", f"[b]Size:[/b]  {p.stat().st_size:,} bytes", ""]
            for a, d in digests.items():
                line = f"  [#8a8a8a]{a:<10}[/#8a8a8a] {d}"
                if check and d.lower() == check.lower():
                    line += "  [#7fb069]✓ совпадает[/#7fb069]"
                lines.append(line)
            return "\n".join(lines)

        # --- Hash text ---
        if text:
            data = text.encode("utf-8")
            digests = _hash_bytes(data, algos)
            if json_out:
                return json.dumps({"text": text, "hashes": digests}, indent=2, ensure_ascii=False)
            lines = [f"[b]Input:[/b] {text}", ""]
            for a, d in digests.items():
                line = f"  [#8a8a8a]{a:<10}[/#8a8a8a] {d}"
                if check and d.lower() == check.lower():
                    line += "  [#7fb069]✓ совпадает[/#7fb069]"
                lines.append(line)
            return "\n".join(lines)

        # --- Base64 encode ---
        if b64:
            encoded = base64.b64encode(b64.encode("utf-8")).decode("utf-8")
            if json_out:
                return json.dumps({"mode": "base64-encode", "input": b64, "output": encoded}, indent=2)
            return f"[b]Base64 encode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {b64}\n  [#7fb069]out:[/#7fb069] {encoded}"

        # --- Base64 decode (safe, with alphabet check) ---
        if b64d:
            try:
                decoded = _b64_decode_safe(b64d, urlsafe=False).decode("utf-8", errors="replace")
            except ValueError as e:
                return f"[#e63946]Base64 decode error:[/#e63946] {e}\n[#555555]Вход не соответствует base64-алфавиту.[/#555555]"
            except Exception as e:
                return f"[#e63946]Base64 decode error:[/#e63946] {e}"
            if json_out:
                return json.dumps({"mode": "base64-decode", "input": b64d, "output": decoded}, indent=2)
            return f"[b]Base64 decode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {b64d}\n  [#7fb069]out:[/#7fb069] {decoded}"

        # --- Hex encode ---
        if hex_in:
            encoded = hex_in.encode("utf-8").hex()
            if json_out:
                return json.dumps({"mode": "hex-encode", "input": hex_in, "output": encoded}, indent=2)
            return f"[b]Hex encode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {hex_in}\n  [#7fb069]out:[/#7fb069] {encoded}"

        # --- Hex decode ---
        if hexd:
            if not HEX_ALPHABET.match(hexd) or len(hexd) % 2 != 0:
                return "[#e63946]Hex decode error:[/#e63946] вход должен быть чётной длины и содержать только 0-9, a-f"
            decoded = bytes.fromhex(hexd).decode("utf-8", errors="replace")
            if json_out:
                return json.dumps({"mode": "hex-decode", "input": hexd, "output": decoded}, indent=2)
            return f"[b]Hex decode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {hexd}\n  [#7fb069]out:[/#7fb069] {decoded}"

        # --- URL encode ---
        if url:
            encoded = urllib.parse.quote(url)
            if json_out:
                return json.dumps({"mode": "url-encode", "input": url, "output": encoded}, indent=2)
            return f"[b]URL encode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {url}\n  [#7fb069]out:[/#7fb069] {encoded}"

        # --- URL decode ---
        if urld:
            decoded = urllib.parse.unquote(urld)
            if json_out:
                return json.dumps({"mode": "url-decode", "input": urld, "output": decoded}, indent=2)
            return f"[b]URL decode:[/b]\n  [#8a8a8a]in:[/#8a8a8a]  {urld}\n  [#7fb069]out:[/#7fb069] {decoded}"

        return "Error: pass text=... | file=... | identify=... | b64=... | b64d=... | hex=... | hexd=... | url=... | urld=... | jwt=..."


PLUGIN = HashTool()
