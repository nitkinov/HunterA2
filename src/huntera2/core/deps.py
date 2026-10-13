"""Проверка зависимостей при старте HunterA 2."""
import importlib.util

# (module, pip_spec, termux_native_pkg, purpose)
DEPENDENCIES = [
    ("textual", "textual>=0.50", None, "TUI"),
    ("httpx", "httpx>=0.27", None, "http_probe, dir_brute, crawl"),
    ("pydantic", "pydantic>=2.6", None, "config"),
    ("pydantic_core", "pydantic-core", "TUR", "pydantic (Rust)"),
    ("dns", "dnspython>=2.6", None, "dns, subdomain"),
    ("whois", "python-whois>=0.9", None, "whois"),
    ("bs4", "beautifulsoup4>=4.12", None, "crawl"),
    ("cryptography", "cryptography>=42.0", "python-cryptography", "ssl"),
    ("lxml", "lxml>=5.0", None, "crawl (parser)"),
]


def check_dependencies() -> list[dict]:
    missing = []
    for mod, pip_spec, native, purpose in DEPENDENCIES:
        try:
            if importlib.util.find_spec(mod) is None:
                missing.append({
                    "module": mod,
                    "pip": pip_spec,
                    "native": native,
                    "purpose": purpose,
                })
        except (ImportError, ValueError):
            missing.append({
                "module": mod,
                "pip": pip_spec,
                "native": native,
                "purpose": purpose,
            })
    return missing


def deps_warning() -> str:
    missing = check_dependencies()
    if not missing:
        return ""
    lines = ["[#e6b800]⚠ Отсутствуют зависимости:[/#e6b800]"]
    for m in missing:
        hint = f"pkg install {m['native']}" if m["native"] else f"pip install {m['pip']}"
        lines.append(f"  [#e63946]✗[/#e63946] {m['module']}  [#555555]({m['purpose']})[/#555555]")
        lines.append(f"    [#555555]→ {hint}[/#555555]")
    lines.append("")
    lines.append("[#8a8a8a]Быстро: [b]bash install.sh[/b][/#8a8a8a]")
    return "\n".join(lines)
