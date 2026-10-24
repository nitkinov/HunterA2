"""Менеджер встроенных словарей. Скачивает и кэширует SecLists по алиасам."""
import urllib.request
from pathlib import Path

from huntera2.core.log import get_logger

log = get_logger()

WORDLIST_DIR = Path.home() / ".cache" / "huntera2" / "wordlists"

# Алиасы: @имя -> (имя_файла, URL)
BUILTIN_WORDLISTS = {
    "@common": (
        "common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    ),
    "@subdomains": (
        "subdomains-5000.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
    ),
}


def _download(url: str, dest: Path) -> bool:
    """Скачивает файл. Возвращает True при успехе."""
    try:
        log.info(f"Downloading wordlist: {url}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "HunterA2/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp, dest.open("wb") as f:
            f.write(resp.read())
        return True
    except Exception as e:
        log.error(f"Failed to download wordlist {url}: {e}")
        if dest.exists():
            dest.unlink()
        return False


def resolve_wordlist(spec: str) -> list[str]:
    """Возвращает список строк из словаря.

    Если spec начинается с '@', ищет в BUILTIN_WORDLISTS.
    Скачивает при необходимости.
    Иначе читает как обычный файл.
    """
    spec = spec.strip()
    
    # Встроенный алиас
    if spec.startswith("@"):
        if spec not in BUILTIN_WORDLISTS:
            raise ValueError(f"Unknown wordlist alias: {spec}. Available: {', '.join(BUILTIN_WORDLISTS)}")
        
        filename, url = BUILTIN_WORDLISTS[spec]
        path = WORDLIST_DIR / filename
        
        if not path.exists():
            if not _download(url, path):
                raise RuntimeError(f"Failed to download {spec}. Check internet connection.")
        
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    # Обычный файл
    p = Path(spec)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {spec}")
    
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
