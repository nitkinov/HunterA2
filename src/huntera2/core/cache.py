"""Единый файловый кэш для плагинов HunterA 2."""
import hashlib
import json
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "huntera2" / "data"


def _key(plugin_name: str, args: dict) -> str:
    payload = json.dumps(
        [plugin_name, sorted(args.items())],
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _path(plugin_name: str, args: dict) -> Path:
    return CACHE_DIR / f"{plugin_name}_{_key(plugin_name, args)}.json"


def get(plugin_name: str, args: dict):
    p = _path(plugin_name, args)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if time.time() > data.get("expires_at", 0):
            p.unlink(missing_ok=True)
            return None
        return data.get("value")
    except Exception:
        return None


def set(plugin_name: str, args: dict, value: str, ttl: int) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "plugin": plugin_name,
        "args": args,
        "value": value,
        "created_at": time.time(),
        "expires_at": time.time() + ttl,
        "ttl": ttl,
    }
    try:
        _path(plugin_name, args).write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def clear() -> int:
    """Удаляет все файлы кэша. Возвращает количество удалённых."""
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for p in CACHE_DIR.glob("*.json"):
        try:
            p.unlink()
            count += 1
        except Exception:
            pass
    return count


def stats() -> dict:
    """Статистика кэша: количество файлов и размер."""
    if not CACHE_DIR.exists():
        return {"files": 0, "size": 0}
    files = list(CACHE_DIR.glob("*.json"))
    size = sum(p.stat().st_size for p in files)
    return {"files": len(files), "size": size}


def human_ttl(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"
