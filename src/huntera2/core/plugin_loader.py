"""Загрузчик плагинов: builtin + entry points. Не падает при ошибке одного плагина."""
import importlib
import importlib.metadata
import pkgutil
from typing import Iterable

from huntera2.core.log import get_logger
from huntera2.sdk import Plugin

log = get_logger()


def discover_builtin() -> list[Plugin]:
    """Загружает все встроенные плагины из huntera2.plugins."""
    import huntera2.plugins as pkg
    result: list[Plugin] = []
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        try:
            mod = importlib.import_module(f"huntera2.plugins.{modname}")
        except Exception as e:
            log.error(f"plugin '{modname}' failed to import: {e}")
            continue
        plugin = getattr(mod, "PLUGIN", None)
        if isinstance(plugin, Plugin):
            result.append(plugin)
        else:
            log.warning(f"plugin '{modname}' has no valid PLUGIN instance")
    return result


def discover_external() -> list[Plugin]:
    """Загружает сторонние плагины через entry points 'huntera2.plugins'."""
    result: list[Plugin] = []
    for ep in importlib.metadata.entry_points(group="huntera2.plugins"):
        try:
            obj = ep.load()
            plugin = getattr(obj, "PLUGIN", None) or obj
            if isinstance(plugin, Plugin):
                result.append(plugin)
            else:
                log.warning(f"external plugin '{ep.name}' is not a Plugin instance")
        except Exception as e:
            log.error(f"external plugin '{ep.name}' failed: {e}")
            continue
    return result


def load_all() -> list[Plugin]:
    """Загружает и сортирует все плагины по категории и имени."""
    plugins = discover_builtin() + discover_external()
    return sorted(plugins, key=lambda p: (p.category, p.name))
