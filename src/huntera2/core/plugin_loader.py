import importlib
import importlib.metadata
import pkgutil

from huntera2.sdk import Plugin


def discover_builtin() -> list[Plugin]:
    import huntera2.plugins as pkg
    result: list[Plugin] = []
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"huntera2.plugins.{modname}")
        plugin = getattr(mod, "PLUGIN", None)
        if isinstance(plugin, Plugin):
            result.append(plugin)
    return result


def discover_external() -> list[Plugin]:
    result: list[Plugin] = []
    for ep in importlib.metadata.entry_points(group="huntera2.plugins"):
        try:
            obj = ep.load()
            plugin = getattr(obj, "PLUGIN", None) or obj
            if isinstance(plugin, Plugin):
                result.append(plugin)
        except Exception:
            continue
    return result


def load_all() -> list[Plugin]:
    return discover_builtin() + discover_external()
