"""Ленивая загрузка плагинов: импорт только по требованию.

Вместо `import huntera2.plugins.X` (тянет все зависимости X),
мы храним только имена модулей, и импортируем при первом обращении.
"""
import importlib
import importlib.metadata
import pkgutil
from typing import Optional

from huntera2.core.log import get_logger
from huntera2.sdk import Plugin

log = get_logger()


class PluginStub:
    """Легковесный placeholder для плагина: только метаданные, без импорта.

    TUI использует поля name, icon, category, description, usage —
    всё это доступно без загрузки модуля, если мы прочитаем их из AST.
    """

    __slots__ = ("name", "_module_path", "icon", "category", "description", "usage",
                 "needs_network", "supports_stream", "cache_ttl", "_loaded", "_plugin")

    def __init__(self, name: str, module_path: str) -> None:
        self.name = name
        self._module_path = module_path
        # Дефолты из sdk.Plugin
        self.icon = "◆"
        self.category = "Other"
        self.description = ""
        self.usage = ""
        self.needs_network = False
        self.supports_stream = False
        self.cache_ttl = 0
        self._loaded = False
        self._plugin: Optional[Plugin] = None

    def load(self) -> Optional[Plugin]:
        """Импортирует модуль и возвращает настоящий Plugin."""
        if self._loaded:
            return self._plugin
        try:
            mod = importlib.import_module(self._module_path)
            plugin = getattr(mod, "PLUGIN", None)
            if isinstance(plugin, Plugin):
                self._plugin = plugin
        except Exception as e:
            log.error(f"lazy load '{self.name}' failed: {e}")
        self._loaded = True
        return self._plugin

    def read_metadata_from_source(self) -> None:
        """Читает метаданные из исходника, не импортируя модуль.

        Извлекает значения атрибутов через регулярки — быстро и без импорта.
        """
        try:
            mod = importlib.util.find_spec(self._module_path)
            if not mod or not mod.origin:
                return
            with open(mod.origin, "r", encoding="utf-8") as f:
                src = f.read()
        except Exception:
            return

        import re
        patterns = {
            "icon":          r'^\s+icon\s*=\s*"([^"]*)"',
            "category":      r'^\s+category\s*=\s*"([^"]*)"',
            "description":   r'^\s+description\s*=\s*"([^"]*)"',
            "usage":         r'^\s+usage\s*=\s*"([^"]*)"',
            "needs_network": r'^\s+needs_network\s*=\s*(True|False)',
            "supports_stream": r'^\s+supports_stream\s*=\s*(True|False)',
            "cache_ttl":     r'^\s+cache_ttl\s*=\s*(\d+)',
        }
        for attr, pattern in patterns.items():
            m = re.search(pattern, src, re.MULTILINE)
            if m:
                value = m.group(1)
                if attr in ("needs_network", "supports_stream"):
                    value = value == "True"
                elif attr == "cache_ttl":
                    value = int(value)
                setattr(self, attr, value)


def discover_builtin_stubs() -> list[PluginStub]:
    """Возвращает stubs для встроенных плагинов — без импорта модулей."""
    import huntera2.plugins as pkg
    result = []
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        module_path = f"huntera2.plugins.{modname}"
        stub = PluginStub(name=modname, module_path=module_path)
        stub.read_metadata_from_source()
        result.append(stub)
    return result


def discover_external_stubs() -> list[PluginStub]:
    """Внешние плагины через entry points. Их всё равно нужно импортировать для метаданных."""
    result = []
    for ep in importlib.metadata.entry_points(group="huntera2.plugins"):
        try:
            obj = ep.load()
            plugin = getattr(obj, "PLUGIN", None) or obj
            if isinstance(plugin, Plugin):
                stub = PluginStub(name=plugin.name, module_path=ep.value.split(":")[0])
                stub._plugin = plugin
                stub._loaded = True
                stub.icon = plugin.icon
                stub.category = plugin.category
                stub.description = plugin.description
                stub.usage = plugin.usage
                stub.needs_network = plugin.needs_network
                stub.supports_stream = plugin.supports_stream
                stub.cache_ttl = plugin.cache_ttl
                result.append(stub)
        except Exception as e:
            log.error(f"external stub '{ep.name}' failed: {e}")
    return result


def load_stubs() -> list[PluginStub]:
    """Загружает stubs всех плагинов — быстро, без импорта тяжёлых модулей."""
    stubs = discover_builtin_stubs() + discover_external_stubs()
    return sorted(stubs, key=lambda s: (s.category, s.name))
