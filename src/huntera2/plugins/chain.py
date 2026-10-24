"""Auto-chain: последовательный запуск нескольких плагинов для одной цели."""
import asyncio

from huntera2.sdk import Plugin
from huntera2.core.plugin_loader import load_all
from huntera2.core.log import get_logger

log = get_logger()

# Какие плагины запускать для каждого типа цепочки
CHAINS = {
    "recon": ["dns", "whois", "portscan", "waf_detect"],
    "web":   ["http_probe", "ssl", "robots"],
    "full":  ["dns", "whois", "portscan", "waf_detect", "ssl", "http_probe", "robots"],
}

# Какой аргумент ожидает каждый плагин (target → key=value)
ARG_MAP = {
    "dns":        "host",
    "whois":      "domain",
    "portscan":   "host",
    "waf_detect": "url",
    "http_probe": "url",
    "ssl":        "host",
    "robots":     "url",
}


def _build_args(plugin_name: str, target: str) -> dict:
    """Формирует аргументы для конкретного плагина, основываясь на target."""
    key = ARG_MAP.get(plugin_name)
    if not key:
        return {}
    
    value = target
    # Для url-плагинов добавляем схему, если её нет
    if key == "url" and not value.startswith(("http://", "https://")):
        value = "https://" + value
        
    return {key: value}


class Chain(Plugin):
    name = "chain"
    description = "Auto-chain: run multiple plugins sequentially (recon, web, full)"
    usage = "chain=recon | chain=web | chain=full target=example.com"
    icon = "⛓"
    category = "Utils"
    needs_network = True
    supports_stream = True

    def run(self, args: dict) -> str:
        return self._run(args, emit=None)

    def run_stream(self, args: dict, emit) -> str:
        return self._run(args, emit=emit)

    def _run(self, args: dict, emit) -> str:
        chain_name = args.get("chain", "").lower()
        target = args.get("target", "").strip()

        if not chain_name:
            return "Error: pass chain=recon|web|full target=example.com"
        if not target:
            return "Error: pass target=example.com"

        if chain_name not in CHAINS:
            return f"Error: unknown chain '{chain_name}'. Available: {', '.join(CHAINS.keys())}"

        plugin_names = CHAINS[chain_name]
        
        # Загружаем все доступные плагины в словарь для быстрого доступа
        all_plugins = {p.name: p for p in load_all()}
        
        output_lines = []
        output_lines.append(f"[b #e63946]⛓ Auto-Chain: {chain_name.upper()}[/b #e63946]")
        output_lines.append(f"[b]Target:[/b] {target}")
        output_lines.append(f"[b]Steps:[/b]  {len(plugin_names)}")
        output_lines.append("")
        
        if emit:
            emit("\n".join(output_lines) + "\n")
            
        for i, pname in enumerate(plugin_names, 1):
            if pname not in all_plugins:
                msg = f"[#e6b800]⚠ Step {i}/{len(plugin_names)}: plugin '{pname}' not found, skipping[/#e6b800]\n"
                output_lines.append(msg)
                if emit: emit(msg)
                continue
                
            plugin = all_plugins[pname]
            pargs = _build_args(pname, target)
            
            header = f"[b #7fb069]=== Step {i}/{len(plugin_names)}: {plugin.icon} {pname} ===[/b #7fb069]\n"
            if emit: emit("\n" + header)
            output_lines.append("\n" + header)
            
            try:
                # Запускаем плагин
                if plugin.supports_stream and emit:
                    # Если плагин поддерживает стрим (например portscan), передаем emit
                    res = plugin.run_stream(pargs, emit)
                else:
                    res = plugin.run(pargs)
                    if emit:
                        emit(res + "\n")
                output_lines.append(res + "\n")
            except Exception as e:
                log.error(f"Chain step {pname} failed: {e}")
                err = f"[#e63946]✗ Error in {pname}: {e}[/#e63946]\n"
                output_lines.append(err)
                if emit: emit(err)
                
        footer = "\n[b #e63946]⛓ Chain completed[/b #e63946]\n"
        if emit: emit(footer)
        output_lines.append(footer)
        
        return "".join(output_lines)


PLUGIN = Chain()
