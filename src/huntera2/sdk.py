from typing import Callable


class Plugin:
    """Базовый класс для всех плагинов HunterA 2."""
    name: str = "unnamed"
    description: str = ""
    usage: str = ""
    icon: str = "◆"
    category: str = "Other"
    needs_network: bool = False
    supports_stream: bool = False
    cache_ttl: int = 0  # секунд; 0 = кэш отключён

    def run(self, args: dict) -> str:
        raise NotImplementedError

    def run_stream(self, args: dict, emit: Callable[[str], None]) -> str:
        result = self.run(args)
        emit(result)
        return result
