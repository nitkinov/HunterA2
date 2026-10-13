from typing import Callable


class Plugin:
    """Базовый класс для всех плагинов HunterA 2."""
    name: str = "unnamed"
    description: str = ""
    usage: str = ""
    icon: str = "◆"
    category: str = "Other"     # группа в TUI
    needs_network: bool = False
    supports_stream: bool = False

    def run(self, args: dict) -> str:
        raise NotImplementedError

    def run_stream(self, args: dict, emit: Callable[[str], None]) -> str:
        result = self.run(args)
        emit(result)
        return result
