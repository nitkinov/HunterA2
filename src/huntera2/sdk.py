"""SDK HunterA 2: базовый класс для всех плагинов."""
from typing import Callable


class Plugin:
    """Базовый класс для всех плагинов HunterA 2.

    Наследники описывают метаданные как атрибуты класса и реализуют run().
    """

    # --- Идентификация ---
    name: str = "unnamed"
    version: str = "1.0.0"
    author: str = ""

    # --- Описание для TUI ---
    description: str = ""
    usage: str = ""
    icon: str = "◆"
    category: str = "Other"  # Recon / Web / Network / TLS / Utils

    # --- Требования и поведение ---
    needs_network: bool = False
    supports_stream: bool = False
    cache_ttl: int = 0  # секунд; 0 = без кэша

    def run(self, args: dict) -> str:
        """Основной метод. args — словарь аргументов из CLI.

        Возвращает Rich-markup строку.
        """
        raise NotImplementedError

    def run_stream(self, args: dict, emit: Callable[[str], None]) -> str:
        """Потоковый режим. По умолчанию — вызывает run() и отправляет результат одним куском."""
        result = self.run(args)
        emit(result)
        return result
