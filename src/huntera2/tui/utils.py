"""Утилиты TUI: парсинг аргументов и экранирование разметки."""

from rich.markup import escape as rich_escape


def parse_args(raw: str) -> dict[str, str]:
    """Парсит строку 'key1=val1 key2=val2' в словарь.

    Пример: 'host=example.com ports=80,443' →
            {'host': 'example.com', 'ports': '80,443'}
    """
    result: dict[str, str] = {}
    for token in raw.split():
        if "=" in token:
            k, v = token.split("=", 1)
            result[k] = v
    return result


def escape_markup(text: str) -> str:
    """Экранирует спецсимволы Rich-markup ([, ], <, >).

    Использует встроенный rich.markup.escape вместо самописной замены.
    """
    if not text:
        return ""
    return rich_escape(text)
