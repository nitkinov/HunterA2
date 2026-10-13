"""Утилиты для цветной подсветки уровней угроз в выводе плагинов."""

# Rich-markup для каждого уровня. Фон + контрастный текст.
LEVELS = {
    "critical": "[bold white on #8b0000] CRITICAL [/]",
    "high":     "[bold black on #e63946] HIGH [/]",
    "medium":   "[bold black on #e6b800] MEDIUM [/]",
    "low":      "[bold black on #a3c94b] LOW [/]",
    "info":     "[bold white on #4a7c9e] INFO [/]",
    "ok":       "[bold black on #7fb069] OK [/]",
    "skip":     "[bold white on #555555] SKIP [/]",
}

# Цвета для свободного использования
COLORS = {
    "critical": "#8b0000",
    "high":     "#e63946",
    "medium":   "#e6b800",
    "low":      "#a3c94b",
    "info":     "#4a7c9e",
    "ok":       "#7fb069",
    "skip":     "#555555",
}


def tag(level: str) -> str:
    """Возвращает Rich-markup тег для уровня. Пример: tag('critical') → '[bold white on #8b0000] CRITICAL [/]'"""
    return LEVELS.get(level.lower(), LEVELS["info"])


def color(level: str) -> str:
    """Возвращает hex-цвет для уровня. Пример: color('high') → '#e63946'"""
    return COLORS.get(level.lower(), COLORS["info"])


def level_icon(level: str) -> str:
    """Иконка для уровня."""
    return {
        "critical": "✖",
        "high":     "✖",
        "medium":   "⚠",
        "low":      "•",
        "info":     "ℹ",
        "ok":       "✓",
        "skip":     "—",
    }.get(level.lower(), "•")


def line(level: str, text: str) -> str:
    """Формирует строку с тегом и текстом. Пример: line('high', 'CORS reflects origin')"""
    return f"  {tag(level)}  {text}"


def grade(score: int) -> str:
    """Цветной бейдж оценки A+–F."""
    if score >= 95:
        return "[bold black on #7fb069] A+ [/]"
    if score >= 90:
        return "[bold black on #7fb069] A [/]"
    if score >= 80:
        return "[bold black on #a3c94b] B [/]"
    if score >= 70:
        return "[bold black on #e6b800] C [/]"
    if score >= 60:
        return "[bold black on #e68a00] D [/]"
    return "[bold white on #8b0000] F [/]"
