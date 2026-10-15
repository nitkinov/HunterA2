"""Цветные бейджи уровней угроз для вывода плагинов."""

LEVELS = {
    "critical": "[bold white on #8b0000] CRITICAL [/]",
    "high":     "[bold black on #e63946] HIGH [/]",
    "medium":   "[bold black on #e6b800] MEDIUM [/]",
    "low":      "[bold black on #a3c94b] LOW [/]",
    "info":     "[bold white on #4a7c9e] INFO [/]",
    "ok":       "[bold black on #7fb069] OK [/]",
    "skip":     "[bold white on #555555] SKIP [/]",
}


def tag(level: str) -> str:
    """Rich-markup тег для уровня. Пример: tag('critical')."""
    return LEVELS.get(level.lower(), LEVELS["info"])


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
