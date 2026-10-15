"""Логика боковой панели: список плагинов по категориям, фильтр, поиск."""

from textual.widgets import ListView, ListItem, Label

from huntera2.tui.constants import CATEGORY_ORDER, CATEGORY_ICONS


class PluginListPanel:
    """Управляет списком плагинов в сайдбаре.

    Не виджет Textual — обёртка, которая знает как строить список,
    как фильтровать и как находить плагин по индексу.
    """

    LIST_ID = "#plugin-list"
    CATEGORY_BAR_ID = "#category-bar"

    def __init__(self, query_one, plugins: list, by_name: dict) -> None:
        self._query_one = query_one
        self._plugins = plugins
        self._by_name = by_name
        self._filter = "all"

    # --- Свойства ---

    @property
    def filter(self) -> str:
        return self._filter

    # --- Фильтр ---

    def set_filter(self, cat: str) -> None:
        self._filter = cat

    def category_bar_text(self) -> str:
        """Строка '1:all 2:Recon 3:Web ...' с подсветкой активного."""
        active = self._filter
        parts = []
        c = "#e63946" if active == "all" else "#8a8a8a"
        parts.append(f"[{c}]1[/{c}][#555555]:all[/#555555]")
        for i, cat in enumerate(["Recon", "Web", "Network", "TLS", "Utils"], start=2):
            color = "#e63946" if active == cat else "#8a8a8a"
            parts.append(f"[{color}]{i}[/{color}][#555555]:{cat}[/#555555]")
        return " ".join(parts)

    # --- Построение списка ---

    def rebuild(self) -> None:
        """Перестраивает список с учётом фильтра. Ставит фокус на первый плагин."""
        lv = self._query_one(self.LIST_ID, ListView)
        lv.clear()

        if self._filter == "all":
            plugins = self._plugins
        else:
            plugins = [p for p in self._plugins if p.category == self._filter]

        by_cat: dict[str, list] = {}
        for p in plugins:
            by_cat.setdefault(p.category, []).append(p)

        ordered = [c for c in CATEGORY_ORDER if c in by_cat]
        for cat in ordered:
            count = len(by_cat[cat])
            header = ListItem(
                Label(f"{CATEGORY_ICONS.get(cat, '◆')} {cat}  [#555555]({count})[/#555555]"),
                id=f"cat-{cat}",
                disabled=True,
            )
            header.add_class("category-header")
            lv.append(header)
            for p in sorted(by_cat[cat], key=lambda x: x.name):
                lv.append(ListItem(Label(f" {p.icon}  {p.name}"), id=f"plugin-{p.name}"))

        # Фокус на первый плагин
        for i, item in enumerate(lv.children):
            if item.id and item.id.startswith("plugin-"):
                lv.index = i
                break
        lv.focus()

        # Обновляем фильтр-бар
        from textual.widgets import Static
        self._query_one(self.CATEGORY_BAR_ID, Static).update(self.category_bar_text())

    # --- Доступ ---

    def plugin_at(self, idx) -> object | None:
        """Возвращает плагин по индексу в ListView, или None для заголовка категории."""
        lv = self._query_one(self.LIST_ID, ListView)
        if idx is None or idx >= len(lv.children):
            return None
        item = lv.children[idx]
        if not item.id or not item.id.startswith("plugin-"):
            return None
        return self._by_name.get(item.id[len("plugin-"):])
