import asyncio

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Footer, ListView, ListItem, Label,
    Input, Button, RichLog, Static,
)
from textual.binding import Binding
from textual.worker import Worker, get_current_worker

from huntera2 import __version__
from huntera2.tui.constants import CATEGORY_ORDER, CATEGORY_ICONS, MAX_BUFFER_LINES
from huntera2.tui.utils import parse_args, escape_markup
from huntera2.tui.widgets.chart import ChartPanel, PLOTEXT_AVAILABLE
from huntera2.tui.widgets.sidebar import PluginListPanel

if PLOTEXT_AVAILABLE:
    from textual_plotext import PlotextPlot
from huntera2.core import cache
from huntera2.core.config import load_config
from huntera2.core.lazy_loader import load_stubs


CATEGORY_ORDER = ["Recon", "Web", "Network", "TLS", "Utils", "Other"]
CATEGORY_ICONS = {
    "Recon":   "🔎",
    "Web":     "🌐",
    "Network": "📡",
    "TLS":     "🔒",
    "Utils":   "🔧",
    "Other":   "◆",
}



class HunterApp(App):
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("c", "clear", "Clear"),
        Binding("r", "run", "Run"),
        Binding("g", "toggle_chart", "Chart", show=True),
        Binding("escape", "cancel_worker", "Cancel", show=False),
        Binding("tab", "focus_next", "Focus", show=False),
        Binding("shift+tab", "focus_previous", "Focus back", show=False),
        Binding("pageup", "log_up", "Log up", show=False),
        Binding("pagedown", "log_down", "Log down", show=False),
        Binding("1", "filter('all')", "All", show=False),
        Binding("2", "filter('Recon')", "Recon", show=False),
        Binding("3", "filter('Web')", "Web", show=False),
        Binding("4", "filter('Network')", "Network", show=False),
        Binding("5", "filter('TLS')", "TLS", show=False),
        Binding("6", "filter('Utils')", "Utils", show=False),
        Binding("X", "clear_cache", "Clear cache", show=False),
        Binding("ctrl+p", "command_palette", "Palette", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.plugins = load_stubs()
        self.plugins_by_name = {p.name: p for p in self.plugins}
        self.config = load_config()
        self.current_plugin = None
        self._stream_buffer = ""
        self._worker = None
        self._chart = ChartPanel(self.query_one)
        self._sidebar = PluginListPanel(self.query_one, self.plugins, self.plugins_by_name)

    # ---------- Status ----------
    def _status(self, text: str, color: str = "#8a8a8a") -> None:
        try:
            self.query_one("#status", Static).update(f"[{color}]{text}[/{color}]")
        except Exception:
            pass

    # ---------- Layout ----------
    def compose(self) -> ComposeResult:
        banner = (
            f"[b #e63946]HunterA 2[/b #e63946] "
            f"[#8a8a8a]v{__version__}[/#8a8a8a]"
            f"  [#555555]|[/#555555]  "
            f"[#8a8a8a]by tg [b #e63946]@heyscally[/b #e63946][/#8a8a8a]"
        )
        yield Static(banner, id="banner")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Label("⚔ PLUGINS", id="sidebar-title")
                yield Static(self._sidebar.category_bar_text(), id="category-bar")
                yield ListView(id="plugin-list")
            with Vertical(id="main"):
                yield Static("Select a plugin", id="plugin-title")
                yield Static("", id="plugin-desc")
                yield Static("", id="hint")
                yield Input(placeholder="$ args...", id="args")
                yield Button("▶  RUN", id="run")
                yield RichLog(id="output", wrap=True, markup=True, highlight=False)
                if PLOTEXT_AVAILABLE:
                    yield PlotextPlot(id="chart")
        yield Static("ready", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._sidebar.rebuild()
        if PLOTEXT_AVAILABLE:
            self._status("ready", "#7fb069")
        else:
            self._status("ready · pip install textual-plotext", "#e6b800")



    def _get_plugin_at(self, idx):
        lv = self.query_one("#plugin-list", ListView)
        if idx is None or idx >= len(lv.children):
            return None
        item = lv.children[idx]
        if not item.id or not item.id.startswith("plugin-"):
            return None
        name = item.id[len("plugin-"):]
        return self.plugins_by_name.get(name)

    def _apply_plugin(self, plugin) -> None:
        # Если это stub — подгружаем настоящий плагин
        real = plugin.load() if hasattr(plugin, "load") else plugin
        if real is None:
            return
        self.current_plugin = real
        plugin = real  # для остальных обращений
        self.query_one("#plugin-title", Static).update(
            f"{plugin.icon}  {plugin.name}  [#555555]· {plugin.category}[/#555555]"
        )
        self.query_one("#plugin-desc", Static).update(escape_markup(plugin.description))
        usage = plugin.usage or "key=value ..."
        safe_usage = escape_markup(usage)
        self.query_one("#hint", Static).update(f"[#555555]usage:[/#555555] {safe_usage}")
        inp = self.query_one("#args", Input)
        inp.placeholder = f"$ {usage}"
        inp.value = ""
        if PLOTEXT_AVAILABLE and self._chart.visible:
            self._chart.hide()

    def _apply_highlight(self, selected_idx: int) -> None:
        """Красит текст выбранного Label в кровавый через styles.color."""
        from textual.widgets import Label
        try:
            lv = self.query_one("#plugin-list", ListView)
        except Exception:
            return
        for i, item in enumerate(lv.children):
            if not item.id or not item.id.startswith("plugin-"):
                continue
            try:
                label = item.query_one(Label)
            except Exception:
                continue
            if i == selected_idx:
                label.styles.color = "#ff2a2a"
                label.styles.text_style = "bold"
            else:
                label.styles.color = "#b0b0b0"
                label.styles.text_style = "none"

    # ---------- Events ----------
    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        idx = event.list_view.index
        self._apply_highlight(idx)
        plugin = self._sidebar.plugin_at(idx)
        if plugin is None:
            return
        self._apply_plugin(plugin)
        self._status(f"selected: {plugin.name}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self._run_current()

    # ---------- Run ----------
    def _run_current(self) -> None:
        output = self.query_one("#output", RichLog)
        output.clear()
        self._stream_buffer = ""

        if self.current_plugin is None:
            output.write("[#e63946]No plugin selected[/#e63946]")
            return

        plugin = self.current_plugin
        if hasattr(plugin, "load"):
            plugin = plugin.load()
            if plugin is None:
                output.write("[#e63946]Failed to load plugin[/#e63946]")
                return

        args = parse_args(self.query_one("#args", Input).value.strip())
        self._status(f"running: {plugin.name}", "#e6b800")

        self._worker = self.run_worker(
            self._execute_plugin(plugin, args),
            name=f"plugin-{plugin.name}",
            exclusive=True,
        )

    async def _execute_plugin(self, plugin, args: dict) -> None:
        worker = get_current_worker()

        def emit(chunk: str) -> None:
            if worker.is_cancelled:
                return
            self.call_from_thread(self._flush_stream, chunk)

        try:
            no_cache = args.get("no-cache") in ("1", "true", "yes")
            ttl = getattr(plugin, "cache_ttl", 0)
            use_cache = (not plugin.supports_stream) and ttl > 0 and not no_cache

            if use_cache:
                cached = cache.get(plugin.name, args)
                if cached is not None:
                    self._flush_stream(
                        f"[#555555]cached (ttl {cache.human_ttl(ttl)})[/#555555]"
                    )
                    self._flush_stream(cached)
                    self._status("done (cached)", "#7fb069")
                    return

            if plugin.supports_stream:
                await asyncio.to_thread(plugin.run_stream, args, emit)
            else:
                result = await asyncio.to_thread(plugin.run, args)
                self._flush_stream(result)
                if use_cache and result:
                    cache.set(plugin.name, args, result, ttl)

            self._status("done", "#7fb069")

            if plugin.name == "portscan" and PLOTEXT_AVAILABLE:
                results = getattr(plugin, "_last_results", None)
                if results:
                    self._chart.show_services(results)
        except Exception as e:
            self._flush_stream(f"[#e63946]Error: {e}[/#e63946]")
            self._status(f"error: {e}", "#e63946")

    def _flush_stream(self, chunk: str) -> None:
        if not chunk:
            return
        self._stream_buffer += chunk
        if self._stream_buffer.count("\n") > MAX_BUFFER_LINES:
            lines = self._stream_buffer.split("\n")
            self._stream_buffer = "\n".join(lines[-MAX_BUFFER_LINES:])
            self.query_one("#output", RichLog).clear()
        self.query_one("#output", RichLog).write(chunk)

    # ---------- Chart ----------


    def action_toggle_chart(self) -> None:
        if not PLOTEXT_AVAILABLE:
            self._status("pip install textual-plotext", "#e6b800")
            return
        if self._chart.visible:
            self._chart.hide()
            self._status("chart hidden")
            return
        # Пытаемся показать из последних результатов portscan
        if self.current_plugin and self.current_plugin.name == "portscan":
            results = getattr(self.current_plugin, "_last_results", None)
            if results:
                self._chart.show_services(results)
                if count:
                    self._status(f"chart: {count} services", "#7fb069")
                    return
        self._status("no chart data — run portscan", "#e6b800")


    def action_clear(self) -> None:
        self.query_one("#output", RichLog).clear()
        self._stream_buffer = ""
        self._status("cleared")

    def action_run(self) -> None:
        self._run_current()

    def action_cancel_worker(self) -> None:
        if self._worker and not self._worker.is_finished:
            self._worker.cancel()
            self._status("cancelled", "#e63946")

    def action_log_up(self) -> None:
        self.query_one("#output", RichLog).scroll_page_up(animate=False)

    def action_log_down(self) -> None:
        self.query_one("#output", RichLog).scroll_page_down(animate=False)

    def action_filter(self, cat: str) -> None:
        self._sidebar.set_filter(cat)
        self._sidebar.rebuild()
        self._status(f"filter: {cat}", "#7fb069")

    def action_clear_cache(self) -> None:
        count = cache.clear()
        self._status(f"cache cleared ({count} files)", "#7fb069")


def main() -> None:
    HunterApp().run()


if __name__ == "__main__":
    main()
