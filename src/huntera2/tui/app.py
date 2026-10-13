import asyncio

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Footer, ListView, ListItem, Label,
    Input, Button, RichLog, Static,
)
from textual.binding import Binding
from textual.worker import Worker, get_current_worker

try:
    from textual_plotext import PlotextPlot
    PLOTEXT_AVAILABLE = True
except ImportError:
    PLOTEXT_AVAILABLE = False

from huntera2 import __version__
from huntera2.core import cache
from huntera2.core.config import load_config
from huntera2.core.plugin_loader import load_all


CATEGORY_ORDER = ["Recon", "Web", "Network", "TLS", "Utils", "Other"]
CATEGORY_ICONS = {
    "Recon":   "🔎",
    "Web":     "🌐",
    "Network": "📡",
    "TLS":     "🔒",
    "Utils":   "🔧",
    "Other":   "◆",
}


def parse_args(raw: str) -> dict:
    result = {}
    for token in raw.split():
        if "=" in token:
            k, v = token.split("=", 1)
            result[k] = v
    return result


class HunterApp(App):
    CSS = """
    Screen { background: #0d0d0d; color: #d4d4d4; }

    #banner {
        height: 3; padding: 0;
        background: #1c1c1c;
        border: heavy #8b0000;
        content-align: center middle;
        text-align: center;
    }

    #body { height: 1fr; }

    #sidebar {
        width: 30; background: #161616;
        border-right: heavy #8b0000;
        padding: 0 1;
    }

    #sidebar-title {
        padding: 0 1; color: #e63946;
        text-style: bold; height: 1;
    }

    #category-bar {
        height: 1; color: #555555;
        padding: 0 1;
    }

    #plugin-list { background: transparent; height: 1fr; }

    ListItem { 
        background: transparent; 
        padding: 0 1; 
    }
    ListView > ListItem > Label { 
        background: transparent;
        width: 100%;
    }

    .category-header {
        color: #e63946;
        text-style: bold;
        padding: 1 0 0 0;
        background: transparent;
    }
    .category-header.--highlight {
        background: transparent;
        color: #e63946;
    }

    #main { padding: 0 1; background: #0d0d0d; }

    #plugin-title {
        text-style: bold; color: #e63946;
        padding: 0 1 1 1;
        height: 2;
        border-bottom: solid #4a0d0d;
    }

    #plugin-desc { color: #b0b0b0; padding: 0 1; height: 1; }
    #hint { color: #555555; padding: 0 1; height: 1; }

    #args {
        background: #1c1c1c;
        border: heavy #4a0d0d;
        color: #d4d4d4;
    }
    #args:focus { border: heavy #e63946; }

    #run {
        margin: 1 0; background: #8b0000;
        color: #ffffff;
        border: heavy #e63946;
        width: 100%;
    }
    #run:hover { background: #e63946; }

    #output {
        background: #0a0a0a;
        border: round #4a0d0d;
        padding: 0 2;
        scrollbar-size-vertical: 1;
        scrollbar-color: #8b0000;
        scrollbar-background: #1c1c1c;
    }
    #output:focus { border: round #e63946; }

    #chart {
        height: 18;
        background: #0a0a0a;
        border: round #4a0d0d;
        padding: 0 1;
        margin-top: 1;
        display: none;
    }

    #status {
        height: 1; background: #161616;
        color: #8a8a8a; padding: 0 2;
        text-style: bold;
    }

    Footer { background: #161616; }
    """

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

    MAX_BUFFER_LINES = 5000

    def __init__(self) -> None:
        super().__init__()
        self.plugins = load_all()
        self.plugins_by_name = {p.name: p for p in self.plugins}
        self.config = load_config()
        self.current_plugin = None
        self._stream_buffer = ""
        self._worker = None
        self._chart_visible = False
        self._filter = "all"

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
                yield Static(self._category_bar_text(), id="category-bar")
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
        self._rebuild_plugin_list()
        if PLOTEXT_AVAILABLE:
            self._status("ready", "#7fb069")
        else:
            self._status("ready · pip install textual-plotext", "#e6b800")

    # ---------- Category bar ----------
    def _category_bar_text(self) -> str:
        active = self._filter
        parts = []
        c = "#e63946" if active == "all" else "#8a8a8a"
        parts.append(f"[{c}]1[/{c}][#555555]:all[/#555555]")
        for i, cat in enumerate(["Recon", "Web", "Network", "TLS", "Utils"], start=2):
            color = "#e63946" if active == cat else "#8a8a8a"
            parts.append(f"[{color}]{i}[/{color}][#555555]:{cat}[/#555555]")
        return " ".join(parts)

    # ---------- Plugin list ----------
    def _rebuild_plugin_list(self) -> None:
        lv = self.query_one("#plugin-list", ListView)
        lv.clear()

        if self._filter == "all":
            plugins = self.plugins
        else:
            plugins = [p for p in self.plugins if p.category == self._filter]

        by_cat: dict = {}
        for p in plugins:
            by_cat.setdefault(p.category, []).append(p)

        ordered_cats = [c for c in CATEGORY_ORDER if c in by_cat]
        for cat in ordered_cats:
            count = len(by_cat[cat])
            header = ListItem(
                Label(f"{CATEGORY_ICONS.get(cat, '◆')} {cat}  [#555555]({count})[/#555555]"),
                id=f"cat-{cat}",
                disabled=True,
            )
            header.add_class("category-header")
            lv.append(header)
            for p in sorted(by_cat[cat], key=lambda x: x.name):
                lbl = Label(f" {p.icon}  {p.name}")
                lbl.styles.color = "#b0b0b0"
                lv.append(ListItem(lbl, id=f"plugin-{p.name}"))

        for i, item in enumerate(lv.children):
            if item.id and item.id.startswith("plugin-"):
                lv.index = i
                break
        lv.focus()
        self.query_one("#category-bar", Static).update(self._category_bar_text())
        # Подсветить первый после рендера
        self.call_after_refresh(self._apply_highlight, lv.index)

    def _apply_highlight(self, selected_idx: int) -> None:
        """Красит текст выбранного Label в кровавый через styles.color."""
        lv = self.query_one("#plugin-list", ListView)
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


    def _get_plugin_at(self, idx):
        lv = self.query_one("#plugin-list", ListView)
        if idx is None or idx >= len(lv.children):
            return None
        item = lv.children[idx]
        if not item.id or not item.id.startswith("plugin-"):
            return None
        name = item.id[len("plugin-"):]
        return self.plugins_by_name.get(name)

    @staticmethod
    def _escape_markup(text: str) -> str:
        return text.replace("[", "\\[").replace("<", "\\<").replace(">", "\\>")

    def _apply_plugin(self, plugin) -> None:
        self.current_plugin = plugin
        self.query_one("#plugin-title", Static).update(
            f"{plugin.icon}  {plugin.name}  [#555555]· {plugin.category}[/#555555]"
        )
        self.query_one("#plugin-desc", Static).update(self._escape_markup(plugin.description))
        usage = plugin.usage or "key=value ..."
        safe_usage = self._escape_markup(usage)
        self.query_one("#hint", Static).update(f"[#555555]usage:[/#555555] {safe_usage}")
        inp = self.query_one("#args", Input)
        inp.placeholder = f"$ {usage}"
        inp.value = ""
        if PLOTEXT_AVAILABLE and self._chart_visible:
            self._hide_chart()

    # ---------- Events ----------
    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        idx = event.list_view.index
        self._apply_highlight(idx)
        plugin = self._get_plugin_at(idx)
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

        args = parse_args(self.query_one("#args", Input).value.strip())
        plugin = self.current_plugin
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
                    self._show_chart(results)
        except Exception as e:
            self._flush_stream(f"[#e63946]Error: {e}[/#e63946]")
            self._status(f"error: {e}", "#e63946")

    def _flush_stream(self, chunk: str) -> None:
        if not chunk:
            return
        self._stream_buffer += chunk
        if self._stream_buffer.count("\n") > self.MAX_BUFFER_LINES:
            lines = self._stream_buffer.split("\n")
            self._stream_buffer = "\n".join(lines[-self.MAX_BUFFER_LINES:])
            self.query_one("#output", RichLog).clear()
        self.query_one("#output", RichLog).write(chunk)

    # ---------- Chart ----------
    def _show_chart(self, results_by_host: list) -> None:
        if not PLOTEXT_AVAILABLE:
            return
        services: dict = {}
        for _, results in results_by_host:
            for r in results:
                svc = r.get("service", "unknown").split(" ")[0]
                services[svc] = services.get(svc, 0) + 1
        if not services:
            self._status("graph: no data", "#e6b800")
            return
        sorted_svcs = sorted(services.items(), key=lambda x: -x[1])[:10]
        labels = [s[0] for s in sorted_svcs]
        values = [s[1] for s in sorted_svcs]
        chart = self.query_one("#chart", PlotextPlot)
        plt = chart.plt
        plt.clear_figure()
        plt.theme("dark")
        plt.bar(labels, values, orientation="horizontal", color="red")
        plt.title("Open Ports by Service")
        chart.styles.display = "block"
        self._chart_visible = True
        self._status(f"chart: {len(services)} services", "#7fb069")

    def _hide_chart(self) -> None:
        if not PLOTEXT_AVAILABLE:
            return
        self.query_one("#chart", PlotextPlot).styles.display = "none"
        self._chart_visible = False

    # ---------- Actions ----------
    def action_toggle_chart(self) -> None:
        if not PLOTEXT_AVAILABLE:
            self._status("pip install textual-plotext", "#e6b800")
            return
        if self._chart_visible:
            self._hide_chart()
            self._status("chart hidden")
        else:
            if self.current_plugin and self.current_plugin.name == "portscan":
                results = getattr(self.current_plugin, "_last_results", None)
                if results:
                    self._show_chart(results)
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
        self._filter = cat
        self._rebuild_plugin_list()
        self._status(f"filter: {cat}", "#7fb069")

    def action_clear_cache(self) -> None:
        count = cache.clear()
        self._status(f"cache cleared ({count} files)", "#7fb069")


def main() -> None:
    HunterApp().run()


if __name__ == "__main__":
    main()
