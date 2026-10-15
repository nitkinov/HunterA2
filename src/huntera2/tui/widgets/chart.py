"""Виджет-обёртка над PlotextPlot для графиков сервисов."""

try:
    from textual_plotext import PlotextPlot
    PLOTEXT_AVAILABLE = True
except ImportError:
    PLOTEXT_AVAILABLE = False


class ChartPanel:
    """Обёртка для графика. Хранит состояние и умеет показывать/скрывать себя."""

    WIDGET_ID = "#chart"

    def __init__(self, query_one) -> None:
        self._query_one = query_one
        self._visible = False

    @property
    def available(self) -> bool:
        return PLOTEXT_AVAILABLE

    @property
    def visible(self) -> bool:
        return self._visible

    def show_services(self, results_by_host: list) -> int:
        """Строит bar chart сервисов. Возвращает количество сервисов или 0."""
        if not PLOTEXT_AVAILABLE:
            return 0

        services: dict[str, int] = {}
        for _, results in results_by_host:
            for r in results:
                svc = r.get("service", "unknown").split(" ")[0]
                services[svc] = services.get(svc, 0) + 1

        if not services:
            return 0

        sorted_svcs = sorted(services.items(), key=lambda x: -x[1])[:10]
        labels = [s[0] for s in sorted_svcs]
        values = [s[1] for s in sorted_svcs]

        chart = self._query_one(self.WIDGET_ID, PlotextPlot)
        plt = chart.plt
        plt.clear_figure()
        plt.theme("dark")
        plt.bar(labels, values, orientation="horizontal", color="red")
        plt.title("Open Ports by Service")
        chart.styles.display = "block"
        self._visible = True
        return len(services)

    def hide(self) -> None:
        if not PLOTEXT_AVAILABLE:
            return
        try:
            self._query_one(self.WIDGET_ID, PlotextPlot).styles.display = "none"
        except Exception:
            pass
        self._visible = False
