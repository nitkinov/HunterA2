"""Модальный экран справки: горячие клавиши, подсказки, инфо."""
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static
from textual.containers import Container
from textual.binding import Binding


HELP_TEXT = """
[bold #e63946]🩸 HunterA 2 — Справка[/]

[bold #7fb069]◆ Горячие клавиши:[/]
  [bold #ff2a2a]r[/]       Запустить текущий плагин
  [bold #ff2a2a]c[/]       Очистить вывод
  [bold #ff2a2a]g[/]       Показать/скрыть график
  [bold #ff2a2a]Esc[/]     Отменить выполнение
  [bold #ff2a2a]X[/]       Очистить кэш
  [bold #ff2a2a]?[/]       Эта справка
  [bold #ff2a2a]q[/]       Выход

[bold #7fb069]◆ Категории (клавиши 1-6):[/]
  [bold #ff2a2a]1[/]  All        [bold #ff2a2a]2[/]  Recon      [bold #ff2a2a]3[/]  Web
  [bold #ff2a2a]4[/]  Network    [bold #ff2a2a]5[/]  TLS        [bold #ff2a2a]6[/]  Utils

[bold #7fb069]◆ Навигация:[/]
  [bold #ff2a2a]↑ / ↓[/]  Выбор плагина
  [bold #ff2a2a]Tab[/]    Переход к полю ввода
  [bold #ff2a2a]Enter[/]  Подтвердить ввод

[bold #7fb069]◆ Примеры:[/]
  [dim]dns host=example.com[/]
  [dim]whois domain=example.com[/]
  [dim]portscan host=scanme.nmap.org ports=top100[/]
  [dim]robots url=https://example.com check=1[/]

[dim #555555]Нажми Esc или ? чтобы закрыть[/]
"""


class HelpScreen(ModalScreen):
    """Модальное окно со справкой."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("question_mark", "dismiss", "Close", show=False),
        Binding("q", "dismiss", "Close", show=False),
    ]

    CSS = """
    HelpScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }

    #help-container {
        width: 64;
        height: auto;
        background: #161616;
        border: heavy #8b0000;
        padding: 1 2;
    }

    #help-text {
        width: 100%;
        height: auto;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="help-container"):
            yield Static(HELP_TEXT, id="help-text")

    def action_dismiss(self) -> None:
        self.dismiss()
