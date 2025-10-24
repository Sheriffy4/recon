"""
Расширенный интерактивный менеджер для Recon DPI Bypass.
Предоставляет доступ ко всей функциональности проекта через удобное меню.
"""

import os
import sys
import subprocess
import platform
import ctypes
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.table import Table
    from rich.columns import Columns

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:
        def print(self, text, *args, **kwargs):
            import re

            clean_text = re.sub("\\[/?[^\\]]*\\]", "", str(text))
            print(clean_text)

    class Panel:
        def __init__(self, text, **kwargs):
            self.text = text
            print(str(text))

    class Prompt:
        @staticmethod
        def ask(text, choices=None, default=None):
            return input(text)

    class Confirm:
        @staticmethod
        def ask(text, default=False):
            response = input(f"{text} [y/N]: ").lower()
            return response == "y"

    class Table:
        def __init__(self, *args, **kwargs):
            pass

        def add_column(self, *args, **kwargs):
            pass

        def add_row(self, *args, **kwargs):
            pass

    class Columns:
        def __init__(self, *args, **kwargs):
            pass


if __name__ == "__main__" and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

from core.signature_manager import SignatureManager

console = Console()
IS_DEBUG_MODE = "--debug" in sys.argv


class AdvancedSetupManager:
    """Расширенный менеджер настройки и управления проектом."""

    def __init__(self):
        self.console = console
        self.project_root = Path(__file__).parent

        # Основные файлы
        self.sites_file = "sites.txt"
        self.strategy_file = "best_strategy.json"
        self.cli_script = "cli.py"
        self.service_script = "recon_service.py"

        # Загружаем информацию о модулях
        self.load_module_info()

    def load_module_info(self):
        """Загружает информацию о доступных модулях."""
        self.modules = {
            "cli_tools": [
                {
                    "file": "cli.py",
                    "name": "Основной CLI",
                    "desc": "Полнофункциональный CLI с PCAP анализом",
                },
                {
                    "file": "simple_cli.py",
                    "name": "Простой CLI",
                    "desc": "Упрощенный CLI для быстрых операций",
                },
                {
                    "file": "smart_bypass_cli.py",
                    "name": "Smart Bypass CLI",
                    "desc": "Умный CLI с автоматическим обходом",
                },
                {
                    "file": "subdomain_detector.py",
                    "name": "Детектор поддоменов",
                    "desc": "Автоматическое обнаружение заблокированных поддоменов",
                },
                {
                    "file": "browser_network_monitor.py",
                    "name": "Монитор браузера",
                    "desc": "Мониторинг сетевых запросов браузера",
                },
            ],
            "analyzers": [
                {
                    "file": "simple_pcap_analyzer.py",
                    "name": "PCAP Анализатор",
                    "desc": "Анализ PCAP файлов для диагностики",
                },
                {
                    "file": "comprehensive_bypass_analyzer.py",
                    "name": "Комплексный анализатор",
                    "desc": "Детальный анализ эффективности обхода",
                },
                {
                    "file": "x_com_subdomain_analyzer.py",
                    "name": "X.com анализатор",
                    "desc": "Специализированный анализатор для X.com",
                },
                {
                    "file": "project_analyzer.py",
                    "name": "Анализатор проекта",
                    "desc": "Анализ структуры и модулей проекта",
                },
            ],
            "tests": [
                {
                    "file": "quick_test.py",
                    "name": "Быстрый тест",
                    "desc": "Быстрая проверка системы обхода",
                },
                {
                    "file": "simple_bypass_test.py",
                    "name": "Тест обхода",
                    "desc": "Тестирование стратегий обхода",
                },
                {
                    "file": "final_bypass_test.py",
                    "name": "Финальный тест",
                    "desc": "Комплексное тестирование системы",
                },
            ],
            "utilities": [
                {
                    "file": "setup_hosts_bypass.py",
                    "name": "Настройка hosts",
                    "desc": "Управление hosts файлом",
                },
                {
                    "file": "apply_improved_strategies.py",
                    "name": "Применение стратегий",
                    "desc": "Применение улучшенных стратегий",
                },
                {
                    "file": "adaptive_strategy_finder.py",
                    "name": "Поиск стратегий",
                    "desc": "Адаптивный поиск оптимальных стратегий",
                },
            ],
            "monitors": [
                {
                    "file": "subdomain_detector.py monitor",
                    "name": "Мониторинг доменов",
                    "desc": "Автоматический мониторинг и исправление доменов",
                },
                {
                    "file": "browser_network_monitor.py diagnose-xcom",
                    "name": "Диагностика X.com",
                    "desc": "Автоматическая диагностика проблем X.com",
                },
            ],
            "brute_force_tools": [
                {
                    "file": "tools/strategy_bruteforce.py",
                    "name": "Strategy Bruteforcer",
                    "desc": "Test all available attacks against a domain.",
                }
            ],
        }

    def is_admin(self) -> bool:
        """Проверяет права администратора."""
        try:
            if platform.system() == "Windows":
                return ctypes.windll.shell32.IsUserAnAdmin() == 1
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def run_command(
        self, command: list, needs_admin: bool = False, capture_output: bool = False
    ):
        """Запускает команду."""
        if needs_admin and not self.is_admin():
            self.console.print(
                "[bold red]Ошибка:[/bold red] Требуются права администратора."
            )
            return None

        try:
            if IS_DEBUG_MODE and command and command[0].endswith(".py"):
                command.insert(1, "--debug")

            full_command = [sys.executable] + command
            self.console.print(f"\n[dim]Выполняется: {' '.join(full_command)}[/dim]\n")

            if capture_output:
                return subprocess.run(
                    full_command,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
            else:
                process = subprocess.Popen(full_command)
                process.wait()
                return process

        except Exception as e:
            self.console.print(f"[bold red]Ошибка:[/bold red] {e}")
            return None

    def show_main_menu(self):
        """Показывает главное меню."""
        while True:
            self.console.print("\n" * 2)

            # Статус системы
            sig_manager = SignatureManager()
            stats = sig_manager.get_statistics()

            status_text = Text()
            if os.path.exists(self.strategy_file):
                status_text.append("✅ Стратегия найдена", style="green")
            else:
                status_text.append("❌ Стратегия не найдена", style="yellow")

            status_text.append(" | ", style="dim")
            if self.is_admin():
                status_text.append("✅ Права администратора", style="green")
            else:
                status_text.append("⚠️ Нет прав администратора", style="yellow")

            status_text.append(" | ", style="dim")
            status_text.append(
                f"📖 Сигнатур: {stats.get('total_signatures', 0)}", style="blue"
            )
            status_text.justify = "center"

            # Главное меню
            menu_text = """
[bold]ОСНОВНЫЕ ФУНКЦИИ:[/bold]
[1] Найти лучшую стратегию обхода
[2] Запустить службу обхода (требуются права администратора)
[3] Быстрый тест системы

[bold]РАСШИРЕННЫЕ ИНСТРУМЕНТЫ:[/bold]
[4] CLI инструменты
[5] Анализаторы и диагностика
[6] Тесты и проверки
[7] Утилиты и настройки
[8] Мониторинг и автоматизация
[9] Брутфорс стратегий

[bold]ИНФОРМАЦИЯ:[/bold]
[10] Помощь и документация
[0] Выход
            """

            panel_content = Text(menu_text, justify="left")
            panel_content.append("\n")
            panel_content.append(status_text)

            self.console.print(
                Panel(
                    panel_content,
                    title="[bold cyan]Recon DPI Bypass - Расширенный менеджер[/bold cyan]",
                    border_style="blue",
                )
            )

            choice = Prompt.ask(
                "Выберите пункт",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "0"],
                default="0",
            )

            if choice == "1":
                self.action_find_strategy()
            elif choice == "2":
                self.action_start_service()
            elif choice == "3":
                self.action_quick_test()
            elif choice == "4":
                self.show_cli_tools_menu()
            elif choice == "5":
                self.show_analyzers_menu()
            elif choice == "6":
                self.show_tests_menu()
            elif choice == "7":
                self.show_utilities_menu()
            elif choice == "8":
                self.show_monitoring_menu()
            elif choice == "9":
                self.show_brute_force_menu()
            elif choice == "10":
                self.show_help()
            elif choice == "0":
                self.console.print("[bold]Выход...[/bold]")
                break

    def show_cli_tools_menu(self):
        """Показывает меню CLI инструментов."""
        while True:
            self.console.print("\n")

            table = Table(
                title="CLI Инструменты", show_header=True, header_style="bold magenta"
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, tool in enumerate(self.modules["cli_tools"], 1):
                table.add_row(str(i), tool["name"], tool["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите CLI инструмент", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["cli_tools"]):
                    tool = self.modules["cli_tools"][idx]
                    self.run_cli_tool(tool)
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def run_cli_tool(self, tool):
        """Запускает CLI инструмент."""
        self.console.print(f"\n[bold]Запуск: {tool['name']}[/bold]")
        self.console.print(f"Описание: {tool['desc']}")

        if tool["file"] == "cli.py":
            # Для основного CLI показываем дополнительные опции
            self.console.print("\nДоступные режимы:")
            self.console.print("1. Стандартный режим")
            self.console.print("2. Эволюционный поиск")
            self.console.print("3. Индивидуальное тестирование доменов")

            mode = Prompt.ask("Выберите режим", choices=["1", "2", "3"], default="1")

            if mode == "1":
                command = [tool["file"], self.sites_file, "--domains-file"]
            elif mode == "2":
                command = [
                    tool["file"],
                    self.sites_file,
                    "--domains-file",
                    "--evolutionary",
                ]
            elif mode == "3":
                command = [
                    tool["file"],
                    self.sites_file,
                    "--domains-file",
                    "--individual",
                ]

        elif tool["file"] == "simple_cli.py":
            # Для простого CLI показываем команды
            self.console.print("\nДоступные команды:")
            self.console.print("1. Быстрый тест системы")
            self.console.print("2. Проверка домена")
            self.console.print("3. Тестирование множества доменов")
            self.console.print("4. Настройка hosts файла")

            cmd_choice = Prompt.ask(
                "Выберите команду", choices=["1", "2", "3", "4"], default="1"
            )

            if cmd_choice == "1":
                command = [tool["file"], "quick-test"]
            elif cmd_choice == "2":
                domain = Prompt.ask("Введите домен для проверки", default="x.com")
                command = [tool["file"], "check", domain]
            elif cmd_choice == "3":
                command = [
                    tool["file"],
                    "test-multi",
                    "x.com",
                    "instagram.com",
                    "rutracker.org",
                ]
            elif cmd_choice == "4":
                command = [tool["file"], "setup-hosts"]

        elif tool["file"] == "smart_bypass_cli.py":
            # Для Smart Bypass CLI
            self.console.print("\nДоступные команды:")
            self.console.print("1. Тестирование доменов")
            self.console.print("2. Генерация отчета")
            self.console.print("3. Статистика")

            cmd_choice = Prompt.ask(
                "Выберите команду", choices=["1", "2", "3"], default="1"
            )

            if cmd_choice == "1":
                command = [
                    tool["file"],
                    "test-multiple",
                    "x.com",
                    "instagram.com",
                    "rutracker.org",
                ]
            elif cmd_choice == "2":
                command = [tool["file"], "report"]
            elif cmd_choice == "3":
                command = [tool["file"], "stats"]

        else:
            # Для остальных инструментов
            command = [tool["file"]]

        if Confirm.ask(f"Запустить {tool['name']}?", default=True):
            self.run_command(command)

    def show_analyzers_menu(self):
        """Показывает меню анализаторов."""
        while True:
            self.console.print("\n")

            table = Table(
                title="Анализаторы и диагностика",
                show_header=True,
                header_style="bold green",
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, analyzer in enumerate(self.modules["analyzers"], 1):
                table.add_row(str(i), analyzer["name"], analyzer["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите анализатор", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["analyzers"]):
                    analyzer = self.modules["analyzers"][idx]
                    if Confirm.ask(f"Запустить {analyzer['name']}?", default=True):
                        self.run_command([analyzer["file"]])
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def show_tests_menu(self):
        """Показывает меню тестов."""
        while True:
            self.console.print("\n")

            table = Table(
                title="Тесты и проверки", show_header=True, header_style="bold yellow"
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, test in enumerate(self.modules["tests"], 1):
                table.add_row(str(i), test["name"], test["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите тест", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["tests"]):
                    test = self.modules["tests"][idx]
                    if Confirm.ask(f"Запустить {test['name']}?", default=True):
                        self.run_command([test["file"]])
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def show_utilities_menu(self):
        """Показывает меню утилит."""
        while True:
            self.console.print("\n")

            table = Table(
                title="Утилиты и настройки", show_header=True, header_style="bold blue"
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, util in enumerate(self.modules["utilities"], 1):
                table.add_row(str(i), util["name"], util["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите утилиту", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["utilities"]):
                    util = self.modules["utilities"][idx]
                    if Confirm.ask(f"Запустить {util['name']}?", default=True):
                        self.run_command([util["file"]])
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def show_monitoring_menu(self):
        """Показывает меню мониторинга."""
        while True:
            self.console.print("\n")

            table = Table(
                title="Мониторинг и автоматизация",
                show_header=True,
                header_style="bold red",
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, monitor in enumerate(self.modules["monitors"], 1):
                table.add_row(str(i), monitor["name"], monitor["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите режим мониторинга", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["monitors"]):
                    monitor = self.modules["monitors"][idx]

                    if "monitor" in monitor["file"]:
                        # Мониторинг доменов
                        domains = Prompt.ask(
                            "Введите домены для мониторинга (через пробел)",
                            default="x.com instagram.com",
                        ).split()
                        command = monitor["file"].split() + domains
                    else:
                        # Диагностика X.com
                        command = monitor["file"].split()

                    if Confirm.ask(f"Запустить {monitor['name']}?", default=True):
                        self.run_command(command)
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def action_find_strategy(self):
        """Поиск стратегии."""
        self.console.print(
            Panel(
                f"[bold]Поиск лучшей стратегии[/bold]\n\nЗапуск анализа DPI и тестирования техник обхода.\nИспользуются домены из файла [cyan]'{self.sites_file}'[/cyan].",
                title="Поиск стратегии",
                border_style="green",
            )
        )

        if Confirm.ask("Начать поиск?", default=True):
            command = [self.cli_script, self.sites_file, "--domains-file"]
            self.run_command(command)

    def action_start_service(self):
        """Запуск службы."""
        self.console.print(
            Panel(
                f"[bold]Запуск службы обхода[/bold]\n\nСлужба будет применять стратегии к доменам из [cyan]'{self.sites_file}'[/cyan].",
                title="Запуск службы",
                border_style="green",
            )
        )

        if not os.path.exists(self.strategy_file):
            self.console.print("[yellow]Файл стратегии не найден.[/yellow]")
            if Confirm.ask("Запустить поиск стратегии?", default=True):
                self.action_find_strategy()

        if Confirm.ask("Запустить службу?", default=True):
            self.run_command([self.service_script], needs_admin=True)

    def show_brute_force_menu(self):
        """Показывает меню брутфорс инструментов."""
        while True:
            self.console.print("\n")

            table = Table(
                title="Advanced Tools (Bruteforce)",
                show_header=True,
                header_style="bold red",
            )
            table.add_column("№", style="dim", width=3)
            table.add_column("Название", style="cyan")
            table.add_column("Описание", style="white")

            for i, tool in enumerate(self.modules["brute_force_tools"], 1):
                table.add_row(str(i), tool["name"], tool["desc"])

            table.add_row("0", "Назад", "Вернуться в главное меню")

            self.console.print(table)

            choice = Prompt.ask("Выберите инструмент", default="0")

            if choice == "0":
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.modules["brute_force_tools"]):
                    tool = self.modules["brute_force_tools"][idx]
                    domain = Prompt.ask("Введите домен для брутфорса", default="x.com")
                    if Confirm.ask(
                        f"Запустить {tool['name']} для домена {domain}?", default=True
                    ):
                        self.run_command([tool["file"], domain])
            except ValueError:
                self.console.print("[red]Неверный выбор[/red]")

    def action_quick_test(self):
        """Быстрый тест системы."""
        self.console.print(
            Panel(
                "[bold]Быстрый тест системы[/bold]\n\nПроверка доступности ключевых доменов и работоспособности обхода.",
                title="Быстрый тест",
                border_style="blue",
            )
        )

        if Confirm.ask("Запустить быстрый тест?", default=True):
            self.run_command(["quick_test.py"])

    def show_help(self):
        """Показывает справку."""
        help_text = """
[bold]Расширенный менеджер Recon DPI Bypass[/bold]

[bold cyan]Основные функции:[/bold cyan]
• [bold]Поиск стратегии[/bold] - автоматический анализ DPI и поиск оптимальных техник обхода
• [bold]Запуск службы[/bold] - применение найденных стратегий к заблокированным доменам
• [bold]Быстрый тест[/bold] - проверка работоспособности системы обхода

[bold cyan]CLI инструменты:[/bold cyan]
• [bold]Основной CLI[/bold] - полнофункциональный интерфейс с PCAP анализом
• [bold]Простой CLI[/bold] - упрощенный интерфейс для быстрых операций
• [bold]Smart Bypass CLI[/bold] - умный CLI с автоматическим обходом

[bold cyan]Анализаторы:[/bold cyan]
• [bold]PCAP анализатор[/bold] - диагностика проблем через анализ сетевого трафика
• [bold]Детектор поддоменов[/bold] - автоматическое обнаружение заблокированных поддоменов
• [bold]Монитор браузера[/bold] - анализ сетевых запросов браузера

[bold cyan]Мониторинг:[/bold cyan]
• [bold]Автоматический мониторинг[/bold] - непрерывная проверка и исправление доменов
• [bold]Диагностика X.com[/bold] - специализированная диагностика проблем с Twitter/X

[bold yellow]Совет:[/bold yellow] Начните с быстрого теста, затем используйте специализированные инструменты по необходимости.
        """

        self.console.print(Panel(help_text, title="Справка", border_style="yellow"))
        input("\nНажмите Enter для продолжения...")


def main():
    """Главная функция."""
    manager = AdvancedSetupManager()

    # Проверяем и создаем необходимые файлы
    if not os.path.exists(manager.sites_file):
        console.print(f"[yellow]Создание файла {manager.sites_file}...[/yellow]")
        try:
            with open(manager.sites_file, "w", encoding="utf-8") as f:
                f.write("# Список заблокированных доменов\n")
                f.write("x.com\n")
                f.write("instagram.com\n")
                f.write("rutracker.org\n")
                f.write("nnmclub.to\n")
            console.print(f"[green]Файл {manager.sites_file} создан.[/green]")
        except Exception as e:
            console.print(f"[red]Ошибка создания файла: {e}[/red]")

    # Запускаем главное меню
    manager.show_main_menu()


if __name__ == "__main__":
    main()
