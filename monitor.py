# recon/monitor.py - CLI для системы мониторинга

import asyncio
import argparse
import signal
import sys
import logging
from pathlib import Path

# Добавляем путь к проекту
if __name__ == "__main__" and __package__ is None:
    recon_dir = Path(__file__).parent
    project_root = recon_dir.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from recon.core.monitoring_system import (
    MonitoringSystem,
    MonitoringConfig,
    load_monitoring_config,
)
from recon.web.monitoring_server import MonitoringWebServer

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.live import Live
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:
        def print(self, *args, **kwargs):
            print(*args)

    class Panel:
        def __init__(self, text, **kwargs):
            self.text = text

        def __str__(self):
            return str(self.text)


console = Console() if RICH_AVAILABLE else Console()


class MonitoringCLI:
    """CLI интерфейс для системы мониторинга."""

    def __init__(self):
        self.monitoring_system: MonitoringSystem = None
        self.web_server: MonitoringWebServer = None
        self.running = False
        self.learning_cache = None

    def setup_signal_handlers(self):
        """Настраивает обработчики сигналов для graceful shutdown."""

        def signal_handler(signum, frame):
            console.print(
                "\n[yellow]Received shutdown signal. Stopping monitoring...[/yellow]"
            )
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start_monitoring(self, args):
        """Запускает систему мониторинга."""
        # Загружаем конфигурацию
        config = load_monitoring_config(args.config)

        # Настраиваем логирование
        logging.basicConfig(
            level=getattr(logging, config.log_level),
            format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )

        # Загружаем кэш обучения если доступен
        if not args.disable_learning:
            try:
                from recon.cli import AdaptiveLearningCache

                self.learning_cache = AdaptiveLearningCache()
                console.print("[dim]🧠 Adaptive learning cache loaded[/dim]")
            except ImportError:
                console.print("[yellow]⚠️ Adaptive learning not available[/yellow]")

        # Создаем систему мониторинга
        self.monitoring_system = MonitoringSystem(config, self.learning_cache)

        # Добавляем сайты из аргументов командной строки
        if args.sites:
            for site in args.sites:
                if ":" in site:
                    domain, port = site.split(":", 1)
                    port = int(port)
                else:
                    domain, port = site, 443

                self.monitoring_system.add_site(domain, port)

        # Загружаем сайты из файла
        if args.sites_file and Path(args.sites_file).exists():
            with open(args.sites_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if ":" in line:
                            domain, port = line.split(":", 1)
                            port = int(port)
                        else:
                            domain, port = line, 443

                        self.monitoring_system.add_site(domain, port)

        # Запускаем веб-интерфейс если включен
        if args.web_interface:
            try:
                self.web_server = MonitoringWebServer(
                    self.monitoring_system, config.web_interface_port
                )
                await self.web_server.start()
            except ImportError:
                console.print(
                    "[red]❌ Web interface requires aiohttp. Install with: pip install aiohttp[/red]"
                )
                args.web_interface = False

        # Запускаем мониторинг
        await self.monitoring_system.start()

        console.print(
            Panel(
                f"[bold green]🚀 Monitoring System Started[/bold green]\n\n"
                f"Sites monitored: {len(self.monitoring_system.monitored_sites)}\n"
                f"Check interval: {config.check_interval_seconds}s\n"
                f"Auto-recovery: {'✅ Enabled' if config.enable_auto_recovery else '❌ Disabled'}\n"
                f"Web interface: {'✅ http://localhost:' + str(config.web_interface_port) if args.web_interface else '❌ Disabled'}",
                title="Status",
            )
        )

        self.running = True

        # Основной цикл с отображением статуса
        if args.interactive:
            await self.interactive_loop()
        else:
            await self.simple_loop()

    async def interactive_loop(self):
        """Интерактивный цикл с live обновлением статуса."""
        if not RICH_AVAILABLE:
            console.print(
                "[yellow]Interactive mode requires rich. Install with: pip install rich[/yellow]"
            )
            await self.simple_loop()
            return

        def generate_table():
            table = Table(title="🛡️ DPI Bypass Monitor")
            table.add_column("Site", style="cyan")
            table.add_column("Status", justify="center")
            table.add_column("Response", justify="right")
            table.add_column("Bypass", style="green")
            table.add_column("Failures", justify="center")
            table.add_column("Last Check", style="dim")

            for site_key, health in self.monitoring_system.monitored_sites.items():
                status = "✅ Online" if health.is_accessible else "❌ Offline"
                response = f"{health.response_time_ms:.1f}ms"
                bypass = "🔧 Active" if health.bypass_active else "⚪ None"
                failures = str(health.consecutive_failures)
                last_check = health.last_check.strftime("%H:%M:%S")

                table.add_row(
                    f"{health.domain}:{health.port}",
                    status,
                    response,
                    bypass,
                    failures,
                    last_check,
                )

            return table

        with Live(generate_table(), refresh_per_second=1) as live:
            while self.running:
                live.update(generate_table())
                await asyncio.sleep(1)

    async def simple_loop(self):
        """Простой цикл без интерактивного интерфейса."""
        last_report_time = 0

        while self.running:
            current_time = asyncio.get_event_loop().time()

            # Выводим отчет каждые 30 секунд
            if current_time - last_report_time >= 30:
                summary = self.monitoring_system.get_health_summary()
                console.print(f"[dim]{summary}[/dim]")
                last_report_time = current_time

            await asyncio.sleep(1)

    async def stop_monitoring(self):
        """Останавливает систему мониторинга."""
        if self.monitoring_system:
            await self.monitoring_system.stop()

        if self.web_server:
            await self.web_server.stop()

        console.print("[green]✅ Monitoring system stopped[/green]")


async def main():
    parser = argparse.ArgumentParser(
        description="DPI Bypass Monitoring System",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Основные параметры
    parser.add_argument(
        "sites", nargs="*", help="Sites to monitor (domain:port format)"
    )
    parser.add_argument("-f", "--sites-file", help="File with list of sites to monitor")
    parser.add_argument(
        "-c",
        "--config",
        default="monitoring_config.json",
        help="Configuration file (default: monitoring_config.json)",
    )

    # Режимы работы
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactive mode with live status updates",
    )
    parser.add_argument(
        "-w", "--web-interface", action="store_true", help="Enable web interface"
    )
    parser.add_argument(
        "--disable-learning",
        action="store_true",
        help="Disable adaptive learning integration",
    )

    # Конфигурация
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Check interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failure threshold for auto-recovery (default: 3)",
    )
    parser.add_argument(
        "--no-auto-recovery", action="store_true", help="Disable automatic recovery"
    )
    parser.add_argument(
        "--web-port", type=int, default=8080, help="Web interface port (default: 8080)"
    )

    args = parser.parse_args()

    # Создаем конфигурацию из аргументов
    if not Path(args.config).exists():
        config = MonitoringConfig(
            check_interval_seconds=args.interval,
            failure_threshold=args.threshold,
            enable_auto_recovery=not args.no_auto_recovery,
            web_interface_port=args.web_port,
        )

        # Сохраняем конфигурацию по умолчанию
        from recon.core.monitoring_system import save_monitoring_config

        save_monitoring_config(config, args.config)
        console.print(f"[green]Created default configuration: {args.config}[/green]")

    # Проверяем наличие сайтов для мониторинга
    if not args.sites and not args.sites_file:
        console.print("[red]❌ No sites specified for monitoring.[/red]")
        console.print("Use: python monitor.py site1.com site2.com:8080")
        console.print("Or:  python monitor.py -f sites.txt")
        return

    # Запускаем мониторинг
    cli = MonitoringCLI()
    cli.setup_signal_handlers()

    try:
        await cli.start_monitoring(args)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
    finally:
        await cli.stop_monitoring()


if __name__ == "__main__":
    asyncio.run(main())
