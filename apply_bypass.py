# recon/apply_bypass.py
import subprocess
import sys
import os
import platform
import time

# Try to use Rich for consistent formatting
try:
    from rich.console import Console

    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:
        def print(self, text, *args, **kwargs):
            # Strip Rich markup for plain text output
            import re

            clean_text = re.sub(r"\[/?[^\]]*\]", "", str(text))
            print(clean_text, *args, **kwargs)

    console = Console()


def check_admin_rights():
    """Проверяет права администратора."""
    if platform.system() == "Windows":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    # Для Linux/macOS проверяем UID
    return os.geteuid() == 0


def find_executable(name):
    """Ищет исполняемый файл в PATH."""
    from shutil import which

    return which(name)


def apply_system_bypass(strategy: str, zapret_path: str = "zapret"):
    """
    Запускает реальный zapret/nfqws с найденной стратегией как системный прокси.
    """
    if not check_admin_rights():
        console.print(
            "[bold red]Error:[/bold red] This functionality requires administrator/root privileges."
        )
        sys.exit(1)

    executable = find_executable(zapret_path)
    if not executable:
        console.print(
            f"[bold red]Error:[/bold red] '{zapret_path}' executable not found in your system's PATH."
        )
        console.print(
            "Please install Zapret/nfqws or provide a direct path to the executable."
        )
        sys.exit(1)

    # Разбираем строку стратегии на аргументы
    args = strategy.split()

    # Формируем полную команду для запуска
    # Добавляем параметры для работы в режиме прокси (примерные, могут отличаться)
    # --http-proxy - для перехвата HTTP/HTTPS трафика
    command = (
        [executable]
        + args
        + [
            "--http-proxy=127.0.0.1:8080",  # Запускаем локальный HTTP прокси
            "--dns-proxy=127.0.0.1:5353",  # Запускаем DNS прокси для перехвата DNS запросов
        ]
    )

    console.print(f"🚀 Launching system-wide bypass with the best strategy...")
    console.print(f"   Command: [cyan]{' '.join(command)}[/cyan]")
    console.print("\n[bold yellow]Your system proxy is now active![/bold yellow]")
    console.print(
        "Configure your browser or system to use HTTP proxy: [bold]127.0.0.1:8080[/bold]"
    )
    console.print("Press [bold]Ctrl+C[/bold] to stop the bypass.")

    try:
        # Запускаем процесс и ждем его завершения
        process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
    except KeyboardInterrupt:
        console.print("\nStopping bypass service...")
        process.terminate()
        # Даем время на освобождение портов
        time.sleep(1)
    except Exception as e:
        console.print(
            f"\n[bold red]An error occurred while running Zapret:[/bold red] {e}"
        )
    finally:
        console.print("Bypass service stopped.")
