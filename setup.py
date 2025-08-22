"""
Интерактивный установщик и менеджер для Recon DPI Bypass.
Предоставляет пользователю простой интерфейс для основных действий:
- Поиск лучшей стратегии обхода.
- Запуск системной службы обхода с найденной стратегией.
- Отображение справочной информации.
"""
import os
import sys
import subprocess
import platform
import ctypes
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

    class Console:

        def print(self, text, *args, **kwargs):
            import re
            clean_text = re.sub('\\[/?[^\\]]*\\]', '', str(text))
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
            response = input(f'{text} [y/N]: ').lower()
            return response == 'y'
if __name__ == '__main__' and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    __package__ = 'recon'
from recon.core.signature_manager import SignatureManager
console = Console()
IS_DEBUG_MODE = '--debug' in sys.argv
SITES_FILE = 'sites.txt'
STRATEGY_FILE = 'best_strategy.json'
CLI_SCRIPT = 'cli.py'
SERVICE_SCRIPT = 'recon_service.py'

def is_admin() -> bool:
    """Проверяет, запущен ли скрипт с правами администратора."""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def run_command(command: list, needs_admin: bool=False, capture_output: bool=False):
    """Универсальная функция для запуска дочерних процессов с пробросом флага --debug."""
    if needs_admin and (not is_admin()):
        console.print('[bold red]Ошибка:[/bold red] Для этой операции требуются права администратора.')
        console.print('Пожалуйста, перезапустите скрипт из терминала, запущенного от имени администратора.')
        return None
    try:
        if IS_DEBUG_MODE and command and (command[0] in [CLI_SCRIPT, SERVICE_SCRIPT]):
            command.insert(1, '--debug')
        full_command = [sys.executable] + command
        console.print(f"\n[dim]Выполняется команда: {' '.join(full_command)}[/dim]\n")
        if capture_output:
            return subprocess.run(full_command, check=True, capture_output=True, text=True, encoding='utf-8')
        else:
            process = subprocess.Popen(full_command)
            process.wait()
            return process
    except FileNotFoundError:
        console.print(f"[bold red]Ошибка:[/bold red] Скрипт '{command[0]}' не найден.")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Ошибка выполнения скрипта '{command[0]}':[/bold red]")
        if e.stdout:
            console.print(f'[bold]STDOUT:[/bold]\n{e.stdout}')
        if e.stderr:
            console.print(f'[bold]STDERR:[/bold]\n{e.stderr}')
        return None
    except Exception as e:
        console.print(f'[bold red]Непредвиденная ошибка:[/bold red] {e}')
        return None

def check_files():
    """Проверяет наличие необходимых файлов и создает их при необходимости."""
    if not os.path.exists(SITES_FILE):
        console.print(f"[yellow]Файл '{SITES_FILE}' не найден. Создаем файл с примерами...[/yellow]")
        try:
            with open(SITES_FILE, 'w', encoding='utf-8') as f:
                f.write('# Список заблокированных доменов для обхода DPI\n')
                f.write('# Каждый домен на новой строке. Строки с # игнорируются.\n\n')
                f.write('rutracker.org\n')
                f.write('nnmclub.to\n')
                f.write('rutor.info\n')
            console.print(f"[green]Файл '{SITES_FILE}' успешно создан.[/green]")
            console.print('Пожалуйста, отредактируйте его, добавив нужные вам сайты.')
        except Exception as e:
            console.print(f"[bold red]Не удалось создать '{SITES_FILE}': {e}[/bold red]")

def show_main_menu():
    """Отображает главное меню и обрабатывает выбор пользователя."""
    sig_manager = SignatureManager()
    while True:
        console.print('\n' * 2)
        stats = sig_manager.get_statistics()
        menu_items_text = '\nВыберите действие:\n\n[1] Найти лучшую стратегию обхода\n[2] Запустить службу обхода (требуются права администратора)\n[3] Помощь и информация\n[4] Выход\n\n'
        panel_content = Text(menu_items_text, justify='center')
        status_text = Text()
        if os.path.exists(STRATEGY_FILE):
            status_text.append('✅ Стратегия найдена', style='green')
        else:
            status_text.append('❌ Стратегия не найдена', style='yellow')
        status_text.append(' | ', style='dim')
        if is_admin():
            status_text.append('✅ Права администратора', style='green')
        else:
            status_text.append('⚠️ Нет прав администратора', style='yellow')
        status_text.append(' | ', style='dim')
        status_text.append(f"📖 Сигнатур в базе: {stats.get('total_signatures', 0)}", style='blue')
        status_text.justify = 'center'
        panel_content.append('\n')
        panel_content.append(status_text)
        console.print(Panel(panel_content, title='[bold cyan]Recon DPI Bypass Manager[/bold cyan]', border_style='blue'))
        choice = Prompt.ask('Введите номер', choices=['1', '2', '3', '4'], default='4')
        if choice == '1':
            action_find_strategy()
        elif choice == '2':
            action_start_service()
        elif choice == '3':
            action_show_help()
        elif choice == '4':
            console.print('[bold]Выход...[/bold]')
            break

def action_find_strategy():
    """Запускает процесс поиска стратегии."""
    console.print(Panel(f"[bold]Поиск лучшей стратегии[/bold]\n\nСейчас будет запущен процесс анализа и тестирования различных техник обхода.\nОн будет использовать домены из файла [cyan]'{SITES_FILE}'[/cyan].\nПроцесс может занять несколько минут.", title='[1] Поиск стратегии', border_style='green'))
    if not Confirm.ask('Начать поиск?', default=True):
        return
    command = [CLI_SCRIPT, SITES_FILE, '--domains-file']
    run_command(command)
    if os.path.exists(STRATEGY_FILE):
        console.print(f"\n[bold green]🎉 Поиск завершен! Лучшая стратегия сохранена в '{STRATEGY_FILE}'.[/bold green]")
        console.print('Теперь вы можете запустить службу обхода (пункт 2).')
    else:
        console.print('\n[bold yellow]⚠️ Поиск завершен, но рабочая стратегия не найдена.[/bold yellow]')
        console.print('Попробуйте отредактировать список сайтов или запустить поиск еще раз.')

def action_start_service():
    """Запускает службу обхода."""
    console.print(Panel(f"[bold]Запуск службы обхода[/bold]\n\nСлужба будет перехватывать трафик к доменам из [cyan]'{SITES_FILE}'[/cyan] и применять к ним лучшую найденную стратегию.\nДля остановки службы просто закройте это окно или нажмите [bold]Ctrl+C[/bold].", title='[2] Запуск службы', border_style='green'))
    if not os.path.exists(STRATEGY_FILE):
        console.print(f"[bold yellow]Предупреждение:[/bold yellow] Файл '{STRATEGY_FILE}' не найден.")
        if Confirm.ask('Хотите сначала запустить поиск стратегии?', default=True):
            action_find_strategy()
        if not os.path.exists(STRATEGY_FILE):
            console.print('[bold red]Невозможно запустить службу без файла стратегии.[/bold red]')
            return
    command = [SERVICE_SCRIPT]
    run_command(command, needs_admin=True)

def action_show_help():
    """Показывает справочную информацию."""
    help_text = '\n[bold]Рабочий процесс Recon:[/bold]\n\n[bold]1. Настройка:[/bold]\n   - Откройте файл [cyan]sites.txt[/cyan] в текстовом редакторе.\n   - Добавьте в него домены, доступ к которым заблокирован. Каждый домен с новой строки.\n\n[bold]2. Поиск стратегии (Пункт 1 в меню):[/bold]\n   - Скрипт проанализирует DPI вашего провайдера и протестирует множество техник обхода.\n   - Самая быстрая и стабильная стратегия будет автоматически сохранена в файл [cyan]best_strategy.json[/cyan].\n   - Этот шаг нужно выполнять один раз, или если старая стратегия перестала работать.\n\n[bold]3. Запуск службы (Пункт 2 в меню):[/bold]\n   - Скрипт запустит фоновый процесс, который будет использовать найденную стратегию для разблокировки сайтов из [cyan]sites.txt[/cyan].\n   - Это действие требует прав администратора.\n   - Обход будет работать, пока открыто окно консоли.\n\n[bold]Совет:[/bold] Если обход перестал работать, просто повторите шаг 2, чтобы найти новую актуальную стратегию.\n'
    console.print(Panel(help_text, title='[3] Помощь', border_style='yellow'))
    input('\nНажмите Enter, чтобы вернуться в меню...')
if __name__ == '__main__':
    check_files()
    show_main_menu()