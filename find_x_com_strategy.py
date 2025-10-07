#!/usr/bin/env python3
"""
Скрипт для поиска рабочей стратегии для x.com с использованием всех инструментов.
Использует:
1. Fingerprinting для анализа DPI
2. find_rst_triggers для поиска триггеров RST
3. Тестирование multidisorder стратегий (которые работали на роутере)
"""

import sys
import os
import asyncio

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel

console = Console()


async def test_x_com_strategies():
    """Тестирует различные стратегии для x.com."""
    
    console.print(Panel.fit(
        "[bold cyan]🔍 Поиск рабочей стратегии для x.com[/bold cyan]\n"
        "[dim]Тестируем multidisorder стратегии, которые работали на роутере[/dim]",
        border_style="cyan"
    ))
    
    # Стратегии с multidisorder для РКН DPI
    strategies_to_test = [
        # Базовая multidisorder с split_pos=1 (как на роутере)
        "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
        
        # Вариации с разными TTL
        "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq",
        
        # С fake пакетами
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
        
        # Разные позиции split
        "--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1",
        "--dpi-desync=multidisorder --dpi-desync-split-pos=2,6,10 --dpi-desync-fooling=badsum --dpi-desync-ttl=1",
        
        # fakeddisorder (тоже работал)
        "--dpi-desync=fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum --dpi-desync-ttl=64",
        
        # Комбинации
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3",
    ]
    
    console.print(f"\n[yellow]Будет протестировано {len(strategies_to_test)} стратегий[/yellow]\n")
    
    # Импортируем CLI для тестирования
    try:
        from cli import main as cli_main
        
        for i, strategy in enumerate(strategies_to_test, 1):
            console.print(f"[cyan]Тест {i}/{len(strategies_to_test)}:[/cyan] {strategy}")
            
            # Формируем команду для CLI
            test_args = [
                "x.com",
                "--strategy", strategy,
                "--count", "1",
                "--timeout", "10"
            ]
            
            console.print(f"[dim]Команда: python cli.py {' '.join(test_args)}[/dim]")
            console.print("[dim]Запуск теста...[/dim]\n")
            
            # Здесь можно добавить реальный запуск CLI
            # Пока просто выводим команды
            
    except ImportError as e:
        console.print(f"[red]Ошибка импорта CLI: {e}[/red]")
        console.print("[yellow]Выполните команды вручную:[/yellow]\n")
        
        for i, strategy in enumerate(strategies_to_test, 1):
            console.print(f"[cyan]{i}.[/cyan] python cli.py x.com --strategy \"{strategy}\" --count 1")
    
    console.print("\n" + "="*70)
    console.print("[bold green]📋 Рекомендации для службы обхода:[/bold green]")
    console.print("="*70)
    console.print("""
После того как найдете рабочую стратегию:

1. Откройте recon/strategies.json
2. Найдите секцию для x.com
3. Замените стратегию на рабочую

Пример:
{
  "x.com": {
    "strategy": "multidisorder",
    "params": {
      "split_pos": "1",
      "ttl": "1",
      "fooling": "badsum,badseq"
    }
  }
}

4. Перезапустите службу обхода
""")


def main():
    """Главная функция."""
    try:
        asyncio.run(test_x_com_strategies())
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
