#!/usr/bin/env python3
"""
Прямое тестирование x.com с правильным форматом стратегий.
Исправляет ошибку парсинга стратегий.
"""

import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def test_strategy(strategy_full, description=""):
    """Тестирует одну стратегию."""
    
    console.print(f"\n[cyan]Тест:[/cyan] {description}")
    console.print(f"[dim]Стратегия: {strategy_full}[/dim]")
    
    cmd = [
        sys.executable, "cli.py",
        "x.com",
        "--strategy", strategy_full,
        "--count", "1",
        "--timeout", "15"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Проверяем результат
        if result.returncode == 0:
            # Ищем признаки успеха в выводе
            output = result.stdout.lower()
            if "success" in output or "✓" in result.stdout:
                console.print("[green]✓ УСПЕХ - Стратегия работает![/green]")
                return True
            else:
                console.print("[yellow]⚠ Завершено, но результат неясен[/yellow]")
                return False
        else:
            # Проверяем ошибки
            if "No valid DPI methods" in result.stderr or "Could not parse" in result.stderr:
                console.print("[red]✗ ОШИБКА ПАРСИНГА - Неправильный формат стратегии[/red]")
            else:
                console.print(f"[red]✗ ОШИБКА - Код возврата: {result.returncode}[/red]")
            
            if result.stderr:
                console.print(f"[dim]Ошибка: {result.stderr[:200]}[/dim]")
            return False
            
    except subprocess.TimeoutExpired:
        console.print("[red]✗ TIMEOUT[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ ИСКЛЮЧЕНИЕ: {e}[/red]")
        return False


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 Тестирование x.com с правильным форматом стратегий[/bold cyan]\n"
        "[dim]Исправлена ошибка парсинга - используем полный формат zapret[/dim]",
        border_style="cyan"
    ))
    
    # Стратегии в ПРАВИЛЬНОМ формате (с --dpi-desync=)
    strategies = [
        {
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
            "desc": "multidisorder split_pos=1 ttl=1 (как на роутере)"
        },
        {
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
            "desc": "multidisorder split_pos=1 ttl=2"
        },
        {
            "strategy": "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
            "desc": "fake+multidisorder split_pos=1 ttl=1"
        },
        {
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=1",
            "desc": "multidisorder split_pos=1,5,10"
        },
        {
            "strategy": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq",
            "desc": "fakeddisorder split_pos=1 ttl=1"
        },
    ]
    
    console.print(f"\n[yellow]Будет протестировано {len(strategies)} стратегий[/yellow]\n")
    
    results = []
    
    for i, strat_info in enumerate(strategies, 1):
        console.print(f"\n{'='*70}")
        console.print(f"[bold]Тест {i}/{len(strategies)}[/bold]")
        console.print(f"{'='*70}")
        
        success = test_strategy(strat_info["strategy"], strat_info["desc"])
        results.append({
            "desc": strat_info["desc"],
            "strategy": strat_info["strategy"],
            "success": success
        })
    
    # Итоговая таблица
    console.print("\n" + "="*70)
    console.print("[bold]📊 Итоговые результаты:[/bold]")
    console.print("="*70 + "\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("№", style="dim", width=3)
    table.add_column("Описание", width=40)
    table.add_column("Результат", width=15)
    
    for i, result in enumerate(results, 1):
        status = "[green]✓ Работает[/green]" if result["success"] else "[red]✗ Не работает[/red]"
        table.add_row(str(i), result["desc"], status)
    
    console.print(table)
    
    # Рекомендации
    working = [r for r in results if r["success"]]
    
    if working:
        console.print(f"\n[bold green]✅ Найдено {len(working)} рабочих стратегий![/bold green]\n")
        
        best = working[0]
        console.print("[bold]Рекомендуемая стратегия:[/bold]")
        console.print(f"[cyan]{best['strategy']}[/cyan]\n")
        
        console.print("[bold]Для обновления strategies.json:[/bold]")
        console.print("python fix_x_com_service.py\n")
    else:
        console.print("\n[yellow]⚠ Рабочие стратегии не найдены[/yellow]")
        console.print("[dim]Возможно проблема в сети или DPI изменился[/dim]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
