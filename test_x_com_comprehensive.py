#!/usr/bin/env python3
"""
Комплексный тест x.com с использованием всех возможностей:
1. Fingerprinting DPI
2. Тестирование multidisorder стратегий
3. Анализ результатов
"""

import sys
import os
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def run_cli_test(strategy, domain="x.com"):
    """Запускает CLI тест с заданной стратегией."""
    cmd = [
        sys.executable, "cli.py",
        domain,
        "--strategy", strategy,
        "--count", "1",
        "--fingerprint",
        "--timeout", "15"
    ]
    
    console.print(f"[dim]Команда: {' '.join(cmd)}[/dim]")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "Timeout"
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e)
        }


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 Комплексный тест x.com для РКН DPI[/bold cyan]\n"
        "[dim]Тестируем стратегии которые работали на роутере[/dim]",
        border_style="cyan"
    ))
    
    # Стратегии для тестирования (приоритет - multidisorder)
    strategies = [
        ("multidisorder split_pos=1 ttl=1", 
         "multidisorder --split-pos=1 --ttl=1 --fooling=badsum,badseq"),
        
        ("multidisorder split_pos=1 ttl=2", 
         "multidisorder --split-pos=1 --ttl=2 --fooling=badsum,badseq"),
        
        ("fake+multidisorder split_pos=1", 
         "fake,multidisorder --split-pos=1 --ttl=1 --fooling=badsum,badseq"),
        
        ("multidisorder split_pos=1,5,10", 
         "multidisorder --split-pos=1,5,10 --fooling=badsum,badseq --ttl=1"),
        
        ("fakeddisorder split_pos=1", 
         "fakeddisorder --split-pos=1 --ttl=1 --fooling=badsum,badseq"),
    ]
    
    console.print(f"\n[yellow]Тестируем {len(strategies)} стратегий...[/yellow]\n")
    
    results = []
    
    for name, strategy in strategies:
        console.print(f"[cyan]Тест:[/cyan] {name}")
        console.print(f"[dim]Стратегия: {strategy}[/dim]")
        
        result = run_cli_test(strategy)
        
        # Анализ результата
        success = False
        if result["success"]:
            # Проверяем наличие успешных результатов в выводе
            if "success_rate" in result["stdout"].lower() or "✓" in result["stdout"]:
                success = True
        
        results.append({
            "name": name,
            "strategy": strategy,
            "success": success,
            "output": result["stdout"][:200] if result["stdout"] else result["stderr"][:200]
        })
        
        status = "[green]✓ УСПЕХ[/green]" if success else "[red]✗ НЕУДАЧА[/red]"
        console.print(f"Результат: {status}\n")
    
    # Вывод итоговой таблицы
    console.print("\n" + "="*70)
    console.print("[bold]📊 Итоговые результаты:[/bold]")
    console.print("="*70 + "\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("№", style="dim", width=3)
    table.add_column("Стратегия", width=35)
    table.add_column("Результат", width=10)
    
    for i, result in enumerate(results, 1):
        status = "[green]✓ Работает[/green]" if result["success"] else "[red]✗ Не работает[/red]"
        table.add_row(str(i), result["name"], status)
    
    console.print(table)
    
    # Рекомендации
    working_strategies = [r for r in results if r["success"]]
    
    if working_strategies:
        console.print(f"\n[bold green]✅ Найдено {len(working_strategies)} рабочих стратегий![/bold green]\n")
        
        console.print("[bold]Рекомендуемая стратегия для службы обхода:[/bold]")
        best = working_strategies[0]
        console.print(f"[cyan]{best['strategy']}[/cyan]\n")
        
        console.print("[bold]Для обновления службы обхода:[/bold]")
        console.print("1. Откройте recon/strategies.json")
        console.print("2. Обновите стратегию для x.com")
        console.print("3. Перезапустите службу\n")
    else:
        console.print("\n[yellow]⚠ Рабочие стратегии не найдены[/yellow]")
        console.print("[dim]Попробуйте запустить с --fingerprint для анализа DPI[/dim]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Прервано пользователем[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
