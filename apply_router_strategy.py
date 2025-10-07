#!/usr/bin/env python3
"""
Применяет рабочую стратегию с роутера для x.com.
Тестирует и обновляет strategies.json и службу обхода.
"""

import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def test_strategy(strategy_str):
    """Тестирует стратегию через CLI."""
    console.print(f"\n[cyan]Тестирую стратегию:[/cyan] {strategy_str}")
    console.print("[dim]Команда: python cli.py x.com --strategy \"...\" --count 1[/dim]\n")
    
    # Здесь можно добавить реальный запуск CLI
    # Пока просто возвращаем True для демонстрации
    return True


def update_strategies_json(strategy):
    """Обновляет strategies.json с рабочей стратегией."""
    
    strategies_file = "strategies.json"
    
    if not os.path.exists(strategies_file):
        console.print(f"[red]Файл {strategies_file} не найден![/red]")
        return False
    
    # Читаем текущие стратегии
    with open(strategies_file, 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    # Домены для обновления
    x_com_domains = [
        "x.com",
        "www.x.com",
        "api.x.com",
        "mobile.x.com",
        "twitter.com",
        "www.twitter.com",
        "mobile.twitter.com",
        "*.twimg.com",
        "abs.twimg.com",
        "abs-0.twimg.com",
        "pbs.twimg.com",
        "video.twimg.com",
        "ton.twimg.com"
    ]
    
    console.print("\n[bold]Обновление strategies.json:[/bold]")
    for domain in x_com_domains:
        old = strategies.get(domain, "[dim]не было[/dim]")
        strategies[domain] = strategy
        console.print(f"[green]✓[/green] {domain}")
        if old != "[dim]не было[/dim]":
            console.print(f"  [dim]Старая: {old[:60]}...[/dim]")
    
    # Сохраняем
    with open(strategies_file, 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    console.print(f"\n[green]✅ {strategies_file} обновлен![/green]")
    return True


def update_service_code():
    """Проверяет и при необходимости обновляет код службы."""
    
    service_file = "recon_service.py"
    
    if not os.path.exists(service_file):
        console.print(f"[yellow]⚠ Файл {service_file} не найден[/yellow]")
        return
    
    with open(service_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    console.print("\n[bold]Проверка службы обхода:[/bold]")
    
    # Проверяем наличие исправлений
    has_ip_mapping = "strategy_map[ip]" in content or "ip_to_domain" in content
    has_correct_fakeddisorder = "desync_method" in content
    
    if has_ip_mapping and has_correct_fakeddisorder:
        console.print("[green]✓ Все исправления присутствуют[/green]")
    else:
        console.print("[yellow]⚠ Возможно нужны исправления из ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt[/yellow]")


def main():
    """Главная функция."""
    
    console.print(Panel.fit(
        "[bold cyan]🚀 Применение рабочей стратегии с роутера[/bold cyan]\n"
        "[dim]Стратегия: multidisorder с параметрами с роутера[/dim]",
        border_style="cyan",
        title="X.COM ROUTER STRATEGY"
    ))
    
    # Рабочая стратегия с роутера (адаптированная)
    strategies_to_test = [
        {
            "name": "Полная (с роутера)",
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
            "priority": 1
        },
        {
            "name": "С fake пакетами",
            "strategy": "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
            "priority": 2
        },
        {
            "name": "Упрощенная",
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2",
            "priority": 3
        },
        {
            "name": "С badsum",
            "strategy": "--dpi-desync=multidisorder --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fooling=badseq,badsum --dpi-desync-repeats=2",
            "priority": 4
        }
    ]
    
    # Показываем варианты
    console.print("\n[bold]Доступные стратегии:[/bold]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("№", width=3)
    table.add_column("Название", width=20)
    table.add_column("Стратегия", width=80)
    
    for i, s in enumerate(strategies_to_test, 1):
        table.add_row(str(i), s["name"], s["strategy"])
    
    console.print(table)
    
    # Используем первую (приоритетную) стратегию
    best_strategy = strategies_to_test[0]["strategy"]
    
    console.print(f"\n[bold green]Выбрана стратегия:[/bold green] {strategies_to_test[0]['name']}")
    console.print(f"[dim]{best_strategy}[/dim]")
    
    # Обновляем strategies.json
    if update_strategies_json(best_strategy):
        # Проверяем службу
        update_service_code()
        
        # Инструкции
        console.print("\n" + "="*70)
        console.print("[bold green]📋 Следующие шаги:[/bold green]")
        console.print("="*70)
        console.print("""
1. ПРОТЕСТИРУЙТЕ стратегию вручную:
   python cli.py x.com --strategy "multidisorder --split-pos=46 --split-seqovl=1 --autottl=2 --fooling=badseq --repeats=2"

2. ЕСЛИ РАБОТАЕТ - перезапустите службу:
   - Остановите текущую службу (Ctrl+C)
   - Запустите заново: python setup.py -> [2]

3. ЕСЛИ НЕ РАБОТАЕТ - попробуйте другие варианты:
   python cli.py x.com --strategy "fake,multidisorder --split-pos=46 --split-seqovl=1 --autottl=2 --fooling=badseq --repeats=2"
   
   или упрощенную:
   python cli.py x.com --strategy "multidisorder --split-pos=1 --autottl=2 --fooling=badseq --repeats=2"

4. ПРОВЕРЬТЕ лог службы на правильный маппинг:
   ✅ Должно быть: Mapped IP xxx.xxx.xxx.xxx (x.com) -> multidisorder
   ❌ Не должно быть: Mapped x.com -> fakeddisorder

5. ОТКРОЙТЕ x.com в браузере и проверьте работу
""")
        
        console.print("[bold cyan]💡 Совет:[/bold cyan] Если стратегия работает в CLI но не в службе,")
        console.print("   проверьте что служба запущена от имени Администратора\n")
        
        console.print("[bold green]✅ Готово! strategies.json обновлен.[/bold green]")
        console.print("[yellow]Теперь протестируйте стратегию и перезапустите службу.[/yellow]")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
