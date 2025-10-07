#!/usr/bin/env python3
"""
Исправление службы обхода для x.com.
Использует рабочую стратегию с роутера: multidisorder с split_pos=1, ttl=1
"""

import json
import os
from rich.console import Console
from rich.panel import Panel

console = Console()


def update_strategies_json():
    """Обновляет strategies.json с рабочей стратегией для x.com."""
    
    strategies_file = "strategies.json"
    
    if not os.path.exists(strategies_file):
        console.print(f"[red]Файл {strategies_file} не найден![/red]")
        return False
    
    # Читаем текущие стратегии
    with open(strategies_file, 'r', encoding='utf-8') as f:
        strategies = json.load(f)
    
    # Рабочая стратегия с роутера (ПРАВИЛЬНЫЙ ФОРМАТ с --dpi-desync=)
    working_strategy = "--dpi-desync=multidisorder --dpi-desync-split-pos=1 --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq"
    
    console.print(Panel.fit(
        "[bold cyan]🔧 Обновление стратегии для x.com[/bold cyan]\n"
        f"[dim]Старая стратегия:[/dim]\n{strategies.get('x.com', 'не найдена')}\n\n"
        f"[dim]Новая стратегия (с роутера):[/dim]\n[green]{working_strategy}[/green]",
        border_style="cyan"
    ))
    
    # Обновляем стратегии для всех доменов x.com/twitter.com
    x_com_domains = [
        "x.com",
        "www.x.com",
        "api.x.com",
        "mobile.x.com",
        "twitter.com",
        "www.twitter.com",
        "mobile.twitter.com"
    ]
    
    for domain in x_com_domains:
        old_strategy = strategies.get(domain, "не было")
        strategies[domain] = working_strategy
        console.print(f"[cyan]✓[/cyan] Обновлен {domain}")
    
    # Сохраняем обновленные стратегии
    with open(strategies_file, 'w', encoding='utf-8') as f:
        json.dump(strategies, f, indent=2, ensure_ascii=False)
    
    console.print(f"\n[green]✅ Файл {strategies_file} успешно обновлен![/green]")
    return True


def check_service_code():
    """Проверяет код службы обхода на наличие исправлений."""
    
    service_file = "recon_service.py"
    
    if not os.path.exists(service_file):
        console.print(f"[yellow]⚠ Файл {service_file} не найден[/yellow]")
        return
    
    with open(service_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    console.print("\n" + "="*70)
    console.print("[bold]🔍 Проверка кода службы обхода:[/bold]")
    console.print("="*70)
    
    # Проверяем наличие исправлений из ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt
    checks = [
        ("IP маппинг", "strategy_map[ip]" in content or "ip_to_domain" in content),
        ("Правильный fakeddisorder", "desync_method" in content and "fakeddisorder" in content),
        ("Маппинг по IP", "for ip, domain in" in content or "ip_to_domain.items()" in content),
    ]
    
    all_ok = True
    for check_name, check_result in checks:
        status = "[green]✓ OK[/green]" if check_result else "[red]✗ НЕ НАЙДЕНО[/red]"
        console.print(f"{status} - {check_name}")
        if not check_result:
            all_ok = False
    
    if all_ok:
        console.print("\n[green]✅ Все исправления присутствуют в коде![/green]")
    else:
        console.print("\n[yellow]⚠ Некоторые исправления могут отсутствовать[/yellow]")
        console.print("[dim]Проверьте файл ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt[/dim]")


def print_instructions():
    """Выводит инструкции по перезапуску службы."""
    
    console.print("\n" + "="*70)
    console.print("[bold green]📋 Следующие шаги:[/bold green]")
    console.print("="*70)
    console.print("""
1. ОСТАНОВИТЕ текущую службу обхода:
   - Нажмите Ctrl+C в окне службы
   - Дождитесь "Service stopped gracefully"

2. ПЕРЕЗАПУСТИТЕ службу:
   - Откройте командную строку от имени Администратора
   - cd recon
   - python setup.py
   - Выберите [2] Запустить службу обхода

3. ПРОВЕРЬТЕ в логе правильный маппинг:
   
   ✅ ДОЛЖНО БЫТЬ:
   Mapped IP xxx.xxx.xxx.xxx (x.com) -> multidisorder
   
   ❌ НЕ ДОЛЖНО БЫТЬ:
   Mapped x.com -> fakeddisorder
   Applying bypass for xxx.xxx.xxx.xxx -> Type: badsum_race

4. ПОПРОБУЙТЕ открыть x.com в браузере

5. ЕСЛИ НЕ РАБОТАЕТ:
   - Проверьте что служба запущена от имени Администратора
   - Проверьте лог на наличие ошибок
   - Попробуйте перезагрузить компьютер
   - Запустите тест: python test_x_com_comprehensive.py
""")


def main():
    """Главная функция."""
    
    console.print(Panel.fit(
        "[bold cyan]🚀 Исправление службы обхода для x.com[/bold cyan]\n"
        "[dim]Применяем рабочую стратегию с роутера: multidisorder[/dim]",
        border_style="cyan",
        title="X.COM FIX"
    ))
    
    # Обновляем strategies.json
    if update_strategies_json():
        # Проверяем код службы
        check_service_code()
        
        # Выводим инструкции
        print_instructions()
        
        console.print("\n[bold green]✅ Готово! Теперь перезапустите службу обхода.[/bold green]")
    else:
        console.print("\n[red]✗ Ошибка при обновлении strategies.json[/red]")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        console.print(f"\n[red]Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
