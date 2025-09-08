#!/usr/bin/env python3
"""
Быстрый тест умной системы обхода блокировок.
Демонстрирует работу с заблокированными доменами через DoH.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine
from core.blocked_domain_detector import BlockedDomainDetector

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger("test_smart_bypass")


async def test_domain_detection():
    """Тест определения заблокированных доменов."""
    print("=== Тест определения заблокированных доменов ===")
    
    detector = BlockedDomainDetector()
    
    # Тестовые домены (включая заведомо заблокированные)
    test_domains = [
        'x.com',           # Заблокирован в России
        'instagram.com',   # Заблокирован в России  
        'google.com',      # Обычно доступен
        'github.com',      # Обычно доступен
        'youtube.com',     # Может быть заблокирован
        'facebook.com'     # Заблокирован в России
    ]
    
    print(f"Проверяем {len(test_domains)} доменов...")
    
    results = await detector.check_multiple_domains(test_domains)
    
    print(f"{'Домен':<20} {'Заблокирован':<12} {'Тип блокировки':<15} {'Обход нужен'}")
    print("-" * 65)
    
    for domain, status in results.items():
        blocked_str = "Да" if status.is_blocked else "Нет"
        bypass_str = "Да" if status.bypass_required else "Нет"
        
        print(f"{domain:<20} {blocked_str:<12} {status.block_type:<15} {bypass_str}")
        
        # Показываем IP адреса для заблокированных доменов
        if status.is_blocked or status.bypass_required:
            if status.system_ips:
                print(f"  Системный DNS: {list(status.system_ips)}")
            if status.doh_ips:
                print(f"  DoH адреса: {list(status.doh_ips)}")
            if status.hosts_ips:
                print(f"  Hosts файл: {list(status.hosts_ips)}")
    
    await detector.cleanup()
    return results


async def test_bypass_engine():
    """Тест движка обхода."""
    print("\n=== Тест движка обхода ===")
    
    config = {
        'doh_providers': ['cloudflare', 'google'],
        'cache_ttl': 300
    }
    
    engine = SmartBypassEngine(config)
    
    # Тестируем проблемные домены
    problem_domains = ['x.com', 'instagram.com', 'facebook.com']
    
    print(f"Тестируем подключения к {len(problem_domains)} доменам...")
    
    results = await engine.test_multiple_domains(problem_domains)
    
    print(f"{'Домен':<20} {'Статус':<8} {'Метод':<12} {'IP':<15} {'Задержка'}")
    print("-" * 70)
    
    for domain, result in results.items():
        status_icon = "✓" if result.success else "✗"
        ip_display = result.ip_used[:15] if len(result.ip_used) <= 15 else result.ip_used[:12] + "..."
        
        print(f"{domain:<20} {status_icon:<8} {result.method_used:<12} "
              f"{ip_display:<15} {result.latency_ms:.1f}ms")
        
        if not result.success and result.error:
            print(f"  └─ Ошибка: {result.error}")
    
    # Показываем статистику
    stats = engine.get_statistics()
    print(f"\nСтатистика:")
    print(f"  Успешных: {stats['successful_bypasses']}")
    print(f"  Неудачных: {stats['failed_bypasses']}")
    print(f"  Процент успеха: {stats['success_rate_percent']:.1f}%")
    
    if stats['methods_used']:
        print(f"  Методы: {stats['methods_used']}")
    
    await engine.cleanup()
    return results


async def test_doh_resolver():
    """Тест DoH resolver отдельно."""
    print("\n=== Тест DoH Resolver ===")
    
    from core.doh_resolver import DoHResolver
    
    resolver = DoHResolver(['cloudflare', 'google'])
    
    test_domains = ['x.com', 'instagram.com', 'google.com']
    
    for domain in test_domains:
        print(f"\nРазрешение {domain} через DoH...")
        
        # Получаем все IP
        all_ips = await resolver.resolve_all(domain)
        print(f"  Все IP: {list(all_ips) if all_ips else 'Не найдено'}")
        
        # Получаем один IP
        single_ip = await resolver.resolve(domain)
        print(f"  Выбранный IP: {single_ip if single_ip else 'Не найдено'}")
    
    await resolver._cleanup()


async def test_optimal_ip_selection():
    """Тест выбора оптимального IP."""
    print("\n=== Тест выбора оптимального IP ===")
    
    engine = SmartBypassEngine()
    
    test_domains = ['x.com', 'instagram.com', 'google.com']
    
    for domain in test_domains:
        print(f"\nАнализ {domain}:")
        
        # Анализируем домен
        status = await engine.analyze_domain(domain)
        print(f"  Статус: заблокирован={status.is_blocked}, тип={status.block_type}")
        
        # Получаем оптимальный IP
        ip, method = await engine.get_optimal_ip(domain)
        print(f"  Оптимальный IP: {ip} (метод: {method})")
        
        # Ищем лучшую стратегию
        best_strategy = await engine.find_best_strategy_for_domain(domain)
        print(f"  Лучшая стратегия: {best_strategy}")
    
    await engine.cleanup()


async def generate_hosts_recommendations():
    """Генерирует рекомендации для файла hosts."""
    print("\n=== Рекомендации для файла hosts ===")
    
    detector = BlockedDomainDetector()
    
    blocked_domains = ['x.com', 'instagram.com', 'facebook.com', 'youtube.com']
    
    print("Рекомендуемые записи для файла hosts:")
    print("(C:\\Windows\\System32\\drivers\\etc\\hosts)\n")
    
    for domain in blocked_domains:
        status = await detector.check_domain(domain)
        
        if status.doh_ips:
            # Берем первый DoH IP
            ip = list(status.doh_ips)[0]
            print(f"{ip:<15} {domain}")
            
            # Добавляем www версию
            print(f"{ip:<15} www.{domain}")
    
    print(f"\nПосле добавления записей перезапустите браузер или выполните:")
    print("ipconfig /flushdns")
    
    await detector.cleanup()


async def main():
    """Главная функция тестирования."""
    print("Запуск тестов умной системы обхода блокировок...\n")
    
    try:
        # Тест 1: Определение заблокированных доменов
        await test_domain_detection()
        
        # Тест 2: DoH resolver
        await test_doh_resolver()
        
        # Тест 3: Выбор оптимального IP
        await test_optimal_ip_selection()
        
        # Тест 4: Движок обхода
        await test_bypass_engine()
        
        # Тест 5: Рекомендации для hosts
        await generate_hosts_recommendations()
        
        print("\n=== Все тесты завершены ===")
        print("Система готова к использованию!")
        
        print(f"\nДля использования CLI:")
        print(f"python smart_bypass_cli.py check x.com")
        print(f"python smart_bypass_cli.py test-multiple x.com instagram.com")
        print(f"python smart_bypass_cli.py report --output bypass_report.json")
        
    except Exception as e:
        LOG.error(f"Ошибка во время тестирования: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())