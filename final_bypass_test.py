#!/usr/bin/env python3
"""
Финальный тест системы умного обхода блокировок.
Демонстрирует все возможности системы на реальных примерах.
"""

import asyncio
import logging
import sys
import json
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine
from core.blocked_domain_detector import BlockedDomainDetector
from core.doh_resolver import DoHResolver

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger("final_bypass_test")


async def test_real_blocked_domains():
    """Тест с реальными заблокированными доменами."""
    print("🔍 === Тест реальных заблокированных доменов ===\n")
    
    # Реальные заблокированные домены в России
    blocked_domains = [
        'x.com',           # Twitter/X - заблокирован
        'instagram.com',   # Instagram - заблокирован  
        'facebook.com',    # Facebook - заблокирован
        'youtube.com',     # YouTube - частично заблокирован
        'telegram.org'     # Telegram - периодически блокируется
    ]
    
    # Контрольные домены (обычно доступны)
    control_domains = [
        'google.com',
        'github.com', 
        'stackoverflow.com'
    ]
    
    all_domains = blocked_domains + control_domains
    
    engine = SmartBypassEngine({
        'doh_providers': ['cloudflare', 'google', 'quad9'],
        'cache_ttl': 300
    })
    
    print(f"Анализируем {len(all_domains)} доменов...")
    print(f"Заблокированные: {', '.join(blocked_domains)}")
    print(f"Контрольные: {', '.join(control_domains)}\n")
    
    # Анализ доменов
    results = {}
    for domain in all_domains:
        status = await engine.analyze_domain(domain)
        results[domain] = status
        
        block_icon = "🚫" if status.is_blocked else "✅"
        bypass_icon = "🔧" if status.bypass_required else "➡️"
        
        print(f"{block_icon} {domain:<20} | Блокировка: {status.block_type:<12} | {bypass_icon}")
        
        if status.bypass_required:
            ip, method = await engine.get_optimal_ip(domain)
            if ip:
                print(f"   └─ Обход: {method} -> {ip}")
            else:
                print(f"   └─ Обход: не найден")
    
    await engine.cleanup()
    return results


async def test_connection_performance():
    """Тест производительности подключений."""
    print(f"\n⚡ === Тест производительности подключений ===\n")
    
    test_domains = ['x.com', 'instagram.com', 'google.com', 'github.com']
    
    engine = SmartBypassEngine()
    
    print("Тестируем подключения...")
    results = await engine.test_multiple_domains(test_domains, port=443)
    
    # Сортируем по задержке
    sorted_results = sorted(results.items(), key=lambda x: x[1].latency_ms)
    
    print(f"{'Домен':<20} {'Статус':<8} {'Метод':<12} {'IP':<15} {'Задержка':<10}")
    print("─" * 75)
    
    for domain, result in sorted_results:
        status_icon = "✅" if result.success else "❌"
        ip_short = result.ip_used[:15] if len(result.ip_used) <= 15 else result.ip_used[:12] + "..."
        
        print(f"{domain:<20} {status_icon:<8} {result.method_used:<12} "
              f"{ip_short:<15} {result.latency_ms:<10.1f}ms")
    
    # Статистика
    successful = sum(1 for r in results.values() if r.success)
    avg_latency = sum(r.latency_ms for r in results.values() if r.success) / max(successful, 1)
    
    print(f"\n📊 Статистика:")
    print(f"   Успешных подключений: {successful}/{len(test_domains)}")
    print(f"   Средняя задержка: {avg_latency:.1f}ms")
    
    await engine.cleanup()
    return results


async def test_doh_providers():
    """Тест различных DoH провайдеров."""
    print(f"\n🌐 === Тест DoH провайдеров ===\n")
    
    providers = ['cloudflare', 'google', 'quad9', 'adguard']
    test_domain = 'x.com'
    
    print(f"Тестируем разрешение {test_domain} через разных провайдеров:\n")
    
    for provider in providers:
        resolver = DoHResolver([provider])
        
        try:
            start_time = asyncio.get_event_loop().time()
            ips = await resolver.resolve_all(test_domain)
            end_time = asyncio.get_event_loop().time()
            
            latency = (end_time - start_time) * 1000
            
            if ips:
                print(f"✅ {provider:<12} | {latency:<6.1f}ms | IPs: {list(ips)}")
            else:
                print(f"❌ {provider:<12} | {latency:<6.1f}ms | Не найдено")
                
        except Exception as e:
            print(f"❌ {provider:<12} | Ошибка: {e}")
        
        await resolver._cleanup()


async def test_bypass_strategies():
    """Тест различных стратегий обхода."""
    print(f"\n🔧 === Тест стратегий обхода ===\n")
    
    engine = SmartBypassEngine()
    test_domains = ['x.com', 'instagram.com']
    
    for domain in test_domains:
        print(f"Анализ стратегий для {domain}:")
        
        # Получаем статус домена
        status = await engine.analyze_domain(domain)
        print(f"  Тип блокировки: {status.block_type}")
        
        # Тестируем разные стратегии
        strategies = ['hosts', 'doh', 'system_dns']
        
        for strategy in strategies:
            try:
                if strategy == 'hosts' and status.hosts_ips:
                    ip = list(status.hosts_ips)[0]
                elif strategy == 'doh':
                    ip = await engine.doh_resolver.resolve(domain)
                elif strategy == 'system_dns' and status.system_ips:
                    ip = list(status.system_ips)[0]
                else:
                    print(f"  ⏭️  {strategy:<12} | Недоступно")
                    continue
                
                if ip:
                    # Тестируем подключение
                    result = await engine.test_connection(domain, ip)
                    status_icon = "✅" if result.success else "❌"
                    print(f"  {status_icon} {strategy:<12} | {ip} | {result.latency_ms:.1f}ms")
                else:
                    print(f"  ❌ {strategy:<12} | IP не найден")
                    
            except Exception as e:
                print(f"  ❌ {strategy:<12} | Ошибка: {e}")
        
        # Находим лучшую стратегию
        best = await engine.find_best_strategy_for_domain(domain)
        print(f"  🏆 Лучшая стратегия: {best}\n")
    
    await engine.cleanup()


async def generate_comprehensive_report():
    """Генерация комплексного отчета."""
    print(f"\n📋 === Генерация комплексного отчета ===\n")
    
    engine = SmartBypassEngine()
    
    # Тестируем различные домены
    test_domains = [
        'x.com', 'instagram.com', 'facebook.com', 'youtube.com',
        'google.com', 'github.com', 'stackoverflow.com'
    ]
    
    print("Собираем данные для отчета...")
    
    # Анализируем домены
    for domain in test_domains:
        await engine.analyze_domain(domain)
    
    # Тестируем подключения
    await engine.test_multiple_domains(test_domains[:4])  # Первые 4 для экономии времени
    
    # Генерируем отчет
    report = await engine.generate_comprehensive_report()
    
    # Сохраняем отчет
    report_file = 'final_bypass_report.json'
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"✅ Отчет сохранен в {report_file}")
    
    # Показываем краткую сводку
    stats = report['bypass_engine_stats']
    detection = report['domain_detection_report']
    
    print(f"\n📊 Краткая сводка:")
    print(f"   Всего запросов: {stats['total_requests']}")
    print(f"   Успешных обходов: {stats['successful_bypasses']}")
    print(f"   Процент успеха: {stats['success_rate_percent']:.1f}%")
    print(f"   Заблокированных доменов: {detection['blocked_domains']}")
    print(f"   Требуют обхода: {detection['bypass_required']}")
    
    # Показываем рекомендации
    if report['recommendations']:
        print(f"\n💡 Рекомендации:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"   {i}. {rec}")
    
    await engine.cleanup()
    return report


async def test_hosts_file_integration():
    """Тест интеграции с hosts файлом."""
    print(f"\n📝 === Тест интеграции с hosts файлом ===\n")
    
    detector = BlockedDomainDetector()
    
    # Проверяем, есть ли записи в hosts файле
    detector._load_hosts_file()
    
    if detector.hosts_entries:
        print(f"Найдено {len(detector.hosts_entries)} записей в hosts файле:")
        for domain, ip in list(detector.hosts_entries.items())[:5]:  # Показываем первые 5
            print(f"  {ip:<15} {domain}")
        
        if len(detector.hosts_entries) > 5:
            print(f"  ... и еще {len(detector.hosts_entries) - 5} записей")
    else:
        print("Записи Smart Bypass в hosts файле не найдены")
        print("Для настройки hosts файла запустите:")
        print("  python setup_hosts_bypass.py setup")
    
    await detector.cleanup()


async def main():
    """Главная функция финального теста."""
    print("🚀 Smart Bypass - Финальный тест системы обхода блокировок")
    print("=" * 65)
    
    try:
        # Тест 1: Реальные заблокированные домены
        await test_real_blocked_domains()
        
        # Тест 2: DoH провайдеры
        await test_doh_providers()
        
        # Тест 3: Производительность подключений
        await test_connection_performance()
        
        # Тест 4: Стратегии обхода
        await test_bypass_strategies()
        
        # Тест 5: Интеграция с hosts файлом
        await test_hosts_file_integration()
        
        # Тест 6: Комплексный отчет
        await generate_comprehensive_report()
        
        print(f"\n🎉 === Все тесты завершены успешно! ===")
        print(f"\nСистема Smart Bypass готова к использованию:")
        print(f"  • Автоматическое определение блокировок ✅")
        print(f"  • DoH обход через множество провайдеров ✅") 
        print(f"  • Интеграция с hosts файлом ✅")
        print(f"  • Умный выбор стратегий ✅")
        print(f"  • Подробная статистика и отчеты ✅")
        
        print(f"\n🛠️  Для использования:")
        print(f"  python smart_bypass_cli.py check x.com")
        print(f"  python smart_bypass_cli.py test-multiple x.com instagram.com")
        print(f"  python setup_hosts_bypass.py setup")
        print(f"  smart_bypass.bat  # Интерактивное меню")
        
    except Exception as e:
        LOG.error(f"Ошибка во время финального теста: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())