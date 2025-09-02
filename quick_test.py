#!/usr/bin/env python3
"""
Быстрый тест всей системы обхода блокировок
"""

import asyncio
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.append(str(Path(__file__).parent))

from core.smart_bypass_engine import SmartBypassEngine

async def quick_system_test():
    """Быстрый тест всех компонентов системы."""
    
    print("🚀 Быстрый тест системы обхода блокировок")
    print("=" * 50)
    
    # Конфигурация по умолчанию
    config = {
        'doh_providers': ['cloudflare', 'google', 'quad9'],
        'cache_ttl': 300,
        'doh_cache_ttl': 600,
        'hosts_file_path': None
    }
    
    # Тестируемые домены
    test_domains = ['x.com', 'instagram.com', 'rutracker.org', 'nnmclub.to']
    
    try:
        # Инициализация движка
        print("🔧 Инициализация Smart Bypass Engine...")
        engine = SmartBypassEngine(config)
        
        # Тестирование доменов
        print(f"🌐 Тестирование {len(test_domains)} доменов...")
        results = await engine.test_multiple_domains(test_domains)
        
        # Вывод результатов
        print("\n📊 Результаты тестирования:")
        print("-" * 60)
        
        success_count = 0
        for domain, result in results.items():
            status_icon = "✅" if result.success else "❌"
            print(f"{status_icon} {domain:<20} | {result.ip_used:<15} | {result.latency_ms:.1f}ms")
            if result.success:
                success_count += 1
        
        # Итоговая статистика
        print("-" * 60)
        success_rate = (success_count / len(test_domains)) * 100
        print(f"📈 Успешно: {success_count}/{len(test_domains)} ({success_rate:.1f}%)")
        
        if success_rate >= 75:
            print("🎉 Система работает отлично!")
        elif success_rate >= 50:
            print("⚠️  Система работает частично. Требуется настройка.")
        else:
            print("❌ Система требует исправления.")
        
        # Очистка ресурсов
        await engine.cleanup()
        
        return success_rate >= 75
        
    except Exception as e:
        print(f"❌ Ошибка тестирования: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(quick_system_test())
    sys.exit(0 if success else 1)