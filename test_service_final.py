#!/usr/bin/env python3
"""
Финальный тест службы с исправленным парсингом.
"""

import sys
import os
import json
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def create_test_config():
    """Создает тестовую конфигурацию с проблемными стратегиями."""
    
    # Стратегии из реального лога, которые вызывали проблемы
    strategies = {
        "domain_strategies": {
            "external.xx.fbcdn.net": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
            "instagram.com": "--dpi-desync=fake,disorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=76 --dpi-desync-autottl=1",
            "facebook.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "youtube.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3"
        }
    }
    
    with open("domain_strategies.json", "w", encoding="utf-8") as f:
        json.dump(strategies, f, indent=2)
    
    # Создаем sites.txt
    domains = list(strategies["domain_strategies"].keys())
    with open("sites.txt", "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(f"{domain}\n")
    
    print(f"✅ Создана конфигурация с {len(domains)} проблемными стратегиями")
    return domains

def test_service_strategy_loading():
    """Тестирует загрузку стратегий в службе."""
    print("\n🔍 Тестируем загрузку стратегий в службе...")
    
    try:
        from recon_service import DPIBypassService
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        service = DPIBypassService()
        
        # Загружаем стратегии
        if not service.load_strategies():
            print("❌ ОШИБКА: Не удалось загрузить стратегии")
            return False
        
        if not service.load_domains():
            print("❌ ОШИБКА: Не удалось загрузить домены")
            return False
        
        print(f"✅ Загружено {len(service.domain_strategies)} стратегий")
        print(f"✅ Загружено {len(service.monitored_domains)} доменов")
        
        # Тестируем каждую проблемную стратегию
        loader = UnifiedStrategyLoader()
        
        test_cases = [
            ("external.xx.fbcdn.net", "fakeddisorder"),
            ("instagram.com", "fakeddisorder"),
            ("facebook.com", "fakeddisorder"),
            ("x.com", "fakeddisorder"),
            ("youtube.com", "fakeddisorder"),
        ]
        
        all_correct = True
        
        for domain, expected_type in test_cases:
            strategy_str = service.get_strategy_for_domain(domain)
            if strategy_str:
                try:
                    normalized = loader.load_strategy(strategy_str)
                    
                    if normalized.type == expected_type:
                        print(f"✅ {domain}: {strategy_str[:50]}... → {normalized.type}")
                    else:
                        print(f"❌ {domain}: {strategy_str[:50]}... → {normalized.type} (ожидался {expected_type})")
                        all_correct = False
                        
                except Exception as e:
                    print(f"❌ {domain}: Ошибка парсинга - {e}")
                    all_correct = False
            else:
                print(f"❌ {domain}: Стратегия не найдена")
                all_correct = False
        
        return all_correct
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании службы: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_service_initialization():
    """Тестирует инициализацию службы без запуска движка."""
    print("\n🔍 Тестируем инициализацию службы...")
    
    try:
        from recon_service import DPIBypassService
        
        service = DPIBypassService()
        
        # Загружаем конфигурацию
        if not service.load_strategies() or not service.load_domains():
            print("❌ ОШИБКА: Не удалось загрузить конфигурацию")
            return False
        
        print("✅ Конфигурация загружена успешно")
        
        # Проверяем, что все стратегии содержат fake,disorder
        fake_disorder_count = 0
        for domain, strategy in service.domain_strategies.items():
            if 'fake' in strategy and ('disorder' in strategy or 'disorder2' in strategy):
                fake_disorder_count += 1
        
        print(f"✅ Найдено {fake_disorder_count} стратегий с fake+disorder")
        
        # Проверяем, что служба готова к работе
        if len(service.monitored_domains) > 0 and len(service.domain_strategies) > 0:
            print("✅ Служба готова к запуску")
            return True
        else:
            print("❌ Служба не готова к запуску")
            return False
        
    except Exception as e:
        print(f"❌ Ошибка при инициализации службы: {e}")
        import traceback
        traceback.print_exc()
        return False

def cleanup():
    """Очищает тестовые файлы."""
    files_to_remove = ["domain_strategies.json", "sites.txt"]
    
    for file_name in files_to_remove:
        try:
            if os.path.exists(file_name):
                os.remove(file_name)
        except:
            pass

def main():
    """Основная функция тестирования."""
    print("🧪 ФИНАЛЬНЫЙ ТЕСТ СЛУЖБЫ С ИСПРАВЛЕННЫМ ПАРСИНГОМ")
    print("=" * 60)
    print("Проверяем, что служба теперь правильно обрабатывает fake,disorder")
    print("=" * 60)
    
    try:
        # Создаем тестовую конфигурацию
        domains = create_test_config()
        
        results = []
        
        # Тест 1: Загрузка стратегий
        results.append(("Strategy Loading", test_service_strategy_loading()))
        
        # Тест 2: Инициализация службы
        results.append(("Service Initialization", test_service_initialization()))
        
        # Результаты
        print("\n" + "=" * 60)
        print("📊 ФИНАЛЬНЫЕ РЕЗУЛЬТАТЫ:")
        
        all_passed = True
        for test_name, result in results:
            status = "✅ ПРОШЕЛ" if result else "❌ ПРОВАЛЕН"
            print(f"   {test_name}: {status}")
            if not result:
                all_passed = False
        
        print("\n" + "=" * 60)
        if all_passed:
            print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
            print("\n✅ ИСПРАВЛЕНИЕ ПОЛНОСТЬЮ РАБОТАЕТ:")
            print("   • fake,disorder → fakeddisorder ✅")
            print("   • fake,disorder2 → fakeddisorder ✅")
            print("   • Служба правильно загружает стратегии ✅")
            print("   • Все проблемные домены исправлены ✅")
            print("\n🚀 СЛУЖБА ГОТОВА К ЗАПУСКУ!")
            print("   Теперь Instagram, Facebook, X.com и другие сайты")
            print("   будут использовать правильную атаку fakeddisorder")
            print("   вместо простой fake")
            print("\n💡 РЕКОМЕНДАЦИЯ:")
            print("   Запустите службу командой:")
            print("   python recon_service.py")
        else:
            print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
            print("   Требуется дополнительная отладка")
        
        return all_passed
        
    finally:
        cleanup()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)