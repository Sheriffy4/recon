#!/usr/bin/env python3
"""
Тест службы с реальной стратегией Instagram для проверки исправления.
"""

import sys
import os
import json
import time
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def create_test_config():
    """Создает тестовую конфигурацию с Instagram стратегией."""
    
    # Создаем domain_strategies.json с Instagram стратегией
    test_strategies = {
        "domain_strategies": {
            "instagram.com": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
        }
    }
    
    with open("domain_strategies.json", "w", encoding="utf-8") as f:
        json.dump(test_strategies, f, indent=2)
    
    # Создаем sites.txt с Instagram
    with open("sites.txt", "w", encoding="utf-8") as f:
        f.write("instagram.com\n")
    
    print("✅ Создана тестовая конфигурация:")
    print(f"   domain_strategies.json: Instagram -> fake,disorder")
    print(f"   sites.txt: instagram.com")

def test_service_strategy_processing():
    """Тестирует обработку стратегий в службе."""
    print("\n🔍 Тестируем обработку стратегий в службе...")
    
    try:
        from recon_service import DPIBypassService
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        # Создаем службу
        service = DPIBypassService()
        
        # Загружаем стратегии
        if not service.load_strategies():
            print("❌ ОШИБКА: Не удалось загрузить стратегии")
            return False
        
        print("✅ Стратегии загружены")
        
        # Загружаем домены
        if not service.load_domains():
            print("❌ ОШИБКА: Не удалось загрузить домены")
            return False
        
        print("✅ Домены загружены")
        
        # Проверяем стратегию для Instagram
        instagram_strategy = service.get_strategy_for_domain("instagram.com")
        print(f"📝 Стратегия Instagram: {instagram_strategy}")
        
        if not instagram_strategy:
            print("❌ ОШИБКА: Стратегия для Instagram не найдена")
            return False
        
        # Тестируем парсинг через UnifiedStrategyLoader
        loader = UnifiedStrategyLoader(debug=True)
        normalized = loader.load_strategy(instagram_strategy)
        
        print(f"✅ Результат парсинга:")
        print(f"   Тип: {normalized.type}")
        print(f"   Параметры: {normalized.params}")
        
        # Проверяем, что fake,disorder -> fakeddisorder
        if normalized.type != 'fakeddisorder':
            print(f"❌ ОШИБКА: Ожидался fakeddisorder, получен {normalized.type}")
            return False
        
        # Создаем forced override
        forced_config = loader.create_forced_override(normalized)
        
        print(f"✅ Forced override создан:")
        print(f"   type: {forced_config.get('type')}")
        print(f"   no_fallbacks: {forced_config.get('no_fallbacks')}")
        print(f"   forced: {forced_config.get('forced')}")
        
        # Проверяем флаги
        if not forced_config.get('no_fallbacks') or not forced_config.get('forced'):
            print("❌ ОШИБКА: Неправильные флаги forced override")
            return False
        
        print("✅ УСПЕХ: Служба правильно обрабатывает fake,disorder -> fakeddisorder")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании службы: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_engine_initialization():
    """Тестирует инициализацию движка с исправленными стратегиями."""
    print("\n🔍 Тестируем инициализацию движка...")
    
    try:
        from recon_service import DPIBypassService
        
        # Создаем службу
        service = DPIBypassService()
        
        # Загружаем конфигурацию
        if not service.load_strategies() or not service.load_domains():
            print("❌ ОШИБКА: Не удалось загрузить конфигурацию")
            return False
        
        print("✅ Конфигурация загружена")
        
        # Проверяем, что служба готова к запуску движка
        print(f"   Доменов для мониторинга: {len(service.monitored_domains)}")
        print(f"   Стратегий загружено: {len(service.domain_strategies)}")
        
        # Проверяем конкретную стратегию Instagram
        instagram_strategy = service.get_strategy_for_domain("instagram.com")
        if instagram_strategy and "fake,disorder" in instagram_strategy:
            print("✅ Instagram стратегия содержит fake,disorder")
            
            # Проверяем, что UnifiedStrategyLoader правильно её парсит
            from core.unified_strategy_loader import UnifiedStrategyLoader
            loader = UnifiedStrategyLoader()
            normalized = loader.load_strategy(instagram_strategy)
            
            if normalized.type == 'fakeddisorder':
                print("✅ УСПЕХ: fake,disorder правильно парсится как fakeddisorder")
                print("   Служба готова к запуску с исправленным парсингом")
                return True
            else:
                print(f"❌ ОШИБКА: Неправильный тип атаки: {normalized.type}")
                return False
        else:
            print("❌ ОШИБКА: Instagram стратегия не найдена или неправильная")
            return False
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании инициализации: {e}")
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
                print(f"🗑️ Удален {file_name}")
        except Exception as e:
            print(f"⚠️ Не удалось удалить {file_name}: {e}")

def main():
    """Основная функция тестирования."""
    print("🧪 ТЕСТ СЛУЖБЫ С ИСПРАВЛЕННЫМ ПАРСИНГОМ СТРАТЕГИЙ")
    print("=" * 60)
    print("Проверяем, что fake,disorder теперь правильно работает в службе")
    print("=" * 60)
    
    try:
        # Создаем тестовую конфигурацию
        create_test_config()
        
        results = []
        
        # Тест 1: Обработка стратегий
        results.append(("Strategy Processing", test_service_strategy_processing()))
        
        # Тест 2: Инициализация движка
        results.append(("Engine Initialization", test_engine_initialization()))
        
        # Результаты
        print("\n" + "=" * 60)
        print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
        
        all_passed = True
        for test_name, result in results:
            status = "✅ ПРОШЕЛ" if result else "❌ ПРОВАЛЕН"
            print(f"   {test_name}: {status}")
            if not result:
                all_passed = False
        
        print("\n" + "=" * 60)
        if all_passed:
            print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
            print("   Служба теперь правильно обрабатывает fake,disorder -> fakeddisorder")
            print("   Instagram и другие домены будут использовать правильную атаку")
            print("\n💡 РЕКОМЕНДАЦИЯ:")
            print("   Теперь можно запустить службу и она будет выполнять")
            print("   атаку fakeddisorder вместо простой fake для Instagram")
        else:
            print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
            print("   Требуется дополнительная отладка")
        
        return all_passed
        
    finally:
        # Очищаем тестовые файлы
        cleanup()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)