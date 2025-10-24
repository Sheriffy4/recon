#!/usr/bin/env python3
"""
Тест исправления парсинга стратегий в службе.
Проверяет, что fake,disorder правильно интерпретируется как fakeddisorder.
"""

import sys
import os
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def test_unified_strategy_loader():
    """Тест UnifiedStrategyLoader для парсинга fake,disorder."""
    print("🔍 Тестируем UnifiedStrategyLoader...")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=True)
        
        # Тестируем проблемную стратегию из лога
        strategy_str = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
        
        print(f"📝 Исходная стратегия: {strategy_str}")
        
        # Парсим стратегию
        normalized = loader.load_strategy(strategy_str)
        
        print(f"✅ Результат парсинга:")
        print(f"   Тип: {normalized.type}")
        print(f"   Параметры: {normalized.params}")
        print(f"   no_fallbacks: {normalized.no_fallbacks}")
        print(f"   forced: {normalized.forced}")
        
        # Проверяем, что fake,disorder -> fakeddisorder
        if normalized.type == 'fakeddisorder':
            print("✅ УСПЕХ: fake,disorder правильно интерпретирован как fakeddisorder")
            return True
        else:
            print(f"❌ ОШИБКА: fake,disorder интерпретирован как {normalized.type}, ожидался fakeddisorder")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка при тестировании UnifiedStrategyLoader: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_service_strategy_loading():
    """Тест загрузки стратегий в службе."""
    print("\n🔍 Тестируем загрузку стратегий в службе...")
    
    try:
        from recon_service import DPIBypassService
        
        # Создаем временный файл стратегий
        test_strategies = {
            "domain_strategies": {
                "instagram.com": "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
            }
        }
        
        import json
        with open("test_domain_strategies.json", "w", encoding="utf-8") as f:
            json.dump(test_strategies, f, indent=2)
        
        # Создаем службу
        service = DPIBypassService()
        
        # Загружаем стратегии
        if service.load_strategies():
            print("✅ Стратегии загружены успешно")
            
            # Проверяем стратегию для instagram.com
            strategy = service.get_strategy_for_domain("instagram.com")
            print(f"📝 Стратегия для instagram.com: {strategy}")
            
            if strategy and "fake,disorder" in strategy:
                print("✅ УСПЕХ: Стратегия содержит fake,disorder")
                return True
            else:
                print("❌ ОШИБКА: Стратегия не найдена или не содержит fake,disorder")
                return False
        else:
            print("❌ ОШИБКА: Не удалось загрузить стратегии")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка при тестировании службы: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Удаляем временный файл
        try:
            os.remove("test_domain_strategies.json")
        except:
            pass

def test_instagram_strategy_specifically():
    """Тест конкретной стратегии для Instagram из лога."""
    print("\n🔍 Тестируем конкретную стратегию Instagram...")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=True)
        
        # Стратегия из лога для instagram.com
        instagram_strategy = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
        
        print(f"📝 Instagram стратегия: {instagram_strategy}")
        
        # Парсим
        normalized = loader.load_strategy(instagram_strategy)
        
        print(f"✅ Результат:")
        print(f"   Тип: {normalized.type}")
        print(f"   split_pos: {normalized.params.get('split_pos')}")
        print(f"   fooling: {normalized.params.get('fooling')}")
        print(f"   ttl: {normalized.params.get('ttl')}")
        
        # Создаем forced override
        forced_config = loader.create_forced_override(normalized)
        
        print(f"✅ Forced override:")
        print(f"   type: {forced_config.get('type')}")
        print(f"   no_fallbacks: {forced_config.get('no_fallbacks')}")
        print(f"   forced: {forced_config.get('forced')}")
        
        # Проверяем корректность
        success = True
        if normalized.type != 'fakeddisorder':
            print(f"❌ ОШИБКА: Ожидался тип fakeddisorder, получен {normalized.type}")
            success = False
        
        if not forced_config.get('no_fallbacks'):
            print("❌ ОШИБКА: no_fallbacks должен быть True")
            success = False
            
        if not forced_config.get('forced'):
            print("❌ ОШИБКА: forced должен быть True")
            success = False
        
        if success:
            print("✅ УСПЕХ: Instagram стратегия корректно обработана")
        
        return success
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании Instagram стратегии: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Основная функция тестирования."""
    print("🧪 Тестирование исправления парсинга стратегий")
    print("=" * 60)
    
    results = []
    
    # Тест 1: UnifiedStrategyLoader
    results.append(("UnifiedStrategyLoader", test_unified_strategy_loader()))
    
    # Тест 2: Служба
    results.append(("Service Strategy Loading", test_service_strategy_loading()))
    
    # Тест 3: Instagram стратегия
    results.append(("Instagram Strategy", test_instagram_strategy_specifically()))
    
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
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! Исправление работает корректно.")
        print("   fake,disorder теперь правильно интерпретируется как fakeddisorder")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ! Требуется дополнительная отладка.")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)