#!/usr/bin/env python3
"""
Тест конкретной проблемной стратегии из лога.
"""

import sys
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

def test_problematic_strategy():
    """Тестирует конкретную проблемную стратегию."""
    print("🔍 Тестируем проблемную стратегию из лога...")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=True)
        
        # Проблемная стратегия из лога
        problematic_strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq"
        
        print(f"📝 Проблемная стратегия: {problematic_strategy}")
        
        # Парсим стратегию
        normalized = loader.load_strategy(problematic_strategy)
        
        print(f"✅ Результат парсинга:")
        print(f"   Тип: {normalized.type}")
        print(f"   Параметры: {normalized.params}")
        
        # Проверяем результат
        if normalized.type == 'fakeddisorder':
            print("✅ УСПЕХ: fake,fakeddisorder правильно парсится как fakeddisorder")
            return True
        else:
            print(f"❌ ОШИБКА: fake,fakeddisorder парсится как {normalized.type}, ожидался fakeddisorder")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка при тестировании: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_various_fake_combinations():
    """Тестирует различные комбинации fake с другими методами."""
    print("\n🔍 Тестируем различные комбинации fake...")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=False)
        
        test_cases = [
            # fake + disorder variants -> fakeddisorder
            ("--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
            ("--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
            ("--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
            ("--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
            
            # fake + non-disorder -> fake
            ("--dpi-desync=fake,split --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fake"),
            ("--dpi-desync=fake,seqovl --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-split-seqovl=20", "fake"),
            
            # Порядок не важен
            ("--dpi-desync=disorder,fake --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
            ("--dpi-desync=disorder2,fake --dpi-desync-split-pos=3 --dpi-desync-ttl=3", "fakeddisorder"),
        ]
        
        all_passed = True
        
        for strategy_str, expected_type in test_cases:
            try:
                normalized = loader.load_strategy(strategy_str)
                
                if normalized.type == expected_type:
                    print(f"✅ {strategy_str[:50]}... → {normalized.type}")
                else:
                    print(f"❌ {strategy_str[:50]}... → {normalized.type} (ожидался {expected_type})")
                    all_passed = False
                    
            except Exception as e:
                print(f"❌ Ошибка парсинга {strategy_str[:50]}...: {e}")
                all_passed = False
        
        return all_passed
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании комбинаций: {e}")
        return False

def debug_parsing_logic():
    """Отладка логики парсинга."""
    print("\n🔍 Отладка логики парсинга...")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        import re
        
        # Тестируем regex напрямую
        strategy_string = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3"
        
        print(f"📝 Тестовая строка: {strategy_string}")
        
        desync_match = re.search(r'--dpi-desync=([^\s]+)', strategy_string)
        if desync_match:
            desync_methods = [m.strip() for m in desync_match.group(1).split(',')]
            print(f"🔍 Найденные методы: {desync_methods}")
            
            # Проверяем логику
            if 'fake' in desync_methods:
                print("✅ fake найден")
                
                disorder_variants = ['disorder', 'disorder2', 'multidisorder']
                has_disorder = any(variant in desync_methods for variant in disorder_variants)
                
                print(f"🔍 Проверка disorder вариантов: {disorder_variants}")
                print(f"🔍 has_disorder: {has_disorder}")
                
                if has_disorder:
                    print("✅ Должен быть fakeddisorder")
                    attack_type = 'fakeddisorder'
                else:
                    print("⚠️ Должен быть fake")
                    attack_type = 'fake'
            else:
                print("❌ fake не найден")
                attack_type = "unknown"
            
            print(f"🎯 Определенный тип: {attack_type}")
            
            # Сравниваем с реальным парсером
            loader = UnifiedStrategyLoader(debug=False)
            normalized = loader.load_strategy(strategy_string)
            
            print(f"🎯 Реальный результат: {normalized.type}")
            
            if attack_type == normalized.type:
                print("✅ Логика работает правильно")
                return True
            else:
                print("❌ Логика работает неправильно")
                return False
        else:
            print("❌ Regex не сработал")
            return False
            
    except Exception as e:
        print(f"❌ Ошибка при отладке: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Основная функция тестирования."""
    print("🧪 ТЕСТ КОНКРЕТНОЙ ПРОБЛЕМНОЙ СТРАТЕГИИ")
    print("=" * 60)
    
    results = []
    
    # Тест 1: Проблемная стратегия
    results.append(("Problematic Strategy", test_problematic_strategy()))
    
    # Тест 2: Различные комбинации
    results.append(("Various Combinations", test_various_fake_combinations()))
    
    # Тест 3: Отладка логики
    results.append(("Debug Logic", debug_parsing_logic()))
    
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
        print("   Логика парсинга работает правильно")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
        print("   Требуется дополнительная отладка")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)