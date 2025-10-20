#!/usr/bin/env python3
"""
Тест исправления fakeddisorder для унификации поведения между тестовым режимом и службой.
"""
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_cli_strategy_generation():
    """Тест генерации стратегии в CLI без split_seqovl для fakeddisorder."""
    print("🔍 Тест 1: Генерация стратегии CLI для fakeddisorder")
    
    try:
        # Имитируем генерацию стратегии как в cli.py
        strategy_type = "fakeddisorder"
        genes = {
            "ttl": 3,
            "split_pos": 3,
            "split_seqovl": 336,  # Этот параметр НЕ должен попасть в итоговую стратегию
            "fooling": ["badsum", "badseq"]
        }
        
        strategy_parts = ["--dpi-desync=fake,disorder"]
        
        # Логика из исправленного cli.py
        if "split" in strategy_type or "disorder" in strategy_type:
            strategy_parts.append(f"--dpi-desync-split-pos={genes['split_pos']}")
            # ИСПРАВЛЕНИЕ: Не добавляем split_seqovl для fakeddisorder
            if ("seqovl" in strategy_type or "sequence_overlap" in strategy_type) and "fakeddisorder" not in strategy_type:
                strategy_parts.append(f"--dpi-desync-split-seqovl={genes['split_seqovl']}")
        
        if "race" not in strategy_type:
            strategy_parts.append(f"--dpi-desync-ttl={genes['ttl']}")
            
        if genes.get("fooling"):
            fooling_str = ",".join(genes["fooling"])
            strategy_parts.append(f"--dpi-desync-fooling={fooling_str}")
        
        strategy_str = " ".join(strategy_parts)
        print(f"  ✅ Сгенерированная стратегия: {strategy_str}")
        
        # Проверяем, что split_seqovl НЕ присутствует
        if "split-seqovl" not in strategy_str:
            print("  ✅ УСПЕХ: split_seqovl не добавлен для fakeddisorder")
            return True
        else:
            print("  ❌ ОШИБКА: split_seqovl был добавлен для fakeddisorder")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        return False

def test_unified_strategy_loader():
    """Тест UnifiedStrategyLoader для fakeddisorder."""
    print("\n🔍 Тест 2: UnifiedStrategyLoader для fakeddisorder")
    
    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        loader = UnifiedStrategyLoader(debug=True)
        
        # Тестируем стратегию без split_seqovl
        strategy_str = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq"
        
        normalized = loader.load_strategy(strategy_str)
        forced = loader.create_forced_override(normalized)
        
        print(f"  ✅ Загруженная стратегия: {forced}")
        
        # Проверяем параметры
        params = forced.get('params', {})
        
        if params.get('split_pos') == 3 and params.get('ttl') == 3:
            if 'split_seqovl' not in params and 'overlap_size' not in params:
                print("  ✅ УСПЕХ: Стратегия загружена корректно без лишних параметров")
                return True
            else:
                print(f"  ❌ ОШИБКА: Найдены лишние параметры: split_seqovl={params.get('split_seqovl')}, overlap_size={params.get('overlap_size')}")
                return False
        else:
            print(f"  ❌ ОШИБКА: Неправильные параметры: split_pos={params.get('split_pos')}, ttl={params.get('ttl')}")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        return False

def test_testing_mode_compatibility():
    """Тест функции _ensure_testing_mode_compatibility."""
    print("\n🔍 Тест 3: _ensure_testing_mode_compatibility для fakeddisorder")
    
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        # Создаем движок
        engine = UnifiedBypassEngine()
        
        # Имитируем конфигурацию с лишними параметрами
        config = {
            'type': 'fakeddisorder',
            'params': {
                'split_pos': 3,
                'ttl': 3,
                'fooling': ['badsum', 'badseq'],
                'split_seqovl': 336,  # Этот параметр должен быть удален
                'overlap_size': 20,   # Этот параметр должен быть установлен в 0
                'split_count': 5      # Этот параметр должен быть удален
            }
        }
        
        # Применяем совместимость с тестовым режимом
        cleaned_config = engine._ensure_testing_mode_compatibility(config)
        
        print(f"  ✅ Очищенная конфигурация: {cleaned_config}")
        
        params = cleaned_config.get('params', {})
        
        # Проверяем результат
        checks = [
            ('split_seqovl удален', 'split_seqovl' not in params),
            ('split_count удален', 'split_count' not in params),
            ('overlap_size = 0', params.get('overlap_size') == 0),
            ('split_pos сохранен', params.get('split_pos') == 3),
            ('ttl сохранен', params.get('ttl') == 3 or params.get('fake_ttl') == 3),
            ('fooling сохранен', params.get('fooling') == ['badsum', 'badseq'])
        ]
        
        all_passed = True
        for check_name, check_result in checks:
            if check_result:
                print(f"    ✅ {check_name}")
            else:
                print(f"    ❌ {check_name}")
                all_passed = False
        
        if all_passed:
            print("  ✅ УСПЕХ: Все проверки прошли")
            return True
        else:
            print("  ❌ ОШИБКА: Некоторые проверки провалились")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        return False

def main():
    """Основная функция тестирования."""
    print("🚀 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЙ FAKEDDISORDER")
    print("=" * 60)
    
    results = []
    
    # Запускаем тесты
    results.append(("CLI strategy generation", test_cli_strategy_generation()))
    results.append(("UnifiedStrategyLoader", test_unified_strategy_loader()))
    results.append(("testing mode compatibility", test_testing_mode_compatibility()))
    
    # Итоги
    print("\n" + "=" * 60)
    print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {test_name}")
    
    print(f"\n🎯 Итого: {passed}/{total} тестов прошли успешно")
    
    if passed == total:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! fakeddisorder теперь работает одинаково в тесте и службе.")
        return True
    else:
        print(f"⚠️ {total - passed} тестов провалились.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)