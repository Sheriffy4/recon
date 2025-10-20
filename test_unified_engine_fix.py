#!/usr/bin/env python3
"""
Тест исправления unified_bypass_engine для применения _ensure_testing_mode_compatibility.
"""
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ensure_engine_task_with_fakeddisorder():
    """Тест функции _ensure_engine_task с fakeddisorder."""
    print("🔍 Тест 1: _ensure_engine_task с fakeddisorder")
    
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        # Создаем движок
        engine = UnifiedBypassEngine()
        
        # Тестируем стратегию с split_seqovl (которая должна быть очищена)
        strategy_str = "fakeddisorder(split_pos=3,split_seqovl=336,ttl=3,fooling=['badsum','badseq'])"
        
        engine_task = engine._ensure_engine_task(strategy_str)
        
        print(f"  ✅ Результат обработки: {engine_task}")
        
        if engine_task:
            params = engine_task.get('params', {})
            
            # Проверяем результат
            checks = [
                ('type = fakeddisorder', engine_task.get('type') == 'fakeddisorder'),
                ('split_seqovl удален', 'split_seqovl' not in params),
                ('overlap_size = 0', params.get('overlap_size') == 0),
                ('split_pos сохранен', params.get('split_pos') == 3),
                ('ttl сохранен', params.get('ttl') == 3 or params.get('fake_ttl') == 3),
                ('fooling сохранен', params.get('fooling') == ['badsum', 'badseq']),
                ('forced = True', engine_task.get('forced') == True),
                ('no_fallbacks = True', engine_task.get('no_fallbacks') == True)
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
        else:
            print("  ❌ ОШИБКА: engine_task is None")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_zapret_string_parsing():
    """Тест парсинга zapret строки."""
    print("\n🔍 Тест 2: Парсинг zapret строки")
    
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        
        # Создаем движок
        engine = UnifiedBypassEngine()
        
        # Тестируем полную zapret строку
        strategy_str = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq"
        
        engine_task = engine._ensure_engine_task(strategy_str)
        
        print(f"  ✅ Результат обработки: {engine_task}")
        
        if engine_task:
            params = engine_task.get('params', {})
            
            # Проверяем результат
            checks = [
                ('type = fakeddisorder', engine_task.get('type') == 'fakeddisorder'),
                ('split_seqovl удален', 'split_seqovl' not in params),
                ('overlap_size = 0', params.get('overlap_size') == 0),
                ('split_pos сохранен', params.get('split_pos') == 3),
                ('ttl сохранен', params.get('ttl') == 3 or params.get('fake_ttl') == 3),
                ('fooling сохранен', 'badsum' in params.get('fooling', []) and 'badseq' in params.get('fooling', [])),
                ('forced = True', engine_task.get('forced') == True),
                ('no_fallbacks = True', engine_task.get('no_fallbacks') == True)
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
        else:
            print("  ❌ ОШИБКА: engine_task is None")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_strategy_comparison():
    """Тест сравнения стратегий между службой и тестом."""
    print("\n🔍 Тест 3: Сравнение стратегий служба vs тест")
    
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        from core.unified_strategy_loader import UnifiedStrategyLoader
        
        # Создаем компоненты
        engine = UnifiedBypassEngine()
        loader = UnifiedStrategyLoader(debug=True)
        
        # Стратегия как в службе
        service_strategy = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq"
        
        # Стратегия как в тесте (с лишним параметром)
        test_strategy = "fakeddisorder(split_pos=3,split_seqovl=336,ttl=3,fooling=['badsum','badseq'])"
        
        # Обрабатываем обе стратегии
        service_task = engine._ensure_engine_task(service_strategy)
        test_task = engine._ensure_engine_task(test_strategy)
        
        print(f"  ✅ Служба: {service_task}")
        print(f"  ✅ Тест: {test_task}")
        
        if service_task and test_task:
            # Сравниваем ключевые параметры
            service_params = service_task.get('params', {})
            test_params = test_task.get('params', {})
            
            key_params = ['split_pos', 'ttl', 'fake_ttl', 'fooling', 'overlap_size']
            
            all_match = True
            for param in key_params:
                service_val = service_params.get(param)
                test_val = test_params.get(param)
                
                if service_val == test_val:
                    print(f"    ✅ {param}: {service_val} == {test_val}")
                else:
                    print(f"    ❌ {param}: {service_val} != {test_val}")
                    all_match = False
            
            # Проверяем, что split_seqovl удален из обеих
            if 'split_seqovl' not in service_params and 'split_seqovl' not in test_params:
                print("    ✅ split_seqovl удален из обеих стратегий")
            else:
                print(f"    ❌ split_seqovl найден: служба={service_params.get('split_seqovl')}, тест={test_params.get('split_seqovl')}")
                all_match = False
            
            if all_match:
                print("  ✅ УСПЕХ: Стратегии идентичны после обработки")
                return True
            else:
                print("  ❌ ОШИБКА: Стратегии различаются")
                return False
        else:
            print("  ❌ ОШИБКА: Одна из стратегий не обработалась")
            return False
            
    except Exception as e:
        print(f"  ❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Основная функция тестирования."""
    print("🚀 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЙ UNIFIED_BYPASS_ENGINE")
    print("=" * 60)
    
    results = []
    
    # Запускаем тесты
    results.append(("_ensure_engine_task with fakeddisorder", test_ensure_engine_task_with_fakeddisorder()))
    results.append(("zapret string parsing", test_zapret_string_parsing()))
    results.append(("strategy comparison", test_strategy_comparison()))
    
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
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! unified_bypass_engine теперь применяет совместимость.")
        return True
    else:
        print(f"⚠️ {total - passed} тестов провалились.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)