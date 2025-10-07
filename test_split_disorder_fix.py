#!/usr/bin/env python3
"""
Тест исправления для split и disorder стратегий
Проверяет что стратегии теперь правильно распознаются и тестируются
"""
import sys
import os

# Добавляем путь к recon в sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_alias_normalization():
    """Тест 1: Проверка нормализации алиасов"""
    print("="*80)
    print("ТЕСТ 1: Нормализация алиасов")
    print("="*80)
    
    from core.bypass.attacks.alias_map import normalize_attack_name
    
    tests = [
        ("split", "split"),
        ("disorder", "disorder"),
        ("tcp_split", "split"),
        ("tcp_disorder", "disorder"),
        ("fakeddisorder", "fakeddisorder"),
        ("multisplit", "multisplit"),
    ]
    
    all_passed = True
    for input_name, expected in tests:
        result = normalize_attack_name(input_name)
        status = "✅ PASS" if result == expected else "❌ FAIL"
        print(f"{status} - normalize_attack_name('{input_name}') = '{result}' (expected: '{expected}')")
        if result != expected:
            all_passed = False
    
    return all_passed

def test_strategy_parsing():
    """Тест 2: Проверка парсинга стратегий"""
    print("\n" + "="*80)
    print("ТЕСТ 2: Парсинг стратегий")
    print("="*80)
    
    from core.strategy_interpreter import StrategyInterpreter
    
    interpreter = StrategyInterpreter()
    
    tests = [
        ("--dpi-desync=split --dpi-desync-split-pos=3", "split", {"split_pos": 3}),
        ("--dpi-desync=disorder --dpi-desync-split-pos=5", "disorder", {"split_pos": 5}),
        ("--dpi-desync=fake,disorder --dpi-desync-split-pos=3", "fakeddisorder", None),
    ]
    
    all_passed = True
    for strategy_str, expected_type, expected_params in tests:
        try:
            parsed = interpreter.interpret_strategy(strategy_str)
            if not parsed:
                print(f"❌ FAIL - Could not parse: {strategy_str}")
                all_passed = False
                continue
            
            actual_type = parsed.get("type", "unknown")
            actual_params = parsed.get("params", {})
            
            type_ok = actual_type == expected_type
            params_ok = expected_params is None or all(
                actual_params.get(k) == v for k, v in expected_params.items()
            )
            
            if type_ok and params_ok:
                print(f"✅ PASS - {strategy_str}")
                print(f"         Type: {actual_type}, Params: {actual_params}")
            else:
                print(f"❌ FAIL - {strategy_str}")
                print(f"         Expected type: {expected_type}, got: {actual_type}")
                if expected_params:
                    print(f"         Expected params: {expected_params}, got: {actual_params}")
                all_passed = False
        except Exception as e:
            print(f"❌ FAIL - Exception parsing {strategy_str}: {e}")
            all_passed = False
    
    return all_passed

def test_engine_task_conversion():
    """Тест 3: Проверка конвертации в engine task"""
    print("\n" + "="*80)
    print("ТЕСТ 3: Конвертация в engine task")
    print("="*80)
    
    from core.unified_bypass_engine import UnifiedBypassEngine
    
    engine = UnifiedBypassEngine(debug=False)
    
    tests = [
        ({"type": "split", "params": {"split_pos": 3}}, "split"),
        ({"type": "disorder", "params": {"split_pos": 5}}, "disorder"),
        ("--dpi-desync=split --dpi-desync-split-pos=3", "split"),
        ("--dpi-desync=disorder --dpi-desync-split-pos=5", "disorder"),
    ]
    
    all_passed = True
    for strategy, expected_type in tests:
        try:
            engine_task = engine._ensure_engine_task(strategy)
            if not engine_task:
                print(f"❌ FAIL - Could not convert to engine task: {strategy}")
                all_passed = False
                continue
            
            actual_type = engine_task.get("type", "unknown")
            
            if actual_type == expected_type:
                print(f"✅ PASS - {strategy}")
                print(f"         Engine task: {engine_task}")
            else:
                print(f"❌ FAIL - {strategy}")
                print(f"         Expected type: {expected_type}, got: {actual_type}")
                print(f"         Engine task: {engine_task}")
                all_passed = False
        except Exception as e:
            print(f"❌ FAIL - Exception converting {strategy}: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    return all_passed

def main():
    """Запускает все тесты"""
    print("🚀 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЯ SPLIT/DISORDER")
    print("="*80)
    
    results = []
    
    # Тест 1: Нормализация алиасов
    results.append(("Нормализация алиасов", test_alias_normalization()))
    
    # Тест 2: Парсинг стратегий
    results.append(("Парсинг стратегий", test_strategy_parsing()))
    
    # Тест 3: Конвертация в engine task
    results.append(("Конвертация в engine task", test_engine_task_conversion()))
    
    # Итоговый отчет
    print("\n" + "="*80)
    print("📊 ИТОГОВЫЙ ОТЧЕТ")
    print("="*80)
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("-" * 80)
    print(f"Пройдено: {passed_count}/{total_count}")
    
    if passed_count == total_count:
        print("\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("✅ Исправление работает!")
        print("\n📝 Следующий шаг:")
        print("   Запустите реальный тест:")
        print("   python cli.py x.com --strategy \"--dpi-desync=split --dpi-desync-split-pos=3\" --pcap test_split.pcap")
        return 0
    else:
        print(f"\n❌ ПРОВАЛЕНО {total_count - passed_count} ТЕСТОВ")
        print("⚠️ Исправление НЕ работает полностью")
        return 1

if __name__ == "__main__":
    sys.exit(main())
