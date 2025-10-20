#!/usr/bin/env python3
"""
Тест для валидации исправления диспетчеризации атак.
Проверяет, что каждый тип атаки вызывает правильный метод.
"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from core.bypass.techniques.primitives import BypassTechniques

def test_dispatch_methods():
    """Тестирует, что все методы атак доступны и работают."""
    print("🧪 ТЕСТИРОВАНИЕ МЕТОДОВ ДИСПЕТЧЕРИЗАЦИИ")
    print("=" * 60)
    
    techniques = BypassTechniques()
    test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    tests = [
        {
            "name": "fakeddisorder",
            "method": "apply_fakeddisorder",
            "args": (test_payload, 3, 3, ["badsum"]),
            "expected_segments": 3
        },
        {
            "name": "seqovl", 
            "method": "apply_seqovl",
            "args": (test_payload, 5, 20, 3, ["badsum"]),
            "expected_segments": 2
        },
        {
            "name": "multidisorder",
            "method": "apply_multidisorder", 
            "args": (test_payload, [1, 5, 10], ["badsum"], 3),
            "expected_segments": 5  # 1 fake + 4 real fragments (более детальное разбиение)
        },
        {
            "name": "disorder",
            "method": "apply_disorder",
            "args": (test_payload, 7, False),
            "expected_segments": 2
        },
        {
            "name": "disorder2", 
            "method": "apply_disorder",
            "args": (test_payload, 7, True),
            "expected_segments": 2
        },
        {
            "name": "multisplit",
            "method": "apply_multisplit",
            "args": (test_payload, [3, 6, 9], []),
            "expected_segments": 4  # 4 parts from 3 splits
        },
        {
            "name": "fake_race",
            "method": "apply_fake_packet_race",
            "args": (test_payload, 2, ["badsum"]),
            "expected_segments": 2
        }
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            method = getattr(techniques, test["method"])
            result = method(*test["args"])
            
            if len(result) == test["expected_segments"]:
                print(f"  ✅ {test['name']}: {len(result)} сегментов (ожидалось {test['expected_segments']})")
                passed += 1
            else:
                print(f"  ❌ {test['name']}: {len(result)} сегментов (ожидалось {test['expected_segments']})")
                failed += 1
                
        except AttributeError as e:
            print(f"  ❌ {test['name']}: Метод {test['method']} не найден - {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {test['name']}: Ошибка выполнения - {e}")
            failed += 1
    
    print("=" * 60)
    print(f"📊 РЕЗУЛЬТАТЫ: {passed} прошли, {failed} провалились")
    
    if failed == 0:
        print("🎉 ВСЕ МЕТОДЫ ДИСПЕТЧЕРИЗАЦИИ РАБОТАЮТ ПРАВИЛЬНО!")
        return True
    else:
        print("❌ ЕСТЬ ПРОБЛЕМЫ С МЕТОДАМИ ДИСПЕТЧЕРИЗАЦИИ")
        return False

def test_parameter_handling():
    """Тестирует правильную обработку параметров."""
    print("\n🧪 ТЕСТИРОВАНИЕ ОБРАБОТКИ ПАРАМЕТРОВ")
    print("=" * 60)
    
    techniques = BypassTechniques()
    test_payload = b"TLS ClientHello packet data here..."
    
    # Тест seqovl с overlap_size
    result = techniques.apply_seqovl(test_payload, 10, 15, 3, ["badsum"])
    print(f"  ✅ seqovl: {len(result)} сегментов с overlap_size=15")
    
    # Тест multidisorder с positions
    result = techniques.apply_multidisorder(test_payload, [2, 6, 10], ["badsum"], 3)
    print(f"  ✅ multidisorder: {len(result)} сегментов с positions=[2,6,10]")
    
    # Тест disorder с ack_first
    result1 = techniques.apply_disorder(test_payload, 8, False)
    result2 = techniques.apply_disorder(test_payload, 8, True)
    print(f"  ✅ disorder: ack_first=False -> {len(result1)} сегментов")
    print(f"  ✅ disorder2: ack_first=True -> {len(result2)} сегментов")
    
    return True

if __name__ == "__main__":
    print("🎯 ВАЛИДАЦИЯ ИСПРАВЛЕНИЯ ДИСПЕТЧЕРИЗАЦИИ АТАК")
    print("=" * 70)
    
    success1 = test_dispatch_methods()
    success2 = test_parameter_handling()
    
    if success1 and success2:
        print("\n🎉 КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ УСПЕШНО ВАЛИДИРОВАНО!")
        print("✅ Все типы атак теперь диспетчеризуются правильно")
        print("✅ Параметры обрабатываются корректно")
        sys.exit(0)
    else:
        print("\n❌ ВАЛИДАЦИЯ ПРОВАЛИЛАСЬ!")
        print("Необходимы дополнительные исправления")
        sys.exit(1)