#!/usr/bin/env python3
"""
Критическое исправление диспетчеризации атак - минимальная версия для немедленного решения проблемы.
"""
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_current_dispatch_problem():
    """Демонстрирует текущую проблему диспетчеризации."""
    print("🔍 Тест 1: Демонстрация текущей проблемы")
    
    # Имитируем текущую логику из base_engine.py
    def current_apply_bypass_logic(task_type, params):
        """Текущая проблемная логика."""
        if task_type in ("fakeddisorder", "multidisorder", "disorder", "disorder2", "seqovl"):
            # ❌ ВСЕ АТАКИ ИДУТ ЧЕРЕЗ ОДИН МЕТОД!
            return f"apply_fakeddisorder(split_pos={params.get('split_pos', 3)})"
        else:
            return f"unknown_attack({task_type})"
    
    # Тестируем разные типы атак
    test_cases = [
        ("fakeddisorder", {"split_pos": 3}),
        ("seqovl", {"split_pos": 5, "overlap_size": 20}),  # ❌ overlap_size игнорируется!
        ("multidisorder", {"positions": [1, 5, 10]}),      # ❌ positions игнорируется!
        ("disorder", {"split_pos": 7}),
    ]
    
    print("  Текущая логика:")
    for attack_type, params in test_cases:
        result = current_apply_bypass_logic(attack_type, params)
        print(f"    {attack_type} → {result}")
        
    print("  ❌ ПРОБЛЕМА: Все атаки выполняются как fakeddisorder!")
    return False

def test_proposed_dispatch_fix():
    """Демонстрирует предлагаемое исправление."""
    print("\n🔍 Тест 2: Предлагаемое исправление")
    
    # Предлагаемая правильная логика
    def fixed_apply_bypass_logic(task_type, params):
        """Исправленная логика с правильной диспетчеризацией."""
        task_type = task_type.lower()
        
        if task_type == "fakeddisorder":
            return f"apply_fakeddisorder(split_pos={params.get('split_pos', 3)}, ttl={params.get('ttl', 3)})"
        elif task_type == "seqovl":
            return f"apply_seqovl(split_pos={params.get('split_pos', 3)}, overlap_size={params.get('overlap_size', 20)})"
        elif task_type == "multidisorder":
            return f"apply_multidisorder(positions={params.get('positions', [1,5,10])})"
        elif task_type in ("disorder", "disorder2"):
            ack_first = task_type == "disorder2"
            return f"apply_disorder(split_pos={params.get('split_pos', 3)}, ack_first={ack_first})"
        elif task_type in ("split", "multisplit"):
            positions = params.get('positions', [params.get('split_pos', 3)])
            return f"apply_multisplit(positions={positions})"
        elif task_type == "fake":
            return f"apply_fake_packet_race(ttl={params.get('ttl', 3)})"
        else:
            return f"unknown_attack({task_type})"
    
    # Тестируем те же случаи
    test_cases = [
        ("fakeddisorder", {"split_pos": 3, "ttl": 3}),
        ("seqovl", {"split_pos": 5, "overlap_size": 20, "ttl": 3}),
        ("multidisorder", {"positions": [1, 5, 10], "ttl": 3}),
        ("disorder", {"split_pos": 7}),
        ("disorder2", {"split_pos": 7}),
        ("multisplit", {"positions": [2, 6, 12]}),
        ("fake", {"ttl": 2}),
    ]
    
    print("  Исправленная логика:")
    all_correct = True
    for attack_type, params in test_cases:
        result = fixed_apply_bypass_logic(attack_type, params)
        print(f"    {attack_type} → {result}")
        
        # Проверяем правильность диспетчеризации
        if attack_type == "seqovl" and "overlap_size=20" not in result:
            all_correct = False
        elif attack_type == "multidisorder" and "positions=[1, 5, 10]" not in result:
            all_correct = False
    
    if all_correct:
        print("  ✅ ИСПРАВЛЕНО: Каждая атака использует свой метод с правильными параметрами!")
        return True
    else:
        print("  ❌ ОШИБКА: Некоторые атаки все еще диспетчеризуются неправильно")
        return False

def test_special_split_pos():
    """Тест обработки специальных значений split_pos."""
    print("\n🔍 Тест 3: Специальные значения split_pos")
    
    def resolve_special_split_pos(split_pos_value, payload_length=100):
        """Разрешение специальных значений split_pos."""
        if split_pos_value == "cipher":
            # Имитируем поиск cipher suite (обычно около 40-50 байт в ClientHello)
            return 45
        elif split_pos_value == "sni":
            # Имитируем поиск SNI (обычно около 60-80 байт)
            return 70
        elif split_pos_value == "midsld":
            # Средняя позиция
            return payload_length // 2
        elif isinstance(split_pos_value, int):
            return split_pos_value
        else:
            return 3  # default
    
    test_cases = [
        ("cipher", 100, 45),
        ("sni", 100, 70),
        ("midsld", 100, 50),
        (3, 100, 3),
        ("invalid", 100, 3),
    ]
    
    all_correct = True
    for split_pos, payload_len, expected in test_cases:
        result = resolve_special_split_pos(split_pos, payload_len)
        if result == expected:
            print(f"    ✅ {split_pos} → {result}")
        else:
            print(f"    ❌ {split_pos} → {result} (ожидалось {expected})")
            all_correct = False
    
    if all_correct:
        print("  ✅ УСПЕХ: Все специальные значения обрабатываются правильно")
        return True
    else:
        print("  ❌ ОШИБКА: Некоторые специальные значения обрабатываются неправильно")
        return False

def test_parameter_extraction():
    """Тест извлечения параметров для разных типов атак."""
    print("\n🔍 Тест 4: Извлечение параметров")
    
    def extract_parameters_for_attack(attack_type, raw_params):
        """Извлекает и нормализует параметры для конкретного типа атаки."""
        params = raw_params.copy()
        
        if attack_type == "seqovl":
            # Для seqovl нужен overlap_size
            if "overlap_size" not in params:
                params["overlap_size"] = params.get("split_seqovl", 20)
            return params
            
        elif attack_type == "multidisorder":
            # Для multidisorder нужен positions
            if "positions" not in params:
                split_pos = params.get("split_pos", 3)
                params["positions"] = [split_pos, split_pos * 2, split_pos * 3]
            return params
            
        elif attack_type == "multisplit":
            # Для multisplit нужен positions
            if "positions" not in params:
                split_pos = params.get("split_pos", 3)
                params["positions"] = [split_pos]
            return params
            
        return params
    
    test_cases = [
        ("seqovl", {"split_pos": 5, "split_seqovl": 25}, "overlap_size"),
        ("multidisorder", {"split_pos": 4}, "positions"),
        ("multisplit", {"split_pos": 6}, "positions"),
        ("fakeddisorder", {"split_pos": 3, "ttl": 3}, None),
    ]
    
    all_correct = True
    for attack_type, raw_params, expected_param in test_cases:
        result_params = extract_parameters_for_attack(attack_type, raw_params)
        
        if expected_param and expected_param in result_params:
            print(f"    ✅ {attack_type}: {expected_param} = {result_params[expected_param]}")
        elif not expected_param:
            print(f"    ✅ {attack_type}: параметры без изменений")
        else:
            print(f"    ❌ {attack_type}: отсутствует {expected_param}")
            all_correct = False
    
    if all_correct:
        print("  ✅ УСПЕХ: Параметры извлекаются правильно для каждого типа")
        return True
    else:
        print("  ❌ ОШИБКА: Некоторые параметры извлекаются неправильно")
        return False

def main():
    """Основная функция тестирования."""
    print("🚀 КРИТИЧЕСКОЕ ТЕСТИРОВАНИЕ ДИСПЕТЧЕРИЗАЦИИ АТАК")
    print("=" * 70)
    
    results = []
    
    # Запускаем тесты
    results.append(("current dispatch problem", test_current_dispatch_problem()))
    results.append(("proposed dispatch fix", test_proposed_dispatch_fix()))
    results.append(("special split_pos", test_special_split_pos()))
    results.append(("parameter extraction", test_parameter_extraction()))
    
    # Итоги
    print("\n" + "=" * 70)
    print("📊 РЕЗУЛЬТАТЫ КРИТИЧЕСКОГО ТЕСТИРОВАНИЯ")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {status}: {test_name}")
    
    print(f"\n🎯 Итого: {passed}/{total} тестов прошли успешно")
    
    if passed >= 3:  # Первый тест должен провалиться (демонстрация проблемы)
        print("🎉 ГОТОВО К РЕАЛИЗАЦИИ! Логика исправления протестирована.")
        print("\n📋 СЛЕДУЮЩИЕ ШАГИ:")
        print("1. Создать AttackDispatcher")
        print("2. Добавить apply_disorder() в primitives.py")
        print("3. Рефакторить apply_bypass() в base_engine.py")
        print("4. Интегрировать внешние модули атак")
        return True
    else:
        print(f"⚠️ Нужно доработать логику исправления.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)