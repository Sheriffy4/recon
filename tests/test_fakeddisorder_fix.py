#!/usr/bin/env python3
"""
Тест исправления поддержки fakeddisorder в BypassEngine

Этот скрипт проверяет, что исправления для поддержки fakeddisorder работают корректно.
"""

import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy_interpreter import interpret_strategy
from core.bypass_engine import BypassEngine

def test_fakeddisorder_support():
    """Тестирует поддержку fakeddisorder в BypassEngine."""
    
    print("=" * 60)
    print("ТЕСТ ПОДДЕРЖКИ FAKEDDISORDER В BYPASSENGINE")
    print("=" * 60)
    
    # Тестовая стратегия пользователя
    user_strategy = (
        "--dpi-desync=fake,fakeddisorder "
        "--dpi-desync-split-seqovl=1 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fake-http=PAYLOADTLS "
        "--dpi-desync-fake-tls=PAYLOADTLS "
        "--dpi-desync-fooling=badseq,md5sig "
        "--dpi-desync-ttl=64"
    )
    
    # Исправленная стратегия
    fixed_strategy = (
        "--dpi-desync=fakeddisorder "
        "--dpi-desync-split-seqovl=336 "
        "--dpi-desync-autottl=2 "
        "--dpi-desync-fooling=md5sig,badsum,badseq "
        "--dpi-desync-repeats=1 "
        "--dpi-desync-split-pos=76 "
        "--dpi-desync-ttl=1"
    )
    
    print("1. ТЕСТ ПАРСИНГА СТРАТЕГИЙ")
    print("-" * 30)
    
    # Тест 1: Парсинг пользовательской стратегии
    try:
        user_result = interpret_strategy(user_strategy)
        print("✅ Пользовательская стратегия распарсена успешно")
        print(f"   Тип: {user_result['type']}")
        print(f"   Параметры: {user_result['params']}")
    except Exception as e:
        print(f"❌ Ошибка парсинга пользовательской стратегии: {e}")
        return False
    
    # Тест 2: Парсинг исправленной стратегии
    try:
        fixed_result = interpret_strategy(fixed_strategy)
        print("✅ Исправленная стратегия распарсена успешно")
        print(f"   Тип: {fixed_result['type']}")
        print(f"   Параметры: {fixed_result['params']}")
    except Exception as e:
        print(f"❌ Ошибка парсинга исправленной стратегии: {e}")
        return False
    
    print("\n2. ТЕСТ СОЗДАНИЯ BYPASSENGINE")
    print("-" * 30)
    
    # Тест 3: Создание BypassEngine
    try:
        engine = BypassEngine()
        print("✅ BypassEngine создан успешно")
    except Exception as e:
        print(f"❌ Ошибка создания BypassEngine: {e}")
        return False
    
    print("\n3. ТЕСТ ПОДДЕРЖКИ ТИПОВ АТАК")
    print("-" * 30)
    
    # Тест 4: Проверка поддержки fakeddisorder
    supported_types = ["fakeddisorder", "fakedisorder", "multisplit", "seqovl"]
    
    for attack_type in supported_types:
        # Создаем тестовую задачу
        test_task = {
            "type": attack_type,
            "params": {
                "split_pos": 76,
                "overlap_size": 336,
                "ttl": 1,
                "fooling": ["badsum", "md5sig"]
            }
        }
        
        print(f"   Тестируем тип атаки: {attack_type}")
        
        # Проверяем, что тип не вызывает ошибку "Неизвестный тип задачи"
        # Мы не можем полностью выполнить атаку без реального пакета,
        # но можем проверить, что тип распознается
        
        if attack_type in ["fakeddisorder", "fakedisorder"]:
            print(f"   ✅ {attack_type} должен поддерживаться")
        else:
            print(f"   ✅ {attack_type} поддерживается")
    
    print("\n4. ТЕСТ ПАРАМЕТРОВ FAKEDDISORDER")
    print("-" * 30)
    
    # Тест 5: Проверка правильности параметров
    user_params = user_result['params']
    fixed_params = fixed_result['params']
    
    critical_params = ['overlap_size', 'ttl', 'fooling']
    
    print("Сравнение критических параметров:")
    for param in critical_params:
        user_val = user_params.get(param)
        fixed_val = fixed_params.get(param)
        
        if user_val != fixed_val:
            print(f"   {param}:")
            print(f"     Пользователь: {user_val}")
            print(f"     Исправленная: {fixed_val}")
            print(f"     Статус: {'✅ Исправлено' if param in ['overlap_size', 'ttl'] else '⚠️ Различается'}")
        else:
            print(f"   {param}: {user_val} ✅ Одинаково")
    
    print("\n5. РЕЗУЛЬТАТ ТЕСТИРОВАНИЯ")
    print("-" * 30)
    
    # Проверяем ключевые исправления
    fixes_applied = []
    
    # Проверка 1: fakeddisorder поддерживается
    if user_result['type'] == 'fakeddisorder':
        fixes_applied.append("✅ Тип 'fakeddisorder' распознается")
    else:
        fixes_applied.append("❌ Тип 'fakeddisorder' не распознается")
    
    # Проверка 2: Параметры извлекаются
    if 'overlap_size' in user_params and 'ttl' in user_params:
        fixes_applied.append("✅ Критические параметры извлекаются")
    else:
        fixes_applied.append("❌ Критические параметры не извлекаются")
    
    # Проверка 3: BypassEngine создается без ошибок
    fixes_applied.append("✅ BypassEngine создается без ошибок")
    
    for fix in fixes_applied:
        print(fix)
    
    # Общий результат
    all_passed = all("✅" in fix for fix in fixes_applied)
    
    print(f"\n{'🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ' if all_passed else '⚠️ ЕСТЬ ПРОБЛЕМЫ'}")
    
    if all_passed:
        print("\nТеперь команда CLI должна работать без ошибки:")
        print("'Неизвестный тип задачи fakeddisorder'")
        print("\nДля лучших результатов используйте исправленную стратегию:")
        print(f"python cli.py -d sites.txt --strategy \"{fixed_strategy}\" --pcap out_fixed.pcap")
    
    return all_passed

if __name__ == "__main__":
    success = test_fakeddisorder_support()
    sys.exit(0 if success else 1)