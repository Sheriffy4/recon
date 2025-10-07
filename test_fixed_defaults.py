#!/usr/bin/env python3
"""
Тест для проверки исправленных значений по умолчанию в FixedFakeDisorderConfig.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_fixed_defaults():
    """Проверка, что значения по умолчанию исправлены."""
    print("=" * 80)
    print("ТЕСТ ИСПРАВЛЕННЫХ ЗНАЧЕНИЙ ПО УМОЛЧАНИЮ")
    print("=" * 80)
    print()
    
    try:
        from core.bypass.attacks.tcp.fake_disorder_attack import FixedFakeDisorderConfig
        
        # Создаем конфигурацию с defaults
        config = FixedFakeDisorderConfig()
        
        print("Проверка значений по умолчанию:")
        print()
        
        # Проверка split_pos
        print(f"1. split_pos: {config.split_pos}")
        if config.split_pos == 3:
            print("   ✅ ПРАВИЛЬНО! (было 76)")
        else:
            print(f"   ❌ НЕПРАВИЛЬНО! Ожидалось 3, получено {config.split_pos}")
            return False
        print()
        
        # Проверка split_seqovl
        print(f"2. split_seqovl: {config.split_seqovl}")
        if config.split_seqovl == 0:
            print("   ✅ ПРАВИЛЬНО! (было 336)")
        else:
            print(f"   ❌ НЕПРАВИЛЬНО! Ожидалось 0, получено {config.split_seqovl}")
            return False
        print()
        
        # Проверка ttl
        print(f"3. ttl: {config.ttl}")
        if config.ttl == 3:
            print("   ✅ ПРАВИЛЬНО! (было 1)")
        else:
            print(f"   ❌ НЕПРАВИЛЬНО! Ожидалось 3, получено {config.ttl}")
            return False
        print()
        
        # Проверка fooling_methods
        print(f"4. fooling_methods: {config.fooling_methods}")
        if config.fooling_methods == ['badsum', 'badseq']:
            print("   ✅ ПРАВИЛЬНО! (было ['md5sig', 'badsum', 'badseq'])")
        else:
            print(f"   ❌ НЕПРАВИЛЬНО! Ожидалось ['badsum', 'badseq'], получено {config.fooling_methods}")
            return False
        print()
        
        print("=" * 80)
        print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!")
        print("=" * 80)
        print()
        print("Исправления применены успешно:")
        print("  ✓ split_pos = 3 (Zapret-совместимо)")
        print("  ✓ split_seqovl = 0 (без overlap)")
        print("  ✓ ttl = 3 (правильный TTL)")
        print("  ✓ fooling = ['badsum', 'badseq'] (без md5sig)")
        print()
        return True
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ttl_not_limited():
    """Проверка, что TTL не ограничивается принудительно."""
    print("=" * 80)
    print("ТЕСТ ОТСУТСТВИЯ ПРИНУДИТЕЛЬНОГО ОГРАНИЧЕНИЯ TTL")
    print("=" * 80)
    print()
    
    try:
        from core.bypass.attacks.tcp.fake_disorder_attack import (
            FixedFakeDisorderConfig,
            FixedFakeDisorderAttack
        )
        
        # Создаем конфигурацию с TTL=5
        config = FixedFakeDisorderConfig(ttl=5)
        attack = FixedFakeDisorderAttack(config=config)
        
        # Проверяем, что TTL не ограничивается до 3
        calculated_ttl = attack._calculate_zapret_ttl()
        
        print(f"Конфигурация: ttl={config.ttl}")
        print(f"Рассчитанный TTL: {calculated_ttl}")
        print()
        
        if calculated_ttl == 5:
            print("✅ ПРАВИЛЬНО! TTL не ограничивается (было min(3, ttl))")
            print()
            return True
        else:
            print(f"❌ НЕПРАВИЛЬНО! Ожидалось 5, получено {calculated_ttl}")
            print("   TTL всё ещё ограничивается!")
            print()
            return False
            
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_parameter_override():
    """Проверка, что параметры можно переопределить."""
    print("=" * 80)
    print("ТЕСТ ПЕРЕОПРЕДЕЛЕНИЯ ПАРАМЕТРОВ")
    print("=" * 80)
    print()
    
    try:
        from core.bypass.attacks.tcp.fake_disorder_attack import FixedFakeDisorderConfig
        
        # Создаем конфигурацию с кастомными значениями
        config = FixedFakeDisorderConfig(
            split_pos=10,
            split_seqovl=5,
            ttl=4,
            fooling_methods=['badsum']
        )
        
        print("Проверка переопределения:")
        print()
        
        tests_passed = True
        
        if config.split_pos == 10:
            print(f"✅ split_pos переопределен: {config.split_pos}")
        else:
            print(f"❌ split_pos НЕ переопределен: {config.split_pos}")
            tests_passed = False
        
        if config.split_seqovl == 5:
            print(f"✅ split_seqovl переопределен: {config.split_seqovl}")
        else:
            print(f"❌ split_seqovl НЕ переопределен: {config.split_seqovl}")
            tests_passed = False
        
        if config.ttl == 4:
            print(f"✅ ttl переопределен: {config.ttl}")
        else:
            print(f"❌ ttl НЕ переопределен: {config.ttl}")
            tests_passed = False
        
        if config.fooling_methods == ['badsum']:
            print(f"✅ fooling_methods переопределен: {config.fooling_methods}")
        else:
            print(f"❌ fooling_methods НЕ переопределен: {config.fooling_methods}")
            tests_passed = False
        
        print()
        
        if tests_passed:
            print("✅ ВСЕ ПАРАМЕТРЫ ПЕРЕОПРЕДЕЛЯЮТСЯ ПРАВИЛЬНО!")
        else:
            print("❌ НЕКОТОРЫЕ ПАРАМЕТРЫ НЕ ПЕРЕОПРЕДЕЛЯЮТСЯ!")
        
        print()
        return tests_passed
        
    except Exception as e:
        print(f"❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЙ" + " " * 33 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    results = []
    
    # Тест 1: Defaults
    results.append(("Defaults", test_fixed_defaults()))
    print()
    
    # Тест 2: TTL не ограничивается
    results.append(("TTL не ограничивается", test_ttl_not_limited()))
    print()
    
    # Тест 3: Переопределение параметров
    results.append(("Переопределение", test_parameter_override()))
    print()
    
    # Итоги
    print("=" * 80)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 80)
    print()
    
    for name, passed in results:
        status = "✅ ПРОЙДЕН" if passed else "❌ ПРОВАЛЕН"
        print(f"{name:30} {status}")
    
    print()
    
    all_passed = all(passed for _, passed in results)
    
    if all_passed:
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 25 + "✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ!" + " " * 30 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        print("Исправления применены успешно!")
        print("Можно перезапускать сервис и тестировать x.com")
        print()
        return 0
    else:
        print("╔" + "=" * 78 + "╗")
        print("║" + " " * 25 + "❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!" + " " * 23 + "║")
        print("╚" + "=" * 78 + "╝")
        print()
        print("Проверьте, что все исправления применены правильно!")
        print()
        return 1

if __name__ == "__main__":
    sys.exit(main())
