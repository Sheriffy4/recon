#!/usr/bin/env python3
"""
Быстрый тест реального движка для проверки исправления диспетчеризации
"""

import sys
import os

sys.path.insert(0, os.path.abspath("."))


def test_real_engine_import():
    """Тестирует, что реальный движок импортируется без ошибок"""
    print("🧪 ТЕСТ ИМПОРТА РЕАЛЬНОГО ДВИЖКА")
    print("=" * 50)

    try:
        from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

        print("✅ WindowsBypassEngine импортирован успешно")

        # Проверяем, что метод apply_bypass существует
        if hasattr(WindowsBypassEngine, "apply_bypass"):
            print("✅ Метод apply_bypass найден")
        else:
            print("❌ Метод apply_bypass не найден")
            return False

        # Проверяем primitives
        from core.bypass.techniques.primitives import BypassTechniques

        techniques = BypassTechniques()

        required_methods = [
            "apply_fakeddisorder",
            "apply_seqovl",
            "apply_multidisorder",
            "apply_disorder",
            "apply_multisplit",
            "apply_fake_packet_race",
        ]

        for method_name in required_methods:
            if hasattr(techniques, method_name):
                print(f"✅ {method_name} найден")
            else:
                print(f"❌ {method_name} не найден")
                return False

        print("\n🎉 ВСЕ КОМПОНЕНТЫ ИСПРАВЛЕНИЯ ДОСТУПНЫ!")
        return True

    except ImportError as e:
        print(f"❌ Ошибка импорта: {e}")
        return False
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        return False


def test_primitives_methods():
    """Тестирует, что все методы primitives работают"""
    print("\n🧪 ТЕСТ МЕТОДОВ PRIMITIVES")
    print("=" * 50)

    try:
        from core.bypass.techniques.primitives import BypassTechniques

        techniques = BypassTechniques()
        test_payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"

        # Тестируем каждый метод
        tests = [
            (
                "apply_fakeddisorder",
                lambda: techniques.apply_fakeddisorder(test_payload, 3, 3, ["badsum"]),
            ),
            (
                "apply_seqovl",
                lambda: techniques.apply_seqovl(test_payload, 5, 20, 3, ["badsum"]),
            ),
            (
                "apply_multidisorder",
                lambda: techniques.apply_multidisorder(
                    test_payload, [1, 5, 10], ["badsum"], 3
                ),
            ),
            (
                "apply_disorder",
                lambda: techniques.apply_disorder(test_payload, 7, False),
            ),
            (
                "apply_multisplit",
                lambda: techniques.apply_multisplit(test_payload, [3, 6, 9], []),
            ),
            (
                "apply_fake_packet_race",
                lambda: techniques.apply_fake_packet_race(test_payload, 2, ["badsum"]),
            ),
        ]

        all_passed = True
        for method_name, test_func in tests:
            try:
                result = test_func()
                if result and len(result) > 0:
                    print(f"✅ {method_name}: {len(result)} сегментов")
                else:
                    print(f"❌ {method_name}: пустой результат")
                    all_passed = False
            except Exception as e:
                print(f"❌ {method_name}: ошибка - {e}")
                all_passed = False

        return all_passed

    except Exception as e:
        print(f"❌ Ошибка тестирования primitives: {e}")
        return False


if __name__ == "__main__":
    print("🎯 БЫСТРЫЙ ТЕСТ РЕАЛЬНОГО ДВИЖКА")
    print("=" * 60)

    test1 = test_real_engine_import()
    test2 = test_primitives_methods()

    print("\n" + "=" * 60)
    if test1 and test2:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ! ИСПРАВЛЕНИЕ РАБОТАЕТ!")
        sys.exit(0)
    else:
        print("❌ ЕСТЬ ПРОБЛЕМЫ С ИСПРАВЛЕНИЕМ")
        sys.exit(1)
