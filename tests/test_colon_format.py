#!/usr/bin/env python3
"""
Тест нового формата стратегий с двоеточием.
"""

import sys
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_colon_format():
    """Тестирует формат attack:param1=value1,param2=value2"""
    print("🔍 Тестируем формат с двоеточием...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader(debug=False)

        test_cases = [
            # Полный формат
            ("seqovl:split_pos=10,overlap_size=20,fake_ttl=1", "seqovl"),
            (
                "fakeddisorder:split_pos=sni,ttl=1,fooling=[badsum,badseq,md5sig]",
                "fakeddisorder",
            ),
            ("multisplit:positions=[1,5,10],ttl=3", "multisplit"),
            ("fake:ttl=3,fooling=[badsum]", "fake"),
            ("disorder:split_pos=5,ttl=2", "disorder"),
            # Сокращенный формат (одиночное значение)
            ("split:3", "split"),
            ("split:10", "split"),
            ("split:sni", "split"),
            ("split:cipher", "split"),
            ("disorder:3", "disorder"),
            ("disorder:10", "disorder"),
            ("disorder:sni", "disorder"),
            ("fake:3", "fake"),
            ("fakeddisorder:5", "fakeddisorder"),
        ]

        all_passed = True

        for strategy_str, expected_type in test_cases:
            try:
                normalized = loader.load_strategy(strategy_str)

                if normalized.type == expected_type:
                    print(f"✅ {strategy_str[:50]}... → {normalized.type}")
                    print(f"   Параметры: {normalized.params}")
                else:
                    print(
                        f"❌ {strategy_str[:50]}... → {normalized.type} (ожидался {expected_type})"
                    )
                    all_passed = False

            except Exception as e:
                print(f"❌ Ошибка парсинга {strategy_str[:50]}...: {e}")
                all_passed = False

        return all_passed

    except Exception as e:
        print(f"❌ Ошибка при тестировании: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Основная функция тестирования."""
    print("🧪 ТЕСТ ФОРМАТА СТРАТЕГИЙ С ДВОЕТОЧИЕМ")
    print("=" * 60)

    success = test_colon_format()

    print("\n" + "=" * 60)
    if success:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
        print("   Формат attack:param1=value1,param2=value2 теперь поддерживается")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
        print("   Требуется дополнительная отладка")

    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
