#!/usr/bin/env python3
"""
Тест исправления парсинга различных вариантов disorder.
"""

import sys
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_disorder_variants():
    """Тестирует все варианты disorder с fake."""
    print("🔍 Тестируем варианты disorder...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader(debug=False)

        # Тестовые случаи
        test_cases = [
            # fake + disorder variants -> fakeddisorder
            ("--dpi-desync=fake,disorder", "fakeddisorder"),
            ("--dpi-desync=fake,disorder2", "fakeddisorder"),
            ("--dpi-desync=fake,multidisorder", "fakeddisorder"),
            ("--dpi-desync=disorder,fake", "fakeddisorder"),  # Порядок не важен
            ("--dpi-desync=disorder2,fake", "fakeddisorder"),
            # fake без disorder -> fake
            ("--dpi-desync=fake", "fake"),
            ("--dpi-desync=fake,split", "fake"),  # fake + не-disorder
            # disorder без fake -> disorder
            ("--dpi-desync=disorder", "disorder"),
            ("--dpi-desync=disorder2", "disorder2"),
            ("--dpi-desync=multidisorder", "multidisorder"),
            # Другие комбинации
            ("--dpi-desync=multisplit", "multisplit"),
            ("--dpi-desync=seqovl", "seqovl"),
        ]

        all_passed = True

        for strategy_str, expected_type in test_cases:
            try:
                normalized = loader.load_strategy(strategy_str)

                if normalized.type == expected_type:
                    print(f"✅ {strategy_str} → {normalized.type}")
                else:
                    print(
                        f"❌ {strategy_str} → {normalized.type} (ожидался {expected_type})"
                    )
                    all_passed = False

            except Exception as e:
                print(f"❌ Ошибка парсинга {strategy_str}: {e}")
                all_passed = False

        return all_passed

    except Exception as e:
        print(f"❌ Ошибка при тестировании: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_real_problematic_strategy():
    """Тестирует конкретную проблемную стратегию из лога."""
    print("\n🔍 Тестируем проблемную стратегию из лога...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader(debug=True)

        # Стратегия, которая вызывала ошибку
        problematic_strategy = "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"

        print(f"📝 Проблемная стратегия: {problematic_strategy}")

        normalized = loader.load_strategy(problematic_strategy)

        print("✅ Результат парсинга:")
        print(f"   Тип: {normalized.type}")
        print(f"   Параметры: {normalized.params}")

        if normalized.type == "fakeddisorder":
            print("✅ УСПЕХ: fake,disorder правильно парсится как fakeddisorder")
            return True
        else:
            print(
                f"❌ ОШИБКА: fake,disorder парсится как {normalized.type}, ожидался fakeddisorder"
            )
            return False

    except Exception as e:
        print(f"❌ Ошибка при тестировании проблемной стратегии: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Основная функция тестирования."""
    print("🧪 ТЕСТ ИСПРАВЛЕНИЯ ПАРСИНГА DISORDER ВАРИАНТОВ")
    print("=" * 60)

    results = []

    # Тест 1: Все варианты disorder
    results.append(("Disorder Variants", test_disorder_variants()))

    # Тест 2: Проблемная стратегия
    results.append(("Problematic Strategy", test_real_problematic_strategy()))

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
        print("   fake,disorder теперь правильно парсится как fakeddisorder")
        print("   fake,disorder2 теперь правильно парсится как fakeddisorder")
        print("   fake,multidisorder теперь правильно парсится как fakeddisorder")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
        print("   Требуется дополнительная отладка")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
