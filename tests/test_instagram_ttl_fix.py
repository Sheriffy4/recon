#!/usr/bin/env python3
"""
Тест исправления проблемы с TTL для Instagram.
"""

import sys
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def test_instagram_strategy():
    """Тестирует проблемную стратегию Instagram."""
    print("🔍 Тестируем стратегию Instagram с TTL конфликтом...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader(debug=True)

        # Проблемная стратегия Instagram с ttl и autottl
        instagram_strategy = "--dpi-desync=fake,disorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=76 --dpi-desync-autottl=1"

        print(f"📝 Instagram стратегия: {instagram_strategy}")

        normalized = loader.load_strategy(instagram_strategy)

        print("✅ Результат парсинга:")
        print(f"   Тип: {normalized.type}")
        print(f"   split_pos: {normalized.params.get('split_pos')}")
        print(f"   autottl: {normalized.params.get('autottl')}")
        print(f"   ttl: {normalized.params.get('ttl')}")
        print(f"   fooling: {normalized.params.get('fooling')}")

        # Проверяем корректность
        success = True

        if normalized.type != "fakeddisorder":
            print(f"❌ ОШИБКА: Ожидался тип fakeddisorder, получен {normalized.type}")
            success = False

        # Проверяем, что есть только один из TTL параметров
        has_ttl = "ttl" in normalized.params and normalized.params["ttl"] is not None
        has_autottl = (
            "autottl" in normalized.params and normalized.params["autottl"] is not None
        )

        if has_ttl and has_autottl:
            print("❌ ОШИБКА: Присутствуют и ttl, и autottl")
            success = False
        elif has_autottl:
            print(f"✅ Используется autottl: {normalized.params['autottl']}")
        elif has_ttl:
            print(f"✅ Используется ttl: {normalized.params['ttl']}")
        else:
            print("⚠️ Нет TTL параметров")

        if success:
            print("✅ УСПЕХ: Instagram стратегия корректно обработана")

        return success

    except Exception as e:
        print(f"❌ Ошибка при тестировании Instagram стратегии: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_ttl_priority():
    """Тестирует приоритет autottl над ttl."""
    print("\n🔍 Тестируем приоритет autottl над ttl...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader()

        test_cases = [
            # Только ttl
            (
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=5",
                "ttl",
                5,
            ),
            # Только autottl
            (
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-autottl=2",
                "autottl",
                2,
            ),
            # И ttl, и autottl - должен выбрать autottl
            (
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=5 --dpi-desync-autottl=2",
                "autottl",
                2,
            ),
        ]

        all_passed = True

        for strategy_str, expected_param, expected_value in test_cases:
            try:
                normalized = loader.load_strategy(strategy_str)

                # Проверяем, что выбран правильный параметр
                if expected_param == "ttl":
                    if normalized.params.get(
                        "ttl"
                    ) == expected_value and not normalized.params.get("autottl"):
                        print(
                            f"✅ TTL приоритет: {strategy_str[:40]}... → ttl={expected_value}"
                        )
                    else:
                        print(
                            f"❌ TTL приоритет: {strategy_str[:40]}... → ttl={normalized.params.get('ttl')}, autottl={normalized.params.get('autottl')}"
                        )
                        all_passed = False
                elif expected_param == "autottl":
                    if normalized.params.get(
                        "autottl"
                    ) == expected_value and not normalized.params.get("ttl"):
                        print(
                            f"✅ AutoTTL приоритет: {strategy_str[:40]}... → autottl={expected_value}"
                        )
                    else:
                        print(
                            f"❌ AutoTTL приоритет: {strategy_str[:40]}... → ttl={normalized.params.get('ttl')}, autottl={normalized.params.get('autottl')}"
                        )
                        all_passed = False

            except Exception as e:
                print(f"❌ Ошибка парсинга {strategy_str[:40]}...: {e}")
                all_passed = False

        return all_passed

    except Exception as e:
        print(f"❌ Ошибка при тестировании приоритета TTL: {e}")
        return False


def main():
    """Основная функция тестирования."""
    print("🧪 ТЕСТ ИСПРАВЛЕНИЯ TTL КОНФЛИКТА")
    print("=" * 50)

    results = []

    # Тест 1: Instagram стратегия
    results.append(("Instagram Strategy", test_instagram_strategy()))

    # Тест 2: Приоритет TTL
    results.append(("TTL Priority", test_ttl_priority()))

    # Результаты
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")

    all_passed = True
    for test_name, result in results:
        status = "✅ ПРОШЕЛ" if result else "❌ ПРОВАЛЕН"
        print(f"   {test_name}: {status}")
        if not result:
            all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
        print("   Instagram стратегия теперь работает корректно")
        print("   autottl имеет приоритет над ttl")
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
        print("   Требуется дополнительная отладка")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
