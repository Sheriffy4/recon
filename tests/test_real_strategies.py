#!/usr/bin/env python3
"""
Финальный тест с реальными стратегиями из лога службы.
Проверяет, что все проблемные стратегии теперь парсятся правильно.
"""

import sys
import os
import json
from pathlib import Path

# Добавляем путь к проекту
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def create_real_strategies_config():
    """Создает конфигурацию с реальными стратегиями из лога."""

    # Реальные стратегии из лога службы
    real_strategies = {
        "domain_strategies": {
            # Проблемные стратегии с fake,disorder
            "instagram.com": "--dpi-desync=fake,disorder --dpi-desync-fooling=badsum --dpi-desync-split-pos=76 --dpi-desync-autottl=1",
            "facebook.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "www.x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "mobile.x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "api.x.com": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            # Другие типы стратегий для сравнения
            "youtube.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "www.youtube.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "lh3.ggpht.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=3",
            "rutracker.org": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "nnmclub.to": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
        }
    }

    with open("domain_strategies.json", "w", encoding="utf-8") as f:
        json.dump(real_strategies, f, indent=2)

    # Создаем sites.txt с этими доменами
    domains = list(real_strategies["domain_strategies"].keys())
    with open("sites.txt", "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(f"{domain}\n")

    print(f"✅ Создана конфигурация с {len(domains)} реальными стратегиями")
    return domains


def test_strategy_parsing():
    """Тестирует парсинг всех реальных стратегий."""
    print("\n🔍 Тестируем парсинг реальных стратегий...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader(debug=False)

        # Тестовые случаи с ожидаемыми результатами
        test_cases = [
            # fake,disorder -> fakeddisorder
            ("--dpi-desync=fake,disorder --dpi-desync-split-pos=3", "fakeddisorder"),
            ("--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3", "fakeddisorder"),
            (
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3",
                "fakeddisorder",
            ),
            # Другие типы
            ("--dpi-desync=multisplit --dpi-desync-split-count=5", "multisplit"),
            ("--dpi-desync=fake --dpi-desync-ttl=3", "fake"),
            ("--dpi-desync=disorder --dpi-desync-split-pos=3", "disorder"),
        ]

        all_passed = True

        for strategy_str, expected_type in test_cases:
            try:
                normalized = loader.load_strategy(strategy_str)

                if normalized.type == expected_type:
                    print(f"✅ {strategy_str[:30]}... → {normalized.type}")
                else:
                    print(
                        f"❌ {strategy_str[:30]}... → {normalized.type} (ожидался {expected_type})"
                    )
                    all_passed = False

            except Exception as e:
                print(f"❌ Ошибка парсинга {strategy_str[:30]}...: {e}")
                all_passed = False

        return all_passed

    except Exception as e:
        print(f"❌ Ошибка при тестировании парсинга: {e}")
        return False


def test_service_with_real_config():
    """Тестирует службу с реальной конфигурацией."""
    print("\n🔍 Тестируем службу с реальными стратегиями...")

    try:
        from recon_service import DPIBypassService

        service = DPIBypassService()

        # Загружаем реальные стратегии
        if not service.load_strategies():
            print("❌ ОШИБКА: Не удалось загрузить стратегии")
            return False

        if not service.load_domains():
            print("❌ ОШИБКА: Не удалось загрузить домены")
            return False

        print(f"✅ Загружено {len(service.domain_strategies)} стратегий")
        print(f"✅ Загружено {len(service.monitored_domains)} доменов")

        # Проверяем проблемные домены
        problem_domains = [
            ("instagram.com", "fakeddisorder"),
            ("facebook.com", "fakeddisorder"),
            ("x.com", "fakeddisorder"),
            ("youtube.com", "fakeddisorder"),
        ]

        all_correct = True

        for domain, expected_type in problem_domains:
            strategy_str = service.get_strategy_for_domain(domain)
            if strategy_str:
                try:
                    from core.unified_strategy_loader import UnifiedStrategyLoader

                    loader = UnifiedStrategyLoader()
                    normalized = loader.load_strategy(strategy_str)

                    if normalized.type == expected_type:
                        print(f"✅ {domain}: {normalized.type}")
                    else:
                        print(
                            f"❌ {domain}: {normalized.type} (ожидался {expected_type})"
                        )
                        all_correct = False

                except Exception as e:
                    print(f"❌ {domain}: Ошибка парсинга - {e}")
                    all_correct = False
            else:
                print(f"❌ {domain}: Стратегия не найдена")
                all_correct = False

        return all_correct

    except Exception as e:
        print(f"❌ Ошибка при тестировании службы: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_forced_override_creation():
    """Тестирует создание forced override для всех стратегий."""
    print("\n🔍 Тестируем создание forced override...")

    try:
        from core.unified_strategy_loader import UnifiedStrategyLoader

        loader = UnifiedStrategyLoader()

        # Тестируем проблемные стратегии
        strategies = [
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
            "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=3 --dpi-desync-ttl=3",
            "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=3",
        ]

        all_correct = True

        for strategy_str in strategies:
            try:
                normalized = loader.load_strategy(strategy_str)
                forced_config = loader.create_forced_override(normalized)

                # Проверяем обязательные флаги
                if not forced_config.get("no_fallbacks"):
                    print(f"❌ no_fallbacks=False для {normalized.type}")
                    all_correct = False

                if not forced_config.get("forced"):
                    print(f"❌ forced=False для {normalized.type}")
                    all_correct = False

                if forced_config.get("type") != normalized.type:
                    print(
                        f"❌ Неправильный тип в forced_config: {forced_config.get('type')} != {normalized.type}"
                    )
                    all_correct = False

                if all_correct:
                    print(f"✅ {normalized.type}: forced override корректен")

            except Exception as e:
                print(f"❌ Ошибка создания forced override: {e}")
                all_correct = False

        return all_correct

    except Exception as e:
        print(f"❌ Ошибка при тестировании forced override: {e}")
        return False


def cleanup():
    """Очищает тестовые файлы."""
    files_to_remove = ["domain_strategies.json", "sites.txt"]

    for file_name in files_to_remove:
        try:
            if os.path.exists(file_name):
                os.remove(file_name)
        except:
            pass


def main():
    """Основная функция тестирования."""
    print("🧪 ФИНАЛЬНЫЙ ТЕСТ С РЕАЛЬНЫМИ СТРАТЕГИЯМИ")
    print("=" * 60)
    print("Проверяем исправление на реальных данных из лога службы")
    print("=" * 60)

    try:
        # Создаем реальную конфигурацию
        domains = create_real_strategies_config()

        results = []

        # Тест 1: Парсинг стратегий
        results.append(("Strategy Parsing", test_strategy_parsing()))

        # Тест 2: Служба с реальной конфигурацией
        results.append(("Service with Real Config", test_service_with_real_config()))

        # Тест 3: Forced Override
        results.append(("Forced Override Creation", test_forced_override_creation()))

        # Результаты
        print("\n" + "=" * 60)
        print("📊 ФИНАЛЬНЫЕ РЕЗУЛЬТАТЫ:")

        all_passed = True
        for test_name, result in results:
            status = "✅ ПРОШЕЛ" if result else "❌ ПРОВАЛЕН"
            print(f"   {test_name}: {status}")
            if not result:
                all_passed = False

        print("\n" + "=" * 60)
        if all_passed:
            print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
            print("\n✅ ИСПРАВЛЕНИЕ ПОЛНОСТЬЮ РАБОТАЕТ:")
            print("   • fake,disorder → fakeddisorder ✅")
            print("   • fake,disorder2 → fakeddisorder ✅")
            print("   • fake,fakeddisorder → fakeddisorder ✅")
            print("   • Forced override создается правильно ✅")
            print("   • Служба готова к работе ✅")
            print("\n🚀 МОЖНО ЗАПУСКАТЬ СЛУЖБУ!")
            print("   Теперь Instagram и другие сайты будут использовать")
            print("   правильную атаку fakeddisorder вместо простой fake")
        else:
            print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ!")
            print("   Требуется дополнительная отладка")

        return all_passed

    finally:
        cleanup()


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
