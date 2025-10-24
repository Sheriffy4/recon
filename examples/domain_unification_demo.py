#!/usr/bin/env python3
"""
Domain Unification Demo - Демонстрация унификации доменов.
Показывает как разрешаются конфликты между www.example.com и example.com.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.strategy.domain_strategy_resolver import DomainStrategyResolver
from core.strategy.unified_strategy_saver import UnifiedStrategySaver


def demo_basic_resolution():
    """Демо 1: Базовое разрешение конфликтов"""
    print("\n" + "=" * 80)
    print("DEMO 1: Базовое Разрешение Конфликтов")
    print("=" * 80)

    resolver = DomainStrategyResolver()

    # Добавить конфликтующие стратегии (из вашего лога)
    resolver.add_strategy(
        domain="www.x.com",
        strategy="--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
        latency_ms=2317.8,
        confidence=0.95,
    )

    resolver.add_strategy(
        domain="x.com",
        strategy="--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        latency_ms=1254.4,
        confidence=0.90,
    )

    resolver.add_strategy(
        domain="mobile.x.com",
        strategy="--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        latency_ms=1264.3,
        confidence=0.90,
    )

    # Разрешить конфликты
    resolved = resolver.resolve_conflicts()

    print("\nВходные стратегии: 3")
    print(f"Унифицированные домены: {len(resolved)}")

    # Показать результат
    for canonical, strategy in resolved.items():
        print(f"\n{canonical}:")
        print(f"  Стратегия: {strategy.strategy[:80]}...")
        print(f"  Применяется к: {', '.join(strategy.applies_to)}")
        print(f"  Latency: {strategy.latency_ms:.1f}ms")
        print(f"  Confidence: {strategy.confidence:.2f}")


def demo_real_world_data():
    """Демо 2: Реальные данные из вашего лога"""
    print("\n" + "=" * 80)
    print("DEMO 2: Реальные Данные из Лога")
    print("=" * 80)

    # Данные из вашего лога
    strategies = {
        "www.x.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
            "latency_ms": 2317.8,
            "confidence": 0.95,
        },
        "x.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1254.4,
            "confidence": 0.90,
        },
        "mobile.x.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1264.3,
            "confidence": 0.90,
        },
        "www.youtube.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            "latency_ms": 634.6,
            "confidence": 0.95,
        },
        "youtube.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1782.4,
            "confidence": 0.90,
        },
        "www.facebook.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=4 --dpi-desync-ttl=4",
            "latency_ms": 201.9,
            "confidence": 0.95,
        },
        "facebook.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 2279.9,
            "confidence": 0.90,
        },
        "instagram.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 3034.7,
            "confidence": 0.90,
        },
    }

    resolver = DomainStrategyResolver()
    resolver.add_strategies_from_dict(strategies)
    resolver.resolve_conflicts()

    # Вывести отчет
    resolver.print_report()


def demo_save_and_load():
    """Демо 3: Сохранение и загрузка"""
    print("\n" + "=" * 80)
    print("DEMO 3: Сохранение и Загрузка")
    print("=" * 80)

    strategies = {
        "www.x.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
            "latency_ms": 2317.8,
            "confidence": 0.95,
        },
        "x.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1254.4,
            "confidence": 0.90,
        },
    }

    # Сохранить
    saver = UnifiedStrategySaver(
        output_file="demo_unified_strategies.json",
        report_file="demo_strategy_resolution_report.json",
    )

    unified = saver.save_strategies(strategies)

    print(f"\n✅ Сохранено {len(unified)} унифицированных стратегий")
    print("📄 Файлы:")
    print("   - demo_unified_strategies.json")
    print("   - demo_strategy_resolution_report.json")

    # Загрузить
    loaded = saver.load_strategies()

    print(f"\n✅ Загружено {len(loaded)} стратегий")

    # Получить стратегию для разных вариантов
    print("\n🔍 Тест получения стратегии:")
    test_domains = ["x.com", "www.x.com", "WWW.X.COM", "mobile.x.com"]

    for domain in test_domains:
        strategy = saver.get_strategy_for_domain(domain)
        if strategy:
            print(f"   {domain:20} → {strategy[:60]}...")
        else:
            print(f"   {domain:20} → Не найдено")


def demo_score_calculation():
    """Демо 4: Расчет score для выбора стратегии"""
    print("\n" + "=" * 80)
    print("DEMO 4: Расчет Score для Выбора Стратегии")
    print("=" * 80)

    print("\nФормула: score = confidence * (1 - latency/5000)")
    print("\nПример из вашего лога:")

    strategies = [
        ("www.x.com", 2317.8, 0.95),
        ("x.com", 1254.4, 0.90),
        ("mobile.x.com", 1264.3, 0.90),
    ]

    print("\n" + "-" * 80)
    for domain, latency, confidence in strategies:
        normalized_latency = min(latency / 5000.0, 1.0)
        score = confidence * (1.0 - normalized_latency)

        print(f"\n{domain}:")
        print(f"  Latency: {latency:.1f}ms")
        print(f"  Confidence: {confidence:.2f}")
        print(f"  Normalized Latency: {normalized_latency:.3f}")
        print(f"  Score: {score:.3f}")

    print("\n" + "-" * 80)
    print("\n✅ Выбрана: x.com (score 0.674 - самый высокий)")


def demo_subdomain_inheritance():
    """Демо 5: Наследование стратегий поддоменами"""
    print("\n" + "=" * 80)
    print("DEMO 5: Наследование Стратегий Поддоменами")
    print("=" * 80)

    resolver = DomainStrategyResolver()

    # Добавить стратегию для родительского домена
    resolver.add_strategy(
        domain="example.com",
        strategy="--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1",
        latency_ms=1000.0,
        confidence=0.90,
    )

    # Добавить стратегию для конкретного поддомена
    resolver.add_strategy(
        domain="api.example.com",
        strategy="--dpi-desync=multisplit --dpi-desync-split-count=5",
        latency_ms=500.0,
        confidence=0.95,
    )

    resolver.resolve_conflicts()

    print("\nСтратегии:")
    print("  example.com     → стратегия A")
    print("  api.example.com → стратегия B (своя)")

    print("\nПолучение стратегий:")

    test_domains = [
        "example.com",
        "www.example.com",
        "api.example.com",
        "unknown.example.com",
    ]

    for domain in test_domains:
        strategy = resolver.get_strategy_for_domain(domain)
        if strategy:
            strategy_short = strategy.strategy[:50] + "..."
            print(f"  {domain:25} → {strategy_short}")
        else:
            print(f"  {domain:25} → Не найдено")

    print("\n💡 unknown.example.com наследует стратегию от example.com")


def main():
    """Запустить все демо"""
    print("\n" + "=" * 80)
    print("DOMAIN UNIFICATION DEMO")
    print("=" * 80)

    try:
        # Демо 1: Базовое разрешение
        demo_basic_resolution()

        # Демо 2: Реальные данные
        demo_real_world_data()

        # Демо 3: Сохранение и загрузка
        demo_save_and_load()

        # Демо 4: Расчет score
        demo_score_calculation()

        # Демо 5: Наследование поддоменами
        demo_subdomain_inheritance()

    except KeyboardInterrupt:
        print("\n\nДемо прервано пользователем")
    except Exception as e:
        print(f"\n\n❌ Ошибка: {e}")
        import traceback

        traceback.print_exc()

    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print("\n📚 Документация:")
    print("   - docs/DOMAIN_STRATEGY_RESOLUTION.md")
    print("   - DOMAIN_UNIFICATION_SUMMARY.md")
    print("\n💾 Созданные файлы:")
    print("   - demo_unified_strategies.json")
    print("   - demo_strategy_resolution_report.json")


if __name__ == "__main__":
    main()
