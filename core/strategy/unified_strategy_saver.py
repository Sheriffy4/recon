# core/strategy/unified_strategy_saver.py
"""
Unified Strategy Saver - Сохраняет стратегии с автоматическим разрешением конфликтов.
Интегрируется с DomainStrategyResolver для унификации www/non-www доменов.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime

from .domain_strategy_resolver import DomainStrategyResolver, ResolvedStrategy

LOG = logging.getLogger(__name__)


class UnifiedStrategySaver:
    """
    Сохраняет стратегии с автоматическим разрешением конфликтов доменов.

    Особенности:
    - Автоматически унифицирует www.example.com и example.com
    - Разрешает конфликты по latency + confidence
    - Сохраняет детальный отчет о разрешении конфликтов
    - Поддерживает обратную совместимость
    """

    def __init__(
        self,
        output_file: str = "unified_strategies.json",
        report_file: Optional[str] = "strategy_resolution_report.json",
        auto_resolve: bool = True,
    ):
        """
        Args:
            output_file: Файл для сохранения унифицированных стратегий
            report_file: Файл для отчета о разрешении конфликтов (None = не сохранять)
            auto_resolve: Автоматически разрешать конфликты
        """
        self.output_file = Path(output_file)
        self.report_file = Path(report_file) if report_file else None
        self.auto_resolve = auto_resolve
        self.logger = logging.getLogger(__name__)

        self.resolver = DomainStrategyResolver()

    def save_strategies(
        self, strategies: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Сохранить стратегии с разрешением конфликтов.

        Args:
            strategies: {domain: {strategy: str, latency_ms: float, ...}}
            metadata: Дополнительные метаданные

        Returns:
            Унифицированные стратегии {canonical_domain: strategy}
        """
        self.logger.info(f"Saving {len(strategies)} strategies with conflict resolution")

        # Добавить стратегии в resolver
        self.resolver.add_strategies_from_dict(strategies)

        # Разрешить конфликты
        if self.auto_resolve:
            resolved = self.resolver.resolve_conflicts()
            self.logger.info(f"Resolved to {len(resolved)} canonical domains")
        else:
            # Без разрешения конфликтов - просто нормализовать домены
            resolved = {}
            for domain, data in strategies.items():
                canonical = self.resolver.normalize_domain(domain)
                if canonical not in resolved:
                    resolved[canonical] = ResolvedStrategy(
                        canonical_domain=canonical,
                        strategy=(data.get("strategy", "") if isinstance(data, dict) else data),
                        applies_to=[domain],
                        latency_ms=(data.get("latency_ms", 0.0) if isinstance(data, dict) else 0.0),
                        confidence=(data.get("confidence", 1.0) if isinstance(data, dict) else 1.0),
                    )

        # Экспортировать унифицированные стратегии
        unified = self.resolver.export_unified_strategies()

        # Подготовить данные для сохранения
        output_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_input_strategies": len(strategies),
                "unified_strategies": len(unified),
                "conflicts_resolved": len(strategies) - len(unified),
                **(metadata or {}),
            },
            "strategies": unified,
        }

        # Сохранить унифицированные стратегии
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Saved unified strategies to {self.output_file}")

        # Сохранить отчет о разрешении конфликтов
        if self.report_file:
            report = self.resolver.export_detailed_report()
            report["metadata"] = output_data["metadata"]

            self.report_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Saved resolution report to {self.report_file}")

        return unified

    def load_strategies(self) -> Dict[str, str]:
        """
        Загрузить сохраненные стратегии.

        Returns:
            {canonical_domain: strategy}
        """
        if not self.output_file.exists():
            self.logger.warning(f"Strategies file not found: {self.output_file}")
            return {}

        with open(self.output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        strategies = data.get("strategies", {})
        self.logger.info(f"Loaded {len(strategies)} strategies from {self.output_file}")

        return strategies

    def get_strategy_for_domain(self, domain: str) -> Optional[str]:
        """
        Получить стратегию для домена (с поддержкой www/non-www).

        Args:
            domain: Домен (может быть с www или без)

        Returns:
            Стратегия или None
        """
        strategies = self.load_strategies()

        # Нормализовать домен
        canonical = self.resolver.normalize_domain(domain)

        # Прямое совпадение
        if canonical in strategies:
            return strategies[canonical]

        # Поиск родительского домена для поддоменов
        parts = canonical.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in strategies:
                self.logger.debug(f"Using parent domain strategy: {domain} -> {parent}")
                return strategies[parent]

        return None

    def merge_with_existing(
        self, new_strategies: Dict[str, Any], prefer_new: bool = True
    ) -> Dict[str, str]:
        """
        Объединить новые стратегии с существующими.

        Args:
            new_strategies: Новые стратегии
            prefer_new: Предпочитать новые стратегии при конфликтах

        Returns:
            Объединенные стратегии
        """
        # Загрузить существующие
        existing = self.load_strategies()

        # Создать новый resolver
        resolver = DomainStrategyResolver()

        # Добавить существующие стратегии
        for domain, strategy in existing.items():
            resolver.add_strategy(
                domain=domain,
                strategy=strategy,
                latency_ms=0.0,
                confidence=0.8,  # Средний confidence для старых стратегий
                source="existing",
            )

        # Добавить новые стратегии
        for domain, data in new_strategies.items():
            if isinstance(data, dict):
                resolver.add_strategy(
                    domain=domain,
                    strategy=data.get("strategy", ""),
                    latency_ms=data.get("latency_ms", 0.0),
                    confidence=data.get("confidence", 1.0) if prefer_new else 0.9,
                    source="new",
                )
            else:
                resolver.add_strategy(
                    domain=domain,
                    strategy=data,
                    latency_ms=0.0,
                    confidence=1.0 if prefer_new else 0.9,
                    source="new",
                )

        # Разрешить конфликты
        resolver.resolve_conflicts()

        # Сохранить
        unified = resolver.export_unified_strategies()

        output_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_strategies": len(unified),
                "existing_strategies": len(existing),
                "new_strategies": len(new_strategies),
                "merge_mode": "prefer_new" if prefer_new else "prefer_existing",
            },
            "strategies": unified,
        }

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        self.logger.info(
            f"Merged {len(existing)} existing + {len(new_strategies)} new = {len(unified)} unified strategies"
        )

        return unified

    def print_conflicts_report(self):
        """Вывести отчет о конфликтах"""
        if not self.report_file or not self.report_file.exists():
            self.logger.warning("No resolution report available")
            return

        with open(self.report_file, "r", encoding="utf-8") as f:
            report = json.load(f)

        print("\n" + "=" * 80)
        print("STRATEGY RESOLUTION REPORT")
        print("=" * 80)
        print(f"Total strategies: {report['total_strategies']}")
        print(f"Resolved domains: {report['resolved_domains']}")
        print(f"Conflicts detected: {report['conflicts_detected']}")

        if report["conflicts_detected"] > 0:
            print("\n" + "-" * 80)
            print("CONFLICTS RESOLVED:")
            print("-" * 80)

            for strategy in report["strategies"]:
                if strategy.get("has_conflict"):
                    print(f"\n{strategy['canonical_domain']}:")
                    print(f"  Strategy: {strategy['strategy'][:80]}...")
                    print(f"  Applies to: {', '.join(strategy['applies_to'])}")
                    print(f"  Latency: {strategy['latency_ms']:.1f}ms")
                    print(f"  Confidence: {strategy['confidence']:.2f}")

        print("\n" + "=" * 80)


def save_unified_strategies(
    strategies: Dict[str, Any],
    output_file: str = "unified_strategies.json",
    report_file: Optional[str] = "strategy_resolution_report.json",
) -> Dict[str, str]:
    """
    Удобная функция для быстрого сохранения с разрешением конфликтов.

    Args:
        strategies: {domain: {strategy: str, latency_ms: float, ...}}
        output_file: Файл для сохранения
        report_file: Файл для отчета

    Returns:
        Унифицированные стратегии
    """
    saver = UnifiedStrategySaver(output_file, report_file)
    return saver.save_strategies(strategies)


# Пример использования
if __name__ == "__main__":
    # Пример данных из вашего лога
    strategies = {
        "www.x.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
            "latency_ms": 2317.8,
            "confidence": 0.95,
            "success_rate": 1.0,
        },
        "x.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1254.4,
            "confidence": 0.90,
            "success_rate": 1.0,
        },
        "mobile.x.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1264.3,
            "confidence": 0.90,
            "success_rate": 1.0,
        },
        "www.youtube.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            "latency_ms": 634.6,
            "confidence": 0.95,
            "success_rate": 1.0,
        },
        "youtube.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 1782.4,
            "confidence": 0.90,
            "success_rate": 1.0,
        },
        "www.facebook.com": {
            "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=4 --dpi-desync-ttl=4",
            "latency_ms": 201.9,
            "confidence": 0.95,
            "success_rate": 1.0,
        },
        "facebook.com": {
            "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
            "latency_ms": 2279.9,
            "confidence": 0.90,
            "success_rate": 1.0,
        },
    }

    # Сохранить с разрешением конфликтов
    saver = UnifiedStrategySaver(
        output_file="unified_strategies.json",
        report_file="strategy_resolution_report.json",
    )

    unified = saver.save_strategies(strategies)

    print("\n" + "=" * 80)
    print("UNIFIED STRATEGIES SAVED")
    print("=" * 80)
    for domain, strategy in unified.items():
        print(f"{domain}: {strategy[:80]}...")

    # Вывести отчет
    saver.print_conflicts_report()

    # Тест получения стратегии
    print("\n" + "=" * 80)
    print("STRATEGY LOOKUP TEST")
    print("=" * 80)

    test_domains = ["x.com", "www.x.com", "mobile.x.com", "api.x.com"]
    for domain in test_domains:
        strategy = saver.get_strategy_for_domain(domain)
        if strategy:
            print(f"{domain}: {strategy[:60]}...")
        else:
            print(f"{domain}: No strategy found")
