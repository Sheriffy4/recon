# core/strategy/domain_strategy_resolver.py
"""
Domain Strategy Resolver - Унифицирует стратегии для доменов с www/без www.
Решает конфликты когда для www.example.com и example.com разные стратегии.
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict

LOG = logging.getLogger(__name__)


@dataclass
class DomainStrategy:
    """Стратегия для домена"""

    domain: str
    strategy: str
    latency_ms: float
    success_rate: float = 1.0
    confidence: float = 1.0
    source: str = "unknown"  # откуда стратегия: recon, fingerprint, manual

    def __repr__(self):
        return f"DomainStrategy({self.domain}, {self.strategy[:50]}..., {self.latency_ms:.1f}ms)"


@dataclass
class ResolvedStrategy:
    """Разрешенная стратегия после унификации"""

    canonical_domain: str  # канонический домен (без www)
    strategy: str
    applies_to: List[str]  # список доменов к которым применяется
    latency_ms: float
    confidence: float
    reasoning: List[str] = field(default_factory=list)


class DomainStrategyResolver:
    """
    Унифицирует стратегии для доменов.

    Правила:
    1. www.example.com и example.com считаются одним доменом
    2. Если стратегии разные, выбирается лучшая (по latency + confidence)
    3. Поддомены (api.example.com) обрабатываются отдельно
    4. Wildcard стратегии (*.example.com) применяются к поддоменам
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.strategies: Dict[str, DomainStrategy] = {}
        self.resolved: Dict[str, ResolvedStrategy] = {}

    def add_strategy(
        self,
        domain: str,
        strategy: str,
        latency_ms: float,
        success_rate: float = 1.0,
        confidence: float = 1.0,
        source: str = "unknown",
    ):
        """Добавить стратегию для домена"""
        ds = DomainStrategy(
            domain=domain,
            strategy=strategy,
            latency_ms=latency_ms,
            success_rate=success_rate,
            confidence=confidence,
            source=source,
        )
        self.strategies[domain] = ds
        self.logger.debug(f"Added strategy for {domain}: {strategy[:50]}...")

    def add_strategies_from_dict(self, strategies_dict: Dict[str, Any]):
        """
        Добавить стратегии из словаря (формат из recon_summary.json).

        Args:
            strategies_dict: {domain: {strategy: str, latency_ms: float, ...}}
        """
        for domain, data in strategies_dict.items():
            if isinstance(data, dict):
                self.add_strategy(
                    domain=domain,
                    strategy=data.get("strategy", ""),
                    latency_ms=data.get("latency_ms", 0.0),
                    success_rate=data.get("success_rate", 1.0),
                    confidence=data.get("confidence", 1.0),
                    source=data.get("source", "recon"),
                )
            elif isinstance(data, str):
                # Простой формат: domain -> strategy
                self.add_strategy(
                    domain=domain, strategy=data, latency_ms=0.0, source="manual"
                )

    def normalize_domain(self, domain: str) -> str:
        """
        Нормализовать домен к каноническому виду.

        www.example.com -> example.com
        WWW.EXAMPLE.COM -> example.com
        """
        domain = domain.lower().strip()

        # Убрать www. префикс
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    def get_domain_variants(self, domain: str) -> List[str]:
        """
        Получить все варианты домена.

        example.com -> [example.com, www.example.com]
        """
        canonical = self.normalize_domain(domain)
        variants = [canonical]

        # Добавить www вариант если его нет
        if not domain.startswith("www."):
            variants.append(f"www.{canonical}")

        return variants

    def is_subdomain(self, domain: str, parent: str) -> bool:
        """
        Проверить является ли domain поддоменом parent.

        api.example.com является поддоменом example.com
        example.com НЕ является поддоменом example.com
        """
        domain = self.normalize_domain(domain)
        parent = self.normalize_domain(parent)

        if domain == parent:
            return False

        return domain.endswith("." + parent)

    def resolve_conflicts(self) -> Dict[str, ResolvedStrategy]:
        """
        Разрешить конфликты между стратегиями.

        Returns:
            Dict[canonical_domain, ResolvedStrategy]
        """
        self.resolved = {}

        # Группировать домены по каноническому виду
        domain_groups = defaultdict(list)

        for domain, strategy in self.strategies.items():
            canonical = self.normalize_domain(domain)
            domain_groups[canonical].append((domain, strategy))

        # Разрешить конфликты в каждой группе
        for canonical, group in domain_groups.items():
            resolved = self._resolve_group(canonical, group)
            self.resolved[canonical] = resolved

        self.logger.info(
            f"Resolved {len(self.resolved)} canonical domains from {len(self.strategies)} strategies"
        )

        return self.resolved

    def _resolve_group(
        self, canonical: str, group: List[Tuple[str, DomainStrategy]]
    ) -> ResolvedStrategy:
        """
        Разрешить конфликт в группе доменов.

        Правила выбора:
        1. Если стратегии одинаковые -> выбрать любую
        2. Если разные -> выбрать с лучшим score (latency * confidence)
        3. Если score одинаковый -> выбрать с меньшим latency
        """
        if len(group) == 1:
            # Нет конфликта
            domain, strategy = group[0]
            return ResolvedStrategy(
                canonical_domain=canonical,
                strategy=strategy.strategy,
                applies_to=[domain],
                latency_ms=strategy.latency_ms,
                confidence=strategy.confidence,
                reasoning=[f"Single strategy for {domain}"],
            )

        # Проверить одинаковые ли стратегии
        strategies_set = set(s.strategy for _, s in group)

        if len(strategies_set) == 1:
            # Все стратегии одинаковые
            domains = [d for d, _ in group]
            strategy = group[0][1]

            return ResolvedStrategy(
                canonical_domain=canonical,
                strategy=strategy.strategy,
                applies_to=domains,
                latency_ms=min(s.latency_ms for _, s in group),
                confidence=max(s.confidence for _, s in group),
                reasoning=[f"Same strategy for all variants: {', '.join(domains)}"],
            )

        # Стратегии разные - выбрать лучшую
        self.logger.warning(
            f"Conflict detected for {canonical}: {len(strategies_set)} different strategies"
        )

        # Вычислить score для каждой стратегии
        scored = []
        for domain, strategy in group:
            # Score: чем меньше latency и выше confidence, тем лучше
            # Нормализуем latency к [0, 1] (предполагаем max 5000ms)
            normalized_latency = min(strategy.latency_ms / 5000.0, 1.0)

            # Score = confidence * (1 - normalized_latency)
            # Высокий confidence и низкий latency дают высокий score
            score = strategy.confidence * (1.0 - normalized_latency)

            scored.append((score, domain, strategy))

        # Сортировать по score (убывание)
        scored.sort(reverse=True, key=lambda x: x[0])

        best_score, best_domain, best_strategy = scored[0]

        # Собрать reasoning
        reasoning = [
            f"Conflict resolved for {canonical}:",
            f"  Selected: {best_domain} (score: {best_score:.3f}, latency: {best_strategy.latency_ms:.1f}ms)",
        ]

        for score, domain, strategy in scored[1:]:
            reasoning.append(
                f"  Rejected: {domain} (score: {score:.3f}, latency: {strategy.latency_ms:.1f}ms)"
            )

        self.logger.info("\n".join(reasoning))

        return ResolvedStrategy(
            canonical_domain=canonical,
            strategy=best_strategy.strategy,
            applies_to=[d for d, _ in group],
            latency_ms=best_strategy.latency_ms,
            confidence=best_strategy.confidence,
            reasoning=reasoning,
        )

    def get_strategy_for_domain(self, domain: str) -> Optional[ResolvedStrategy]:
        """
        Получить стратегию для домена.

        Args:
            domain: Домен (может быть с www или без)

        Returns:
            ResolvedStrategy или None если не найдено
        """
        canonical = self.normalize_domain(domain)

        # Прямое совпадение
        if canonical in self.resolved:
            return self.resolved[canonical]

        # Поиск родительского домена для поддоменов
        # api.example.com -> example.com
        parts = canonical.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.resolved:
                self.logger.debug(f"Using parent domain strategy: {domain} -> {parent}")
                return self.resolved[parent]

        return None

    def export_unified_strategies(self) -> Dict[str, str]:
        """
        Экспортировать унифицированные стратегии.

        Returns:
            Dict[canonical_domain, strategy]
        """
        return {
            canonical: resolved.strategy
            for canonical, resolved in self.resolved.items()
        }

    def export_detailed_report(self) -> Dict[str, Any]:
        """
        Экспортировать детальный отчет.

        Returns:
            Dict с полной информацией о разрешении конфликтов
        """
        report = {
            "total_strategies": len(self.strategies),
            "resolved_domains": len(self.resolved),
            "conflicts_detected": 0,
            "strategies": [],
        }

        for canonical, resolved in self.resolved.items():
            strategy_info = {
                "canonical_domain": canonical,
                "strategy": resolved.strategy,
                "applies_to": resolved.applies_to,
                "latency_ms": resolved.latency_ms,
                "confidence": resolved.confidence,
                "has_conflict": len(resolved.applies_to) > 1
                and len(set(self.strategies[d].strategy for d in resolved.applies_to))
                > 1,
                "reasoning": resolved.reasoning,
            }

            if strategy_info["has_conflict"]:
                report["conflicts_detected"] += 1

            report["strategies"].append(strategy_info)

        return report

    def print_report(self):
        """Вывести отчет в консоль"""
        report = self.export_detailed_report()

        print("\n" + "=" * 80)
        print("DOMAIN STRATEGY RESOLUTION REPORT")
        print("=" * 80)
        print(f"Total strategies: {report['total_strategies']}")
        print(f"Resolved domains: {report['resolved_domains']}")
        print(f"Conflicts detected: {report['conflicts_detected']}")

        if report["conflicts_detected"] > 0:
            print("\n" + "-" * 80)
            print("CONFLICTS RESOLVED:")
            print("-" * 80)

            for strategy in report["strategies"]:
                if strategy["has_conflict"]:
                    print(f"\n{strategy['canonical_domain']}:")
                    print(f"  Strategy: {strategy['strategy'][:80]}...")
                    print(f"  Applies to: {', '.join(strategy['applies_to'])}")
                    print(f"  Latency: {strategy['latency_ms']:.1f}ms")
                    print(f"  Confidence: {strategy['confidence']:.2f}")
                    if strategy["reasoning"]:
                        print("  Reasoning:")
                        for reason in strategy["reasoning"]:
                            print(f"    {reason}")

        print("\n" + "=" * 80)


def resolve_domain_strategies(strategies_dict: Dict[str, Any]) -> Dict[str, str]:
    """
    Удобная функция для быстрого разрешения конфликтов.

    Args:
        strategies_dict: {domain: {strategy: str, latency_ms: float, ...}}

    Returns:
        {canonical_domain: strategy}
    """
    resolver = DomainStrategyResolver()
    resolver.add_strategies_from_dict(strategies_dict)
    resolver.resolve_conflicts()
    return resolver.export_unified_strategies()


# Пример использования
if __name__ == "__main__":
    # Пример данных из вашего лога
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
    }

    resolver = DomainStrategyResolver()
    resolver.add_strategies_from_dict(strategies)
    resolver.resolve_conflicts()
    resolver.print_report()

    # Получить унифицированные стратегии
    unified = resolver.export_unified_strategies()

    print("\n" + "=" * 80)
    print("UNIFIED STRATEGIES:")
    print("=" * 80)
    for domain, strategy in unified.items():
        print(f"{domain}: {strategy[:80]}...")
