# recon/core/strategy_manager.py - Управление стратегиями по доменам

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any, List
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class DomainStrategy:
    """Стратегия для конкретного домена."""

    domain: str
    strategy: str
    success_rate: float
    avg_latency_ms: float
    last_tested: str
    test_count: int = 1
    # --- Новые микропараметры для калибратора ---
    split_pos: Optional[int] = None
    overlap_size: Optional[int] = None
    fake_ttl_source: Optional[Any] = None
    fooling_modes: Optional[List[str]] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "DomainStrategy":
        return cls(**data)


class StrategyManager:
    """Менеджер стратегий для доменов."""

    def __init__(
        self,
        strategies_file: str = "domain_strategies.json",
        legacy_file: str = "best_strategy.json",
    ):
        self.strategies_file = Path(strategies_file)
        self.legacy_file = Path(legacy_file)
        self.domain_strategies: Dict[str, DomainStrategy] = {}
        self.logger = logging.getLogger(__name__)
        self.load_strategies()

    def load_strategies(self):
        """Загружает стратегии из файла."""
        # Сначала пытаемся загрузить из нового формата
        if self.strategies_file.exists():
            try:
                with open(self.strategies_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for domain, strategy_data in data.get("domain_strategies", {}).items():
                    self.domain_strategies[domain] = DomainStrategy.from_dict(
                        strategy_data
                    )

                self.logger.info(
                    f"Loaded {len(self.domain_strategies)} domain strategies"
                )
                return
            except Exception as e:
                self.logger.warning(
                    f"Failed to load strategies from {self.strategies_file}: {e}"
                )

        # Fallback к старому формату
        if self.legacy_file.exists():
            try:
                with open(self.legacy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Конвертируем старый формат
                if "strategy" in data:
                    # Это старый формат с одной стратегией
                    domain = "default"  # Используем default для совместимости
                    strategy = DomainStrategy(
                        domain=domain,
                        strategy=data["strategy"],
                        success_rate=data.get("success_rate", 1.0),
                        avg_latency_ms=data.get("avg_latency_ms", 0.0),
                        last_tested=datetime.now().isoformat(),
                        test_count=1,
                    )
                    self.domain_strategies[domain] = strategy
                    self.logger.info("Converted legacy strategy for default domain")
            except Exception as e:
                self.logger.warning(
                    f"Failed to load legacy strategy from {self.legacy_file}: {e}"
                )

    def save_strategies(self):
        """Сохраняет стратегии в файл."""
        try:
            data = {
                "version": "2.0",
                "last_updated": datetime.now().isoformat(),
                "domain_strategies": {
                    domain: strategy.to_dict()
                    for domain, strategy in self.domain_strategies.items()
                },
            }

            with open(self.strategies_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Также сохраняем в старом формате для совместимости
            self.save_legacy_format()

            self.logger.info(f"Saved {len(self.domain_strategies)} domain strategies")
        except Exception as e:
            self.logger.error(f"Failed to save strategies: {e}")

    def save_legacy_format(self):
        """Сохраняет в старом формате для совместимости."""
        try:
            if not self.domain_strategies:
                return

            # Берем лучшую стратегию (с наибольшим success_rate)
            best_strategy = max(
                self.domain_strategies.values(), key=lambda s: s.success_rate
            )

            legacy_data = {
                "strategy": best_strategy.strategy,
                "success_rate": best_strategy.success_rate,
                "avg_latency_ms": best_strategy.avg_latency_ms,
                "domain": best_strategy.domain,
                "last_tested": best_strategy.last_tested,
                "format_version": "1.0_compat",
            }

            with open(self.legacy_file, "w", encoding="utf-8") as f:
                json.dump(legacy_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to save legacy format: {e}")

    def add_strategy(
        self, domain: str, strategy: str, success_rate: float, avg_latency_ms: float, **kwargs
    ):
        """Добавляет или обновляет стратегию для домена, включая микропараметры."""
        domain = domain.lower().strip()

        if domain in self.domain_strategies:
            # Обновляем существующую стратегию
            existing = self.domain_strategies[domain]
            existing.strategy = strategy
            existing.success_rate = success_rate
            existing.avg_latency_ms = avg_latency_ms
            existing.last_tested = datetime.now().isoformat()
            existing.test_count += 1
            # Update micro-parameters
            existing.split_pos = kwargs.get("split_pos", existing.split_pos)
            existing.overlap_size = kwargs.get("overlap_size", existing.overlap_size)
            existing.fake_ttl_source = kwargs.get("fake_ttl_source", existing.fake_ttl_source)
            existing.fooling_modes = kwargs.get("fooling_modes", existing.fooling_modes)
        else:
            # Создаем новую стратегию
            self.domain_strategies[domain] = DomainStrategy(
                domain=domain,
                strategy=strategy,
                success_rate=success_rate,
                avg_latency_ms=avg_latency_ms,
                last_tested=datetime.now().isoformat(),
                # Add micro-parameters
                split_pos=kwargs.get("split_pos"),
                overlap_size=kwargs.get("overlap_size"),
                fake_ttl_source=kwargs.get("fake_ttl_source"),
                fooling_modes=kwargs.get("fooling_modes"),
            )

        self.logger.info(f"Added/updated strategy for {domain}: {strategy} with params {kwargs}")

    def get_strategy(self, domain: str) -> Optional[DomainStrategy]:
        """Получает стратегию для домена."""
        domain = domain.lower().strip()
        return self.domain_strategies.get(domain)

    def get_all_strategies(self) -> Dict[str, DomainStrategy]:
        """Получает все стратегии."""
        return self.domain_strategies.copy()

    def get_best_strategy(self) -> Optional[DomainStrategy]:
        """Получает лучшую стратегию (с наибольшим success_rate)."""
        if not self.domain_strategies:
            return None
        return max(self.domain_strategies.values(), key=lambda s: s.success_rate)

    def get_strategies_for_service(self) -> Dict[str, str]:
        """Возвращает стратегии в формате для службы обхода."""
        return {
            domain: strategy.strategy
            for domain, strategy in self.domain_strategies.items()
        }

    def remove_strategy(self, domain: str) -> bool:
        """Удаляет стратегию для домена."""
        domain = domain.lower().strip()
        if domain in self.domain_strategies:
            del self.domain_strategies[domain]
            self.logger.info(f"Removed strategy for {domain}")
            return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Возвращает статистику стратегий."""
        if not self.domain_strategies:
            return {
                "total_domains": 0,
                "avg_success_rate": 0.0,
                "avg_latency": 0.0,
                "best_domain": None,
                "worst_domain": None,
            }

        strategies = list(self.domain_strategies.values())
        avg_success = sum(s.success_rate for s in strategies) / len(strategies)
        avg_latency = sum(s.avg_latency_ms for s in strategies) / len(strategies)

        best = max(strategies, key=lambda s: s.success_rate)
        worst = min(strategies, key=lambda s: s.success_rate)

        return {
            "total_domains": len(strategies),
            "avg_success_rate": avg_success,
            "avg_latency": avg_latency,
            "best_domain": best.domain,
            "best_success_rate": best.success_rate,
            "worst_domain": worst.domain,
            "worst_success_rate": worst.success_rate,
        }

    def cleanup_old_strategies(self, max_age_days: int = 30):
        """Удаляет старые стратегии."""
        from datetime import timedelta

        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        removed_count = 0

        domains_to_remove = []
        for domain, strategy in self.domain_strategies.items():
            try:
                last_tested = datetime.fromisoformat(strategy.last_tested)
                if last_tested < cutoff_date:
                    domains_to_remove.append(domain)
            except ValueError:
                # Неправильный формат даты, удаляем
                domains_to_remove.append(domain)

        for domain in domains_to_remove:
            del self.domain_strategies[domain]
            removed_count += 1

        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old strategies")

        return removed_count
