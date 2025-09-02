# core/learning/cache.py
import pickle
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
import statistics
from typing import Dict, Any, Optional, Tuple, List
import logging

# Use standard logging instead of rich console
logger = logging.getLogger(__name__)


@dataclass
class StrategyPerformanceRecord:
    """Запись о производительности стратегии."""

    strategy: str  # This will become a dict
    domain: str
    ip: str
    success_rate: float
    avg_latency: float
    timestamp: str
    dpi_fingerprint_hash: str = ""
    test_count: int = 1

    def update_performance(self, success_rate=None, avg_latency=None, latency=None):
        """Обновляет производительность с учетом нового теста."""
        alpha = 0.3  # Коэффициент обучения
        if success_rate is not None:
            self.success_rate = alpha * success_rate + (1 - alpha) * self.success_rate
        if avg_latency is not None:
            self.avg_latency = alpha * avg_latency + (1 - alpha) * self.avg_latency
        if latency is not None:
            self.avg_latency = alpha * latency + (1 - alpha) * self.avg_latency
        self.test_count += 1
        self.timestamp = datetime.now().isoformat()


class AdaptiveLearningCache:
    """Система адаптивного кэширования и обучения."""

    def __init__(self, cache_file: str = "recon_learning_cache.pkl"):
        self.cache_file = Path(cache_file)
        self.strategy_records: Dict[str, StrategyPerformanceRecord] = {}
        self.domain_patterns: Dict[str, Dict[str, float]] = (
            {}
        )  # domain -> {strategy_type: success_rate}
        self.dpi_patterns: Dict[str, Dict[str, float]] = (
            {}
        )  # dpi_hash -> {strategy_type: success_rate}
        self.load_cache()

    def _strategy_to_string(self, strategy: Dict[str, Any]) -> str:
        """Converts a strategy dictionary to a stable string for hashing."""
        if not isinstance(strategy, dict):
            return str(strategy)  # Fallback for old format

        parts = [f"name={strategy.get('name', 'unknown')}"]
        params = strategy.get("params", {})
        for key in sorted(params.keys()):
            parts.append(f"{key}={params[key]}")
        return ";".join(parts)

    def _strategy_key(self, strategy: Dict[str, Any], domain: str, ip: str) -> str:
        """Создает уникальный ключ для стратегии."""
        strategy_str = self._strategy_to_string(strategy)
        strategy_hash = hashlib.md5(strategy_str.encode()).hexdigest()[:8]
        return f"{domain}_{ip}_{strategy_hash}"

    def _extract_strategy_type(self, strategy: Dict[str, Any]) -> str:
        """Извлекает тип стратегии из словаря."""
        if isinstance(strategy, dict):
            return strategy.get("name", "unknown")

        # Fallback for old string-based format
        if "--dpi-desync=" in strategy:
            value = strategy.split("--dpi-desync=")[1].split()[0]
            parts = value.split(",")
            for part in parts:
                if "fakedisorder" in part or "fakeddisorder" in part:
                    return "fakedisorder"
                if part == "multisplit":
                    return "multisplit"
                if part == "seqovl":
                    return "seqovl"
                if part == "badsum_race":
                    return "badsum_race"
                if part == "md5sig_race":
                    return "md5sig_race"
        if "fakedisorder" in strategy or "fakeddisorder" in strategy:
            return "fakedisorder"
        elif "multisplit" in strategy:
            return "multisplit"
        elif "seqovl" in strategy:
            return "seqovl"
        elif "badsum_race" in strategy:
            return "badsum_race"
        elif "md5sig_race" in strategy or "md5sig" in strategy:
            return "md5sig_race"
        elif "badsum" in strategy:
            return "badsum"
        else:
            return "unknown"

    def record_strategy_performance(
        self,
        strategy: Dict[str, Any],  # Changed to dict
        domain: str,
        ip: str,
        success_rate: float,
        avg_latency: float,
        dpi_fingerprint_hash: str = "",
    ):
        """Записывает производительность стратегии."""
        key = self._strategy_key(strategy, domain, ip)

        if key in self.strategy_records:
            self.strategy_records[key].update_performance(success_rate, avg_latency)
        else:
            self.strategy_records[key] = StrategyPerformanceRecord(
                strategy=self._strategy_to_string(
                    strategy
                ),  # Store as string for record
                domain=domain,
                ip=ip,
                success_rate=success_rate,
                avg_latency=avg_latency,
                timestamp=datetime.now().isoformat(),
                dpi_fingerprint_hash=dpi_fingerprint_hash,
            )

        strategy_type = self._extract_strategy_type(strategy)
        if domain not in self.domain_patterns:
            self.domain_patterns[domain] = {}

        if strategy_type in self.domain_patterns[domain]:
            alpha = 0.2
            old_rate = self.domain_patterns[domain][strategy_type]
            self.domain_patterns[domain][strategy_type] = (
                alpha * success_rate + (1 - alpha) * old_rate
            )
        else:
            self.domain_patterns[domain][strategy_type] = success_rate

        if dpi_fingerprint_hash:
            if dpi_fingerprint_hash not in self.dpi_patterns:
                self.dpi_patterns[dpi_fingerprint_hash] = {}
            if strategy_type in self.dpi_patterns[dpi_fingerprint_hash]:
                alpha = 0.2
                old_rate = self.dpi_patterns[dpi_fingerprint_hash][strategy_type]
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = (
                    alpha * success_rate + (1 - alpha) * old_rate
                )
            else:
                self.dpi_patterns[dpi_fingerprint_hash][strategy_type] = success_rate

    def get_strategy_prediction(
        self, strategy: Dict[str, Any], domain: str, ip: str
    ) -> Optional[float]:
        """Предсказывает успешность стратегии на основе истории."""
        key = self._strategy_key(strategy, domain, ip)
        if key in self.strategy_records:
            record = self.strategy_records[key]
            age_hours = (
                datetime.now() - datetime.fromisoformat(record.timestamp)
            ).total_seconds() / 3600
            confidence = max(0.1, 1.0 - age_hours / (24 * 7))
            return record.success_rate * confidence
        return None

    def get_domain_recommendations(
        self, domain: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для домена."""
        if domain in self.domain_patterns:
            patterns = self.domain_patterns[domain]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_dpi_recommendations(
        self, dpi_fingerprint_hash: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Возвращает рекомендуемые типы стратегий для DPI."""
        if dpi_fingerprint_hash in self.dpi_patterns:
            patterns = self.dpi_patterns[dpi_fingerprint_hash]
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            return sorted_patterns[:top_n]
        return []

    def get_smart_strategy_order(
        self,
        strategies: List[Dict[str, Any]],
        domain: str,
        ip: str,
        dpi_fingerprint_hash: str = "",
    ) -> List[Dict[str, Any]]:
        """Умно сортирует стратегии по предполагаемой эффективности."""
        strategy_scores = []

        for strategy in strategies:
            score = 0.0
            prediction = self.get_strategy_prediction(strategy, domain, ip)
            if prediction is not None:
                score += prediction * 0.6
            strategy_type = self._extract_strategy_type(strategy)
            domain_recs = dict(self.get_domain_recommendations(domain, 10))
            if strategy_type in domain_recs:
                score += domain_recs[strategy_type] * 0.25
            if dpi_fingerprint_hash:
                dpi_recs = dict(self.get_dpi_recommendations(dpi_fingerprint_hash, 10))
                if strategy_type in dpi_recs:
                    score += dpi_recs[strategy_type] * 0.15
            strategy_scores.append((strategy, score))

        strategy_scores.sort(key=lambda x: x[1], reverse=True)
        return [strategy for strategy, _ in strategy_scores]

    def save_cache(self):
        """Сохраняет кэш в файл."""
        try:
            cache_data = {
                "strategy_records": self.strategy_records,
                "domain_patterns": self.domain_patterns,
                "dpi_patterns": self.dpi_patterns,
                "version": "1.1",  # Bump version for new dict format
                "saved_at": datetime.now().isoformat(),
            }
            with open(self.cache_file, "wb") as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            logger.warning(f"Warning: Could not save learning cache: {e}")

    def load_cache(self):
        """Загружает кэш из файла."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "rb") as f:
                    cache_data = pickle.load(f)

                # Basic validation
                if not isinstance(cache_data, dict):
                    logger.warning("Invalid cache format. Starting fresh.")
                    return

                self.strategy_records = cache_data.get("strategy_records", {})
                self.domain_patterns = cache_data.get("domain_patterns", {})
                self.dpi_patterns = cache_data.get("dpi_patterns", {})

                logger.info(
                    f"Loaded learning cache: {len(self.strategy_records)} records, "
                    f"{len(self.domain_patterns)} domain patterns"
                )
        except Exception as e:
            logger.warning(f"Warning: Could not load learning cache: {e}")
            self.strategy_records = {}
            self.domain_patterns = {}
            self.dpi_patterns = {}

    def get_cache_stats(self) -> dict:
        """Возвращает статистику кэша."""
        total_tests = sum(
            record.test_count for record in self.strategy_records.values()
        )
        avg_success_rate = (
            statistics.mean(
                [record.success_rate for record in self.strategy_records.values()]
            )
            if self.strategy_records
            else 0
        )

        return {
            "total_strategy_records": len(self.strategy_records),
            "total_tests_performed": total_tests,
            "domains_learned": len(self.domain_patterns),
            "dpi_patterns_learned": len(self.dpi_patterns),
            "average_success_rate": avg_success_rate,
        }
