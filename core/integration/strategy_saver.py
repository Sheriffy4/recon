# recon/core/integration/strategy_saver.py
"""
Strategy Saver

Handles proper saving of effective strategies to best_strategy.json.
Validates strategy completeness and ensures only truly effective strategies are saved.
"""

import json
import time
import logging
import hashlib
import random
from typing import Dict, List, Any, Optional
from pathlib import Path

# Импортируем synth для преобразования нативных задач в zapret-команды
from ..zapret import synth

LOG = logging.getLogger("StrategySaver")


class StrategySaver:
    def __init__(
        self,
        strategy_file: str = "best_strategy.json",
        max_strategies_per_fingerprint: int = 5,
    ):
        """
        Initialize strategy saver.

        Args:
            strategy_file: Path to strategy file
            max_strategies_per_fingerprint: Maximum number of strategies to keep per fingerprint
        """
        self.strategy_file = strategy_file
        self.max_strategies_per_fingerprint = max_strategies_per_fingerprint
        # Пороги для валидации, если нет данных от RealEffectivenessTester
        self.min_success_rate = 0.7
        self.max_latency_threshold = 4000  # 4 секунды

    def save_effective_strategies(self, strategies: List[Dict[str, Any]]) -> bool:
        """
        Save only truly effective strategies to best_strategy.json.

        Args:
            strategies: List of strategy dictionaries to evaluate and save

        Returns:
            True if strategies were saved successfully, False otherwise
        """
        try:
            LOG.info(f"Evaluating {len(strategies)} strategies for saving")

            # 1. Фильтруем и форматируем только эффективные стратегии
            effective_strategies = []
            for strategy in strategies:
                if self.validate_strategy_effectiveness(strategy):
                    formatted_strategy = self.format_strategy_for_service(strategy)
                    if formatted_strategy:
                        effective_strategies.append(formatted_strategy)

            if not effective_strategies:
                LOG.warning("No effective strategies found to save after validation.")
                return False

            # 2. Загружаем существующие стратегии
            existing_config = self._load_existing_strategies()

            # 3. Объединяем старые и новые, оставляя только лучшие
            merged_config = self._merge_strategies(
                existing_config, effective_strategies
            )

            # 4. Сохраняем результат
            return self._save_to_file(merged_config)

        except Exception as e:
            LOG.error(f"Failed to save effective strategies: {e}", exc_info=True)
            return False

    def validate_strategy_effectiveness(self, strategy: Dict[str, Any]) -> bool:
        """
        Validate that a strategy is truly effective, prioritizing real-world test results.
        """
        try:
            # ПРИОРИТЕТ №1: Результат от RealEffectivenessTester
            # Это самый надежный источник.
            if strategy.get("bypass_effective") is True:
                LOG.info(
                    f"Strategy '{strategy.get('attack_name')}' confirmed effective by real-world test."
                )
                return self.validate_strategy_completeness(strategy)

            # Fallback-логика, если нет данных от RealEffectivenessTester
            if not self.validate_strategy_completeness(strategy):
                return False

            success_rate = strategy.get("success_rate", 0)
            if success_rate < self.min_success_rate:
                LOG.debug(
                    f"Strategy rejected: low success rate {success_rate:.2f} < {self.min_success_rate:.2f}"
                )
                return False

            avg_latency = strategy.get("avg_latency_ms", float("inf"))
            if avg_latency > self.max_latency_threshold:
                LOG.debug(
                    f"Strategy rejected: high latency {avg_latency:.1f}ms > {self.max_latency_threshold:.1f}ms"
                )
                return False

            if self._is_false_positive(strategy):
                LOG.debug("Strategy rejected: appears to be a false positive")
                return False

            LOG.info(
                f"Strategy validated as effective based on metrics: {strategy.get('attack_name', 'unknown')}"
            )
            return True

        except Exception as e:
            LOG.error(f"Error validating strategy effectiveness: {e}")
            return False

    def validate_strategy_completeness(self, strategy: Dict[str, Any]) -> bool:
        """
        Validate that a strategy dictionary has all required fields for saving.
        """
        # Для сохранения нам нужна сама задача (task), чтобы ее можно было отформатировать
        required_fields = ["task", "domains", "fingerprint_summary"]

        for field in required_fields:
            if field not in strategy or not strategy[field]:
                LOG.warning(
                    f"Strategy validation failed: missing or empty required field '{field}'."
                )
                return False

        return True

    def format_strategy_for_service(
        self, strategy: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Formats a strategy into the standardized structure for best_strategy.json.
        Decides whether to save it as a 'zapret' command or a 'native' task.
        """
        try:
            task_data = strategy.get("task", {})
            if not task_data:
                LOG.warning("Cannot format strategy: 'task' data is missing.")
                return None

            # Пытаемся синтезировать zapret-команду из нативной задачи
            zapret_command = synth(task_data)

            formatted = {
                "domains": strategy.get("domains", []),
                "fingerprint_summary": strategy.get("fingerprint_summary", "N/A"),
                "metrics": {
                    "success_rate": float(strategy.get("success_rate", 0)),
                    "avg_latency_ms": float(strategy.get("avg_latency_ms", 0)),
                    "bypass_effective": strategy.get("bypass_effective", False),
                },
                "timestamp": time.time(),
                "version": "3.1",
            }

            # Решаем, в каком режиме сохранить стратегию
            if zapret_command and not zapret_command.strip().startswith("#"):
                # Если synth вернул валидную команду, используем режим zapret
                formatted["mode"] = "zapret"
                formatted["config"] = {"command": zapret_command}
                LOG.info(
                    f"Strategy '{task_data.get('name')}' formatted for 'zapret' mode."
                )
            else:
                # Если команда невалидна или это сложная комбо-атака, сохраняем в нативном режиме
                formatted["mode"] = "native"
                formatted["config"] = task_data  # Сохраняем саму задачу
                LOG.info(
                    f"Strategy '{task_data.get('name')}' formatted for 'native' mode."
                )

            return formatted
        except Exception as e:
            LOG.error(f"Failed to format strategy: {e}", exc_info=True)
            return None

    def _load_existing_strategies(self) -> Dict[str, Any]:
        """Load existing strategies from file."""
        try:
            if Path(self.strategy_file).exists():
                with open(self.strategy_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            LOG.warning(f"Could not load existing strategies: {e}")

        # Return default structure if file doesn't exist or is invalid
        return {
            "metadata": {"version": "3.1", "last_updated": time.time()},
            "strategies_by_fingerprint": {},
        }

    def _merge_strategies(
        self, existing_config: Dict[str, Any], new_strategies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Merge new strategies with existing ones, keeping a sorted and deduplicated list of the best strategies.
        Enhanced with configurable limits and improved sorting criteria.
        """
        try:
            existing_config["metadata"]["last_updated"] = time.time()
            strategies_by_fp = existing_config.get("strategies_by_fingerprint", {})

            for strategy in new_strategies:
                fp_hash = self._generate_fingerprint_hash(strategy)

                # Получаем существующий список или создаем новый
                existing_list = strategies_by_fp.get(fp_hash, [])
                existing_list.append(strategy)

                # Сортируем по улучшенным критериям эффективности
                sorted_strategies = self._sort_strategies_by_effectiveness(
                    existing_list
                )

                # Убираем дубликаты, оставляя только лучшие
                unique_strategies = self._deduplicate_strategies(sorted_strategies)

                # Обрезаем до максимального количества стратегий
                trimmed_strategies = unique_strategies[
                    : self.max_strategies_per_fingerprint
                ]

                strategies_by_fp[fp_hash] = trimmed_strategies
                LOG.info(
                    f"Updated strategies for fingerprint {fp_hash}. Now have {len(trimmed_strategies)} unique options (limit: {self.max_strategies_per_fingerprint})."
                )

            existing_config["strategies_by_fingerprint"] = strategies_by_fp
            return existing_config

        except Exception as e:
            LOG.error(f"Failed to merge strategies: {e}", exc_info=True)
            return existing_config

    def _save_to_file(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            with open(self.strategy_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            fingerprint_count = len(config.get("strategies_by_fingerprint", {}))
            LOG.info(
                f"Successfully saved strategies for {fingerprint_count} fingerprints to {self.strategy_file}"
            )
            return True

        except Exception as e:
            LOG.error(f"Failed to save strategies to file: {e}")
            return False

    def _check_bypass_effectiveness(self, strategy: Dict[str, Any]) -> bool:
        """Check if strategy shows real bypass effectiveness."""
        try:
            # Check latency improvement (bypass should be significantly faster)
            avg_latency = strategy.get("avg_latency_ms", 0)

            # If latency is very low (< 2000ms), it's likely a real bypass
            if avg_latency < 2000:
                return True

            # Check for baseline comparison if available
            task = strategy.get("task", {})
            if "baseline_latency" in task:
                baseline_latency = task["baseline_latency"]
                improvement = (baseline_latency - avg_latency) / baseline_latency
                return improvement > self.bypass_effectiveness_threshold

            # Check success rate and latency combination
            success_rate = strategy.get("success_rate", 0)
            if success_rate >= 0.9 and avg_latency < 2500:
                return True

            return False

        except Exception as e:
            LOG.error(f"Error checking bypass effectiveness: {e}")
            return False

    def _is_false_positive(self, strategy: Dict[str, Any]) -> bool:
        """Check if a successful strategy might be a false positive."""
        try:
            success_rate = strategy.get("success_rate", 0)
            avg_latency = strategy.get("avg_latency_ms", 0)
            attack_name = strategy.get("attack_name", "")

            # QUIC атаки могут быть очень быстрыми, это нормально
            is_quic_attack = "quic" in attack_name.lower()

            # Идеальный результат с очень низкой задержкой подозрителен для не-QUIC атак
            if success_rate == 1.0 and avg_latency < 100 and not is_quic_attack:
                LOG.warning(
                    f"Suspicious result for '{attack_name}': perfect success with very low latency."
                )
                return True

            return False

        except Exception as e:
            LOG.error(f"Error checking for false positive: {e}")
            return False

    def _calculate_bypass_effectiveness(self, strategy: Dict[str, Any]) -> bool:
        """Calculate if bypass is effective based on metrics."""
        try:
            success_rate = strategy.get("success_rate", 0)
            avg_latency = strategy.get("avg_latency_ms", float("inf"))

            # Effective if high success rate and reasonable latency
            return success_rate >= 0.8 and avg_latency < 3000

        except Exception as e:
            LOG.error(f"Error calculating bypass effectiveness: {e}")
            return False

    def _calculate_effectiveness_score(self, strategy: Dict[str, Any]) -> float:
        """Calculate overall effectiveness score."""
        try:
            success_rate = strategy.get("success_rate", 0)
            avg_latency = strategy.get("avg_latency_ms", float("inf"))

            # Base score from success rate
            score = success_rate

            # Adjust for latency (lower is better)
            if avg_latency < 1000:
                score *= 1.2  # Bonus for very fast
            elif avg_latency < 2000:
                score *= 1.1  # Bonus for fast
            elif avg_latency > 5000:
                score *= 0.8  # Penalty for slow

            return min(1.0, score)

        except Exception as e:
            LOG.error(f"Error calculating effectiveness score: {e}")
            return 0.0

    def _generate_fingerprint_hash(self, strategy: Dict[str, Any]) -> str:
        """Generate a consistent hash for grouping strategies by fingerprint."""
        try:
            # Используем summary, так как он более стабилен, чем полный словарь
            fingerprint_summary = strategy.get("fingerprint_summary", "")

            # Используем только основной домен для группировки, чтобы избежать дублей
            # из-за разных наборов тестовых доменов
            domains = strategy.get("domains", [])
            primary_domain = domains[0] if domains else "no_domain"

            hash_input = f"{fingerprint_summary}|{primary_domain}"
            return hashlib.md5(hash_input.encode()).hexdigest()[:16]

        except Exception as e:
            LOG.error(f"Error generating fingerprint hash: {e}")
            # Fallback на случайный хэш, чтобы избежать коллизий
            return f"unknown_{int(time.time())}_{random.randint(0, 1000)}"

    def _sort_strategies_by_effectiveness(
        self, strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Sort strategies by effectiveness using multiple criteria.
        Priority: bypass_effective > success_rate > latency > recency
        """
        try:

            def sort_key(strategy):
                metrics = strategy.get("metrics", {})

                # Primary: bypass effectiveness (real-world test results)
                bypass_effective = metrics.get("bypass_effective", False)
                bypass_score = 1.0 if bypass_effective else 0.0

                # Secondary: success rate
                success_rate = metrics.get("success_rate", 0.0)

                # Tertiary: latency (lower is better, so negate for descending sort)
                latency = metrics.get("avg_latency_ms", 9999.0)
                latency_score = -latency if latency > 0 else 0

                # Quaternary: recency (newer is better)
                timestamp = strategy.get("timestamp", 0)

                return (bypass_score, success_rate, latency_score, timestamp)

            return sorted(strategies, key=sort_key, reverse=True)

        except Exception as e:
            LOG.error(f"Error sorting strategies: {e}")
            return strategies

    def _deduplicate_strategies(
        self, strategies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate strategies based on their configuration, keeping the best ones.
        """
        try:
            unique_strategies = []
            seen_configs = set()

            def make_hashable(obj):
                """Recursively convert dicts and lists to hashable tuples."""
                if isinstance(obj, dict):
                    return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
                if isinstance(obj, list):
                    return tuple(make_hashable(e) for e in obj)
                return obj

            for strategy in strategies:
                config_tuple = make_hashable(strategy.get("config", {}))
                if config_tuple not in seen_configs:
                    unique_strategies.append(strategy)
                    seen_configs.add(config_tuple)
                else:
                    LOG.debug(f"Skipping duplicate strategy configuration")

            return unique_strategies

        except Exception as e:
            LOG.error(f"Error deduplicating strategies: {e}")
            return strategies

    def _should_replace_strategy(
        self, existing: Dict[str, Any], new: Dict[str, Any]
    ) -> bool:
        """Determine if new strategy should replace existing one."""
        try:
            # Compare effectiveness scores
            existing_score = existing.get("effectiveness_score", 0)
            new_score = self._calculate_effectiveness_score(new)

            # Replace if new strategy is significantly better
            return new_score > existing_score * 1.1

        except Exception as e:
            LOG.error(f"Error comparing strategies: {e}")
            return False
