"""
Result Processor

Processes and aggregates results from the unified attack system
for integration with existing components.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from statistics import mean, median
from collections import defaultdict
from core.bypass.attacks.base import AttackResult, AttackStatus
from core.integration.integration_config import PerformanceMetrics
from core.bypass.attacks.attack_registry import AttackRegistry

LOG = logging.getLogger("ResultProcessor")


class ResultProcessor:
    """
    Processes AttackResult objects for integration with existing components.
    Converts modern AttackResult objects into legacy dictionary format for reporting
    and provides advanced aggregation and performance analysis capabilities.
    """

    def __init__(self):
        """Initialize result processor."""
        self.result_cache: Dict[str, List[Dict]] = defaultdict(list)
        self.performance_history: List[PerformanceMetrics] = []
        self.max_history_size = 1000
        self.attack_map = self._build_attack_map()

    def _build_attack_map(self) -> Dict[str, str]:
        """Dynamically build the attack name to legacy name mapping."""
        attack_map = {}
        registry = AttackRegistry()
        all_attacks = registry.get_all()
        for name, attack_class in all_attacks.items():
            try:
                instance = attack_class()
                if hasattr(instance, "legacy_name") and instance.legacy_name:
                    attack_map[name] = instance.legacy_name
            except TypeError:
                continue
        return attack_map

    def process_attack_result(
        self,
        result: Optional[AttackResult],
        attack_name: str = "unknown",
        task_data: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Convert AttackResult to legacy format for backward compatibility.
        This version is hardened against None results and missing metadata.
        Enhanced to properly extract strategy information.

        Args:
            result: AttackResult from unified attack system, can be None.
            attack_name: Name of the attack that produced this result.
            task_data: Optional task data containing strategy information.

        Returns:
            Dictionary in legacy format with proper strategy mapping.
        """
        try:
            if result is None:
                LOG.error(f"Received a null result (None) for attack {attack_name}")
                return self._create_error_result(
                    attack_name, "Attack returned None instead of AttackResult"
                )
            strategy_name = self._extract_strategy_name(attack_name, task_data, result)
            bypass_effective = False
            final_latency = result.latency_ms
            if result.metadata and "bypass_results" in result.metadata:
                bypass_results = result.metadata["bypass_results"]
                bypass_effective = bypass_results.get("bypass_effective", False)
                if bypass_effective:
                    final_latency = bypass_results.get("bypass", {}).get(
                        "latency_ms", result.latency_ms
                    )
                elif bypass_results.get("baseline", {}).get("success", False):
                    final_latency = bypass_results.get("baseline", {}).get(
                        "latency_ms", result.latency_ms
                    )
            final_success = result.status == AttackStatus.SUCCESS and bypass_effective
            legacy_result = {
                "success": final_success,
                "status": result.status.value,
                "latency_ms": final_latency,
                "bypass_effective": bypass_effective,
                "packets_sent": result.packets_sent,
                "bytes_sent": result.bytes_sent,
                "connection_established": result.connection_established,
                "data_transmitted": result.data_transmitted,
                "error_message": result.error_message,
                "timestamp": time.time(),
                "attack_name": strategy_name,
                "original_attack_name": attack_name,
                "metadata": result.metadata or {},
            }
            legacy_result["throughput_bps"] = self._calculate_throughput(result)
            legacy_result["efficiency_score"] = self._calculate_efficiency(result)
            self._cache_result(attack_name, legacy_result)
            LOG.debug(
                f"Processed result for {attack_name}: status={result.status.value}, effective={bypass_effective}"
            )
            return legacy_result
        except Exception as e:
            LOG.error(
                f"Failed to process attack result for {attack_name}: {e}", exc_info=True
            )
            return self._create_error_result(attack_name, str(e))

    def aggregate_results(
        self, results: List[AttackResult], attack_names: List[str] = None
    ) -> Dict[str, Any]:
        """
        Aggregate multiple attack results into summary statistics.

        Args:
            results: List of AttackResult objects
            attack_names: Optional list of attack names corresponding to results

        Returns:
            Aggregated statistics dictionary
        """
        if not results:
            return self._create_empty_aggregate()
        try:
            processed_results = [
                self.process_attack_result(res, name)
                for res, name in zip(
                    results,
                    attack_names or [f"attack_{i}" for i in range(len(results))],
                )
            ]
            successful_results = [r for r in processed_results if r["success"]]
            latencies = [
                r["latency_ms"] for r in successful_results if r["latency_ms"] > 0
            ]
            aggregate = {
                "total_attacks": len(results),
                "successful_attacks": len(successful_results),
                "failed_attacks": len(results) - len(successful_results),
                "success_rate": (
                    len(successful_results) / len(results) if results else 0.0
                ),
                "total_latency_ms": sum((r["latency_ms"] for r in processed_results)),
                "average_latency_ms": mean(latencies) if latencies else 0.0,
                "median_latency_ms": median(latencies) if latencies else 0.0,
                "max_latency_ms": max(latencies) if latencies else 0.0,
                "min_latency_ms": min(latencies) if latencies else 0.0,
                "total_packets_sent": sum(
                    (r["packets_sent"] for r in processed_results)
                ),
                "total_bytes_sent": sum((r["bytes_sent"] for r in processed_results)),
                "average_throughput_bps": (
                    mean([r["throughput_bps"] for r in successful_results])
                    if successful_results
                    else 0.0
                ),
                "average_efficiency_score": (
                    mean([r["efficiency_score"] for r in successful_results])
                    if successful_results
                    else 0.0
                ),
                "status_breakdown": self._calculate_status_breakdown(results),
                "attack_breakdown": self._calculate_attack_breakdown(processed_results),
                "aggregation_timestamp": time.time(),
            }
            LOG.info(
                f"Aggregated {len(results)} attack results: {aggregate['success_rate']:.2%} success rate"
            )
            return aggregate
        except Exception as e:
            LOG.error(f"Failed to aggregate attack results: {e}")
            return self._create_error_aggregate(str(e))

    def _extract_strategy_name(
        self,
        attack_name: str,
        task_data: Dict[str, Any] = None,
        result: AttackResult = None,
    ) -> str:
        """
        Extracts a simple, user-friendly strategy name for reporting.
        Handles dynamic_combo strategies by inspecting their stages.
        """
        try:
            if attack_name == "dynamic_combo" or (
                task_data and task_data.get("type") == "dynamic_combo"
            ):
                return self._extract_dynamic_combo_name(
                    task_data or result.metadata.get("task", {})
                )
            if attack_name in self.attack_map:
                return self.attack_map[attack_name]
            if task_data:
                return task_data.get("name") or task_data.get("type", attack_name)
            if result and result.metadata:
                return result.metadata.get("strategy_type") or result.metadata.get(
                    "technique_applied", attack_name
                )
            return attack_name
        except Exception as e:
            LOG.error(f"Error extracting strategy name for {attack_name}: {e}")
            return attack_name

    def _extract_dynamic_combo_name(self, task_data: Dict[str, Any]) -> str:
        """
        Extracts a meaningful name from a dynamic_combo strategy task.
        """
        try:
            stages = task_data.get("params", {}).get("stages", [])
            if not stages:
                return "dynamic_combo_empty"
            stage_names = []
            for stage in stages:
                if isinstance(stage, dict):
                    stage_name = stage.get("name") or stage.get("type")
                    if stage_name:
                        stage_names.append(self.attack_map.get(stage_name, stage_name))
            if not stage_names:
                return f"dynamic_combo_{len(stages)}_stages"
            combo_name = "+".join(stage_names[:3])
            if len(stage_names) > 3:
                combo_name += f"+{len(stage_names) - 3}"
            return combo_name
        except Exception as e:
            LOG.error(f"Error extracting dynamic_combo name: {e}")
            return "dynamic_combo_error"

    def _calculate_throughput(self, result: AttackResult) -> float:
        """Calculates throughput in bits per second."""
        if result.latency_ms <= 0:
            return 0.0
        return result.bytes_sent * 8 / (result.latency_ms / 1000.0)

    def _calculate_efficiency(self, result: AttackResult) -> float:
        """Calculates a heuristic efficiency score (0.0-1.0)."""
        if result.status != AttackStatus.SUCCESS:
            return 0.0
        score = 0.0
        if result.connection_established:
            score += 0.5
        if result.data_transmitted:
            score += 0.5
        if result.latency_ms > 0:
            latency_factor = min(1.0, 1000.0 / result.latency_ms)
            score *= latency_factor
        return min(1.0, score)

    def _calculate_status_breakdown(
        self, results: List[AttackResult]
    ) -> Dict[str, int]:
        """Calculates the breakdown of statuses."""
        breakdown = defaultdict(int)
        for result in results:
            if result:
                breakdown[result.status.value] += 1
        return dict(breakdown)

    def _calculate_attack_breakdown(
        self, processed_results: List[Dict]
    ) -> Dict[str, Dict]:
        """Calculates performance breakdown per attack."""
        breakdown = defaultdict(
            lambda: {"count": 0, "success_count": 0, "total_latency_ms": 0}
        )
        for result in processed_results:
            attack_name = result["attack_name"]
            breakdown[attack_name]["count"] += 1
            if result["success"]:
                breakdown[attack_name]["success_count"] += 1
            breakdown[attack_name]["total_latency_ms"] += result["latency_ms"]
        for attack_name, stats in breakdown.items():
            if stats["count"] > 0:
                stats["success_rate"] = stats["success_count"] / stats["count"]
                stats["average_latency_ms"] = stats["total_latency_ms"] / stats["count"]
        return dict(breakdown)

    def _cache_result(self, attack_name: str, result: Dict):
        """Caches a processed result."""
        self.result_cache[attack_name].append(result)
        if len(self.result_cache[attack_name]) > 100:
            self.result_cache[attack_name] = self.result_cache[attack_name][-100:]

    def _create_error_result(
        self, attack_name: str, error_message: str
    ) -> Dict[str, Any]:
        """Creates a standardized error result dictionary."""
        return {
            "success": False,
            "status": "error",
            "latency_ms": 0,
            "bypass_effective": False,
            "packets_sent": 0,
            "bytes_sent": 0,
            "connection_established": False,
            "data_transmitted": False,
            "error_message": error_message,
            "timestamp": time.time(),
            "attack_name": attack_name,
            "original_attack_name": attack_name,
            "throughput_bps": 0,
            "efficiency_score": 0,
        }

    def _create_empty_aggregate(self) -> Dict[str, Any]:
        """Creates an empty aggregate result dictionary."""
        return {
            "total_attacks": 0,
            "successful_attacks": 0,
            "success_rate": 0.0,
            "average_latency_ms": 0.0,
            "status_breakdown": {},
            "attack_breakdown": {},
            "aggregation_timestamp": time.time(),
        }

    def _create_error_aggregate(self, error_message: str) -> Dict[str, Any]:
        """Creates an aggregate result dictionary for an error case."""
        result = self._create_empty_aggregate()
        result["error_message"] = error_message
        return result
