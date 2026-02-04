"""
Metrics Manager for Attack Performance Tracking
Handles attack metrics, failure analysis, and category health tracking.
"""

import logging
import time
import statistics
from typing import Dict, List, Optional
from dataclasses import dataclass

from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext


@dataclass
class AttackPerformanceMetrics:
    """Performance metrics for unified attacks."""

    attack_name: str
    category: str
    total_executions: int
    successful_executions: int
    failed_executions: int
    avg_latency_ms: float
    success_rate: float
    error_patterns: List[str]
    last_used: float
    health_status: str


@dataclass
class AttackFailureAnalysis:
    """Analysis of attack failures."""

    attack_name: str
    failure_type: str
    frequency: int
    first_occurrence: float
    last_occurrence: float
    error_messages: List[str]
    troubleshooting_steps: List[str]
    alternative_attacks: List[str]


class MetricsManager:
    """Manages attack performance metrics and failure tracking."""

    def __init__(self, attack_adapter, thresholds: Dict[str, float], debug: bool = False):
        self.attack_adapter = attack_adapter
        self.thresholds = thresholds
        self.debug = debug
        self.logger = logging.getLogger("MetricsManager")

        # Metrics storage
        self.attack_metrics: Dict[str, AttackPerformanceMetrics] = {}
        self.attack_failures: Dict[str, AttackFailureAnalysis] = {}
        self.category_health: Dict[str, float] = {}

    def update_attack_metrics(self, attack_name: str, result: AttackResult):
        """Update attack performance metrics."""
        try:
            current_time = time.time()
            if attack_name not in self.attack_metrics:
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                category = attack_info["category"] if attack_info else "unknown"
                self.attack_metrics[attack_name] = AttackPerformanceMetrics(
                    attack_name=attack_name,
                    category=category,
                    total_executions=0,
                    successful_executions=0,
                    failed_executions=0,
                    avg_latency_ms=0.0,
                    success_rate=0.0,
                    error_patterns=[],
                    last_used=current_time,
                    health_status="healthy",
                )

            metrics = self.attack_metrics[attack_name]
            metrics.total_executions += 1
            metrics.last_used = current_time

            if result.status == AttackStatus.SUCCESS:
                metrics.successful_executions += 1
            else:
                metrics.failed_executions += 1
                if result.error_message and result.error_message not in metrics.error_patterns:
                    metrics.error_patterns.append(result.error_message)
                    if len(metrics.error_patterns) > 10:
                        metrics.error_patterns = metrics.error_patterns[-10:]

            metrics.success_rate = metrics.successful_executions / metrics.total_executions

            if result.latency_ms > 0:
                if metrics.avg_latency_ms == 0:
                    metrics.avg_latency_ms = result.latency_ms
                else:
                    alpha = 0.1
                    metrics.avg_latency_ms = (
                        alpha * result.latency_ms + (1 - alpha) * metrics.avg_latency_ms
                    )

            metrics.health_status = self._determine_attack_health_status(
                metrics.success_rate, metrics.avg_latency_ms
            )
            self._update_category_health(metrics.category)

        except Exception as e:
            self.logger.error(f"Error updating attack metrics for {attack_name}: {e}")

    def analyze_attack_failure(
        self, attack_name: str, result: AttackResult, context: Optional[AttackContext]
    ):
        """Analyze attack failure and update failure tracking."""
        try:
            current_time = time.time()
            failure_type = self._categorize_attack_failure(result)

            if attack_name not in self.attack_failures:
                self.attack_failures[attack_name] = AttackFailureAnalysis(
                    attack_name=attack_name,
                    failure_type=failure_type,
                    frequency=0,
                    first_occurrence=current_time,
                    last_occurrence=current_time,
                    error_messages=[],
                    troubleshooting_steps=[],
                    alternative_attacks=[],
                )

            failure_analysis = self.attack_failures[attack_name]
            failure_analysis.frequency += 1
            failure_analysis.last_occurrence = current_time

            if result.error_message and result.error_message not in failure_analysis.error_messages:
                failure_analysis.error_messages.append(result.error_message)
                if len(failure_analysis.error_messages) > 5:
                    failure_analysis.error_messages = failure_analysis.error_messages[-5:]

            failure_analysis.troubleshooting_steps = self._generate_troubleshooting_steps(
                attack_name, failure_type, result
            )
            failure_analysis.alternative_attacks = self._suggest_alternative_attacks(
                attack_name, context
            )

        except Exception as e:
            self.logger.error(f"Error analyzing attack failure for {attack_name}: {e}")

    def calculate_attack_performance_metrics(
        self, attack_name: str, results: List[Dict]
    ) -> AttackPerformanceMetrics:
        """Calculate performance metrics for an attack."""
        try:
            total_executions = len(results)
            successful_executions = sum(
                1 for r in results if r["result"].status == AttackStatus.SUCCESS
            )
            failed_executions = total_executions - successful_executions

            latencies = [r["result"].latency_ms for r in results if r["result"].latency_ms > 0]
            avg_latency = statistics.mean(latencies) if latencies else 0.0

            success_rate = successful_executions / total_executions if total_executions > 0 else 0.0

            error_patterns = []
            for r in results:
                if r["result"].status != AttackStatus.SUCCESS and r["result"].error_message:
                    if r["result"].error_message not in error_patterns:
                        error_patterns.append(r["result"].error_message)

            attack_info = self.attack_adapter.get_attack_info(attack_name)
            category = attack_info["category"] if attack_info else "unknown"

            health_status = self._determine_attack_health_status(success_rate, avg_latency)

            return AttackPerformanceMetrics(
                attack_name=attack_name,
                category=category,
                total_executions=total_executions,
                successful_executions=successful_executions,
                failed_executions=failed_executions,
                avg_latency_ms=avg_latency,
                success_rate=success_rate,
                error_patterns=error_patterns,
                last_used=max(r["timestamp"] for r in results),
                health_status=health_status,
            )
        except Exception as e:
            self.logger.error(f"Error calculating attack performance metrics: {e}")
            return AttackPerformanceMetrics(
                attack_name=attack_name,
                category="unknown",
                total_executions=0,
                successful_executions=0,
                failed_executions=0,
                avg_latency_ms=0.0,
                success_rate=0.0,
                error_patterns=[],
                last_used=time.time(),
                health_status="unknown",
            )

    def _determine_attack_health_status(self, success_rate: float, avg_latency: float) -> str:
        """Determine attack health status based on metrics."""
        if success_rate < self.thresholds.get("health_score_critical", 0.5):
            return "critical"
        elif success_rate < self.thresholds.get("health_score_warning", 0.7):
            return "warning"
        elif avg_latency > self.thresholds.get("attack_latency_critical", 100.0):
            return "critical"
        elif avg_latency > self.thresholds.get("attack_latency_warning", 50.0):
            return "warning"
        else:
            return "healthy"

    def _update_category_health(self, category: str):
        """Update health score for attack category."""
        try:
            category_attacks = [
                metrics for metrics in self.attack_metrics.values() if metrics.category == category
            ]
            if not category_attacks:
                return

            total_success_rate = sum(metrics.success_rate for metrics in category_attacks)
            avg_success_rate = total_success_rate / len(category_attacks)
            self.category_health[category] = avg_success_rate

        except Exception as e:
            self.logger.error(f"Error updating category health for {category}: {e}")

    def _categorize_attack_failure(self, result: AttackResult) -> str:
        """Categorize attack failure type."""
        if result.status == AttackStatus.TIMEOUT:
            return "timeout"
        elif result.status == AttackStatus.BLOCKED:
            return "blocked"
        elif result.status == AttackStatus.INVALID_PARAMS:
            return "invalid_params"
        elif result.status == AttackStatus.ERROR:
            if result.error_message:
                return self._categorize_attack_error(result.error_message)
            return "error"
        else:
            return "unknown"

    def _categorize_attack_error(self, error_message: str) -> str:
        """Categorize attack error message."""
        error_lower = error_message.lower()
        if "timeout" in error_lower:
            return "timeout"
        elif "connection" in error_lower and ("refused" in error_lower or "failed" in error_lower):
            return "connection_failed"
        elif "invalid" in error_lower and "param" in error_lower:
            return "invalid_parameters"
        elif "blocked" in error_lower or "filtered" in error_lower:
            return "blocked"
        elif "permission" in error_lower or "access" in error_lower:
            return "permission_denied"
        elif "network" in error_lower and "unreachable" in error_lower:
            return "network_unreachable"
        else:
            return "unknown_error"

    def _generate_troubleshooting_steps(
        self, attack_name: str, failure_type: str, result: Optional[AttackResult]
    ) -> List[str]:
        """Generate troubleshooting steps for attack failures."""
        steps = []

        if failure_type == "timeout":
            steps.extend(
                [
                    f"Increase timeout value for {attack_name}",
                    "Check network connectivity to target",
                    "Verify target is responsive",
                    "Consider using faster alternative attacks",
                ]
            )
        elif failure_type == "blocked":
            steps.extend(
                [
                    f"Try different parameters for {attack_name}",
                    "Use alternative attacks from same category",
                    "Check if target has updated DPI rules",
                    "Consider combo attacks to bypass detection",
                ]
            )
        elif failure_type == "invalid_params":
            steps.extend(
                [
                    f"Review parameter configuration for {attack_name}",
                    "Check parameter types and ranges",
                    "Validate target compatibility",
                    "Use default parameters as baseline",
                ]
            )
        elif failure_type == "connection_failed":
            steps.extend(
                [
                    "Verify target IP and port are correct",
                    "Check network connectivity",
                    "Ensure target service is running",
                    "Try basic connectivity test first",
                ]
            )
        else:
            steps.extend(
                [
                    f"Review logs for {attack_name} execution",
                    "Check system resources and permissions",
                    "Verify attack prerequisites are met",
                    "Try simpler attacks first",
                ]
            )

        return steps

    def _suggest_alternative_attacks(
        self, attack_name: str, context: Optional[AttackContext]
    ) -> List[str]:
        """Suggest alternative attacks for failed attack."""
        try:
            alternatives = []
            attack_info = self.attack_adapter.get_attack_info(attack_name)
            if not attack_info:
                return alternatives

            category = attack_info["category"]
            protocol = context.protocol if context else "tcp"

            category_attacks = self.attack_adapter.get_available_attacks(
                category=category, protocol=protocol
            )
            alternatives = [a for a in category_attacks if a != attack_name][:3]

            if not alternatives:
                all_attacks = self.attack_adapter.get_available_attacks(protocol=protocol)
                alternatives = [a for a in all_attacks if a != attack_name][:3]

            return alternatives
        except Exception as e:
            self.logger.error(f"Error suggesting alternatives for {attack_name}: {e}")
            return []

    def get_metrics(self) -> Dict[str, AttackPerformanceMetrics]:
        """Get all attack metrics."""
        return self.attack_metrics.copy()

    def get_failures(self) -> Dict[str, AttackFailureAnalysis]:
        """Get all failure analyses."""
        return self.attack_failures.copy()

    def get_category_health(self) -> Dict[str, float]:
        """Get category health scores."""
        return self.category_health.copy()
