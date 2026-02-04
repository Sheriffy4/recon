"""
Strategy effectiveness tracking and monitoring.

Handles strategy-level effectiveness monitoring with production testing and health checks.
"""

import logging
from datetime import datetime
from typing import Dict, Optional
from collections import defaultdict, deque

from .models import EffectivenessReport
from .metrics_calculator import (
    calculate_effectiveness_trend,
    calculate_confidence,
    estimate_latency_from_stats,
)


class EffectivenessTracker:
    """
    Tracks and monitors strategy effectiveness over time.

    Responsibilities:
    - Monitor individual strategy effectiveness using engine stats
    - Track historical effectiveness data
    - Perform production testing (baseline vs bypass)
    - Evaluate strategy health and generate alerts
    - Publish effectiveness reports
    """

    def __init__(
        self,
        fast_bypass_engine=None,
        prod_effectiveness_tester=None,
        health_check=None,
        reporter=None,
        use_https=True,
        alert_threshold=0.6,
        logger=None,
    ):
        """
        Initialize EffectivenessTracker.

        Args:
            fast_bypass_engine: FastBypassEngine instance for stats
            prod_effectiveness_tester: ProductionEffectivenessTester for real-world testing
            health_check: EngineHealthCheck for strategy health evaluation
            reporter: EnhancedReporter for publishing reports
            use_https: Whether to use HTTPS for production testing
            alert_threshold: Success rate threshold for alerts
            logger: Optional logger instance
        """
        self.fast_bypass_engine = fast_bypass_engine
        self.prod_effectiveness_tester = prod_effectiveness_tester
        self.health_check = health_check
        self.reporter = reporter
        self.use_https = use_https
        self.alert_threshold = alert_threshold
        self.logger = logger or logging.getLogger("EffectivenessTracker")

        # Strategy effectiveness tracking
        self.effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.strategy_performance = defaultdict(dict)
        self.domain_strategies = {}

        # Statistics
        self.stats = {
            "strategies_monitored": 0,
            "effectiveness_reports_generated": 0,
        }

    def monitor_strategy_effectiveness(
        self, strategy_id: str, domain: Optional[str] = None
    ) -> EffectivenessReport:
        """
        Monitor effectiveness of a specific strategy using FastBypassEngine stats.

        Args:
            strategy_id: Strategy identifier
            domain: Optional domain to monitor for

        Returns:
            EffectivenessReport with current effectiveness data
        """
        try:
            self.stats["effectiveness_reports_generated"] += 1

            self.logger.debug(f"Monitoring strategy effectiveness: {strategy_id} for {domain}")

            # Get current stats from FastBypassEngine
            if not self.fast_bypass_engine:
                self.logger.warning("FastBypassEngine not available for monitoring")
                return self._create_empty_effectiveness_report(strategy_id, domain)

            combined_stats = self.fast_bypass_engine.get_combined_stats()

            # Calculate effectiveness metrics
            total_packets = combined_stats.get("packets_captured", 0)
            bypassed_packets = combined_stats.get("tls_packets_bypassed", 0) + combined_stats.get(
                "http_packets_bypassed", 0
            )

            success_rate = 0.0
            if total_packets > 0:
                success_rate = bypassed_packets / total_packets

            # Get historical data
            history_key = f"{strategy_id}_{domain}" if domain else strategy_id
            effectiveness_data = self.effectiveness_history[history_key]

            # Add current measurement
            current_measurement = {
                "timestamp": datetime.now(),
                "success_rate": success_rate,
                "total_packets": total_packets,
                "bypassed_packets": bypassed_packets,
            }
            effectiveness_data.append(current_measurement)

            # Calculate trend and confidence using shared utilities
            trend = calculate_effectiveness_trend(effectiveness_data)
            confidence = calculate_confidence(effectiveness_data)

            # Calculate average latency (simulated based on packet processing)
            avg_latency = estimate_latency_from_stats(combined_stats)

            # Create effectiveness report (internal stats view)
            report = EffectivenessReport(
                strategy_id=strategy_id,
                domain=domain or "all",
                success_rate=success_rate,
                avg_latency_ms=avg_latency,
                total_attempts=total_packets,
                successful_attempts=bypassed_packets,
                failed_attempts=total_packets - bypassed_packets,
                trend=trend,
                confidence=confidence,
            )

            # Update last success/failure times
            if bypassed_packets > 0:
                report.last_success = datetime.now()
            if total_packets - bypassed_packets > 0:
                report.last_failure = datetime.now()

            # Production testing and health check (if domain provided)
            if domain:
                self._perform_production_testing(strategy_id, domain, report)

            self.logger.debug(f"Effectiveness report generated: {success_rate:.2f} success rate")
            return report

        except Exception as e:
            self.logger.error(f"Error monitoring strategy effectiveness: {e}")
            self.logger.exception("Detailed effectiveness monitoring error:")
            return self._create_empty_effectiveness_report(strategy_id, domain)

    def monitor_all_strategies(self) -> int:
        """
        Monitor effectiveness of all known strategies.

        Returns:
            Number of strategies monitored
        """
        try:
            monitored_count = 0

            for domain, strategy_id in self.domain_strategies.items():
                # Monitor strategy effectiveness
                report = self.monitor_strategy_effectiveness(strategy_id, domain)

                # Store performance data
                self.strategy_performance[domain][strategy_id] = {
                    "success_rate": report.success_rate,
                    "avg_latency_ms": report.avg_latency_ms,
                    "trend": report.trend,
                    "last_updated": datetime.now(),
                }

                # Check if strategy is failing
                if report.success_rate < 0.3 and report.total_attempts > 10:
                    self.logger.warning(
                        f"Strategy {strategy_id} failing for {domain}: "
                        f"{report.success_rate:.2f} success rate"
                    )

                monitored_count += 1

            self.stats["strategies_monitored"] = len(self.domain_strategies)
            return monitored_count

        except Exception as e:
            self.logger.error(f"Error monitoring all strategies: {e}")
            return 0

    def get_failing_strategies(self, min_attempts: int = 10) -> Dict[str, Dict]:
        """
        Get list of failing strategies that need attention.

        Args:
            min_attempts: Minimum attempts before considering strategy as failing

        Returns:
            Dictionary of domain -> strategy info for failing strategies
        """
        failing = {}

        for domain, strategies in self.strategy_performance.items():
            for strategy_id, perf_data in strategies.items():
                success_rate = perf_data.get("success_rate", 0.0)

                # Check if we have enough data
                history_key = f"{strategy_id}_{domain}"
                effectiveness_data = self.effectiveness_history[history_key]

                if len(effectiveness_data) >= min_attempts and success_rate < 0.3:
                    failing[domain] = {
                        "strategy_id": strategy_id,
                        "success_rate": success_rate,
                        "trend": perf_data.get("trend", "unknown"),
                        "last_updated": perf_data.get("last_updated"),
                    }

        return failing

    def get_effectiveness_stats(self) -> Dict:
        """
        Get effectiveness tracking statistics.

        Returns:
            Dictionary with effectiveness statistics
        """
        stats = self.stats.copy()

        # Add runtime statistics
        stats["monitored_domains"] = len(self.domain_strategies)
        stats["effectiveness_history_size"] = sum(
            len(history) for history in self.effectiveness_history.values()
        )

        # Add strategy performance summary
        if self.strategy_performance:
            avg_success_rates = []
            for domain_strategies in self.strategy_performance.values():
                for strategy_data in domain_strategies.values():
                    if "success_rate" in strategy_data:
                        avg_success_rates.append(strategy_data["success_rate"])

            if avg_success_rates:
                stats["avg_strategy_success_rate"] = sum(avg_success_rates) / len(avg_success_rates)
                stats["best_success_rate"] = max(avg_success_rates)
                stats["worst_success_rate"] = min(avg_success_rates)

        return stats

    def _perform_production_testing(
        self, strategy_id: str, domain: str, report: EffectivenessReport
    ):
        """
        Perform production testing (baseline vs bypass) and health check.

        Args:
            strategy_id: Strategy identifier
            domain: Domain to test
            report: EffectivenessReport to update with production results
        """
        if not self.prod_effectiveness_tester or not self.health_check:
            return

        def _start():
            try:
                if self.fast_bypass_engine and hasattr(self.fast_bypass_engine, "start"):
                    # Minimal engine startup if needed
                    pass
            except Exception:
                pass

        def _stop():
            try:
                if self.fast_bypass_engine and hasattr(self.fast_bypass_engine, "stop"):
                    # Engine shutdown if needed
                    pass
            except Exception:
                pass

        try:
            # Perform production effectiveness test
            prod_report = self.prod_effectiveness_tester.evaluate(
                domain, _start, _stop, use_https=self.use_https
            )

            # Evaluate strategy health based on production result
            health_stats = {
                "success_count": 1 if prod_report.bypass.success else 0,
                "fail_count": 0 if prod_report.bypass.success else 1,
                "avg_latency_ms": prod_report.bypass.latency_ms or 0.0,
            }
            health = self.health_check.evaluate_strategy_health(health_stats)

            self.logger.info(
                f"Strategy '{strategy_id}' health: {health['status']} "
                f"(success_rate={health['success_rate']:.2f}, "
                f"latency={health['avg_latency_ms']:.0f}ms)"
            )

            # Alert on degradation
            if health.get("status") in ("degrading", "failing"):
                self.logger.warning(
                    f"ALERT: Strategy '{strategy_id}' on {domain} is {health['status']} "
                    f"— {health.get('reason') or ''}"
                )

            # Publish report through EnhancedReporter if available
            if self.reporter:
                try:
                    # Import here to avoid circular dependency
                    from core.reporting import StrategyEffectivenessReport

                    ser = StrategyEffectivenessReport(
                        strategy_id=strategy_id,
                        domain=domain,
                        success_rate=report.success_rate,
                        avg_latency_ms=report.avg_latency_ms,
                        total_attempts=report.total_attempts,
                        successful_attempts=report.successful_attempts,
                        failed_attempts=report.failed_attempts,
                        trend=report.trend,
                        confidence=report.confidence,
                    )
                    self.reporter.publish_strategy_report(ser)
                except Exception as e:
                    self.logger.debug(f"Failed to publish report: {e}")

        except Exception as e:
            self.logger.debug(f"Production effectiveness evaluation failed: {e}")

    def _create_empty_effectiveness_report(
        self, strategy_id: str, domain: Optional[str]
    ) -> EffectivenessReport:
        """Create empty effectiveness report for error cases."""
        return EffectivenessReport(
            strategy_id=strategy_id,
            domain=domain or "unknown",
            success_rate=0.0,
            avg_latency_ms=0.0,
            total_attempts=0,
            successful_attempts=0,
            failed_attempts=0,
            trend="unknown",
            confidence=0.0,
        )
