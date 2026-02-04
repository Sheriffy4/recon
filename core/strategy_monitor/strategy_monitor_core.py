"""
Core StrategyMonitor class - orchestrates monitoring components.

Simplified main class that delegates to specialized components for monitoring,
detection, discovery, and database operations.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque

from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.base import AttackResult
from core.effectiveness.production_effectiveness_tester import (
    ProductionEffectivenessTester,
)
from core.bypass.engines.health_check import EngineHealthCheck
from core.reporting import EnhancedReporter, StrategyEffectivenessReport

from .models import EffectivenessReport, DPIChange, Strategy
from .metrics_calculator import (
    calculate_effectiveness_trend,
    calculate_confidence,
    estimate_latency_from_stats,
)
from .database_manager import StrategyDatabaseManager
from .dpi_detector import DPIChangeDetector
from .attack_monitor import AttackMonitor
from .strategy_discovery import StrategyDiscovery


class StrategyMonitor:
    """
    Enhanced automatic strategy effectiveness monitoring and DPI change detection system.
    Integrates with FastBypassEngine and the new unified attack system for real-time monitoring
    and adaptive strategy management with attack-level metrics.
    """

    def __init__(
        self,
        fast_bypass_engine=None,
        advanced_fingerprint_engine=None,
        debug: bool = True,
    ):
        """
        Initialize StrategyMonitor with component delegation.

        Args:
            fast_bypass_engine: FastBypassEngine instance
            advanced_fingerprint_engine: AdvancedFingerprintEngine instance
            debug: Enable debug logging
        """
        self.fast_bypass_engine = fast_bypass_engine
        self.advanced_fingerprint_engine = advanced_fingerprint_engine
        self.debug = debug
        self.logger = logging.getLogger("StrategyMonitor")

        if debug:
            self.logger.setLevel(logging.DEBUG)

        # Initialize unified attack system integration
        self.attack_adapter = AttackAdapter()
        self.attack_registry = AttackRegistry()

        # Monitoring state
        self.running = False
        self.monitor_thread = None

        # Config from engine
        cfg = getattr(getattr(fast_bypass_engine, "config", None), "typed_config", None)
        if cfg and hasattr(cfg, "monitoring"):
            self.monitor_interval = int(cfg.monitoring.monitor_interval_seconds)
            self._alert_success_rate_threshold = float(cfg.monitoring.alert_success_rate_threshold)
            self._use_https = bool(cfg.monitoring.use_https)
        else:
            self.monitor_interval = 60
            self._alert_success_rate_threshold = 0.6
            self._use_https = True

        # Strategy effectiveness tracking (legacy)
        self.effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.strategy_performance = defaultdict(dict)
        self.domain_strategies = {}

        # Strategy discovery
        self.strategy_test_queue = deque()
        self.auto_discovery_enabled = True

        # Statistics
        self.stats = {
            "monitoring_cycles": 0,
            "strategies_monitored": 0,
            "attacks_monitored": 0,
            "changes_detected": 0,
            "strategies_discovered": 0,
            "attacks_discovered": 0,
            "database_updates": 0,
            "effectiveness_reports_generated": 0,
            "attack_reports_generated": 0,
        }

        # Initialize specialized components
        self.db_manager = StrategyDatabaseManager(debug=debug)
        self.dpi_detector = DPIChangeDetector(
            advanced_fingerprint_engine=advanced_fingerprint_engine,
            debug=debug,
        )
        self.attack_monitor = AttackMonitor(
            attack_adapter=self.attack_adapter,
            attack_registry=self.attack_registry,
            debug=debug,
        )
        self.strategy_discovery = StrategyDiscovery(
            fast_bypass_engine=fast_bypass_engine,
            advanced_fingerprint_engine=advanced_fingerprint_engine,
            debug=debug,
        )

        # Production effectiveness components
        self.prod_effectiveness_tester = ProductionEffectivenessTester()
        self.health_check = EngineHealthCheck(debug=self.debug)
        try:
            self.reporter = EnhancedReporter()
        except Exception:
            self.reporter = None

        # Load existing strategies
        self.domain_strategies = self.db_manager.load_existing_strategies()

        self.logger.info(
            "Enhanced StrategyMonitor initialized with unified attack system integration"
        )

    def start_monitoring(self):
        """Start continuous monitoring in background thread."""
        if self.running:
            self.logger.warning("Monitoring already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

        self.logger.info("Strategy monitoring started")

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)

        self.logger.info("Strategy monitoring stopped")

    def monitor_strategy_effectiveness(
        self, strategy_id: str, domain: str = None
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

            # Calculate trend and confidence using extracted functions
            trend = calculate_effectiveness_trend(effectiveness_data)
            avg_latency = estimate_latency_from_stats(combined_stats)
            confidence = calculate_confidence(effectiveness_data)

            # Create effectiveness report
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

            # Production evaluation if domain specified
            if domain:
                self._evaluate_production_effectiveness(strategy_id, domain, report)

            self.logger.debug(f"Effectiveness report generated: {success_rate:.2f} success rate")
            return report

        except Exception as e:
            self.logger.error(f"Error monitoring strategy effectiveness: {e}")
            if self.debug:
                self.logger.exception("Detailed effectiveness monitoring error:")
            return self._create_empty_effectiveness_report(strategy_id, domain)

    def detect_dpi_changes(self, domain: str) -> List[DPIChange]:
        """
        Detect changes in DPI behavior using DPIChangeDetector.

        Args:
            domain: Domain to check for DPI changes

        Returns:
            List of detected DPI changes
        """
        changes = self.dpi_detector.detect_changes(domain)
        self.stats["changes_detected"] += len(changes)
        return changes

    def monitor_attack_effectiveness(self, attack_results: List[AttackResult], domain: str = None):
        """
        Monitor effectiveness of individual attacks using AttackMonitor.

        Args:
            attack_results: List of AttackResult objects from recent executions
            domain: Optional domain to monitor for

        Returns:
            List of AttackEffectivenessReport objects
        """
        reports = self.attack_monitor.monitor_attack_effectiveness(attack_results, domain)
        self.stats["attack_reports_generated"] += len(reports)
        return reports

    def recommend_attack_alternatives(
        self, failing_attacks: List[str], domain: str = None
    ) -> List[str]:
        """
        Recommend alternative attacks when current ones fail.

        Args:
            failing_attacks: List of attack names that are failing
            domain: Optional domain context for recommendations

        Returns:
            List of recommended alternative attack names
        """
        return self.attack_monitor.recommend_attack_alternatives(failing_attacks, domain)

    def update_attack_rankings(self, effectiveness_data: Dict[str, Dict[str, float]]):
        """
        Update attack effectiveness rankings based on collected data.

        Args:
            effectiveness_data: Dictionary of domain -> {attack_name: effectiveness_score}
        """
        self.attack_monitor.update_attack_rankings(effectiveness_data)

    def auto_discover_strategies(self, failed_domains: List[str]) -> List[Strategy]:
        """
        Auto-discover new working strategies using StrategyDiscovery.

        Args:
            failed_domains: List of domains where current strategies failed

        Returns:
            List of newly discovered strategies
        """
        strategies = self.strategy_discovery.auto_discover_strategies(failed_domains)
        self.stats["strategies_discovered"] += len(strategies)
        return strategies

    def update_strategy_database(self, new_strategies: List[Strategy]):
        """
        Update strategy database using DatabaseManager.

        Args:
            new_strategies: List of new strategies to add to database
        """
        added = self.db_manager.update_strategies(new_strategies)
        if added > 0:
            self.stats["database_updates"] += 1

    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics including attack-level metrics."""
        stats = self.stats.copy()

        # Add runtime statistics
        stats["monitoring_active"] = self.running
        stats["monitored_domains"] = len(self.dpi_detector.fingerprint_history)
        stats["effectiveness_history_size"] = sum(
            len(history) for history in self.effectiveness_history.values()
        )
        stats["detected_changes_count"] = len(self.dpi_detector.detected_changes)

        # Add recent changes summary
        recent_changes = self.dpi_detector.get_recent_changes(hours=24)
        stats["recent_changes_24h"] = len(recent_changes)

        # Add strategy performance summary
        if self.strategy_performance:
            avg_success_rates = []
            for domain_strategies in self.strategy_performance.values():
                for strategy_data in domain_strategies.values():
                    if "success_rate" in strategy_data:
                        avg_success_rates.append(strategy_data["success_rate"])

            if avg_success_rates:
                stats["avg_strategy_success_rate"] = sum(avg_success_rates) / len(avg_success_rates)

        # Add attack monitor stats
        attack_stats = self.attack_monitor.get_stats()
        stats.update(attack_stats)

        # Add discovery stats
        discovery_stats = self.strategy_discovery.get_stats()
        stats.update(discovery_stats)

        # Add queue statistics
        stats["strategy_test_queue_size"] = len(self.strategy_test_queue)

        return stats

    # Private helper methods

    def _monitoring_loop(self):
        """Main monitoring loop running in background thread."""
        self.logger.info("Starting enhanced monitoring loop with attack-level metrics")

        while self.running:
            try:
                self.stats["monitoring_cycles"] += 1
                self._monitor_all_strategies()
                self._check_all_domains_for_changes()
                self._process_discovery_queue()
                self._cleanup_old_data()

                time.sleep(self.monitor_interval)
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                if self.debug:
                    self.logger.exception("Detailed monitoring loop error:")
                time.sleep(self.monitor_interval)

    def _monitor_all_strategies(self):
        """Monitor effectiveness of all known strategies."""
        try:
            for domain, strategy_id in self.domain_strategies.items():
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
                        f"Strategy {strategy_id} failing for {domain}: {report.success_rate:.2f} success rate"
                    )

                    # Add to discovery queue for new strategy search
                    if domain not in [item["domain"] for item in self.strategy_test_queue]:
                        self.strategy_test_queue.append(
                            {
                                "domain": domain,
                                "reason": "strategy_failure",
                                "priority": "high",
                            }
                        )

            self.stats["strategies_monitored"] = len(self.domain_strategies)

        except Exception as e:
            self.logger.error(f"Error monitoring all strategies: {e}")

    def _check_all_domains_for_changes(self):
        """Check all monitored domains for DPI changes."""
        try:
            monitored_domains = list(self.dpi_detector.fingerprint_history.keys())

            for domain in monitored_domains:
                changes = self.detect_dpi_changes(domain)

                # Process detected changes
                for change in changes:
                    self.dpi_detector.process_change(change, self.strategy_test_queue)

        except Exception as e:
            self.logger.error(f"Error checking domains for changes: {e}")

    def _process_discovery_queue(self):
        """Process queued domains for strategy discovery."""
        try:
            if not self.strategy_test_queue:
                return

            # Process up to 3 domains per cycle to avoid overload
            for _ in range(min(3, len(self.strategy_test_queue))):
                if not self.strategy_test_queue:
                    break

                item = self.strategy_test_queue.popleft()
                domain = item["domain"]

                self.logger.debug(f"Processing discovery queue item: {domain}")

                # Discover new strategies
                new_strategies = self.auto_discover_strategies([domain])

                # Update database if strategies found
                if new_strategies:
                    self.update_strategy_database(new_strategies)

                    # Update domain strategy mapping
                    best_strategy = max(new_strategies, key=lambda s: s.success_rate)
                    self.domain_strategies[domain] = best_strategy.strategy_id

        except Exception as e:
            self.logger.error(f"Error processing discovery queue: {e}")

    def _cleanup_old_data(self):
        """Clean up old monitoring data to prevent memory leaks."""
        try:
            cutoff_time = datetime.now() - timedelta(days=7)

            # Clean effectiveness history
            for history in self.effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean component data
            self.dpi_detector.cleanup_old_data(days=7)

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")

    def _evaluate_production_effectiveness(
        self, strategy_id: str, domain: str, report: EffectivenessReport
    ):
        """
        Evaluate production effectiveness and health.

        Args:
            strategy_id: Strategy being evaluated
            domain: Domain being tested
            report: Current effectiveness report
        """

        def _start():
            try:
                if self.fast_bypass_engine and hasattr(self.fast_bypass_engine, "start"):
                    pass
            except Exception:
                pass

        def _stop():
            try:
                if self.fast_bypass_engine and hasattr(self.fast_bypass_engine, "stop"):
                    pass
            except Exception:
                pass

        try:
            prod_report = self.prod_effectiveness_tester.evaluate(
                domain, _start, _stop, use_https=self._use_https
            )

            # Evaluate health
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

            # Publish report
            if self.reporter:
                try:
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
                except Exception:
                    pass

        except Exception as e:
            if self.debug:
                self.logger.debug(f"Production effectiveness evaluation failed: {e}")

    def _create_empty_effectiveness_report(
        self, strategy_id: str, domain: str
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
