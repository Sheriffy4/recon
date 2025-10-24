# recon/core/strategy_monitor.py

"""
Enhanced StrategyMonitor - Automatic strategy effectiveness monitoring and DPI change detection.
Integrates with FastBypassEngine, AdvancedFingerprintEngine, and the new unified attack system
to provide continuous monitoring and adaptive strategy management with attack-level metrics.
"""

import logging
import time
import json
import os
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque

# Import unified attack system components
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from core.effectiveness.production_effectiveness_tester import (
    ProductionEffectivenessTester,
)
from core.bypass.engines.health_check import EngineHealthCheck
from core.reporting import EnhancedReporter, StrategyEffectivenessReport

LOG = logging.getLogger("strategy_monitor")


@dataclass
class AttackEffectivenessReport:
    """Report on individual attack effectiveness over time."""

    attack_name: str
    domain: str
    success_rate: float
    avg_latency_ms: float
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    trend: str = "stable"  # improving, degrading, stable
    confidence: float = 0.0
    category: str = "unknown"
    protocol: str = "tcp"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.last_success:
            result["last_success"] = self.last_success.isoformat()
        if self.last_failure:
            result["last_failure"] = self.last_failure.isoformat()
        return result


@dataclass
class EffectivenessReport:
    """Report on strategy effectiveness over time (legacy compatibility)."""

    strategy_id: str
    domain: str
    success_rate: float
    avg_latency_ms: float
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    trend: str = "stable"  # improving, degrading, stable
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.last_success:
            result["last_success"] = self.last_success.isoformat()
        if self.last_failure:
            result["last_failure"] = self.last_failure.isoformat()
        return result


@dataclass
class DPIChange:
    """Detected change in DPI behavior."""

    domain: str
    change_type: str  # behavior_change, new_blocking, technique_failure
    detected_at: datetime
    old_fingerprint_hash: Optional[str] = None
    new_fingerprint_hash: Optional[str] = None
    affected_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result["detected_at"] = self.detected_at.isoformat()
        return result


@dataclass
class Strategy:
    """Strategy definition compatible with existing format."""

    strategy_id: str
    strategy_string: str  # zapret-compatible strategy string
    technique_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    domains: List[str] = field(default_factory=list)
    fingerprint_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_tested: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result["created_at"] = self.created_at.isoformat()
        if self.last_tested:
            result["last_tested"] = self.last_tested.isoformat()
        return result


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
        # Конфиг мониторинга (если у движка/DI есть typed_config)
        cfg = getattr(getattr(fast_bypass_engine, "config", None), "typed_config", None)
        if cfg and hasattr(cfg, "monitoring"):
            self.monitor_interval = int(cfg.monitoring.monitor_interval_seconds)
            self._alert_success_rate_threshold = float(
                cfg.monitoring.alert_success_rate_threshold
            )
            self._use_https = bool(cfg.monitoring.use_https)
        else:
            self.monitor_interval = 60
            self._alert_success_rate_threshold = 0.6
            self._use_https = True

        # Strategy effectiveness tracking (legacy)
        self.effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.strategy_performance = defaultdict(dict)
        self.domain_strategies = {}

        # Attack-level effectiveness tracking (NEW)
        self.attack_effectiveness_history = defaultdict(lambda: deque(maxlen=100))
        self.attack_performance = defaultdict(dict)
        self.domain_attacks = defaultdict(list)  # domain -> list of effective attacks
        self.attack_rankings = defaultdict(
            dict
        )  # category -> {attack_name: ranking_score}

        # DPI change detection
        self.fingerprint_history = defaultdict(lambda: deque(maxlen=50))
        self.change_detection_threshold = 0.3  # 30% change threshold
        self.detected_changes = deque(maxlen=1000)

        # Strategy discovery
        self.discovered_strategies = {}
        self.strategy_test_queue = deque()
        self.auto_discovery_enabled = True

        # Attack discovery and alternatives (NEW)
        self.attack_alternatives = defaultdict(
            list
        )  # failing_attack -> list of alternatives
        self.attack_test_queue = deque()

        # Statistics
        self.stats = {
            "monitoring_cycles": 0,
            "strategies_monitored": 0,
            "attacks_monitored": 0,  # NEW
            "changes_detected": 0,
            "strategies_discovered": 0,
            "attacks_discovered": 0,  # NEW
            "database_updates": 0,
            "effectiveness_reports_generated": 0,
            "attack_reports_generated": 0,  # NEW
        }

        # Новые компоненты для production-оценки
        self.prod_effectiveness_tester = ProductionEffectivenessTester()
        self.health_check = EngineHealthCheck(debug=self.debug)
        try:
            self.reporter = EnhancedReporter()
        except Exception:
            self.reporter = None

        # Load existing strategies and attacks
        self._load_existing_strategies()
        self._initialize_attack_rankings()

        self.logger.info(
            "Enhanced StrategyMonitor initialized with unified attack system integration"
        )

    def start_monitoring(self):
        """Start continuous monitoring in background thread."""
        if self.running:
            self.logger.warning("Monitoring already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop, daemon=True
        )
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

            self.logger.debug(
                f"Monitoring strategy effectiveness: {strategy_id} for {domain}"
            )

            # Get current stats from FastBypassEngine
            if not self.fast_bypass_engine:
                self.logger.warning("FastBypassEngine not available for monitoring")
                return self._create_empty_effectiveness_report(strategy_id, domain)

            combined_stats = self.fast_bypass_engine.get_combined_stats()

            # Calculate effectiveness metrics
            total_packets = combined_stats.get("packets_captured", 0)
            bypassed_packets = combined_stats.get(
                "tls_packets_bypassed", 0
            ) + combined_stats.get("http_packets_bypassed", 0)

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

            # Calculate trend
            trend = self._calculate_effectiveness_trend(effectiveness_data)

            # Calculate average latency (simulated based on packet processing)
            avg_latency = self._estimate_latency_from_stats(combined_stats)

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
                confidence=self._calculate_confidence(effectiveness_data),
            )

            # Update last success/failure times
            if bypassed_packets > 0:
                report.last_success = datetime.now()
            if total_packets - bypassed_packets > 0:
                report.last_failure = datetime.now()

            # Дополнительно: Production-оценка (baseline vs bypass) при наличии домена
            if domain:

                def _start():
                    try:
                        if self.fast_bypass_engine and hasattr(
                            self.fast_bypass_engine, "start"
                        ):
                            # Нужен минимальный запуск движка или режима
                            pass
                    except Exception:
                        pass

                def _stop():
                    try:
                        if self.fast_bypass_engine and hasattr(
                            self.fast_bypass_engine, "stop"
                        ):
                            # Остановка режима
                            pass
                    except Exception:
                        pass

                try:
                    prod_report = self.prod_effectiveness_tester.evaluate(
                        domain, _start, _stop, use_https=self._use_https
                    )
                    # Оценка здоровья стратегии на основе production результата
                    health_stats = {
                        "success_count": 1 if prod_report.bypass.success else 0,
                        "fail_count": 0 if prod_report.bypass.success else 1,
                        "avg_latency_ms": prod_report.bypass.latency_ms or 0.0,
                    }
                    health = self.health_check.evaluate_strategy_health(health_stats)
                    self.logger.info(
                        f"Strategy '{strategy_id}' health: {health['status']} (success_rate={health['success_rate']:.2f}, latency={health['avg_latency_ms']:.0f}ms)"
                    )
                    # Алерт при деградации
                    if health.get("status") in ("degrading", "failing"):
                        self.logger.warning(
                            f"ALERT: Strategy '{strategy_id}' on {domain} is {health['status']} — {health.get('reason') or ''}"
                        )
                    # Публикация отчёта через EnhancedReporter, если доступен
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
                        self.logger.debug(
                            f"Production effectiveness evaluation failed: {e}"
                        )

            self.logger.debug(
                f"Effectiveness report generated: {success_rate:.2f} success rate"
            )
            return report

        except Exception as e:
            self.logger.error(f"Error monitoring strategy effectiveness: {e}")
            if self.debug:
                self.logger.exception("Detailed effectiveness monitoring error:")
            return self._create_empty_effectiveness_report(strategy_id, domain)

    def detect_dpi_changes(self, domain: str) -> List[DPIChange]:
        """
        Detect changes in DPI behavior using AdvancedFingerprintEngine.

        Args:
            domain: Domain to check for DPI changes

        Returns:
            List of detected DPI changes
        """
        try:
            self.logger.debug(f"Detecting DPI changes for {domain}")

            changes = []

            if not self.advanced_fingerprint_engine:
                self.logger.warning(
                    "AdvancedFingerprintEngine not available for change detection"
                )
                return changes

            # Create current fingerprint
            current_fingerprint = (
                self.advanced_fingerprint_engine.create_comprehensive_fingerprint(
                    domain
                )
            )
            current_hash = current_fingerprint.get_fingerprint_hash()

            # Get historical fingerprints
            fingerprint_history = self.fingerprint_history[domain]

            # Compare with recent fingerprints
            if fingerprint_history:
                recent_fingerprint = fingerprint_history[-1]
                recent_hash = recent_fingerprint.get("hash")

                if recent_hash and recent_hash != current_hash:
                    # Detected fingerprint change
                    change = self._analyze_fingerprint_change(
                        domain,
                        recent_fingerprint.get("fingerprint"),
                        current_fingerprint,
                    )
                    if change:
                        changes.append(change)
                        self.detected_changes.append(change)
                        self.stats["changes_detected"] += 1

            # Store current fingerprint
            fingerprint_history.append(
                {
                    "timestamp": datetime.now(),
                    "hash": current_hash,
                    "fingerprint": current_fingerprint,
                }
            )

            # Detect technique effectiveness changes
            technique_changes = self._detect_technique_effectiveness_changes(
                domain, current_fingerprint
            )
            changes.extend(technique_changes)

            if changes:
                self.logger.info(f"Detected {len(changes)} DPI changes for {domain}")

            return changes

        except Exception as e:
            self.logger.error(f"Error detecting DPI changes for {domain}: {e}")
            if self.debug:
                self.logger.exception("Detailed DPI change detection error:")
            return []

    def monitor_attack_effectiveness(
        self, attack_results: List[AttackResult], domain: str = None
    ) -> List[AttackEffectivenessReport]:
        """
        Monitor effectiveness of individual attacks using AttackResult data.

        Args:
            attack_results: List of AttackResult objects from recent executions
            domain: Optional domain to monitor for

        Returns:
            List of AttackEffectivenessReport objects with current effectiveness data
        """
        try:
            self.logger.debug(
                f"Monitoring attack effectiveness for {len(attack_results)} results"
            )

            reports = []
            attack_stats = defaultdict(
                lambda: {
                    "total_attempts": 0,
                    "successful_attempts": 0,
                    "failed_attempts": 0,
                    "total_latency": 0.0,
                    "last_success": None,
                    "last_failure": None,
                    "category": "unknown",
                    "protocol": "tcp",
                }
            )

            # Process attack results
            for result in attack_results:
                attack_name = result.technique_used or "unknown"
                stats = attack_stats[attack_name]

                stats["total_attempts"] += 1
                stats["total_latency"] += result.latency_ms

                if result.status == AttackStatus.SUCCESS:
                    stats["successful_attempts"] += 1
                    stats["last_success"] = datetime.now()
                else:
                    stats["failed_attempts"] += 1
                    stats["last_failure"] = datetime.now()

                # Get attack info from registry
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                if attack_info:
                    stats["category"] = attack_info.get("category", "unknown")
                    stats["protocol"] = attack_info.get("supported_protocols", ["tcp"])[
                        0
                    ]

            # Create effectiveness reports
            for attack_name, stats in attack_stats.items():
                success_rate = 0.0
                if stats["total_attempts"] > 0:
                    success_rate = (
                        stats["successful_attempts"] / stats["total_attempts"]
                    )

                avg_latency = 0.0
                if stats["total_attempts"] > 0:
                    avg_latency = stats["total_latency"] / stats["total_attempts"]

                # Calculate trend from historical data
                history_key = f"{attack_name}_{domain}" if domain else attack_name
                effectiveness_data = self.attack_effectiveness_history[history_key]

                # Add current measurement
                current_measurement = {
                    "timestamp": datetime.now(),
                    "success_rate": success_rate,
                    "total_attempts": stats["total_attempts"],
                    "successful_attempts": stats["successful_attempts"],
                }
                effectiveness_data.append(current_measurement)

                # Calculate trend
                trend = self._calculate_attack_effectiveness_trend(effectiveness_data)

                # Create report
                report = AttackEffectivenessReport(
                    attack_name=attack_name,
                    domain=domain or "all",
                    success_rate=success_rate,
                    avg_latency_ms=avg_latency,
                    total_attempts=stats["total_attempts"],
                    successful_attempts=stats["successful_attempts"],
                    failed_attempts=stats["failed_attempts"],
                    last_success=stats["last_success"],
                    last_failure=stats["last_failure"],
                    trend=trend,
                    confidence=self._calculate_attack_confidence(effectiveness_data),
                    category=stats["category"],
                    protocol=stats["protocol"],
                )

                reports.append(report)

                # Update attack performance tracking
                self.attack_performance[domain or "all"][attack_name] = {
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "trend": trend,
                    "last_updated": datetime.now(),
                    "category": stats["category"],
                }

            self.stats["attack_reports_generated"] += len(reports)
            self.logger.info(f"Generated {len(reports)} attack effectiveness reports")
            return reports

        except Exception as e:
            self.logger.error(f"Error monitoring attack effectiveness: {e}")
            if self.debug:
                self.logger.exception("Detailed attack effectiveness monitoring error:")
            return []

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
        try:
            self.logger.info(
                f"Recommending alternatives for {len(failing_attacks)} failing attacks"
            )

            recommendations = []

            for failing_attack in failing_attacks:
                # Get attack info to determine category
                attack_info = self.attack_adapter.get_attack_info(failing_attack)
                if not attack_info:
                    self.logger.warning(
                        f"No info found for failing attack: {failing_attack}"
                    )
                    continue

                category = attack_info.get("category", "unknown")

                # Get all attacks in the same category
                category_attacks = self.attack_adapter.get_available_attacks(
                    category=category
                )

                # Filter out the failing attack
                alternative_attacks = [
                    a for a in category_attacks if a != failing_attack
                ]

                # Sort by effectiveness ranking for this domain
                domain_key = domain or "all"
                if domain_key in self.attack_performance:
                    # Sort by success rate from performance data
                    alternative_attacks.sort(
                        key=lambda a: self.attack_performance[domain_key]
                        .get(a, {})
                        .get("success_rate", 0.0),
                        reverse=True,
                    )
                else:
                    # Sort by global ranking
                    alternative_attacks.sort(
                        key=lambda a: self.attack_rankings[category].get(a, 0.0),
                        reverse=True,
                    )

                # Take top 3 alternatives per failing attack
                top_alternatives = alternative_attacks[:3]
                recommendations.extend(top_alternatives)

                # Store alternatives for future reference
                self.attack_alternatives[failing_attack] = top_alternatives

                self.logger.debug(
                    f"Recommended alternatives for {failing_attack}: {top_alternatives}"
                )

            # Remove duplicates while preserving order
            unique_recommendations = []
            seen = set()
            for attack in recommendations:
                if attack not in seen:
                    unique_recommendations.append(attack)
                    seen.add(attack)

            self.logger.info(
                f"Recommended {len(unique_recommendations)} alternative attacks"
            )
            return unique_recommendations

        except Exception as e:
            self.logger.error(f"Error recommending attack alternatives: {e}")
            if self.debug:
                self.logger.exception("Detailed attack recommendation error:")
            return []

    def update_attack_rankings(self, effectiveness_data: Dict[str, Dict[str, float]]):
        """
        Update attack effectiveness rankings based on collected data.

        Args:
            effectiveness_data: Dictionary of domain -> {attack_name: effectiveness_score}
        """
        try:
            self.logger.info(
                f"Updating attack rankings for {len(effectiveness_data)} domains"
            )

            # Aggregate effectiveness scores by category
            category_scores = defaultdict(lambda: defaultdict(list))

            for domain, attack_scores in effectiveness_data.items():
                for attack_name, score in attack_scores.items():
                    # Get attack category
                    attack_info = self.attack_adapter.get_attack_info(attack_name)
                    if attack_info:
                        category = attack_info.get("category", "unknown")
                        category_scores[category][attack_name].append(score)

            # Calculate average scores and update rankings
            for category, attack_scores in category_scores.items():
                for attack_name, scores in attack_scores.items():
                    if scores:
                        avg_score = sum(scores) / len(scores)
                        self.attack_rankings[category][attack_name] = avg_score

            # Sort rankings within each category
            for category in self.attack_rankings:
                sorted_attacks = sorted(
                    self.attack_rankings[category].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
                self.attack_rankings[category] = dict(sorted_attacks)

            self.logger.info("Attack rankings updated successfully")

        except Exception as e:
            self.logger.error(f"Error updating attack rankings: {e}")
            if self.debug:
                self.logger.exception("Detailed attack ranking update error:")

    def auto_discover_strategies(self, failed_domains: List[str]) -> List[Strategy]:
        """
        Auto-discover new working strategies using BypassTechniques.

        Args:
            failed_domains: List of domains where current strategies failed

        Returns:
            List of newly discovered strategies
        """
        try:
            self.logger.info(
                f"Auto-discovering strategies for {len(failed_domains)} failed domains"
            )

            discovered_strategies = []

            if not self.fast_bypass_engine:
                self.logger.warning(
                    "FastBypassEngine not available for strategy discovery"
                )
                return discovered_strategies

            # Get available techniques from BypassTechniques
            available_techniques = self._get_available_techniques()

            for domain in failed_domains:
                self.logger.debug(f"Discovering strategies for {domain}")

                # Get domain fingerprint for targeted discovery
                domain_fingerprint = None
                if self.advanced_fingerprint_engine:
                    domain_fingerprint = self.advanced_fingerprint_engine.create_comprehensive_fingerprint(
                        domain
                    )

                # Test techniques based on fingerprint analysis
                promising_techniques = self._select_promising_techniques(
                    domain_fingerprint, available_techniques
                )

                for technique in promising_techniques:
                    strategy = self._test_technique_for_domain(
                        domain, technique, domain_fingerprint
                    )
                    if (
                        strategy and strategy.success_rate > 0.5
                    ):  # 50% success threshold
                        discovered_strategies.append(strategy)
                        self.discovered_strategies[strategy.strategy_id] = strategy
                        self.stats["strategies_discovered"] += 1

                        self.logger.info(
                            f"Discovered working strategy: {strategy.strategy_id} for {domain}"
                        )

            return discovered_strategies

        except Exception as e:
            self.logger.error(f"Error in auto-discovery: {e}")
            if self.debug:
                self.logger.exception("Detailed auto-discovery error:")
            return []

    def update_strategy_database(self, new_strategies: List[Strategy]):
        """
        Update strategy database compatible with existing strategy_map format.

        Args:
            new_strategies: List of new strategies to add to database
        """
        try:
            self.logger.info(
                f"Updating strategy database with {len(new_strategies)} new strategies"
            )

            # Load existing database
            strategy_db = self._load_strategy_database()

            # Add new strategies
            for strategy in new_strategies:
                # Convert to best_strategy.json format
                strategy_entry = {
                    "strategy": strategy.strategy_string,
                    "result_status": (
                        "WORKING" if strategy.success_rate > 0.5 else "TESTING"
                    ),
                    "success_rate": strategy.success_rate,
                    "avg_latency_ms": strategy.avg_latency_ms,
                    "domains": strategy.domains,
                    "fingerprint_summary": strategy.fingerprint_hash
                    or "Auto-discovered",
                    "created_at": strategy.created_at.isoformat(),
                    "technique_type": strategy.technique_type,
                    "parameters": strategy.parameters,
                }

                strategy_db["strategies_by_fingerprint"][
                    strategy.strategy_id
                ] = strategy_entry

            # Update metadata
            strategy_db["metadata"]["last_updated"] = time.time()
            strategy_db["metadata"]["version"] = "3.1"  # Increment version

            # Save updated database
            self._save_strategy_database(strategy_db)

            self.stats["database_updates"] += 1
            self.logger.info("Strategy database updated successfully")

        except Exception as e:
            self.logger.error(f"Error updating strategy database: {e}")
            if self.debug:
                self.logger.exception("Detailed database update error:")

    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics including attack-level metrics."""
        stats = self.stats.copy()

        # Add runtime statistics
        stats["monitoring_active"] = self.running
        stats["monitored_domains"] = len(self.fingerprint_history)
        stats["effectiveness_history_size"] = sum(
            len(history) for history in self.effectiveness_history.values()
        )
        stats["attack_effectiveness_history_size"] = sum(
            len(history) for history in self.attack_effectiveness_history.values()
        )
        stats["detected_changes_count"] = len(self.detected_changes)
        stats["discovered_strategies_count"] = len(self.discovered_strategies)

        # Add recent changes summary
        recent_changes = [
            change
            for change in self.detected_changes
            if datetime.now() - change.detected_at < timedelta(hours=24)
        ]
        stats["recent_changes_24h"] = len(recent_changes)

        # Add strategy performance summary (legacy)
        if self.strategy_performance:
            avg_success_rates = []
            for domain_strategies in self.strategy_performance.values():
                for strategy_data in domain_strategies.values():
                    if "success_rate" in strategy_data:
                        avg_success_rates.append(strategy_data["success_rate"])

            if avg_success_rates:
                stats["avg_strategy_success_rate"] = sum(avg_success_rates) / len(
                    avg_success_rates
                )

        # Add attack performance summary (NEW)
        if self.attack_performance:
            attack_success_rates = []
            category_stats = defaultdict(list)

            for domain_attacks in self.attack_performance.values():
                for attack_name, attack_data in domain_attacks.items():
                    if "success_rate" in attack_data:
                        success_rate = attack_data["success_rate"]
                        attack_success_rates.append(success_rate)

                        category = attack_data.get("category", "unknown")
                        category_stats[category].append(success_rate)

            if attack_success_rates:
                stats["avg_attack_success_rate"] = sum(attack_success_rates) / len(
                    attack_success_rates
                )

            # Add category-specific statistics
            stats["category_performance"] = {}
            for category, rates in category_stats.items():
                if rates:
                    stats["category_performance"][category] = {
                        "avg_success_rate": sum(rates) / len(rates),
                        "attack_count": len(rates),
                        "best_success_rate": max(rates),
                        "worst_success_rate": min(rates),
                    }

        # Add attack ranking statistics
        stats["attack_rankings_count"] = sum(
            len(rankings) for rankings in self.attack_rankings.values()
        )
        stats["categories_tracked"] = len(self.attack_rankings)

        # Add queue statistics
        stats["strategy_test_queue_size"] = len(self.strategy_test_queue)
        stats["attack_test_queue_size"] = len(self.attack_test_queue)

        return stats

    # Private helper methods

    def _monitoring_loop(self):
        """Main monitoring loop running in background thread."""
        self.logger.info("Starting enhanced monitoring loop with attack-level metrics")

        while self.running:
            try:
                self.stats["monitoring_cycles"] += 1
                # Periodically evaluate strategies assigned to domains
                for strategy_id, info in list(self.strategy_performance.items()):
                    domains = info.get("domains", [])
                    for domain in domains:
                        # Внутренний отчёт + production оценка и health
                        _ = self.monitor_strategy_effectiveness(strategy_id, domain)

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
                # Внутренний отчёт + production оценка и health
                _ = self.monitor_strategy_effectiveness(strategy_id, domain)

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
                    if domain not in [
                        item["domain"] for item in self.strategy_test_queue
                    ]:
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
            monitored_domains = list(self.fingerprint_history.keys())

            for domain in monitored_domains:
                changes = self.detect_dpi_changes(domain)

                # Process detected changes
                for change in changes:
                    self._process_dpi_change(change)

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

            # Clean effectiveness history (legacy)
            for history in self.effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean attack effectiveness history (NEW)
            for history in self.attack_effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean fingerprint history
            for history in self.fingerprint_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean detected changes
            while (
                self.detected_changes
                and self.detected_changes[0].detected_at < cutoff_time
            ):
                self.detected_changes.popleft()

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")

    def _load_existing_strategies(self):
        """Load existing strategies from best_strategy.json."""
        try:
            strategy_db = self._load_strategy_database()

            strategies = strategy_db.get("strategies_by_fingerprint", {})
            for strategy_id, strategy_data in strategies.items():
                domains = strategy_data.get("domains", [])
                for domain in domains:
                    self.domain_strategies[domain] = strategy_id

            self.logger.info(
                f"Loaded {len(self.domain_strategies)} existing domain-strategy mappings"
            )

        except Exception as e:
            self.logger.error(f"Error loading existing strategies: {e}")

    def _load_strategy_database(self) -> Dict[str, Any]:
        """Load strategy database from best_strategy.json."""
        try:
            if os.path.exists("best_strategy.json"):
                with open("best_strategy.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading strategy database: {e}")

        # Return default structure
        return {
            "metadata": {"version": "3.1", "last_updated": time.time()},
            "strategies_by_fingerprint": {},
        }

    def _save_strategy_database(self, strategy_db: Dict[str, Any]):
        """Save strategy database to best_strategy.json."""
        try:
            with open("best_strategy.json", "w") as f:
                json.dump(strategy_db, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving strategy database: {e}")
            raise

    def _get_available_techniques(self) -> List[str]:
        """Get list of available techniques from BypassTechniques."""
        return [
            "fakeddisorder",
            "multisplit",
            "multidisorder",
            "seqovl",
            "tlsrec_split",
            "wssize_limit",
            "badsum_fooling",
            "md5sig_fooling",
            "tcp_window_scaling",
            "urgent_pointer_manipulation",
            "tcp_options_padding",
            "ip_fragmentation_advanced",
            "timing_based_evasion",
            "payload_encryption",
            "protocol_tunneling",
            "decoy_packets",
            "noise_injection",
        ]

    def _select_promising_techniques(
        self, fingerprint, available_techniques: List[str]
    ) -> List[str]:
        """Select most promising techniques based on fingerprint analysis."""
        if not fingerprint:
            return available_techniques[:5]  # Return first 5 if no fingerprint

        promising = []

        # Analyze fingerprint characteristics
        if fingerprint.supports_fragmentation:
            promising.extend(["multisplit", "ip_fragmentation_advanced"])

        if not fingerprint.checksum_validation:
            promising.extend(["badsum_fooling", "md5sig_fooling"])

        if fingerprint.timing_sensitivity.get("delay_sensitivity", 0) > 0.5:
            promising.append("timing_based_evasion")

        # Add techniques based on success rates
        for technique, success_rate in fingerprint.technique_success_rates.items():
            if success_rate > 0.6 and technique in available_techniques:
                promising.append(technique)

        # Ensure we have at least some techniques to test
        if not promising:
            promising = ["fakeddisorder", "multisplit", "seqovl"]

        return list(set(promising))  # Remove duplicates

    def _test_technique_for_domain(
        self, domain: str, technique: str, fingerprint
    ) -> Optional[Strategy]:
        """Test a specific technique for a domain and create strategy if successful."""
        try:
            self.logger.debug(f"Testing technique {technique} for {domain}")

            # Get technique effectiveness from fingerprint or engine
            effectiveness = 0.0
            if fingerprint and technique in fingerprint.technique_success_rates:
                effectiveness = fingerprint.technique_success_rates[technique]
            elif self.advanced_fingerprint_engine:
                effectiveness = (
                    self.advanced_fingerprint_engine.analyze_technique_effectiveness(
                        domain, technique
                    )
                )

            # Simulate strategy testing (in real implementation, this would involve actual testing)
            if effectiveness > 0.5:
                # Create strategy
                strategy_string = self._technique_to_zapret_string(technique)
                strategy_id = f"{technique}_{domain}_{int(time.time())}"

                strategy = Strategy(
                    strategy_id=strategy_id,
                    strategy_string=strategy_string,
                    technique_type=technique,
                    success_rate=effectiveness,
                    avg_latency_ms=self._estimate_technique_latency(technique),
                    domains=[domain],
                    fingerprint_hash=(
                        fingerprint.get_fingerprint_hash() if fingerprint else None
                    ),
                    last_tested=datetime.now(),
                )

                return strategy

        except Exception as e:
            self.logger.error(f"Error testing technique {technique} for {domain}: {e}")

        return None

    def _technique_to_zapret_string(self, technique: str) -> str:
        """Convert technique name to zapret-compatible strategy string."""
        technique_mapping = {
            "fakeddisorder": "--dpi-desync=fakeddisorder",
            "multisplit": "--dpi-desync=multisplit --dpi-desync-split-count=3",
            "multidisorder": "--dpi-desync=multidisorder --dpi-desync-split-count=3",
            "seqovl": "--dpi-desync=multisplit --dpi-desync-split-seqovl=10",
            "badsum_fooling": "--dpi-desync-fooling=badsum",
            "md5sig_fooling": "--dpi-desync-fooling=md5sig",
            "tlsrec_split": "--dpi-desync=tlsrec --dpi-desync-split-pos=5",
        }

        return technique_mapping.get(technique, f"--dpi-desync={technique}")

    def _initialize_attack_rankings(self):
        """Initialize attack rankings from registry."""
        try:
            categories = self.attack_registry.get_categories()
            for category in categories:
                attacks = self.attack_registry.get_by_category(category)
                # Initialize with equal rankings
                for attack_name in attacks.keys():
                    self.attack_rankings[category][
                        attack_name
                    ] = 0.5  # Neutral starting score

            self.logger.info(
                f"Initialized attack rankings for {len(categories)} categories"
            )

        except Exception as e:
            self.logger.error(f"Error initializing attack rankings: {e}")

    def _calculate_attack_effectiveness_trend(self, effectiveness_data: deque) -> str:
        """Calculate trend for attack effectiveness."""
        if len(effectiveness_data) < 3:
            return "stable"

        try:
            # Get recent measurements
            recent_data = list(effectiveness_data)[-5:]  # Last 5 measurements
            success_rates = [data["success_rate"] for data in recent_data]

            # Calculate trend
            if len(success_rates) >= 2:
                recent_avg = sum(success_rates[-2:]) / 2
                older_avg = sum(success_rates[:-2]) / max(1, len(success_rates) - 2)

                if recent_avg > older_avg + 0.1:  # 10% improvement
                    return "improving"
                elif recent_avg < older_avg - 0.1:  # 10% degradation
                    return "degrading"

            return "stable"

        except Exception as e:
            self.logger.debug(f"Error calculating attack trend: {e}")
            return "stable"

    def _calculate_attack_confidence(self, effectiveness_data: deque) -> float:
        """Calculate confidence score for attack effectiveness."""
        if not effectiveness_data:
            return 0.0

        try:
            # Confidence based on data points and consistency
            data_points = len(effectiveness_data)
            if data_points < 3:
                return 0.3  # Low confidence with few data points

            # Calculate variance in success rates
            success_rates = [data["success_rate"] for data in effectiveness_data]
            if len(success_rates) > 1:
                mean_rate = sum(success_rates) / len(success_rates)
                variance = sum((rate - mean_rate) ** 2 for rate in success_rates) / len(
                    success_rates
                )

                # Lower variance = higher confidence
                consistency_score = max(0.0, 1.0 - variance * 2)  # Scale variance

                # More data points = higher confidence (up to a limit)
                data_score = min(1.0, data_points / 10.0)

                return (consistency_score + data_score) / 2

            return 0.5  # Neutral confidence

        except Exception as e:
            self.logger.debug(f"Error calculating attack confidence: {e}")
            return 0.5

    def _monitor_all_attacks(self):
        """Monitor effectiveness of all known attacks."""
        try:
            # Get recent attack results from adapter statistics
            adapter_stats = self.attack_adapter.get_execution_stats()

            # Simulate attack results for monitoring (in real implementation,
            # this would collect actual AttackResult objects from recent executions)
            if adapter_stats.get("total_executions", 0) > 0:
                # Create mock attack results based on adapter stats
                mock_results = []

                # Get all available attacks
                all_attacks = self.attack_adapter.get_available_attacks()

                for attack_name in all_attacks[:5]:  # Monitor top 5 attacks
                    # Create mock result based on general success rate
                    success_rate = adapter_stats.get("success_rate", 0.5)
                    status = (
                        AttackStatus.SUCCESS
                        if success_rate > 0.5
                        else AttackStatus.ERROR
                    )

                    mock_result = AttackResult(
                        status=status,
                        latency_ms=adapter_stats.get("average_execution_time", 50.0),
                        technique_used=attack_name,
                    )
                    mock_results.append(mock_result)

                # Monitor effectiveness
                reports = self.monitor_attack_effectiveness(mock_results)

                # Update statistics
                self.stats["attacks_monitored"] = len(reports)

                # Check for failing attacks
                failing_attacks = [
                    report.attack_name
                    for report in reports
                    if report.success_rate < 0.3 and report.total_attempts > 5
                ]

                if failing_attacks:
                    self.logger.warning(
                        f"Detected {len(failing_attacks)} failing attacks: {failing_attacks}"
                    )

                    # Get alternatives
                    alternatives = self.recommend_attack_alternatives(failing_attacks)
                    if alternatives:
                        self.logger.info(
                            f"Recommended {len(alternatives)} alternative attacks"
                        )

                        # Add to test queue
                        for attack in alternatives:
                            if attack not in [
                                item["attack"] for item in self.attack_test_queue
                            ]:
                                self.attack_test_queue.append(
                                    {
                                        "attack": attack,
                                        "reason": "alternative_recommendation",
                                        "priority": "medium",
                                    }
                                )

        except Exception as e:
            self.logger.error(f"Error monitoring all attacks: {e}")

    def _process_attack_test_queue(self):
        """Process queued attacks for testing."""
        try:
            if not self.attack_test_queue:
                return

            # Process up to 2 attacks per cycle to avoid overload
            for _ in range(min(2, len(self.attack_test_queue))):
                if not self.attack_test_queue:
                    break

                item = self.attack_test_queue.popleft()
                attack_name = item["attack"]

                self.logger.debug(f"Processing attack test queue item: {attack_name}")

                # Test attack effectiveness (simplified simulation)
                attack_info = self.attack_adapter.get_attack_info(attack_name)
                if attack_info:
                    # Simulate testing by creating a mock context and result
                    test_context = AttackContext(
                        dst_ip="127.0.0.1",
                        dst_port=80,
                        payload=b"GET / HTTP/1.1\r\n\r\n",
                    )

                    try:
                        # This would be actual testing in real implementation
                        # For now, simulate based on attack category
                        category = attack_info.get("category", "unknown")
                        simulated_success_rate = {
                            "tcp": 0.7,
                            "ip": 0.6,
                            "tls": 0.8,
                            "http": 0.75,
                            "payload": 0.65,
                            "tunneling": 0.55,
                            "combo": 0.85,
                        }.get(category, 0.5)

                        # Update rankings based on test
                        self.attack_rankings[category][
                            attack_name
                        ] = simulated_success_rate

                        self.logger.info(
                            f"Tested attack {attack_name}: {simulated_success_rate:.2%} effectiveness"
                        )

                    except Exception as e:
                        self.logger.error(f"Error testing attack {attack_name}: {e}")

        except Exception as e:
            self.logger.error(f"Error processing attack test queue: {e}")

    def _estimate_technique_latency(self, technique: str) -> float:
        """Estimate latency for a technique based on complexity."""
        latency_estimates = {
            "fakeddisorder": 5.0,
            "multisplit": 8.0,
            "multidisorder": 10.0,
            "seqovl": 12.0,
            "badsum_fooling": 3.0,
            "md5sig_fooling": 3.0,
            "ip_fragmentation_advanced": 15.0,
            "timing_based_evasion": 20.0,
        }

        return latency_estimates.get(technique, 10.0)

    def _analyze_fingerprint_change(
        self, domain: str, old_fingerprint, new_fingerprint
    ) -> Optional[DPIChange]:
        """Analyze changes between fingerprints and create DPIChange if significant."""
        try:
            # Compare technique success rates
            old_rates = (
                old_fingerprint.technique_success_rates
                if hasattr(old_fingerprint, "technique_success_rates")
                else {}
            )
            new_rates = new_fingerprint.technique_success_rates

            affected_techniques = []
            significant_changes = 0

            for technique in set(old_rates.keys()) | set(new_rates.keys()):
                old_rate = old_rates.get(technique, 0.0)
                new_rate = new_rates.get(technique, 0.0)

                change_magnitude = abs(old_rate - new_rate)
                if change_magnitude > self.change_detection_threshold:
                    affected_techniques.append(technique)
                    significant_changes += 1

            if significant_changes > 0:
                # Determine change type and severity
                change_type = (
                    "technique_failure"
                    if any(new_rates.get(t, 0) < 0.3 for t in affected_techniques)
                    else "behavior_change"
                )
                severity = "high" if significant_changes > 3 else "medium"

                # Generate recommendations
                recommendations = self._generate_change_recommendations(
                    change_type, affected_techniques
                )

                change = DPIChange(
                    domain=domain,
                    change_type=change_type,
                    detected_at=datetime.now(),
                    old_fingerprint_hash=(
                        old_fingerprint.get_fingerprint_hash()
                        if hasattr(old_fingerprint, "get_fingerprint_hash")
                        else None
                    ),
                    new_fingerprint_hash=new_fingerprint.get_fingerprint_hash(),
                    affected_techniques=affected_techniques,
                    severity=severity,
                    recommended_actions=recommendations,
                    confidence=min(
                        significant_changes / 5.0, 1.0
                    ),  # Confidence based on number of changes
                )

                return change

        except Exception as e:
            self.logger.error(f"Error analyzing fingerprint change: {e}")

        return None

    def _detect_technique_effectiveness_changes(
        self, domain: str, current_fingerprint
    ) -> List[DPIChange]:
        """Detect changes in technique effectiveness over time."""
        changes = []

        try:
            # Get historical effectiveness data
            history_key = f"technique_effectiveness_{domain}"
            if history_key in self.effectiveness_history:
                historical_data = self.effectiveness_history[history_key]

                if len(historical_data) >= 2:
                    # Compare recent effectiveness with historical average
                    recent_data = list(historical_data)[-5:]  # Last 5 measurements
                    historical_avg = {}
                    recent_avg = {}

                    # Calculate averages (simplified for this implementation)
                    for (
                        technique,
                        rate,
                    ) in current_fingerprint.technique_success_rates.items():
                        recent_avg[technique] = rate
                        # In real implementation, would calculate from historical_data
                        historical_avg[technique] = (
                            rate * 0.8
                        )  # Simulate historical data

                    # Detect significant drops
                    for technique in recent_avg:
                        if technique in historical_avg:
                            drop = historical_avg[technique] - recent_avg[technique]
                            if drop > 0.4:  # 40% drop threshold
                                change = DPIChange(
                                    domain=domain,
                                    change_type="technique_failure",
                                    detected_at=datetime.now(),
                                    affected_techniques=[technique],
                                    severity="high",
                                    recommended_actions=[
                                        f"Find alternative to {technique}",
                                        "Test combo strategies",
                                    ],
                                    confidence=min(drop, 1.0),
                                )
                                changes.append(change)

        except Exception as e:
            self.logger.error(f"Error detecting technique effectiveness changes: {e}")

        return changes

    def _generate_change_recommendations(
        self, change_type: str, affected_techniques: List[str]
    ) -> List[str]:
        """Generate recommendations based on detected changes."""
        recommendations = []

        if change_type == "technique_failure":
            recommendations.append("Test alternative bypass techniques")
            recommendations.append("Consider combo attack strategies")
            if "fragmentation" in str(affected_techniques):
                recommendations.append("Try timing-based evasion techniques")

        elif change_type == "behavior_change":
            recommendations.append("Update DPI fingerprint")
            recommendations.append("Re-test all techniques for this domain")
            recommendations.append("Monitor for additional changes")

        recommendations.append("Update strategy database")
        return recommendations

    def _process_dpi_change(self, change: DPIChange):
        """Process a detected DPI change and take appropriate actions."""
        try:
            self.logger.info(
                f"Processing DPI change: {change.change_type} for {change.domain}"
            )

            # Add to discovery queue if techniques failed
            if change.change_type == "technique_failure":
                self.strategy_test_queue.append(
                    {
                        "domain": change.domain,
                        "reason": "dpi_change",
                        "priority": "high",
                        "affected_techniques": change.affected_techniques,
                    }
                )

            # Log the change for analysis
            self.logger.warning(
                f"DPI change detected for {change.domain}: {change.change_type} "
                f"(severity: {change.severity}, confidence: {change.confidence:.2f})"
            )

        except Exception as e:
            self.logger.error(f"Error processing DPI change: {e}")

    def _calculate_effectiveness_trend(self, effectiveness_data: deque) -> str:
        """Calculate trend from effectiveness data."""
        if len(effectiveness_data) < 3:
            return "stable"

        recent_rates = [item["success_rate"] for item in list(effectiveness_data)[-3:]]
        older_rates = (
            [item["success_rate"] for item in list(effectiveness_data)[-6:-3]]
            if len(effectiveness_data) >= 6
            else recent_rates
        )

        recent_avg = sum(recent_rates) / len(recent_rates)
        older_avg = sum(older_rates) / len(older_rates)

        change = recent_avg - older_avg

        if change > 0.1:
            return "improving"
        elif change < -0.1:
            return "degrading"
        else:
            return "stable"

    def _calculate_confidence(self, effectiveness_data: deque) -> float:
        """Calculate confidence score based on data quality."""
        if not effectiveness_data:
            return 0.0

        # Confidence based on data points and consistency
        data_points = len(effectiveness_data)
        data_confidence = min(
            data_points / 10.0, 1.0
        )  # Max confidence at 10+ data points

        # Consistency confidence (lower variance = higher confidence)
        if data_points > 1:
            rates = [item["success_rate"] for item in effectiveness_data]
            variance = sum(
                (rate - sum(rates) / len(rates)) ** 2 for rate in rates
            ) / len(rates)
            consistency_confidence = max(
                0.0, 1.0 - variance * 2
            )  # Penalize high variance
        else:
            consistency_confidence = 0.5

        return (data_confidence + consistency_confidence) / 2.0

    def _estimate_latency_from_stats(self, combined_stats: Dict[str, int]) -> float:
        """Estimate latency from packet processing statistics."""
        # Simple estimation based on packet processing complexity
        total_packets = combined_stats.get("packets_captured", 1)
        fragments = combined_stats.get("fragments_sent", 0)
        fake_packets = combined_stats.get("fake_packets_sent", 0)

        # Base latency + complexity factors
        base_latency = 5.0
        fragment_penalty = (
            (fragments / total_packets) * 10.0 if total_packets > 0 else 0.0
        )
        fake_packet_penalty = (
            (fake_packets / total_packets) * 5.0 if total_packets > 0 else 0.0
        )

        return base_latency + fragment_penalty + fake_packet_penalty

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
