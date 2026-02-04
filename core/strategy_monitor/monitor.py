"""
Main StrategyMonitor orchestrator.

Coordinates all monitoring components while maintaining backward compatibility.
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import deque

from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.base import AttackResult
from core.effectiveness.production_effectiveness_tester import ProductionEffectivenessTester
from core.bypass.engines.health_check import EngineHealthCheck

from .models import (
    AttackEffectivenessReport,
    EffectivenessReport,
    DPIChange,
    Strategy,
)
from .effectiveness_tracker import EffectivenessTracker
from .dpi_detector import DPIDetector
from .strategy_discovery import StrategyDiscovery
from .attack_manager import AttackManager
from .database_manager import DatabaseManager


class StrategyMonitor:
    """
    Enhanced automatic strategy effectiveness monitoring and DPI change detection system.

    This is now a thin orchestrator that delegates to specialized components:
    - EffectivenessTracker: Strategy effectiveness monitoring
    - DPIDetector: DPI change detection
    - StrategyDiscovery: Auto-discovery of new strategies
    - AttackManager: Attack-level monitoring and recommendations
    - DatabaseManager: Strategy database persistence

    Maintains backward compatibility with the original API.
    """

    def __init__(
        self,
        fast_bypass_engine=None,
        advanced_fingerprint_engine=None,
        debug: bool = True,
    ):
        """
        Initialize StrategyMonitor with all components.

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

        # Load monitoring config from engine if available
        cfg = getattr(getattr(fast_bypass_engine, "config", None), "typed_config", None)
        if cfg and hasattr(cfg, "monitoring"):
            self.monitor_interval = int(cfg.monitoring.monitor_interval_seconds)
            alert_threshold = float(cfg.monitoring.alert_success_rate_threshold)
            use_https = bool(cfg.monitoring.use_https)
        else:
            self.monitor_interval = 60
            alert_threshold = 0.6
            use_https = True

        # Initialize production testing components
        prod_effectiveness_tester = ProductionEffectivenessTester()
        health_check = EngineHealthCheck(debug=self.debug)

        # Try to initialize reporter
        try:
            from core.reporting import EnhancedReporter

            reporter = EnhancedReporter()
        except Exception:
            reporter = None

        # Initialize specialized components
        self.effectiveness_tracker = EffectivenessTracker(
            fast_bypass_engine=fast_bypass_engine,
            prod_effectiveness_tester=prod_effectiveness_tester,
            health_check=health_check,
            reporter=reporter,
            use_https=use_https,
            alert_threshold=alert_threshold,
            logger=self.logger,
        )

        self.dpi_detector = DPIDetector(
            advanced_fingerprint_engine=advanced_fingerprint_engine,
            change_threshold=0.3,
            logger=self.logger,
        )

        self.strategy_discovery = StrategyDiscovery(
            fast_bypass_engine=fast_bypass_engine,
            advanced_fingerprint_engine=advanced_fingerprint_engine,
            logger=self.logger,
        )

        self.attack_manager = AttackManager(
            attack_adapter=self.attack_adapter,
            attack_registry=self.attack_registry,
            logger=self.logger,
        )

        self.database_manager = DatabaseManager(logger=self.logger)

        # Strategy discovery queue
        self.strategy_test_queue = deque()
        self.auto_discovery_enabled = True

        # Load existing strategies
        self.domain_strategies = self.database_manager.load_existing_strategies()
        self.effectiveness_tracker.domain_strategies = self.domain_strategies

        self.logger.info(
            "Enhanced StrategyMonitor initialized with unified attack system integration"
        )

    # ==================== Public API Methods (Backward Compatible) ====================

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
        self, strategy_id: str, domain: Optional[str] = None
    ) -> EffectivenessReport:
        """
        Monitor effectiveness of a specific strategy.

        Delegates to EffectivenessTracker.
        """
        return self.effectiveness_tracker.monitor_strategy_effectiveness(strategy_id, domain)

    def detect_dpi_changes(self, domain: str) -> List[DPIChange]:
        """
        Detect changes in DPI behavior.

        Delegates to DPIDetector.
        """
        return self.dpi_detector.detect_changes(domain)

    def monitor_attack_effectiveness(
        self, attack_results: List[AttackResult], domain: Optional[str] = None
    ) -> List[AttackEffectivenessReport]:
        """
        Monitor effectiveness of individual attacks.

        Delegates to AttackManager.
        """
        return self.attack_manager.monitor_attack_effectiveness(attack_results, domain)

    def recommend_attack_alternatives(
        self, failing_attacks: List[str], domain: Optional[str] = None
    ) -> List[str]:
        """
        Recommend alternative attacks when current ones fail.

        Delegates to AttackManager.
        """
        return self.attack_manager.recommend_attack_alternatives(failing_attacks, domain)

    def update_attack_rankings(self, effectiveness_data: Dict[str, Dict[str, float]]):
        """
        Update attack effectiveness rankings.

        Delegates to AttackManager.
        """
        self.attack_manager.update_attack_rankings(effectiveness_data)

    def auto_discover_strategies(self, failed_domains: List[str]) -> List[Strategy]:
        """
        Auto-discover new working strategies.

        Delegates to StrategyDiscovery.
        """
        return self.strategy_discovery.discover_strategies(failed_domains)

    def update_strategy_database(self, new_strategies: List[Strategy]):
        """
        Update strategy database with new strategies.

        Delegates to DatabaseManager.
        """
        self.database_manager.update_strategies(new_strategies)

    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics from all components."""
        stats = {}

        # Monitoring state
        stats["monitoring_active"] = self.running
        stats["monitor_interval"] = self.monitor_interval

        # Effectiveness tracker stats
        effectiveness_stats = self.effectiveness_tracker.get_effectiveness_stats()
        stats.update(effectiveness_stats)

        # DPI detector stats
        dpi_stats = self.dpi_detector.get_dpi_stats()
        stats.update(dpi_stats)

        # Attack manager stats
        attack_stats = self.attack_manager.get_attack_stats()
        stats.update(attack_stats)

        # Strategy discovery stats
        discovery_stats = self.strategy_discovery.get_discovery_stats()
        stats.update(discovery_stats)

        # Queue statistics
        stats["strategy_test_queue_size"] = len(self.strategy_test_queue)

        return stats

    # ==================== Private Helper Methods ====================

    def _monitoring_loop(self):
        """Main monitoring loop running in background thread."""
        self.logger.info("Starting enhanced monitoring loop with attack-level metrics")

        while self.running:
            try:
                # Monitor all strategies
                self.effectiveness_tracker.monitor_all_strategies()

                # Check for DPI changes
                self._check_all_domains_for_changes()

                # Monitor all attacks
                self.attack_manager.monitor_all_attacks()

                # Process discovery queue
                self._process_discovery_queue()

                # Process attack test queue
                self.attack_manager.process_attack_test_queue()

                # Cleanup old data
                self._cleanup_old_data()

                time.sleep(self.monitor_interval)

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                if self.debug:
                    self.logger.exception("Detailed monitoring loop error:")
                time.sleep(self.monitor_interval)

    def _check_all_domains_for_changes(self):
        """Check all monitored domains for DPI changes."""
        try:
            monitored_domains = list(self.dpi_detector.fingerprint_history.keys())

            for domain in monitored_domains:
                changes = self.dpi_detector.detect_changes(domain)

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
                new_strategies = self.strategy_discovery.discover_strategies([domain])

                # Update database if strategies found
                if new_strategies:
                    self.database_manager.update_strategies(new_strategies)

                    # Update domain strategy mapping
                    best_strategy = max(new_strategies, key=lambda s: s.success_rate)
                    self.domain_strategies[domain] = best_strategy.strategy_id
                    self.effectiveness_tracker.domain_strategies = self.domain_strategies

        except Exception as e:
            self.logger.error(f"Error processing discovery queue: {e}")

    def _process_dpi_change(self, change: DPIChange):
        """Process a detected DPI change and take appropriate actions."""
        try:
            self.logger.info(f"Processing DPI change: {change.change_type} for {change.domain}")

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

    def _cleanup_old_data(self):
        """Clean up old monitoring data to prevent memory leaks."""
        try:
            cutoff_time = datetime.now() - timedelta(days=7)

            # Clean effectiveness history
            for history in self.effectiveness_tracker.effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean attack effectiveness history
            for history in self.attack_manager.attack_effectiveness_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean fingerprint history
            for history in self.dpi_detector.fingerprint_history.values():
                while history and history[0]["timestamp"] < cutoff_time:
                    history.popleft()

            # Clean detected changes
            while (
                self.dpi_detector.detected_changes
                and self.dpi_detector.detected_changes[0].detected_at < cutoff_time
            ):
                self.dpi_detector.detected_changes.popleft()

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
