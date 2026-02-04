"""
Monitoring Coordinator Module

Provides real-time monitoring coordination and health checking
for diagnostic system operations.
"""

import logging
import time
from typing import Dict, Any, Callable


class MonitoringCoordinator:
    """Coordinates real-time monitoring and health checks."""

    def __init__(
        self, thresholds: Dict[str, float], monitoring_interval: float, debug: bool = False
    ):
        """
        Initialize MonitoringCoordinator.

        Args:
            thresholds: Dictionary of threshold values for health checks
            monitoring_interval: Interval between monitoring cycles (seconds)
            debug: Enable debug logging
        """
        self.thresholds = thresholds
        self.monitoring_interval = monitoring_interval
        self.debug = debug
        self.logger = logging.getLogger("MonitoringCoordinator")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def run_monitoring_loop(
        self,
        is_active_callback: Callable[[], bool],
        analyze_effectiveness_callback: Callable[[int], Dict[str, Any]],
        get_technique_metrics_callback: Callable[[], Dict],
        update_stats_callback: Callable[[str], None],
    ):
        """
        Run the main monitoring loop.

        Args:
            is_active_callback: Function that returns True if monitoring should continue
            analyze_effectiveness_callback: Function to analyze bypass effectiveness
            get_technique_metrics_callback: Function to get technique metrics
            update_stats_callback: Function to update statistics
        """
        self.logger.info("Monitoring loop started")

        while is_active_callback():
            try:
                # Update monitoring cycle count
                update_stats_callback("monitoring_cycles")

                # Analyze effectiveness
                effectiveness = analyze_effectiveness_callback(5)  # 5 minute window

                # Check for critical performance issues
                self._check_critical_performance(effectiveness)

                # Check technique performance
                technique_metrics = get_technique_metrics_callback()
                self._check_technique_performance(technique_metrics)

                # Sleep until next cycle
                time.sleep(self.monitoring_interval)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)

        self.logger.info("Monitoring loop stopped")

    def _check_critical_performance(self, effectiveness: Dict[str, Any]):
        """
        Check for critical performance issues.

        Args:
            effectiveness: Effectiveness analysis results
        """
        # Backward/forward compatibility: DiagnosticSystem may expose different keys
        overall_effectiveness = effectiveness.get("overall_effectiveness")
        if overall_effectiveness is None:
            overall_effectiveness = effectiveness.get("bypass_effectiveness", 0)

        critical_threshold = self.thresholds.get("health_score_critical", 0.5)

        if overall_effectiveness < critical_threshold:
            self.logger.warning(
                f"⚠️ Critical performance issue detected: "
                f"Effectiveness={overall_effectiveness:.2f}"
            )

    def _check_technique_performance(self, technique_metrics: Dict):
        """
        Check performance of individual techniques.

        Args:
            technique_metrics: Dictionary of technique performance metrics
        """
        min_success_rate = self.thresholds.get("min_success_rate", 0.8)

        for technique_name, metrics in technique_metrics.items():
            if metrics.success_rate < min_success_rate:
                self.logger.warning(
                    f"⚠️ Technique {technique_name} underperforming: "
                    f"Success rate={metrics.success_rate:.2f}"
                )
