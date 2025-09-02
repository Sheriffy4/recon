"""
Integration module for DPI Behavior Monitoring System - Task 11 Implementation

This module provides integration between the DPI behavior monitoring system
and the existing advanced fingerprinting infrastructure.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import logging
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from core.fingerprint.dpi_behavior_monitor import (
    DPIBehaviorMonitor,
    MonitoringConfig,
    MonitoringAlert,
)
from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter
from core.fingerprint.advanced_models import DPIFingerprint

logger = logging.getLogger(__name__)


class MonitoringIntegration:
    """
    Integration layer for DPI behavior monitoring with existing systems.

    This class provides a high-level interface for integrating the monitoring
    system with existing components like HybridEngine, ZapretStrategyGenerator,
    and AdaptiveLearning.
    """

    def __init__(
        self,
        fingerprinter: AdvancedFingerprinter,
        monitoring_config: Optional[MonitoringConfig] = None,
    ):
        """
        Initialize monitoring integration

        Args:
            fingerprinter: Advanced fingerprinter instance
            monitoring_config: Optional monitoring configuration
        """
        self.fingerprinter = fingerprinter
        self.config = monitoring_config or MonitoringConfig()
        self.logger = logging.getLogger(f"{__name__}.MonitoringIntegration")
        self.monitor = DPIBehaviorMonitor(
            fingerprinter=fingerprinter,
            config=self.config,
            alert_callback=self._handle_monitoring_alert,
        )
        self.alert_handlers: List[Callable[[MonitoringAlert], None]] = []
        self.behavior_change_handlers: List[
            Callable[[str, DPIFingerprint, DPIFingerprint], None]
        ] = []
        self.strategy_update_handlers: List[Callable[[str, List[str]], None]] = []
        self.integration_stats = {
            "alerts_processed": 0,
            "behavior_changes_processed": 0,
            "strategy_updates_triggered": 0,
            "integration_errors": 0,
        }
        self.logger.info("Monitoring integration initialized")

    def add_alert_handler(self, handler: Callable[[MonitoringAlert], None]):
        """Add alert handler callback"""
        self.alert_handlers.append(handler)
        self.logger.debug(f"Added alert handler: {handler.__name__}")

    def add_behavior_change_handler(
        self, handler: Callable[[str, DPIFingerprint, DPIFingerprint], None]
    ):
        """Add behavior change handler callback"""
        self.behavior_change_handlers.append(handler)
        self.logger.debug(f"Added behavior change handler: {handler.__name__}")

    def add_strategy_update_handler(self, handler: Callable[[str, List[str]], None]):
        """Add strategy update handler callback"""
        self.strategy_update_handlers.append(handler)
        self.logger.debug(f"Added strategy update handler: {handler.__name__}")

    def _handle_monitoring_alert(self, alert: MonitoringAlert):
        """Handle monitoring alerts and trigger integration callbacks"""
        try:
            self.integration_stats["alerts_processed"] += 1
            for handler in self.alert_handlers:
                try:
                    handler(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert handler {handler.__name__}: {e}")
                    self.integration_stats["integration_errors"] += 1
            if alert.severity.value in ["high", "critical"]:
                self._trigger_strategy_update(alert)
        except Exception as e:
            self.logger.error(f"Error handling monitoring alert: {e}")
            self.integration_stats["integration_errors"] += 1

    def _trigger_strategy_update(self, alert: MonitoringAlert):
        """Trigger strategy updates based on alert"""
        try:
            recommended_strategies = self._generate_strategy_recommendations(alert)
            if recommended_strategies:
                self.integration_stats["strategy_updates_triggered"] += 1
                for handler in self.strategy_update_handlers:
                    try:
                        handler(alert.target, recommended_strategies)
                    except Exception as e:
                        self.logger.error(
                            f"Error in strategy update handler {handler.__name__}: {e}"
                        )
                        self.integration_stats["integration_errors"] += 1
        except Exception as e:
            self.logger.error(f"Error triggering strategy update: {e}")
            self.integration_stats["integration_errors"] += 1

    def _generate_strategy_recommendations(self, alert: MonitoringAlert) -> List[str]:
        """Generate strategy recommendations based on alert"""
        recommendations = []
        fingerprint = alert.fingerprint
        if fingerprint.dpi_type.value == "roskomnadzor_tspu":
            recommendations.extend(
                [
                    "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
                ]
            )
        elif fingerprint.dpi_type.value == "commercial_dpi":
            recommendations.extend(
                [
                    "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=3",
                    "--dpi-desync=split2 --dpi-desync-split-pos=2",
                    "--dpi-desync=disorder --dpi-desync-fooling=badseq",
                ]
            )
        elif fingerprint.dpi_type.value == "firewall_based":
            recommendations.extend(
                [
                    "--dpi-desync=fake --dpi-desync-ttl=1",
                    "--dpi-desync=split2 --dpi-desync-split-pos=1",
                    "--dpi-desync=disorder",
                ]
            )
        if fingerprint.rst_injection_detected:
            recommendations.append(
                "--dpi-desync=fake --dpi-desync-fooling=badsum --dpi-desync-ttl=1"
            )
        if fingerprint.http_header_filtering:
            recommendations.append("--dpi-desync=split2 --dpi-desync-split-pos=3")
        if fingerprint.dns_hijacking_detected:
            recommendations.extend(["--dns-addr=8.8.8.8", "--dns-addr=1.1.1.1"])
        return recommendations[:5]

    async def start_monitoring(self, targets: Optional[List[tuple]] = None):
        """
        Start monitoring system with optional initial targets

        Args:
            targets: List of (domain, port) tuples to monitor
        """
        try:
            if targets:
                for domain, port in targets:
                    self.monitor.add_target(domain, port)
                    self.logger.info(f"Added monitoring target: {domain}:{port}")
            await self.monitor.start_monitoring()
            self.logger.info("Monitoring system started successfully")
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            raise

    async def stop_monitoring(self):
        """Stop monitoring system"""
        try:
            await self.monitor.stop_monitoring()
            self.logger.info("Monitoring system stopped successfully")
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            raise

    def add_monitoring_target(self, domain: str, port: int = 443):
        """Add target for monitoring"""
        self.monitor.add_target(domain, port)
        self.logger.info(f"Added monitoring target: {domain}:{port}")

    def remove_monitoring_target(self, domain: str, port: int = 443):
        """Remove target from monitoring"""
        self.monitor.remove_target(domain, port)
        self.logger.info(f"Removed monitoring target: {domain}:{port}")

    async def check_target_behavior(
        self, domain: str, port: int = 443
    ) -> Optional[DPIFingerprint]:
        """
        Check behavior of specific target and return fingerprint

        Args:
            domain: Target domain
            port: Target port

        Returns:
            DPI fingerprint if successful, None otherwise
        """
        try:
            change = await self.monitor.force_check(domain, port)
            if change:
                self.integration_stats["behavior_changes_processed"] += 1
                for handler in self.behavior_change_handlers:
                    try:
                        handler(
                            change.target,
                            change.old_fingerprint,
                            change.new_fingerprint,
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Error in behavior change handler {handler.__name__}: {e}"
                        )
                        self.integration_stats["integration_errors"] += 1
                return change.new_fingerprint
            target_status = self.monitor.get_target_status(domain, port)
            if target_status:
                return DPIFingerprint.from_dict(target_status["current_fingerprint"])
            return None
        except Exception as e:
            self.logger.error(
                f"Error checking target behavior for {domain}:{port}: {e}"
            )
            self.integration_stats["integration_errors"] += 1
            return None

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status"""
        monitor_status = self.monitor.get_monitoring_status()
        return {
            "monitoring": monitor_status,
            "integration": {
                "alert_handlers": len(self.alert_handlers),
                "behavior_change_handlers": len(self.behavior_change_handlers),
                "strategy_update_handlers": len(self.strategy_update_handlers),
                "stats": self.integration_stats.copy(),
            },
        }

    def get_target_recommendations(
        self, domain: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Get strategy recommendations for specific target

        Args:
            domain: Target domain
            port: Target port

        Returns:
            Dictionary with recommendations and analysis
        """
        try:
            target_status = self.monitor.get_target_status(domain, port)
            if not target_status:
                return {"error": "Target not monitored", "recommendations": []}
            fingerprint = DPIFingerprint.from_dict(target_status["current_fingerprint"])
            mock_alert = MonitoringAlert(
                id="temp",
                target=f"{domain}:{port}",
                timestamp=datetime.now(),
                severity=alert.AlertSeverity.MEDIUM,
                title="Strategy Recommendation Request",
                description="Generating recommendations",
                fingerprint=fingerprint,
            )
            recommendations = self._generate_strategy_recommendations(mock_alert)
            return {
                "target": f"{domain}:{port}",
                "dpi_type": fingerprint.dpi_type.value,
                "confidence": fingerprint.confidence,
                "recommendations": recommendations,
                "analysis": {
                    "rst_injection": fingerprint.rst_injection_detected,
                    "http_filtering": fingerprint.http_header_filtering,
                    "dns_hijacking": fingerprint.dns_hijacking_detected,
                    "content_inspection": fingerprint.content_inspection_depth > 0,
                },
            }
        except Exception as e:
            self.logger.error(f"Error getting recommendations for {domain}:{port}: {e}")
            return {"error": str(e), "recommendations": []}

    def get_active_alerts(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get active alerts with optional target filtering"""
        try:
            alerts = self.monitor.get_alerts(target=target, unresolved_only=True)
            return [alert.to_dict() for alert in alerts]
        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return []

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert"""
        return self.monitor.acknowledge_alert(alert_id)

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        return self.monitor.resolve_alert(alert_id)

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of monitoring system"""
        try:
            fp_health = await self.fingerprinter.health_check()
            monitor_status = self.monitor.get_monitoring_status()
            overall_health = "healthy"
            if fp_health.get("status") != "healthy":
                overall_health = "degraded"
            if monitor_status["state"] == "error":
                overall_health = "unhealthy"
            return {
                "status": overall_health,
                "timestamp": datetime.now().isoformat(),
                "components": {
                    "fingerprinter": fp_health,
                    "monitor": {
                        "state": monitor_status["state"],
                        "monitored_targets": monitor_status["monitored_targets"],
                        "active_tasks": monitor_status["active_tasks"],
                        "behavior_changes": monitor_status["behavior_changes"],
                        "active_alerts": monitor_status["active_alerts"],
                    },
                    "integration": {
                        "handlers_registered": {
                            "alert_handlers": len(self.alert_handlers),
                            "behavior_change_handlers": len(
                                self.behavior_change_handlers
                            ),
                            "strategy_update_handlers": len(
                                self.strategy_update_handlers
                            ),
                        },
                        "stats": self.integration_stats.copy(),
                    },
                },
            }
        except Exception as e:
            self.logger.error(f"Error in health check: {e}")
            return {
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
            }


def create_monitoring_integration(
    fingerprinter: AdvancedFingerprinter, config: Optional[MonitoringConfig] = None
) -> MonitoringIntegration:
    """
    Create monitoring integration with default configuration

    Args:
        fingerprinter: Advanced fingerprinter instance
        config: Optional monitoring configuration

    Returns:
        MonitoringIntegration instance
    """
    return MonitoringIntegration(fingerprinter, config)


async def setup_basic_monitoring(
    fingerprinter: AdvancedFingerprinter,
    targets: List[tuple],
    alert_handler: Optional[Callable[[MonitoringAlert], None]] = None,
) -> MonitoringIntegration:
    """
    Set up basic monitoring with common configuration

    Args:
        fingerprinter: Advanced fingerprinter instance
        targets: List of (domain, port) tuples to monitor
        alert_handler: Optional alert handler callback

    Returns:
        Configured and started MonitoringIntegration instance
    """
    integration = MonitoringIntegration(fingerprinter)
    if alert_handler:
        integration.add_alert_handler(alert_handler)
    await integration.start_monitoring(targets)
    return integration


def default_alert_handler(alert: MonitoringAlert):
    """Default alert handler that logs alerts"""
    severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}
    emoji = severity_emoji.get(alert.severity.value, "⚠️")
    logger.warning(f"{emoji} DPI Alert: {alert.title}")
    logger.warning(f"   Target: {alert.target}")
    logger.warning(f"   Severity: {alert.severity.value.upper()}")
    logger.warning(f"   Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    if alert.suggested_actions:
        logger.warning("   Suggested actions:")
        for action in alert.suggested_actions:
            logger.warning(f"   - {action}")


def default_behavior_change_handler(
    target: str, old_fp: Optional[DPIFingerprint], new_fp: DPIFingerprint
):
    """Default behavior change handler that logs changes"""
    if old_fp:
        logger.info(f"🔄 DPI behavior change detected for {target}")
        logger.info(
            f"   Old DPI type: {old_fp.dpi_type.value} (confidence: {old_fp.confidence:.2f})"
        )
        logger.info(
            f"   New DPI type: {new_fp.dpi_type.value} (confidence: {new_fp.confidence:.2f})"
        )
    else:
        logger.info(f"🆕 New DPI target analyzed: {target}")
        logger.info(
            f"   DPI type: {new_fp.dpi_type.value} (confidence: {new_fp.confidence:.2f})"
        )


def default_strategy_update_handler(target: str, strategies: List[str]):
    """Default strategy update handler that logs recommendations"""
    logger.info(f"📋 Strategy recommendations for {target}:")
    for i, strategy in enumerate(strategies, 1):
        logger.info(f"   {i}. {strategy}")
