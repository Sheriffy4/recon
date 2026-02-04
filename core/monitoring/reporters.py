"""Reporting functions for monitoring system."""

import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger(__name__)


def generate_status_report(
    monitored_sites: Dict,
    monitoring_stats: Dict,
    modern_bypass_enabled: bool,
    attack_registry=None,
    pool_manager=None,
    closed_loop_metrics_collector=None,
    effectiveness_reporter=None,
) -> dict:
    """Generate comprehensive status report.

    Args:
        monitored_sites: Dictionary of monitored sites
        monitoring_stats: Monitoring statistics
        modern_bypass_enabled: Whether modern bypass is enabled
        attack_registry: Optional AttackRegistry instance
        pool_manager: Optional StrategyPoolManager instance
        closed_loop_metrics_collector: Optional metrics collector
        effectiveness_reporter: Optional effectiveness reporter

    Returns:
        Status report dictionary
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_sites": len(monitored_sites),
        "accessible_sites": sum((1 for h in monitored_sites.values() if h.is_accessible)),
        "sites_with_bypass": sum((1 for h in monitored_sites.values() if h.bypass_active)),
        "average_response_time": 0.0,
        "modern_bypass_enabled": modern_bypass_enabled,
        "monitoring_stats": monitoring_stats.copy(),
        "sites": {},
    }

    # Calculate average response time
    if monitored_sites:
        accessible_sites = [h for h in monitored_sites.values() if h.is_accessible]
        if accessible_sites:
            report["average_response_time"] = sum(
                (h.response_time_ms for h in accessible_sites)
            ) / len(accessible_sites)

    # Add modern bypass stats
    if modern_bypass_enabled:
        if attack_registry:
            try:
                registry_stats = attack_registry.get_stats()
                report["attack_registry_stats"] = registry_stats
            except Exception as e:
                logger.error(f"Failed to get attack registry stats: {e}")
        if pool_manager:
            try:
                pool_stats = pool_manager.get_pool_statistics()
                report["pool_manager_stats"] = pool_stats
            except Exception as e:
                logger.error(f"Failed to get pool manager stats: {e}")

    # Add closed-loop metrics (Task 8.2)
    if closed_loop_metrics_collector:
        try:
            closed_loop_metrics = closed_loop_metrics_collector.get_metrics_dict()

            # Add tags for grouping (pattern_id, root_cause)
            tagged_metrics = {}
            for key, value in closed_loop_metrics.items():
                if key == "success_rate_by_pattern":
                    # Add pattern_id tags
                    for pattern_id, success_rate in value.items():
                        tagged_key = f"{key}.{pattern_id}"
                        tagged_metrics[tagged_key] = {
                            "value": success_rate,
                            "tags": {"pattern_id": pattern_id, "metric_type": "success_rate"},
                        }
                else:
                    tagged_metrics[key] = {
                        "value": value,
                        "tags": {"metric_type": "closed_loop", "component": "adaptive_engine"},
                    }

            report["closed_loop_metrics"] = tagged_metrics
            report["closed_loop_summary"] = closed_loop_metrics_collector.get_summary_report()

        except Exception as e:
            logger.error(f"Failed to get closed-loop metrics: {e}")
            report["closed_loop_metrics"] = {"error": str(e)}

    # Add rule effectiveness availability (Task 8.3)
    report["rule_effectiveness_available"] = effectiveness_reporter is not None

    # Add individual site reports
    for site_key, health in monitored_sites.items():
        report["sites"][site_key] = health.to_dict()

    return report


def generate_health_summary(monitored_sites: Dict) -> str:
    """Generate brief health summary.

    Args:
        monitored_sites: Dictionary of monitored sites

    Returns:
        Summary string
    """
    total = len(monitored_sites)
    accessible = sum((1 for h in monitored_sites.values() if h.is_accessible))
    with_bypass = sum((1 for h in monitored_sites.values() if h.bypass_active))
    return f"📊 Status: {accessible}/{total} accessible, {with_bypass} with bypass"
