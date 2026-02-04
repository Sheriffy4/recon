#!/usr/bin/env python3
"""
Analysis utilities for advanced reporting system.
"""

import logging
from datetime import datetime
from typing import Dict, List, Any

from core.integration.reporting_models import AdvancedAttackReport

LOG = logging.getLogger(__name__)


def analyze_performance_trends(performance_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze performance trends from data."""
    try:
        attack_metrics = performance_data.get("attack_metrics", [])

        if not attack_metrics:
            return {"message": "No performance data available"}

        # Group by time periods
        hourly_performance = {}
        for metric in attack_metrics:
            timestamp = datetime.fromisoformat(metric["timestamp"].replace("Z", "+00:00"))
            hour_key = timestamp.strftime("%Y-%m-%d %H:00")

            if hour_key not in hourly_performance:
                hourly_performance[hour_key] = {
                    "total": 0,
                    "successful": 0,
                    "effectiveness_scores": [],
                }

            hourly_performance[hour_key]["total"] += 1
            if metric["success"]:
                hourly_performance[hour_key]["successful"] += 1
            hourly_performance[hour_key]["effectiveness_scores"].append(
                metric["effectiveness_score"]
            )

        # Calculate trends
        trends = {}
        for hour, data in hourly_performance.items():
            success_rate = (data["successful"] / data["total"]) * 100
            avg_effectiveness = sum(data["effectiveness_scores"]) / len(
                data["effectiveness_scores"]
            )

            trends[hour] = {
                "success_rate": success_rate,
                "average_effectiveness": avg_effectiveness,
                "total_attacks": data["total"],
            }

        return trends

    except Exception as e:
        LOG.error(f"Failed to analyze performance trends: {e}")
        return {"error": str(e)}


def analyze_attack_trend(recent_reports: List[AdvancedAttackReport]) -> Dict[str, Any]:
    """Analyze trend for specific attack."""
    try:
        if len(recent_reports) < 3:
            return {"trend": "insufficient_data"}

        # Calculate success rate trend
        success_rates = []
        for i in range(len(recent_reports) - 2):
            batch = recent_reports[i : i + 3]
            success_rate = sum(1 for r in batch if r.success) / len(batch)
            success_rates.append(success_rate)

        if len(success_rates) < 2:
            return {"trend": "stable"}

        # Determine trend
        recent_rate = success_rates[-1]
        older_rate = success_rates[0]

        if recent_rate > older_rate + 0.1:
            trend = "improving"
        elif recent_rate < older_rate - 0.1:
            trend = "declining"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "recent_success_rate": recent_rate,
            "change_from_baseline": recent_rate - older_rate,
        }

    except Exception as e:
        LOG.error(f"Failed to analyze attack trend: {e}")
        return {"trend": "unknown", "error": str(e)}


def calculate_average_effectiveness(performance_data: Dict[str, Any]) -> float:
    """Calculate average effectiveness from performance data."""
    try:
        attack_metrics = performance_data.get("attack_metrics", [])
        if not attack_metrics:
            return 0.0

        effectiveness_scores = [m["effectiveness_score"] for m in attack_metrics]
        return sum(effectiveness_scores) / len(effectiveness_scores)

    except Exception:
        return 0.0
