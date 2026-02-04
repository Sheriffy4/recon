#!/usr/bin/env python3
"""
Helper functions for report generation and analysis.
"""

import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
from dataclasses import asdict

from core.integration.reporting_models import AdvancedAttackReport

LOG = logging.getLogger(__name__)


def calculate_dpi_analysis(attack_reports: List[AdvancedAttackReport]) -> Dict[str, Any]:
    """Calculate DPI-specific analysis from attack reports."""
    dpi_analysis = {}

    for report in attack_reports:
        dpi_type = report.dpi_type
        if dpi_type not in dpi_analysis:
            dpi_analysis[dpi_type] = {
                "total": 0,
                "successful": 0,
                "effectiveness_scores": [],
            }

        dpi_analysis[dpi_type]["total"] += 1
        if report.success:
            dpi_analysis[dpi_type]["successful"] += 1
        dpi_analysis[dpi_type]["effectiveness_scores"].append(report.effectiveness_score)

    # Calculate DPI-specific metrics
    for dpi_type, data in dpi_analysis.items():
        data["success_rate"] = (data["successful"] / data["total"]) * 100
        data["avg_effectiveness"] = sum(data["effectiveness_scores"]) / len(
            data["effectiveness_scores"]
        )

    return dpi_analysis


def calculate_attack_analysis(target_reports: List[AdvancedAttackReport]) -> Dict[str, Any]:
    """Calculate attack effectiveness analysis by type."""
    attack_analysis = {}

    for report in target_reports:
        attack_name = report.attack_name
        if attack_name not in attack_analysis:
            attack_analysis[attack_name] = {
                "executions": 0,
                "successes": 0,
                "effectiveness_scores": [],
            }

        attack_analysis[attack_name]["executions"] += 1
        if report.success:
            attack_analysis[attack_name]["successes"] += 1
        attack_analysis[attack_name]["effectiveness_scores"].append(report.effectiveness_score)

    # Calculate metrics for each attack
    for attack_name, data in attack_analysis.items():
        data["success_rate"] = (data["successes"] / data["executions"]) * 100
        data["avg_effectiveness"] = sum(data["effectiveness_scores"]) / len(
            data["effectiveness_scores"]
        )

    return attack_analysis


def create_summary_report(comprehensive_report: Dict[str, Any]) -> Dict[str, Any]:
    """Create summary version of comprehensive report."""
    try:
        summary = {
            "report_summary": {
                "generated_at": comprehensive_report["report_metadata"]["generated_at"],
                "period": "24 hours",
            },
            "key_metrics": comprehensive_report["performance_summary"],
            "system_health": {
                "score": comprehensive_report["system_performance"].get("system_health_score", 0),
                "status": (
                    "good"
                    if comprehensive_report["system_performance"].get("system_health_score", 0) > 80
                    else "needs_attention"
                ),
            },
            "top_recommendations": comprehensive_report["system_performance"].get(
                "recommendations", []
            )[:3],
        }

        return summary

    except Exception as e:
        LOG.error(f"Failed to create summary report: {e}")
        return {"error": str(e)}


def filter_recent_reports(
    report_history: List[AdvancedAttackReport], hours: int = 24
) -> List[AdvancedAttackReport]:
    """Filter reports to only include recent ones within specified hours."""
    cutoff_time = datetime.now() - timedelta(hours=hours)
    return [r for r in report_history if r.timestamp >= cutoff_time]


def calculate_performance_summary(recent_reports: List[AdvancedAttackReport]) -> Dict[str, Any]:
    """Calculate performance summary from recent reports."""
    if not recent_reports:
        return {
            "total_attacks_24h": 0,
            "success_rate_24h": 0,
            "average_effectiveness_24h": 0,
            "unique_targets_24h": 0,
            "unique_attacks_used": 0,
        }

    return {
        "total_attacks_24h": len(recent_reports),
        "success_rate_24h": (
            sum(1 for r in recent_reports if r.success) / len(recent_reports) * 100
        ),
        "average_effectiveness_24h": (
            sum(r.effectiveness_score for r in recent_reports) / len(recent_reports)
        ),
        "unique_targets_24h": len(set(r.target_domain for r in recent_reports)),
        "unique_attacks_used": len(set(r.attack_name for r in recent_reports)),
    }
