#!/usr/bin/env python3
"""
Recommendation engine for advanced reporting system.
"""

import logging
from typing import Dict, List, Any

from core.integration.reporting_models import AdvancedAttackReport

LOG = logging.getLogger(__name__)


def generate_attack_recommendations(
    attack_name: str, execution_result: Dict[str, Any], performance_metrics: Dict[str, Any]
) -> List[str]:
    """Generate recommendations for attack improvement."""
    recommendations = []

    try:
        # Success-based recommendations
        if not execution_result.get("success", False):
            recommendations.append(
                "Consider alternative attack parameters or different attack type"
            )

        # Performance-based recommendations
        if execution_result.get("execution_time_ms", 0) > 5000:
            recommendations.append("Optimize attack execution time or increase timeout thresholds")

        # Effectiveness-based recommendations
        effectiveness = execution_result.get("effectiveness_score", 0)
        if effectiveness < 0.3:
            recommendations.append("Review attack configuration and target compatibility")
        elif effectiveness < 0.7:
            recommendations.append("Fine-tune attack parameters for better effectiveness")

        # Performance metrics recommendations
        if performance_metrics and "performance_grade" in performance_metrics:
            grade = performance_metrics["performance_grade"]
            if grade in ["D", "F"]:
                recommendations.append(
                    "Consider replacing this attack with better-performing alternatives"
                )
            elif grade == "C":
                recommendations.append("Monitor performance and consider optimization")

        if not recommendations:
            recommendations.append("Attack performance is within acceptable parameters")

    except Exception as e:
        recommendations.append(f"Unable to generate recommendations: {e}")

    return recommendations


def generate_system_recommendations(
    performance_data: Dict[str, Any],
    performance_trends: Dict[str, Any],
    system_health_score: float,
) -> List[str]:
    """Generate system-level recommendations."""
    recommendations = []

    try:
        # Health score recommendations
        if system_health_score < 60:
            recommendations.append("System health is critical - immediate attention required")
        elif system_health_score < 80:
            recommendations.append("System health needs improvement - review performance metrics")

        # Performance data recommendations
        attack_metrics = performance_data.get("attack_metrics", [])
        if attack_metrics:
            success_rate = (
                sum(1 for m in attack_metrics if m["success"]) / len(attack_metrics) * 100
            )
            if success_rate < 70:
                recommendations.append(
                    "Overall success rate is low - review attack selection and configuration"
                )

        # Trend-based recommendations
        if performance_trends and len(performance_trends) > 1:
            recent_trends = list(performance_trends.values())[-3:]
            if len(recent_trends) >= 2:
                recent_success = [t["success_rate"] for t in recent_trends]
                if all(
                    recent_success[i] < recent_success[i - 1] for i in range(1, len(recent_success))
                ):
                    recommendations.append("Success rate is declining - investigate recent changes")

        if not recommendations:
            recommendations.append("System performance is within acceptable parameters")

    except Exception as e:
        recommendations.append(f"Unable to generate system recommendations: {e}")

    return recommendations


def generate_attack_improvement_recommendations(
    attack_reports: List[AdvancedAttackReport],
) -> List[str]:
    """Generate improvement recommendations for specific attack."""
    recommendations = []

    try:
        if not attack_reports:
            return ["No data available for recommendations"]

        # Success rate analysis
        success_rate = sum(1 for r in attack_reports if r.success) / len(attack_reports) * 100
        if success_rate < 70:
            recommendations.append("Consider reviewing attack parameters and target selection")

        # Effectiveness analysis
        avg_effectiveness = sum(r.effectiveness_score for r in attack_reports) / len(attack_reports)
        if avg_effectiveness < 0.6:
            recommendations.append("Optimize attack configuration for better effectiveness")

        # Performance analysis
        avg_execution_time = sum(r.execution_time_ms for r in attack_reports) / len(attack_reports)
        if avg_execution_time > 3000:
            recommendations.append("Consider performance optimization to reduce execution time")

        # DPI-specific analysis
        dpi_performance = {}
        for report in attack_reports:
            dpi_type = report.dpi_type
            if dpi_type not in dpi_performance:
                dpi_performance[dpi_type] = []
            dpi_performance[dpi_type].append(report.success)

        for dpi_type, successes in dpi_performance.items():
            success_rate = sum(successes) / len(successes) * 100
            if success_rate < 50:
                recommendations.append(
                    f"Poor performance against {dpi_type} - consider alternative approaches"
                )

        if not recommendations:
            recommendations.append("Attack performance is satisfactory")

    except Exception as e:
        recommendations.append(f"Unable to generate improvement recommendations: {e}")

    return recommendations


def generate_target_specific_recommendations(
    target_reports: List[AdvancedAttackReport],
) -> List[str]:
    """Generate recommendations specific to a target."""
    recommendations = []

    try:
        if not target_reports:
            return ["No data available for recommendations"]

        # Overall success analysis
        overall_success = sum(1 for r in target_reports if r.success) / len(target_reports) * 100
        if overall_success < 50:
            recommendations.append(
                "This target appears to be well-protected - consider advanced attack strategies"
            )

        # Attack type analysis
        attack_success = {}
        for report in target_reports:
            attack_name = report.attack_name
            if attack_name not in attack_success:
                attack_success[attack_name] = []
            attack_success[attack_name].append(report.success)

        # Find best performing attack
        best_attack = None
        best_success_rate = 0
        for attack_name, successes in attack_success.items():
            success_rate = sum(successes) / len(successes) * 100
            if success_rate > best_success_rate:
                best_success_rate = success_rate
                best_attack = attack_name

        if best_attack and best_success_rate > 70:
            recommendations.append(f"Use {best_attack} for best results against this target")

        # DPI analysis
        dpi_types = list(set(r.dpi_type for r in target_reports))
        if len(dpi_types) == 1 and dpi_types[0] != "unknown":
            recommendations.append(
                f"Target uses {dpi_types[0]} - optimize attacks for this DPI type"
            )

        if not recommendations:
            recommendations.append("Continue monitoring target performance")

    except Exception as e:
        recommendations.append(f"Unable to generate target recommendations: {e}")

    return recommendations
