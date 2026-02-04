#!/usr/bin/env python3
"""
Reliability report generation utilities.

This module provides functions for generating comprehensive reports
from strategy effectiveness validation results.
"""

import statistics
import time
from typing import Dict, Any, List

from .types import StrategyEffectivenessResult, ReliabilityLevel


def generate_reliability_report(results: List[StrategyEffectivenessResult]) -> Dict[str, Any]:
    """
    Generate comprehensive reliability report from validation results.

    Args:
        results: List of strategy effectiveness results

    Returns:
        Dictionary containing report data with summary, rankings, and recommendations
    """
    if not results:
        return {"error": "No results to analyze"}

    # Overall statistics
    effectiveness_scores = [r.effectiveness_score for r in results]
    consistency_scores = [r.consistency_score for r in results]
    performance_scores = [r.performance_score for r in results]
    false_positive_rates = [r.false_positive_rate for r in results]

    # Reliability level distribution
    reliability_distribution = _calculate_reliability_distribution(results)

    # Strategy performance ranking
    strategy_ranking = _rank_strategies_by_effectiveness(results)

    # Domain analysis
    domain_analysis = _analyze_domains(results)

    # Generate recommendations
    recommendations = _generate_recommendations(
        statistics.mean(effectiveness_scores),
        statistics.mean(false_positive_rates),
        statistics.mean(consistency_scores),
        statistics.mean(performance_scores),
    )

    return {
        "summary": {
            "total_strategies_tested": len(results),
            "avg_effectiveness_score": statistics.mean(effectiveness_scores),
            "avg_consistency_score": statistics.mean(consistency_scores),
            "avg_performance_score": statistics.mean(performance_scores),
            "avg_false_positive_rate": statistics.mean(false_positive_rates),
        },
        "reliability_distribution": reliability_distribution,
        "strategy_ranking": strategy_ranking,
        "domain_analysis": domain_analysis,
        "recommendations": recommendations,
        "detailed_results": results,
        # Additive field: JSON-friendly representation (keeps backward compat)
        "detailed_results_serialized": [
            (r.to_dict() if hasattr(r, "to_dict") else r) for r in results
        ],
        "report_timestamp": time.time(),
    }


def _calculate_reliability_distribution(
    results: List[StrategyEffectivenessResult],
) -> Dict[str, int]:
    """Calculate distribution of reliability levels across results."""
    reliability_distribution = {}
    for level in ReliabilityLevel:
        reliability_distribution[level.value] = sum(
            1 for r in results if r.reliability_level == level
        )
    return reliability_distribution


def _rank_strategies_by_effectiveness(
    results: List[StrategyEffectivenessResult], top_n: int = 10
) -> List[Dict[str, Any]]:
    """Rank strategies by effectiveness score and return top N."""
    strategy_ranking = sorted(results, key=lambda r: r.effectiveness_score, reverse=True)

    return [
        {
            "strategy_id": r.strategy_id,
            "domain": r.domain,
            "effectiveness_score": r.effectiveness_score,
            "reliability_level": r.reliability_level.value,
            "recommendation": r.recommendation,
        }
        for r in strategy_ranking[:top_n]
    ]


def _analyze_domains(results: List[StrategyEffectivenessResult]) -> Dict[str, Dict[str, Any]]:
    """Analyze results grouped by domain."""
    domain_analysis = {}

    for result in results:
        if result.domain not in domain_analysis:
            domain_analysis[result.domain] = {
                "strategies_tested": 0,
                "avg_effectiveness": 0.0,
                "best_strategy": None,
                "reliability_levels": [],
            }

        domain_data = domain_analysis[result.domain]
        domain_data["strategies_tested"] += 1
        domain_data["reliability_levels"].append(result.reliability_level.value)

        if (
            domain_data["best_strategy"] is None
            or result.effectiveness_score > domain_data["avg_effectiveness"]
        ):
            domain_data["best_strategy"] = result.strategy_id
            domain_data["avg_effectiveness"] = result.effectiveness_score

    return domain_analysis


def _generate_recommendations(
    avg_effectiveness: float,
    avg_false_positive_rate: float,
    avg_consistency: float,
    avg_performance: float,
) -> List[str]:
    """Generate actionable recommendations based on average metrics."""
    recommendations = []

    # Overall performance recommendations
    if avg_effectiveness < 0.5:
        recommendations.append(
            "Overall strategy effectiveness is low - consider strategy optimization"
        )

    # False positive recommendations
    if avg_false_positive_rate > 0.2:
        recommendations.append(
            "High false positive rate detected - implement additional validation"
        )

    # Consistency recommendations
    if avg_consistency < 0.7:
        recommendations.append("Low consistency detected - strategies may be unstable")

    # Performance recommendations
    if avg_performance < 0.6:
        recommendations.append("Performance optimization needed - response times are high")

    return recommendations
