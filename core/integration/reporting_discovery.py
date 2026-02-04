#!/usr/bin/env python3
"""
Discovery utilities for identifying top performers and problematic targets.
"""

import logging
from typing import Dict, List, Any

LOG = logging.getLogger(__name__)


def identify_top_performing_attacks(performance_data: Dict[str, Any]) -> List[str]:
    """Identify top performing attacks from data."""
    try:
        attack_metrics = performance_data.get("attack_metrics", [])

        # Group by attack type
        attack_performance = {}
        for metric in attack_metrics:
            attack_name = metric["attack_name"]
            if attack_name not in attack_performance:
                attack_performance[attack_name] = {
                    "total": 0,
                    "successful": 0,
                    "effectiveness_scores": [],
                }

            attack_performance[attack_name]["total"] += 1
            if metric["success"]:
                attack_performance[attack_name]["successful"] += 1
            attack_performance[attack_name]["effectiveness_scores"].append(
                metric["effectiveness_score"]
            )

        # Calculate performance scores
        attack_scores = {}
        for attack_name, data in attack_performance.items():
            success_rate = (data["successful"] / data["total"]) * 100
            avg_effectiveness = sum(data["effectiveness_scores"]) / len(
                data["effectiveness_scores"]
            )

            # Combined score (success rate 60%, effectiveness 40%)
            combined_score = (success_rate * 0.6) + (avg_effectiveness * 100 * 0.4)
            attack_scores[attack_name] = combined_score

        # Return top 3 attacks
        top_attacks = sorted(attack_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        return [attack[0] for attack in top_attacks]

    except Exception as e:
        LOG.error(f"Failed to identify top performing attacks: {e}")
        return []


def identify_problematic_targets(performance_data: Dict[str, Any]) -> List[str]:
    """Identify problematic targets from data."""
    try:
        attack_metrics = performance_data.get("attack_metrics", [])

        # Group by target domain
        target_performance = {}
        for metric in attack_metrics:
            target = metric["target_domain"]
            if target not in target_performance:
                target_performance[target] = {"total": 0, "successful": 0}

            target_performance[target]["total"] += 1
            if metric["success"]:
                target_performance[target]["successful"] += 1

        # Identify targets with low success rates
        problematic_targets = []
        for target, data in target_performance.items():
            success_rate = (data["successful"] / data["total"]) * 100
            if success_rate < 50 and data["total"] >= 3:  # At least 3 attempts with <50% success
                problematic_targets.append(target)

        return problematic_targets[:5]  # Return top 5 problematic targets

    except Exception as e:
        LOG.error(f"Failed to identify problematic targets: {e}")
        return []
