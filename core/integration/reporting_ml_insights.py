#!/usr/bin/env python3
"""
ML insights generation for advanced reporting system.
"""

import logging
from typing import Dict, Any

LOG = logging.getLogger(__name__)


def generate_ml_insights(attack_name: str, execution_result: Dict[str, Any]) -> Dict[str, Any]:
    """Generate ML-based insights for attack execution."""
    try:
        insights = {
            "prediction_accuracy": "unknown",
            "learning_opportunities": [],
            "optimization_suggestions": [],
        }

        # Try to get ML prediction accuracy
        if "ml_prediction" in execution_result:
            predicted_success = execution_result["ml_prediction"].get("success_probability", 0.5)
            actual_success = execution_result.get("success", False)

            if (predicted_success > 0.5 and actual_success) or (
                predicted_success <= 0.5 and not actual_success
            ):
                insights["prediction_accuracy"] = "accurate"
            else:
                insights["prediction_accuracy"] = "inaccurate"
                insights["learning_opportunities"].append("Update ML model with this result")

        # Generate optimization suggestions
        if execution_result.get("execution_time_ms", 0) > 3000:
            insights["optimization_suggestions"].append(
                "Consider parameter optimization for faster execution"
            )

        if execution_result.get("effectiveness_score", 0) < 0.5:
            insights["optimization_suggestions"].append(
                "Review attack configuration for better effectiveness"
            )

        return insights

    except Exception as e:
        LOG.error(f"Failed to generate ML insights: {e}")
        return {"error": str(e)}
