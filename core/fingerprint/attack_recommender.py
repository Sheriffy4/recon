"""
Attack Recommendation Module for Fingerprint Engine

This module handles all attack recommendation logic for the fingerprint engine,
including scoring, parameter optimization, and reasoning generation.

Extracted from advanced_fingerprint_engine.py as part of Step 7 refactoring.
"""

import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile

LOG = logging.getLogger("fingerprint_attack_recommender")


class AttackRecommender:
    """
    Handles attack recommendation logic for fingerprint analysis.

    This class encapsulates all attack recommendation functionality including:
    - Generic recommendations when no fingerprint available
    - Behavior-based recommendations
    - Attack scoring based on historical data
    - Optimal parameter selection
    - Reasoning generation for recommendations
    - Execution order assignment
    """

    def __init__(
        self,
        technique_effectiveness: Optional[Dict[str, Dict[str, List[float]]]] = None,
        debug: bool = True,
    ):
        """
        Initialize attack recommender.

        Args:
            technique_effectiveness: Historical effectiveness data by domain and technique
            debug: Enable debug logging
        """
        self.technique_effectiveness = technique_effectiveness or defaultdict(
            lambda: defaultdict(list)
        )
        self.debug = debug

        LOG.info("AttackRecommender initialized")

    def get_generic_recommendations(self) -> List[Dict[str, Any]]:
        """
        Get generic attack recommendations when no fingerprint available.

        Returns:
            List of generic attack recommendations with scores and parameters
        """
        return [
            {
                "technique": "tcp_fakeddisorder",
                "score": 0.7,
                "confidence": 0.5,
                "parameters": {"split_pos": 3},
                "reasoning": "Generic recommendation - often effective",
            },
            {
                "technique": "tcp_multisplit",
                "score": 0.6,
                "confidence": 0.5,
                "parameters": {"positions": [1, 3, 5]},
                "reasoning": "Generic recommendation - good for many DPIs",
            },
        ]

    def get_behavior_recommendations(self, profile: DPIBehaviorProfile) -> List[str]:
        """
        Get recommendations based on behavioral profile.

        Args:
            profile: DPI behavioral profile

        Returns:
            List of recommended attack technique names
        """
        recommendations = []
        if profile.identified_weaknesses:
            weakness_mapping = {
                "ip_fragmentation": [
                    "ip_basic_fragmentation",
                    "ip_overlap_fragmentation",
                ],
                "tcp_segmentation": ["tcp_fakeddisorder", "tcp_multisplit"],
                "timing_based": ["tcp_timing_manipulation", "tcp_burst_timing"],
            }
            for weakness in profile.identified_weaknesses:
                if weakness in weakness_mapping:
                    recommendations.extend(weakness_mapping[weakness])
        return recommendations

    def calculate_attack_score(
        self,
        technique: str,
        fp: EnhancedFingerprint,
        domain: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> float:
        """
        Calculate attack effectiveness score.

        Args:
            technique: Attack technique name
            fp: EnhancedFingerprint object
            domain: Target domain
            context: Optional context with requirements (stealth_required, speed_priority, etc.)

        Returns:
            Effectiveness score (0.0-1.0)
        """
        score = 0.5

        # Use historical effectiveness data if available
        if (
            domain in self.technique_effectiveness
            and technique in self.technique_effectiveness[domain]
        ):
            historical_scores = self.technique_effectiveness[domain][technique]
            if historical_scores:
                score = sum(historical_scores) / len(historical_scores)

        # Use fingerprint technique success rates if available
        technique_rates = getattr(fp, "technique_success_rates", None) or {}
        if technique in technique_rates:
            score = technique_rates[technique]

        # Apply context-based adjustments
        if context:
            if context.get("stealth_required") and "race" in technique:
                score *= 0.8
            if context.get("speed_priority") and "multi" in technique:
                score *= 0.9

        return min(score, 1.0)

    def get_optimal_parameters(self, technique: str, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """
        Get optimal parameters for a technique based on fingerprint.

        Args:
            technique: Attack technique name
            fp: EnhancedFingerprint object

        Returns:
            Dictionary of optimal parameters for the technique
        """
        # Default parameters for common techniques
        params = {
            "tcp_fakeddisorder": {"split_pos": 3},
            "tcp_multisplit": {"positions": [1, 3, 5]},
            "ip_basic_fragmentation": {"frag_size": 8},
            "tcp_timing_manipulation": {"delay_ms": 10},
        }

        # Override with fingerprint-specific optimal parameters
        if technique == "tcp_fakeddisorder" and hasattr(fp, "optimal_split_pos"):
            params[technique]["split_pos"] = fp.optimal_split_pos

        return params.get(technique, {})

    def get_attack_reasoning(self, technique: str, fp: EnhancedFingerprint) -> str:
        """
        Get reasoning for why this attack was recommended.

        Args:
            technique: Attack technique name
            fp: EnhancedFingerprint object

        Returns:
            Human-readable reasoning string
        """
        reasons = []

        # Check if recommended by classification
        classification_reasons = getattr(fp, "classification_reasons", None)
        if isinstance(classification_reasons, dict):
            candidates = set(classification_reasons.keys())
        else:
            candidates = set(classification_reasons or [])
        if technique in candidates:
            reasons.append(f"Recommended for {getattr(fp, 'dpi_type', 'Unknown')}")

        # Check historical success rate
        technique_rates = getattr(fp, "technique_success_rates", None) or {}
        if technique in technique_rates:
            rate = technique_rates[technique]
            if rate > 0.7:
                reasons.append(f"High historical success rate ({rate:.0%})")

        # Check if exploits predicted weaknesses
        if hasattr(fp, "predicted_weaknesses"):
            for weakness in fp.predicted_weaknesses:
                if technique.lower() in weakness.lower():
                    reasons.append(f"Exploits: {weakness}")

        return "; ".join(reasons) if reasons else "General recommendation"

    def add_execution_order(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Add execution order suggestions to recommendations.

        Args:
            recommendations: List of recommendation dictionaries

        Returns:
            Same list with execution_order and execution_notes added
        """
        for i, rec in enumerate(recommendations):
            rec["execution_order"] = i + 1
            if i == 0:
                rec["execution_notes"] = "Try this first - highest confidence"
            elif i < 3:
                rec["execution_notes"] = "Good alternative if previous fails"
            else:
                rec["execution_notes"] = "Fallback option"
        return recommendations

    def generate_recommendations(
        self,
        domain: str,
        fingerprint: Optional[EnhancedFingerprint] = None,
        behavior_profile: Optional[DPIBehaviorProfile] = None,
        ml_recommendations: Optional[List[tuple]] = None,
        context: Optional[Dict[str, Any]] = None,
        max_recommendations: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Generate comprehensive attack recommendations.

        This is the main entry point that combines all recommendation sources.

        Args:
            domain: Target domain
            fingerprint: EnhancedFingerprint object (optional)
            behavior_profile: DPI behavioral profile (optional)
            ml_recommendations: ML-based recommendations as (technique, score) tuples (optional)
            context: Optional context with requirements
            max_recommendations: Maximum number of recommendations to return

        Returns:
            List of attack recommendations sorted by score
        """
        # If no fingerprint, return generic recommendations
        if not fingerprint:
            LOG.warning(f"No fingerprint available for {domain}, using generic recommendations")
            return self.get_generic_recommendations()

        recommendations = []

        # Collect techniques from all sources
        all_techniques = set()

        # Add classification-based recommendations
        classification_reasons = getattr(fingerprint, "classification_reasons", None)
        if isinstance(classification_reasons, dict):
            all_techniques.update(classification_reasons.keys())
        elif classification_reasons:
            all_techniques.update(classification_reasons)

        # Add ML-based recommendations
        if ml_recommendations:
            all_techniques.update([r[0] for r in ml_recommendations if isinstance(r, tuple)])

        # Add behavior-based recommendations
        if behavior_profile:
            behavior_recommendations = self.get_behavior_recommendations(behavior_profile)
            all_techniques.update(behavior_recommendations)

        # Score and build recommendations for each technique
        for technique in all_techniques:
            score = self.calculate_attack_score(technique, fingerprint, domain, context)
            recommendation = {
                "technique": technique,
                "score": score,
                "confidence": min(score, 1.0),
                "parameters": self.get_optimal_parameters(technique, fingerprint),
                "reasoning": self.get_attack_reasoning(technique, fingerprint),
            }
            recommendations.append(recommendation)

        # Sort by score (highest first)
        recommendations.sort(key=lambda x: x["score"], reverse=True)

        # Add execution order
        recommendations = self.add_execution_order(recommendations)

        # Return top N recommendations
        return recommendations[:max_recommendations]
