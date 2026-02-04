"""
Priority calculator for PCAP analysis reports.

This module calculates priority matrices and recommended fix orders
based on severity, risk, and confidence metrics.
"""

from typing import List, Dict, Any, MutableMapping

from .critical_difference import CriticalDifference
from .fix_generator import CodeFix, RiskLevel


class PriorityCalculator:
    """Calculates priority matrices and fix ordering."""

    def _append_grouped(
        self,
        groups: MutableMapping[str, list],
        key: str,
        fallback_key: str,
        item: Any,
    ) -> None:
        """
        Append to existing bucket; if key unknown -> fallback bucket.
        NOTE: do NOT use setdefault(key, groups[fallback_key]) - that aliases lists.
        """
        bucket = groups.get(key)
        if bucket is None:
            bucket = groups[fallback_key]
        bucket.append(item)

    def _normalize_risk_level(self, risk_value: Any) -> str:
        """
        Normalize risk level into one of: low, medium, high, critical.
        Keeps behavior robust if enum values change case or become unknown.
        """
        val = str(risk_value).strip().lower()
        if val in ("low", "medium", "high", "critical"):
            return val
        return "medium"

    def _risk_score_multiplier(self, risk_level: RiskLevel) -> float:
        risk_scores = {
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 0.7,
            RiskLevel.HIGH: 0.4,
            RiskLevel.CRITICAL: 0.1,
        }
        return risk_scores.get(risk_level, 0.7)

    def create_priority_matrix(
        self,
        critical_differences: List[CriticalDifference],
        generated_fixes: List[CodeFix],
    ) -> Dict[str, Any]:
        """Create priority matrix for fixes and differences."""

        # Group differences by urgency and complexity
        urgency_groups = {"IMMEDIATE": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for diff in critical_differences:
            urgency = diff.get_fix_urgency()
            self._append_grouped(urgency_groups, str(urgency), "LOW", diff.to_dict())

        # Group fixes by risk and confidence
        risk_groups = {"low": [], "medium": [], "high": [], "critical": []}

        for fix in generated_fixes:
            risk_level = self._normalize_risk_level(
                getattr(fix.risk_level, "value", fix.risk_level)
            )
            self._append_grouped(risk_groups, risk_level, "medium", fix.to_dict())

        return {
            "differences_by_urgency": urgency_groups,
            "fixes_by_risk": risk_groups,
            "recommended_order": self.calculate_recommended_fix_order(
                critical_differences, generated_fixes
            ),
        }

    def calculate_recommended_fix_order(
        self, differences: List[CriticalDifference], fixes: List[CodeFix]
    ) -> List[Dict[str, Any]]:
        """Calculate recommended order for applying fixes."""

        # Create combined priority score
        combined_items = []

        for i, diff in enumerate(differences):
            combined_items.append(
                {
                    "type": "difference",
                    "id": f"diff_{i}",
                    "description": diff.description,
                    "priority_score": diff.calculate_severity_score(),
                    "urgency": diff.get_fix_urgency(),
                    "data": diff.to_dict(),
                }
            )

        for fix in fixes:
            priority_score = fix.confidence * self._risk_score_multiplier(fix.risk_level) * 10

            combined_items.append(
                {
                    "type": "fix",
                    "id": fix.fix_id,
                    "description": fix.description,
                    "priority_score": priority_score,
                    "risk_level": fix.risk_level.value,
                    "data": fix.to_dict(),
                }
            )

        # Sort by priority score (stable + deterministic tie-breakers)
        combined_items.sort(
            key=lambda x: (x["priority_score"], x.get("type", ""), x.get("id", "")),
            reverse=True,
        )

        return combined_items[:20]  # Return top 20 items
