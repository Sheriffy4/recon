"""
Executive summary calculator for PCAP analysis reports.

This module calculates executive summary metrics, success probabilities,
and generates actionable recommendations.
"""

from typing import List

from .report_models import ExecutiveSummary
from .comparison_result import ComparisonResult
from .critical_difference import CriticalDifference, DifferenceCategory, ImpactLevel
from .root_cause_analyzer import RootCause
from .fix_generator import CodeFix, FixType, RiskLevel
from .report_helpers import add_action_if_issues


class ExecutiveSummaryCalculator:
    """Calculates executive summary metrics and recommendations."""

    def generate_executive_summary(
        self,
        comparison_result: ComparisonResult,
        critical_differences: List[CriticalDifference],
        root_causes: List[RootCause],
        generated_fixes: List[CodeFix],
    ) -> ExecutiveSummary:
        """Generate executive summary with key findings."""

        # Determine overall status
        similarity_score = comparison_result.similarity_score if comparison_result else 0.0
        critical_count = len(
            [d for d in critical_differences if d.impact_level == ImpactLevel.CRITICAL]
        )
        blocking_count = len([d for d in critical_differences if d.is_blocking()])

        if similarity_score >= 0.9 and critical_count == 0:
            status = "SUCCESS"
        elif similarity_score >= 0.7 and critical_count <= 2:
            status = "PARTIAL_SUCCESS"
        elif critical_count <= 5:
            status = "FAILURE"
        else:
            status = "CRITICAL_FAILURE"

        # Identify primary failure cause
        primary_cause = None
        secondary_causes = []

        if root_causes:
            # Sort by confidence and impact
            sorted_causes = sorted(
                root_causes,
                key=lambda c: (c.confidence * c.impact_on_success),
                reverse=True,
            )

            if sorted_causes:
                primary_cause = sorted_causes[0].description
                secondary_causes = [c.description for c in sorted_causes[1:3]]

        # Calculate success probability after fixes
        success_probability = self.calculate_success_probability(
            similarity_score, critical_differences, generated_fixes
        )

        # Generate immediate actions
        immediate_actions = self.generate_immediate_actions(critical_differences, root_causes)

        # Generate fix recommendations
        recommended_fixes = self.generate_fix_recommendations(generated_fixes)

        # Assess risk
        risk_assessment = self.assess_risk_level(critical_differences, generated_fixes)

        # Estimate fix time
        estimated_time = self.estimate_fix_time(generated_fixes)

        return ExecutiveSummary(
            overall_status=status,
            similarity_score=similarity_score,
            critical_issues_count=critical_count,
            blocking_issues_count=blocking_count,
            primary_failure_cause=primary_cause,
            secondary_causes=secondary_causes,
            success_probability=success_probability,
            immediate_actions=immediate_actions,
            recommended_fixes=recommended_fixes,
            risk_assessment=risk_assessment,
            estimated_fix_time=estimated_time,
            required_expertise=[
                "DPI bypass",
                "Network protocols",
                "Python development",
            ],
            testing_requirements=[
                "PCAP validation",
                "Domain testing",
                "Regression testing",
            ],
            domains_affected=[],  # Will be populated based on context
            bypass_effectiveness_impact="HIGH" if critical_count > 3 else "MEDIUM",
        )

    def calculate_success_probability(
        self,
        similarity_score: float,
        differences: List[CriticalDifference],
        fixes: List[CodeFix],
    ) -> float:
        """Calculate probability of success after applying fixes."""

        # Base probability from similarity score
        base_prob = similarity_score

        # Penalty for critical differences
        critical_penalty = (
            len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL]) * 0.1
        )
        high_penalty = len([d for d in differences if d.impact_level == ImpactLevel.HIGH]) * 0.05

        # Bonus for high-confidence fixes
        fix_bonus = len([f for f in fixes if f.confidence >= 0.8]) * 0.05

        # Calculate final probability
        success_prob = base_prob - critical_penalty - high_penalty + fix_bonus

        return max(0.0, min(1.0, success_prob))

    def generate_immediate_actions(
        self, differences: List[CriticalDifference], root_causes: List[RootCause]
    ) -> List[str]:
        """Generate list of immediate actions needed."""
        actions = []

        # Actions based on critical differences
        critical_diffs = [d for d in differences if d.impact_level == ImpactLevel.CRITICAL]

        if critical_diffs:
            actions.append(f"Address {len(critical_diffs)} critical differences immediately")

        # Actions based on root causes
        blocking_causes = [c for c in root_causes if c.blocking_severity in ["CRITICAL", "HIGH"]]

        if blocking_causes:
            actions.append(f"Fix {len(blocking_causes)} blocking root causes")

        # Specific technical actions using helper
        add_action_if_issues(
            actions,
            differences,
            lambda d: d.category == DifferenceCategory.TTL,
            "Verify TTL parameter configuration in fake packet generation",
        )

        add_action_if_issues(
            actions,
            differences,
            lambda d: d.category == DifferenceCategory.SEQUENCE,
            "Review packet sequence generation logic",
        )

        add_action_if_issues(
            actions,
            differences,
            lambda d: d.category == DifferenceCategory.STRATEGY,
            "Validate strategy parameter mapping and application",
        )

        return actions[:5]  # Return top 5 actions

    def generate_fix_recommendations(self, fixes: List[CodeFix]) -> List[str]:
        """Generate prioritized fix recommendations."""
        recommendations = []

        # Group fixes by type
        fix_types = {}
        for fix in fixes:
            fix_type = fix.fix_type.value
            if fix_type not in fix_types:
                fix_types[fix_type] = []
            fix_types[fix_type].append(fix)

        # Generate recommendations by type
        for fix_type in sorted(fix_types.keys()):
            type_fixes = fix_types[fix_type]
            high_confidence = [f for f in type_fixes if f.confidence >= 0.8]
            if high_confidence:
                recommendations.append(
                    f"Apply {len(high_confidence)} high-confidence {fix_type.replace('_', ' ')} fixes"
                )

        # Add specific recommendations
        if any(f.fix_type == FixType.TTL_FIX for f in fixes):
            recommendations.append("Update TTL configuration to match zapret behavior")

        if any(f.fix_type == FixType.SEQUENCE_FIX for f in fixes):
            recommendations.append("Correct packet sequence generation logic")

        if any(f.fix_type == FixType.CHECKSUM_FIX for f in fixes):
            recommendations.append("Fix checksum corruption implementation")

        return recommendations[:5]  # Return top 5 recommendations

    def assess_risk_level(self, differences: List[CriticalDifference], fixes: List[CodeFix]) -> str:
        """Assess overall risk level of applying fixes."""

        # Count high-risk fixes
        high_risk_fixes = len(
            [f for f in fixes if f.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        )

        # Count critical differences
        critical_diffs = len([d for d in differences if d.impact_level == ImpactLevel.CRITICAL])

        # Assess risk
        if high_risk_fixes > 3 or critical_diffs > 5:
            return "HIGH"
        elif high_risk_fixes > 1 or critical_diffs > 2:
            return "MEDIUM"
        else:
            return "LOW"

    def estimate_fix_time(self, fixes: List[CodeFix]) -> str:
        """Estimate time required to apply all fixes."""

        # Time estimates by fix type (in hours)
        time_estimates = {
            FixType.PARAMETER_CHANGE: 0.5,
            FixType.SEQUENCE_FIX: 2.0,
            FixType.CHECKSUM_FIX: 1.5,
            FixType.TIMING_FIX: 1.0,
            FixType.TTL_FIX: 1.0,
            FixType.SPLIT_POSITION_FIX: 2.0,
            FixType.FOOLING_METHOD_FIX: 1.5,
            FixType.PACKET_ORDER_FIX: 2.5,
            FixType.ENGINE_CONFIG_FIX: 1.0,
        }

        total_hours = 0
        for fix in fixes:
            base_time = time_estimates.get(fix.fix_type, 1.0)

            # Adjust for risk level
            if fix.risk_level == RiskLevel.HIGH:
                base_time *= 1.5
            elif fix.risk_level == RiskLevel.CRITICAL:
                base_time *= 2.0

            total_hours += base_time

        # Add testing time (50% of development time)
        total_hours *= 1.5

        if total_hours < 4:
            return "2-4 hours"
        elif total_hours < 8:
            return "4-8 hours"
        elif total_hours < 16:
            return "1-2 days"
        elif total_hours < 40:
            return "3-5 days"
        else:
            return "1+ weeks"
