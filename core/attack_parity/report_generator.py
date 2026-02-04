"""
Report generation system for attack parity analysis.

This module provides comprehensive reporting capabilities for attack application
parity analysis, generating detailed comparison reports between discovery and
service modes with correlation metrics and accuracy statistics.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import json
from dataclasses import asdict
from pathlib import Path
import logging

from .models import (
    AttackSequence,
    AttackEvent,
    CorrelationResult,
    ParityResult,
    PacketModification,
    TruthViolation,
    ParameterDiff,
    ExecutionMode,
)

logger = logging.getLogger(__name__)


class AttackParityReportGenerator:
    """
    Comprehensive report generator for attack parity analysis.

    Generates detailed comparison reports between modes including correlation
    metrics, accuracy statistics, and discrepancy analysis.
    """

    def __init__(self, output_format: str = "json"):
        """
        Initialize the report generator.

        Args:
            output_format: Output format for reports ("json", "html", "text")
        """
        self.output_format = output_format.lower()
        self.logger = logging.getLogger(__name__)

    def generate_comprehensive_report(
        self,
        correlation_result: CorrelationResult,
        parity_result: ParityResult,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive analysis report.

        Args:
            correlation_result: Results from log-PCAP correlation analysis
            parity_result: Results from cross-mode parity analysis
            analysis_metadata: Additional metadata about the analysis

        Returns:
            Dictionary containing the complete report
        """
        self.logger.info("Generating comprehensive attack parity report")

        report = {
            "report_metadata": self._generate_report_metadata(analysis_metadata),
            "executive_summary": self._generate_executive_summary(
                correlation_result, parity_result
            ),
            "correlation_analysis": self._generate_correlation_report(correlation_result),
            "parity_analysis": self._generate_parity_report(parity_result),
            "discrepancy_analysis": self._generate_discrepancy_analysis(
                correlation_result, parity_result
            ),
            "recommendations": self._generate_recommendations(correlation_result, parity_result),
            "detailed_findings": self._generate_detailed_findings(
                correlation_result, parity_result
            ),
        }

        self.logger.info("Report generation completed")
        return report

    def generate_correlation_metrics_report(
        self, correlation_result: CorrelationResult
    ) -> Dict[str, Any]:
        """
        Generate detailed correlation metrics report.

        Args:
            correlation_result: Results from correlation analysis

        Returns:
            Dictionary containing correlation metrics report
        """
        total_attacks = len(correlation_result.semantically_correct_attacks) + len(
            correlation_result.semantically_incorrect_attacks
        )

        metrics = {
            "overall_metrics": {
                "total_attacks_analyzed": total_attacks,
                "semantically_correct_attacks": len(
                    correlation_result.semantically_correct_attacks
                ),
                "semantically_incorrect_attacks": len(
                    correlation_result.semantically_incorrect_attacks
                ),
                "semantic_accuracy_percentage": correlation_result.semantic_accuracy * 100,
                "truth_consistency_score": correlation_result.truth_consistency_score,
                "truth_consistency_percentage": correlation_result.truth_consistency_score * 100,
            },
            "violation_analysis": {
                "total_violations": len(correlation_result.truth_consistency_violations),
                "violation_types": self._analyze_violation_types(
                    correlation_result.truth_consistency_violations
                ),
                "violation_rate": len(correlation_result.truth_consistency_violations)
                / max(total_attacks, 1),
            },
            "orphaned_modifications": {
                "count": len(correlation_result.orphaned_modifications),
                "percentage": len(correlation_result.orphaned_modifications)
                / max(len(correlation_result.orphaned_modifications) + total_attacks, 1)
                * 100,
                "types": self._analyze_orphaned_modification_types(
                    correlation_result.orphaned_modifications
                ),
            },
            "accuracy_breakdown": self._generate_accuracy_breakdown(correlation_result),
        }

        return metrics

    def generate_success_rate_comparison(self, parity_result: ParityResult) -> Dict[str, Any]:
        """
        Generate success rate comparison between modes.

        Args:
            parity_result: Results from parity analysis

        Returns:
            Dictionary containing success rate comparison
        """
        discovery_success_rates = [seq.success_rate for seq in parity_result.discovery_sequences]
        service_success_rates = [seq.success_rate for seq in parity_result.service_sequences]

        comparison = {
            "discovery_mode": {
                "total_sequences": len(parity_result.discovery_sequences),
                "average_success_rate": (
                    sum(discovery_success_rates) / len(discovery_success_rates)
                    if discovery_success_rates
                    else 0.0
                ),
                "min_success_rate": (
                    min(discovery_success_rates) if discovery_success_rates else 0.0
                ),
                "max_success_rate": (
                    max(discovery_success_rates) if discovery_success_rates else 0.0
                ),
                "success_rate_variance": self._calculate_variance(discovery_success_rates),
            },
            "service_mode": {
                "total_sequences": len(parity_result.service_sequences),
                "average_success_rate": (
                    sum(service_success_rates) / len(service_success_rates)
                    if service_success_rates
                    else 0.0
                ),
                "min_success_rate": min(service_success_rates) if service_success_rates else 0.0,
                "max_success_rate": max(service_success_rates) if service_success_rates else 0.0,
                "success_rate_variance": self._calculate_variance(service_success_rates),
            },
            "comparison_metrics": {
                "success_rate_difference": 0.0,
                "relative_performance": "equivalent",
                "statistical_significance": False,
            },
            "matched_sequences_analysis": self._analyze_matched_sequences_success_rates(
                parity_result.matching_sequences
            ),
        }

        # Calculate comparison metrics
        if discovery_success_rates and service_success_rates:
            disc_avg = comparison["discovery_mode"]["average_success_rate"]
            serv_avg = comparison["service_mode"]["average_success_rate"]

            comparison["comparison_metrics"]["success_rate_difference"] = abs(disc_avg - serv_avg)

            if disc_avg > serv_avg + 0.05:  # 5% threshold
                comparison["comparison_metrics"]["relative_performance"] = "discovery_better"
            elif serv_avg > disc_avg + 0.05:
                comparison["comparison_metrics"]["relative_performance"] = "service_better"

            # Simple statistical significance check (t-test would be more appropriate)
            comparison["comparison_metrics"]["statistical_significance"] = (
                comparison["comparison_metrics"]["success_rate_difference"] > 0.1
            )

        return comparison

    def generate_discrepancy_details_report(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """
        Generate detailed discrepancy analysis report.

        Args:
            correlation_result: Results from correlation analysis
            parity_result: Results from parity analysis

        Returns:
            Dictionary containing detailed discrepancy analysis
        """
        report = {
            "truth_consistency_discrepancies": self._analyze_truth_violations(
                correlation_result.truth_consistency_violations
            ),
            "parameter_discrepancies": self._analyze_parameter_differences(
                parity_result.parameter_differences
            ),
            "timing_discrepancies": self._analyze_timing_differences(
                parity_result.timing_differences
            ),
            "semantic_discrepancies": self._analyze_semantic_discrepancies(correlation_result),
            "summary_statistics": {
                "total_discrepancies": (
                    len(correlation_result.truth_consistency_violations)
                    + len(parity_result.parameter_differences)
                    + len(parity_result.timing_differences)
                ),
                "critical_discrepancies": 0,
                "moderate_discrepancies": 0,
                "minor_discrepancies": 0,
            },
            "impact_assessment": self._assess_discrepancy_impact(correlation_result, parity_result),
        }

        # Categorize discrepancies by severity
        for violation in correlation_result.truth_consistency_violations:
            severity = self._assess_violation_severity(violation)
            report["summary_statistics"][f"{severity}_discrepancies"] += 1

        return report

    def save_report_to_file(
        self, report: Dict[str, Any], output_path: str, format_type: Optional[str] = None
    ) -> str:
        """
        Save report to file in specified format.

        Args:
            report: Report data to save
            output_path: Path where to save the report
            format_type: Format type override

        Returns:
            Path to the saved report file
        """
        format_type = format_type or self.output_format
        output_path = Path(output_path)

        if format_type == "json":
            final_path = output_path.with_suffix(".json")
            with open(final_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=self._json_serializer)

        elif format_type == "html":
            final_path = output_path.with_suffix(".html")
            html_content = self._generate_html_report(report)
            with open(final_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        elif format_type == "text":
            final_path = output_path.with_suffix(".txt")
            text_content = self._generate_text_report(report)
            with open(final_path, "w", encoding="utf-8") as f:
                f.write(text_content)

        else:
            raise ValueError(f"Unsupported format type: {format_type}")

        self.logger.info(f"Report saved to {final_path}")
        return str(final_path)

    def _generate_report_metadata(
        self, analysis_metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate report metadata section."""
        metadata = {
            "report_generated_at": datetime.now().isoformat(),
            "report_version": "1.0",
            "analysis_type": "attack_application_parity",
            "generator": "AttackParityReportGenerator",
        }

        if analysis_metadata:
            metadata.update(analysis_metadata)

        return metadata

    def _generate_executive_summary(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Generate executive summary section."""
        total_attacks = len(correlation_result.semantically_correct_attacks) + len(
            correlation_result.semantically_incorrect_attacks
        )

        summary = {
            "overall_assessment": self._determine_overall_assessment(
                correlation_result, parity_result
            ),
            "key_metrics": {
                "semantic_accuracy": f"{correlation_result.semantic_accuracy:.1%}",
                "truth_consistency": f"{correlation_result.truth_consistency_score:.1%}",
                "parity_score": f"{parity_result.parity_score:.1%}",
                "total_attacks_analyzed": total_attacks,
                "modes_compared": len(parity_result.discovery_sequences) > 0
                and len(parity_result.service_sequences) > 0,
            },
            "critical_findings": self._identify_critical_findings(
                correlation_result, parity_result
            ),
            "recommendations_summary": self._generate_summary_recommendations(
                correlation_result, parity_result
            ),
        }

        return summary

    def _generate_correlation_report(self, correlation_result: CorrelationResult) -> Dict[str, Any]:
        """Generate detailed correlation analysis section."""
        return {
            "summary_metrics": correlation_result.get_summary(),
            "semantic_correctness": {
                "correct_attacks": len(correlation_result.semantically_correct_attacks),
                "incorrect_attacks": len(correlation_result.semantically_incorrect_attacks),
                "accuracy_rate": correlation_result.semantic_accuracy,
                "attack_type_breakdown": self._analyze_attacks_by_type(
                    correlation_result.semantically_correct_attacks,
                    correlation_result.semantically_incorrect_attacks,
                ),
            },
            "truth_consistency": {
                "consistency_score": correlation_result.truth_consistency_score,
                "violations": len(correlation_result.truth_consistency_violations),
                "violation_details": [
                    self._format_truth_violation(v)
                    for v in correlation_result.truth_consistency_violations
                ],
            },
            "orphaned_analysis": {
                "orphaned_modifications": len(correlation_result.orphaned_modifications),
                "orphaned_details": [
                    self._format_orphaned_modification(m)
                    for m in correlation_result.orphaned_modifications
                ],
            },
        }

    def _generate_parity_report(self, parity_result: ParityResult) -> Dict[str, Any]:
        """Generate detailed parity analysis section."""
        return {
            "summary_metrics": parity_result.get_summary(),
            "mode_comparison": {
                "discovery_sequences": len(parity_result.discovery_sequences),
                "service_sequences": len(parity_result.service_sequences),
                "matching_sequences": len(parity_result.matching_sequences),
                "parity_score": parity_result.parity_score,
            },
            "parameter_analysis": {
                "total_differences": len(parity_result.parameter_differences),
                "difference_details": [
                    self._format_parameter_diff(d) for d in parity_result.parameter_differences
                ],
                "impact_categories": self._categorize_parameter_impacts(
                    parity_result.parameter_differences
                ),
            },
            "timing_analysis": {
                "timing_differences": len(parity_result.timing_differences),
                "timing_details": parity_result.timing_differences,
                "timing_consistency": self._assess_timing_consistency(
                    parity_result.timing_differences
                ),
            },
        }

    def _generate_discrepancy_analysis(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Generate comprehensive discrepancy analysis."""
        return self.generate_discrepancy_details_report(correlation_result, parity_result)

    def _generate_recommendations(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations."""
        recommendations = []

        # Semantic accuracy recommendations
        if correlation_result.semantic_accuracy < 0.8:
            recommendations.append(
                {
                    "category": "semantic_accuracy",
                    "priority": "high",
                    "title": "Improve Attack Semantic Accuracy",
                    "description": f"Semantic accuracy is {correlation_result.semantic_accuracy:.1%}, below recommended 80% threshold",
                    "actions": [
                        "Review attack implementation consistency between modes",
                        "Validate canonical attack definitions",
                        "Check for implementation bugs in attack application logic",
                    ],
                }
            )

        # Truth consistency recommendations
        if correlation_result.truth_consistency_score < 0.9:
            recommendations.append(
                {
                    "category": "truth_consistency",
                    "priority": "high",
                    "title": "Address Truth Consistency Issues",
                    "description": f"Truth consistency score is {correlation_result.truth_consistency_score:.1%}, indicating logging inaccuracies",
                    "actions": [
                        "Audit logging mechanisms for accuracy",
                        "Verify PCAP capture completeness",
                        "Check timing synchronization between logs and packet capture",
                    ],
                }
            )

        # Parity recommendations
        if parity_result.parity_score < 0.7:
            recommendations.append(
                {
                    "category": "mode_parity",
                    "priority": "medium",
                    "title": "Improve Cross-Mode Parity",
                    "description": f"Parity score is {parity_result.parity_score:.1%}, indicating significant differences between modes",
                    "actions": [
                        "Standardize attack parameter handling across modes",
                        "Align timing behavior between discovery and service modes",
                        "Review mode-specific implementation differences",
                    ],
                }
            )

        # Parameter difference recommendations
        if len(parity_result.parameter_differences) > 5:
            recommendations.append(
                {
                    "category": "parameters",
                    "priority": "medium",
                    "title": "Reduce Parameter Inconsistencies",
                    "description": f"{len(parity_result.parameter_differences)} parameter differences detected",
                    "actions": [
                        "Standardize parameter validation across modes",
                        "Implement shared parameter handling logic",
                        "Add parameter consistency checks",
                    ],
                }
            )

        return recommendations

    def _generate_detailed_findings(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Generate detailed technical findings."""
        return {
            "attack_type_analysis": self._analyze_attacks_by_type(
                correlation_result.semantically_correct_attacks,
                correlation_result.semantically_incorrect_attacks,
            ),
            "domain_analysis": self._analyze_by_domain(parity_result),
            "timing_patterns": self._analyze_timing_patterns(parity_result),
            "failure_patterns": self._analyze_failure_patterns(correlation_result, parity_result),
        }

    # Helper methods for analysis

    def _analyze_violation_types(self, violations: List[TruthViolation]) -> Dict[str, int]:
        """Analyze types of truth violations."""
        type_counts = {}
        for violation in violations:
            violation_type = violation.violation_type
            type_counts[violation_type] = type_counts.get(violation_type, 0) + 1
        return type_counts

    def _analyze_orphaned_modification_types(
        self, modifications: List[PacketModification]
    ) -> Dict[str, int]:
        """Analyze types of orphaned modifications."""
        type_counts = {}
        for mod in modifications:
            mod_type = mod.modification_type.value
            type_counts[mod_type] = type_counts.get(mod_type, 0) + 1
        return type_counts

    def _generate_accuracy_breakdown(self, correlation_result: CorrelationResult) -> Dict[str, Any]:
        """Generate accuracy breakdown by attack type."""
        correct_by_type = {}
        incorrect_by_type = {}

        for attack in correlation_result.semantically_correct_attacks:
            attack_type = attack.attack_type
            correct_by_type[attack_type] = correct_by_type.get(attack_type, 0) + 1

        for attack in correlation_result.semantically_incorrect_attacks:
            attack_type = attack.attack_type
            incorrect_by_type[attack_type] = incorrect_by_type.get(attack_type, 0) + 1

        breakdown = {}
        all_types = set(correct_by_type.keys()) | set(incorrect_by_type.keys())

        for attack_type in all_types:
            correct = correct_by_type.get(attack_type, 0)
            incorrect = incorrect_by_type.get(attack_type, 0)
            total = correct + incorrect

            breakdown[attack_type] = {
                "correct": correct,
                "incorrect": incorrect,
                "total": total,
                "accuracy": correct / total if total > 0 else 0.0,
            }

        return breakdown

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values."""
        if not values:
            return 0.0

        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    def _analyze_matched_sequences_success_rates(
        self, matching_sequences: List[Tuple[AttackSequence, AttackSequence]]
    ) -> Dict[str, Any]:
        """Analyze success rates for matched sequences."""
        if not matching_sequences:
            return {"matched_pairs": 0, "average_difference": 0.0, "pairs_analysis": []}

        pairs_analysis = []
        differences = []

        for disc_seq, serv_seq in matching_sequences:
            diff = abs(disc_seq.success_rate - serv_seq.success_rate)
            differences.append(diff)

            pairs_analysis.append(
                {
                    "domain": disc_seq.domain,
                    "discovery_success_rate": disc_seq.success_rate,
                    "service_success_rate": serv_seq.success_rate,
                    "difference": diff,
                    "significant_difference": diff > 0.1,  # 10% threshold
                }
            )

        return {
            "matched_pairs": len(matching_sequences),
            "average_difference": sum(differences) / len(differences),
            "max_difference": max(differences),
            "pairs_with_significant_difference": sum(
                1 for p in pairs_analysis if p["significant_difference"]
            ),
            "pairs_analysis": pairs_analysis,
        }

    def _analyze_truth_violations(self, violations: List[TruthViolation]) -> Dict[str, Any]:
        """Analyze truth consistency violations in detail."""
        analysis = {
            "by_type": {},
            "by_attack_type": {},
            "severity_distribution": {"critical": 0, "moderate": 0, "minor": 0},
            "detailed_violations": [],
        }

        for violation in violations:
            # Group by violation type
            v_type = violation.violation_type
            if v_type not in analysis["by_type"]:
                analysis["by_type"][v_type] = {"count": 0, "examples": []}
            analysis["by_type"][v_type]["count"] += 1
            analysis["by_type"][v_type]["examples"].append(violation.description)

            # Group by attack type
            attack_type = violation.attack_event.attack_type
            if attack_type not in analysis["by_attack_type"]:
                analysis["by_attack_type"][attack_type] = 0
            analysis["by_attack_type"][attack_type] += 1

            # Assess severity
            severity = self._assess_violation_severity(violation)
            analysis["severity_distribution"][severity] += 1

            # Add detailed violation info
            analysis["detailed_violations"].append(
                {
                    "type": v_type,
                    "attack_type": attack_type,
                    "description": violation.description,
                    "severity": severity,
                    "timestamp": violation.attack_event.timestamp.isoformat(),
                    "target": violation.attack_event.target_domain,
                }
            )

        return analysis

    def _analyze_parameter_differences(self, differences: List[ParameterDiff]) -> Dict[str, Any]:
        """Analyze parameter differences in detail."""
        analysis = {
            "by_parameter": {},
            "impact_categories": {"high": 0, "medium": 0, "low": 0},
            "detailed_differences": [],
        }

        for diff in differences:
            # Group by parameter name
            param_name = diff.parameter_name
            if param_name not in analysis["by_parameter"]:
                analysis["by_parameter"][param_name] = {"count": 0, "examples": []}
            analysis["by_parameter"][param_name]["count"] += 1
            analysis["by_parameter"][param_name]["examples"].append(
                {"value1": diff.value1, "value2": diff.value2, "impact": diff.impact_description}
            )

            # Assess impact
            impact = self._assess_parameter_impact(diff)
            analysis["impact_categories"][impact] += 1

            # Add detailed difference info
            analysis["detailed_differences"].append(
                {
                    "parameter": param_name,
                    "value1": diff.value1,
                    "value2": diff.value2,
                    "impact_description": diff.impact_description,
                    "impact_level": impact,
                }
            )

        return analysis

    def _analyze_timing_differences(
        self, timing_differences: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze timing differences in detail."""
        if not timing_differences:
            return {"count": 0, "analysis": "No timing differences detected"}

        analysis = {
            "count": len(timing_differences),
            "average_relative_difference": 0.0,
            "max_relative_difference": 0.0,
            "domains_affected": set(),
            "detailed_differences": timing_differences,
        }

        relative_diffs = []
        for diff in timing_differences:
            rel_diff = diff.get("relative_difference", 0.0)
            relative_diffs.append(rel_diff)
            analysis["domains_affected"].add(diff.get("domain", "unknown"))

        if relative_diffs:
            analysis["average_relative_difference"] = sum(relative_diffs) / len(relative_diffs)
            analysis["max_relative_difference"] = max(relative_diffs)

        analysis["domains_affected"] = list(analysis["domains_affected"])

        return analysis

    def _analyze_semantic_discrepancies(
        self, correlation_result: CorrelationResult
    ) -> Dict[str, Any]:
        """Analyze semantic discrepancies from correlation results."""
        return {
            "incorrect_attacks_count": len(correlation_result.semantically_incorrect_attacks),
            "incorrect_attacks_by_type": self._group_attacks_by_type(
                correlation_result.semantically_incorrect_attacks
            ),
            "common_semantic_errors": self._identify_common_semantic_errors(
                correlation_result.semantically_incorrect_attacks
            ),
        }

    def _assess_discrepancy_impact(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Assess overall impact of discrepancies."""
        total_issues = (
            len(correlation_result.truth_consistency_violations)
            + len(correlation_result.semantically_incorrect_attacks)
            + len(parity_result.parameter_differences)
            + len(parity_result.timing_differences)
        )

        total_analyzed = len(correlation_result.semantically_correct_attacks) + len(
            correlation_result.semantically_incorrect_attacks
        )

        impact_score = 1.0 - (total_issues / max(total_analyzed, 1))

        if impact_score >= 0.9:
            impact_level = "low"
        elif impact_score >= 0.7:
            impact_level = "medium"
        else:
            impact_level = "high"

        return {
            "total_issues": total_issues,
            "total_analyzed": total_analyzed,
            "impact_score": impact_score,
            "impact_level": impact_level,
            "description": f"{impact_level.title()} impact with {total_issues} issues across {total_analyzed} analyzed items",
        }

    def _assess_violation_severity(self, violation: TruthViolation) -> str:
        """Assess severity of a truth violation."""
        if violation.violation_type == "missing_modifications":
            return "critical"
        elif violation.violation_type == "unexpected_modifications":
            return "moderate"
        else:
            return "minor"

    def _assess_parameter_impact(self, diff: ParameterDiff) -> str:
        """Assess impact level of a parameter difference."""
        if "success_rate" in diff.parameter_name or "attack_types" in diff.parameter_name:
            return "high"
        elif "packet_count" in diff.parameter_name or "timing" in diff.parameter_name:
            return "medium"
        else:
            return "low"

    def _determine_overall_assessment(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> str:
        """Determine overall assessment of the analysis."""
        semantic_score = correlation_result.semantic_accuracy
        truth_score = correlation_result.truth_consistency_score
        parity_score = parity_result.parity_score

        overall_score = (semantic_score + truth_score + parity_score) / 3

        if overall_score >= 0.9:
            return "excellent"
        elif overall_score >= 0.8:
            return "good"
        elif overall_score >= 0.6:
            return "acceptable"
        else:
            return "needs_improvement"

    def _identify_critical_findings(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> List[str]:
        """Identify critical findings from the analysis."""
        findings = []

        if correlation_result.semantic_accuracy < 0.5:
            findings.append(
                f"Critical: Semantic accuracy is very low ({correlation_result.semantic_accuracy:.1%})"
            )

        if correlation_result.truth_consistency_score < 0.7:
            findings.append(
                f"Critical: Truth consistency issues detected ({correlation_result.truth_consistency_score:.1%})"
            )

        if parity_result.parity_score < 0.5:
            findings.append(
                f"Critical: Significant differences between modes ({parity_result.parity_score:.1%} parity)"
            )

        if len(correlation_result.orphaned_modifications) > len(
            correlation_result.semantically_correct_attacks
        ):
            findings.append("Critical: More orphaned modifications than successful correlations")

        return findings

    def _generate_summary_recommendations(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> List[str]:
        """Generate summary recommendations."""
        recommendations = []

        if correlation_result.semantic_accuracy < 0.8:
            recommendations.append("Review and fix attack implementation consistency")

        if len(correlation_result.truth_consistency_violations) > 0:
            recommendations.append("Audit logging accuracy and PCAP capture completeness")

        if parity_result.parity_score < 0.8:
            recommendations.append("Standardize behavior between discovery and service modes")

        if not recommendations:
            recommendations.append("System shows good parity - continue monitoring")

        return recommendations

    def _analyze_attacks_by_type(
        self, correct_attacks: List[AttackEvent], incorrect_attacks: List[AttackEvent]
    ) -> Dict[str, Dict[str, int]]:
        """Analyze attacks grouped by type."""
        analysis = {}

        for attack in correct_attacks:
            attack_type = attack.attack_type
            if attack_type not in analysis:
                analysis[attack_type] = {"correct": 0, "incorrect": 0}
            analysis[attack_type]["correct"] += 1

        for attack in incorrect_attacks:
            attack_type = attack.attack_type
            if attack_type not in analysis:
                analysis[attack_type] = {"correct": 0, "incorrect": 0}
            analysis[attack_type]["incorrect"] += 1

        # Add totals and accuracy
        for attack_type in analysis:
            correct = analysis[attack_type]["correct"]
            incorrect = analysis[attack_type]["incorrect"]
            total = correct + incorrect
            analysis[attack_type]["total"] = total
            analysis[attack_type]["accuracy"] = correct / total if total > 0 else 0.0

        return analysis

    def _format_truth_violation(self, violation: TruthViolation) -> Dict[str, Any]:
        """Format truth violation for report."""
        return {
            "type": violation.violation_type,
            "description": violation.description,
            "attack_type": violation.attack_event.attack_type,
            "timestamp": violation.attack_event.timestamp.isoformat(),
            "target": violation.attack_event.target_domain,
            "expected_modifications": len(violation.expected_modifications),
            "actual_modifications": len(violation.actual_modifications),
        }

    def _format_orphaned_modification(self, modification: PacketModification) -> Dict[str, Any]:
        """Format orphaned modification for report."""
        return {
            "timestamp": modification.timestamp.isoformat(),
            "type": modification.modification_type.value,
            "packet_index": modification.packet_index,
            "confidence": modification.confidence,
            "attack_signature": modification.attack_signature,
        }

    def _format_parameter_diff(self, diff: ParameterDiff) -> Dict[str, Any]:
        """Format parameter difference for report."""
        return {
            "parameter": diff.parameter_name,
            "value1": diff.value1,
            "value2": diff.value2,
            "impact": diff.impact_description,
        }

    def _categorize_parameter_impacts(self, differences: List[ParameterDiff]) -> Dict[str, int]:
        """Categorize parameter differences by impact level."""
        categories = {"high": 0, "medium": 0, "low": 0}

        for diff in differences:
            impact = self._assess_parameter_impact(diff)
            categories[impact] += 1

        return categories

    def _assess_timing_consistency(self, timing_differences: List[Dict[str, Any]]) -> str:
        """Assess overall timing consistency."""
        if not timing_differences:
            return "consistent"

        significant_diffs = sum(
            1 for diff in timing_differences if diff.get("relative_difference", 0) > 0.2
        )

        if significant_diffs == 0:
            return "mostly_consistent"
        elif significant_diffs < len(timing_differences) / 2:
            return "moderately_consistent"
        else:
            return "inconsistent"

    def _analyze_by_domain(self, parity_result: ParityResult) -> Dict[str, Any]:
        """Analyze results grouped by domain."""
        domain_analysis = {}

        # Analyze discovery sequences by domain
        for seq in parity_result.discovery_sequences:
            domain = seq.domain
            if domain not in domain_analysis:
                domain_analysis[domain] = {
                    "discovery_sequences": 0,
                    "service_sequences": 0,
                    "has_matches": False,
                    "success_rates": {"discovery": [], "service": []},
                }
            domain_analysis[domain]["discovery_sequences"] += 1
            domain_analysis[domain]["success_rates"]["discovery"].append(seq.success_rate)

        # Analyze service sequences by domain
        for seq in parity_result.service_sequences:
            domain = seq.domain
            if domain not in domain_analysis:
                domain_analysis[domain] = {
                    "discovery_sequences": 0,
                    "service_sequences": 0,
                    "has_matches": False,
                    "success_rates": {"discovery": [], "service": []},
                }
            domain_analysis[domain]["service_sequences"] += 1
            domain_analysis[domain]["success_rates"]["service"].append(seq.success_rate)

        # Check for matches
        for disc_seq, serv_seq in parity_result.matching_sequences:
            domain = disc_seq.domain
            if domain in domain_analysis:
                domain_analysis[domain]["has_matches"] = True

        return domain_analysis

    def _analyze_timing_patterns(self, parity_result: ParityResult) -> Dict[str, Any]:
        """Analyze timing patterns across sequences."""
        discovery_durations = [
            seq.total_duration.total_seconds() for seq in parity_result.discovery_sequences
        ]
        service_durations = [
            seq.total_duration.total_seconds() for seq in parity_result.service_sequences
        ]

        return {
            "discovery_timing": {
                "average_duration": (
                    sum(discovery_durations) / len(discovery_durations)
                    if discovery_durations
                    else 0.0
                ),
                "min_duration": min(discovery_durations) if discovery_durations else 0.0,
                "max_duration": max(discovery_durations) if discovery_durations else 0.0,
            },
            "service_timing": {
                "average_duration": (
                    sum(service_durations) / len(service_durations) if service_durations else 0.0
                ),
                "min_duration": min(service_durations) if service_durations else 0.0,
                "max_duration": max(service_durations) if service_durations else 0.0,
            },
            "timing_differences": parity_result.timing_differences,
        }

    def _analyze_failure_patterns(
        self, correlation_result: CorrelationResult, parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Analyze patterns in failures and discrepancies."""
        return {
            "semantic_failures": self._group_attacks_by_type(
                correlation_result.semantically_incorrect_attacks
            ),
            "truth_violations_by_type": self._analyze_violation_types(
                correlation_result.truth_consistency_violations
            ),
            "parameter_issues": len(parity_result.parameter_differences),
            "timing_issues": len(parity_result.timing_differences),
        }

    def _group_attacks_by_type(self, attacks: List[AttackEvent]) -> Dict[str, int]:
        """Group attacks by type and count them."""
        type_counts = {}
        for attack in attacks:
            attack_type = attack.attack_type
            type_counts[attack_type] = type_counts.get(attack_type, 0) + 1
        return type_counts

    def _identify_common_semantic_errors(self, incorrect_attacks: List[AttackEvent]) -> List[str]:
        """Identify common patterns in semantic errors."""
        errors = []

        type_counts = self._group_attacks_by_type(incorrect_attacks)

        for attack_type, count in type_counts.items():
            if count > 1:
                errors.append(
                    f"Multiple {attack_type} attacks failed semantic validation ({count} instances)"
                )

        return errors

    def _json_serializer(self, obj):
        """Custom JSON serializer for datetime and other objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, timedelta):
            return obj.total_seconds()
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        else:
            return str(obj)

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML format report."""
        # This is a simplified HTML generation - in practice, you'd use a template engine
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Attack Parity Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e0e0e0; border-radius: 3px; }}
                .critical {{ color: red; }}
                .good {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>Attack Parity Analysis Report</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Overall Assessment: {report['executive_summary']['overall_assessment']}</p>
                <div class="metric">Semantic Accuracy: {report['executive_summary']['key_metrics']['semantic_accuracy']}</div>
                <div class="metric">Truth Consistency: {report['executive_summary']['key_metrics']['truth_consistency']}</div>
                <div class="metric">Parity Score: {report['executive_summary']['key_metrics']['parity_score']}</div>
            </div>
            <h2>Detailed Analysis</h2>
            <p>Report generated at: {report['report_metadata']['report_generated_at']}</p>
        </body>
        </html>
        """
        return html

    def _generate_text_report(self, report: Dict[str, Any]) -> str:
        """Generate plain text format report."""
        lines = [
            "ATTACK PARITY ANALYSIS REPORT",
            "=" * 50,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 20,
            f"Overall Assessment: {report['executive_summary']['overall_assessment']}",
            f"Semantic Accuracy: {report['executive_summary']['key_metrics']['semantic_accuracy']}",
            f"Truth Consistency: {report['executive_summary']['key_metrics']['truth_consistency']}",
            f"Parity Score: {report['executive_summary']['key_metrics']['parity_score']}",
            "",
            "RECOMMENDATIONS",
            "-" * 15,
        ]

        for rec in report["recommendations"]:
            lines.append(f"• {rec['title']} ({rec['priority']} priority)")
            lines.append(f"  {rec['description']}")
            lines.append("")

        lines.extend(
            [
                "",
                f"Report generated: {report['report_metadata']['report_generated_at']}",
            ]
        )

        return "\n".join(lines)
