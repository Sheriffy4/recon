"""
Report section builders for PCAP analysis reports.

This module contains specialized builders for generating different sections
of the analysis report.
"""

from typing import List, Dict, Any

from .critical_difference import CriticalDifference, DifferenceCategory, ImpactLevel
from .root_cause_analyzer import RootCause
from .fix_generator import CodeFix, RiskLevel
from .strategy_validator import ValidationResult
from .report_models import ReportSection, VisualizationType, AnalysisReport
from .report_helpers import group_by_category, safe_mean


class ReportSectionBuilder:
    """Builds various sections of the analysis report."""

    def _risk_order(self, risk_value: str) -> int:
        """
        Convert risk_level.value -> comparable numeric order.
        Keeps ordering logical instead of lexicographic.
        """
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        return order.get(str(risk_value).lower(), 99)

    def add_overview_section(self, report: AnalysisReport):
        """Add overview section to the report."""
        content = f"""
This report presents a comprehensive analysis of PCAP files comparing recon and zapret
implementations for the domain: **{report.target_domain}**.

### Files Analyzed
- **Recon PCAP**: {report.recon_pcap}
- **Zapret PCAP**: {report.zapret_pcap}
- **Analysis Date**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
- **Analysis Duration**: {report.analysis_duration:.2f} seconds

### Key Metrics
- **Similarity Score**: {report.executive_summary.similarity_score:.2f}/1.0
- **Critical Issues**: {report.executive_summary.critical_issues_count}
- **Blocking Issues**: {report.executive_summary.blocking_issues_count}
- **Overall Status**: {report.executive_summary.overall_status}

### Strategy Configuration
""".strip()

        if report.strategy_used:
            content += f"""
- **DPI Desync**: {report.strategy_used.dpi_desync}
- **Split Position**: {report.strategy_used.split_pos}
- **TTL**: {report.strategy_used.ttl}
- **Fooling Methods**: {', '.join(report.strategy_used.fooling)}
"""
        else:
            content += "- Strategy configuration not available"

        section = ReportSection(
            title="Overview", content=content, priority=1, section_type="overview"
        )

        report.add_section(section)

    def add_comparison_analysis_section(self, report: AnalysisReport):
        """Add PCAP comparison analysis section."""
        if not report.comparison_result:
            return

        result = report.comparison_result

        content = f"""
### Packet Statistics
- **Recon Packets**: {len(result.recon_packets)}
- **Zapret Packets**: {len(result.zapret_packets)}
- **Packet Count Difference**: {result.packet_count_diff}

### Timing Analysis
- **Timing Correlation**: {result.timing_correlation:.3f}
- **Timing Differences Found**: {len(result.timing_differences)}

### Sequence Analysis
- **Sequence Differences**: {len(result.sequence_differences)}
- **Parameter Differences**: {len(result.parameter_differences)}

### Connection Analysis
- **Recon Connections**: {len(result.recon_connections)}
- **Zapret Connections**: {len(result.zapret_connections)}
""".strip()

        # Add detailed differences if any
        if result.sequence_differences:
            content += "\n\n### Critical Sequence Differences"
            for i, diff in enumerate(result.sequence_differences[:5], 1):
                content += f"\n\n#### Difference {i}: {diff.get('type', 'Unknown')}\n"
                content += f"- **Description**: {diff.get('description', 'No description')}\n"
                content += f"- **Severity**: {diff.get('severity', 'Unknown')}\n"

        section = ReportSection(
            title="PCAP Comparison Analysis",
            content=content,
            priority=2,
            section_type="analysis",
            data=result.to_dict(),
        )

        # Add packet sequence visualization
        if result.recon_packets and result.zapret_packets:
            section.add_visualization(
                VisualizationType.PACKET_SEQUENCE,
                {
                    "recon_packets": [p.to_dict() for p in result.recon_packets[:20]],
                    "zapret_packets": [p.to_dict() for p in result.zapret_packets[:20]],
                },
                "Packet Sequence Comparison",
                "First 20 packets from each capture",
            )

        report.add_section(section)

    def add_critical_differences_section(self, report: AnalysisReport):
        """Add critical differences analysis section."""
        if not report.critical_differences:
            return

        # Group differences by category using helper
        diff_groups = group_by_category(report.critical_differences, "category")

        content = f"""
Found **{len(report.critical_differences)}** critical differences between recon and zapret implementations.

### Summary by Category
""".strip()

        content += self._format_diff_summary(diff_groups)
        content += self._format_top_issues(report.critical_differences)

        section = ReportSection(
            title="Critical Differences Analysis",
            content=content,
            priority=3,
            section_type="differences",
            data={
                "differences_by_category": {
                    cat: [d.to_dict() for d in diffs] for cat, diffs in diff_groups.items()
                },
                "top_critical": [
                    d.to_dict()
                    for d in sorted(
                        report.critical_differences,
                        key=lambda d: d.calculate_severity_score(),
                        reverse=True,
                    )[:10]
                ],
            },
        )

        # Add fix priority matrix visualization
        sorted_diffs = sorted(
            report.critical_differences,
            key=lambda d: d.calculate_severity_score(),
            reverse=True,
        )
        section.add_visualization(
            VisualizationType.FIX_PRIORITY_MATRIX,
            {
                "differences": [d.to_dict() for d in sorted_diffs],
                "categories": sorted(diff_groups.keys()),
            },
            "Fix Priority Matrix",
            "Priority matrix showing fix urgency vs complexity",
        )

        report.add_section(section)

    def add_root_cause_analysis_section(self, report: AnalysisReport):
        """Add root cause analysis section."""
        if not report.root_causes:
            return

        content = f"""
Identified **{len(report.root_causes)}** potential root causes for the bypass failures.

### Primary Root Causes
""".strip()

        # Sort by confidence and impact
        sorted_causes = sorted(
            report.root_causes,
            key=lambda c: (c.confidence * c.impact_on_success),
            reverse=True,
        )

        for i, cause in enumerate(sorted_causes[:3], 1):
            content += f"""

#### {i}. {cause.description}
- **Type**: {cause.cause_type.value}
- **Confidence**: {cause.confidence:.2f}
- **Impact on Success**: {cause.impact_on_success:.2f}
- **Blocking Severity**: {cause.blocking_severity}
- **Fix Complexity**: {cause.fix_complexity}
- **Affected Components**: {', '.join(cause.affected_components)}

##### Evidence
"""
            for evidence in cause.evidence[:3]:
                content += f"- {evidence.description} (confidence: {evidence.confidence:.2f})\n"

            if cause.suggested_fixes:
                content += "\n##### Suggested Fixes\n"
                for fix in cause.suggested_fixes[:3]:
                    content += f"- {fix}\n"

        section = ReportSection(
            title="Root Cause Analysis",
            content=content,
            priority=4,
            section_type="root_causes",
            data={
                "root_causes": [c.to_dict() for c in sorted_causes],
                "cause_types": sorted(set(c.cause_type.value for c in report.root_causes)),
            },
        )

        report.add_section(section)

    def add_fix_recommendations_section(self, report: AnalysisReport):
        """Add fix recommendations section."""
        if not report.generated_fixes:
            return

        # Group fixes by type and risk level
        fix_groups = {}
        for fix in report.generated_fixes:
            fix_type = fix.fix_type.value
            if fix_type not in fix_groups:
                fix_groups[fix_type] = []
            fix_groups[fix_type].append(fix)

        content = f"""
Generated **{len(report.generated_fixes)}** automated fixes for the identified issues.

### Fix Summary by Type
""".strip()

        content += self._format_fix_summary(fix_groups)
        content += self._format_fix_order(report.generated_fixes)

        section = ReportSection(
            title="Fix Recommendations",
            content=content,
            priority=5,
            section_type="fixes",
            data={
                "fixes_by_type": {
                    fix_type: [f.to_dict() for f in fixes] for fix_type, fixes in fix_groups.items()
                },
                "prioritized_fixes": [
                    f.to_dict()
                    for f in sorted(
                        report.generated_fixes,
                        key=lambda f: (self._risk_order(f.risk_level.value), -f.confidence),
                        reverse=False,
                    )
                ],
            },
        )

        report.add_section(section)

    def add_validation_results_section(self, report: AnalysisReport):
        """Add validation results section."""
        if not report.validation_results:
            return

        content = f"""
Validation testing was performed on **{len(report.validation_results)}** fix scenarios.

### Validation Summary
""".strip()

        successful_validations = [v for v in report.validation_results if v.success]
        success_rate = (
            len(successful_validations) / len(report.validation_results)
            if report.validation_results
            else 0
        )

        content += f"""
- **Total Validations**: {len(report.validation_results)}
- **Successful**: {len(successful_validations)}
- **Success Rate**: {success_rate:.1%}
"""

        if successful_validations:
            avg_domains_tested = safe_mean([v.domains_tested for v in successful_validations])
            avg_success_rate = safe_mean([v.success_rate for v in successful_validations])

            content += f"""
- **Average Domains Tested**: {avg_domains_tested:.1f}
- **Average Domain Success Rate**: {avg_success_rate:.1%}
"""

        # Add detailed results for top validations
        sorted_validations = sorted(
            report.validation_results, key=lambda v: v.success_rate, reverse=True
        )

        content += "\n\n### Top Validation Results\n"
        for i, validation in enumerate(sorted_validations[:5], 1):
            content += f"""
#### Validation {i}
- **Success**: {'✓' if validation.success else '✗'}
- **Domains Tested**: {validation.domains_tested}
- **Domains Successful**: {validation.domains_successful}
- **Success Rate**: {validation.success_rate:.1%}
"""

            if validation.error_details:
                content += f"- **Error**: {validation.error_details}\n"

        section = ReportSection(
            title="Validation Results",
            content=content,
            priority=6,
            section_type="validation",
            data={
                "validation_summary": {
                    "total": len(report.validation_results),
                    "successful": len(successful_validations),
                    "success_rate": success_rate,
                },
                "detailed_results": [v.to_dict() for v in sorted_validations],
            },
        )

        report.add_section(section)

    def add_technical_details_section(self, report: AnalysisReport):
        """Add technical details section."""
        content = f"""
### Analysis Configuration
- **Report ID**: {report.report_id}
- **Analysis Duration**: {report.analysis_duration:.2f} seconds
- **Timestamp**: {report.timestamp.isoformat()}

### Data Processing Statistics
- **Recon Packets Processed**: {len(report.comparison_result.recon_packets) if report.comparison_result else 0}
- **Zapret Packets Processed**: {len(report.comparison_result.zapret_packets) if report.comparison_result else 0}
- **Differences Detected**: {len(report.critical_differences)}
- **Root Causes Identified**: {len(report.root_causes)}
- **Fixes Generated**: {len(report.generated_fixes)}

### System Information
- **Analysis Engine**: PCAP Comparison System v1.0
- **Target Domain**: {report.target_domain}
- **Strategy Type**: {report.strategy_used.dpi_desync if report.strategy_used else 'Unknown'}
""".strip()

        section = ReportSection(
            title="Technical Details",
            content=content,
            priority=10,
            section_type="technical",
            data={
                "analysis_metadata": {
                    "report_id": report.report_id,
                    "duration": report.analysis_duration,
                    "timestamp": report.timestamp.isoformat(),
                }
            },
        )

        report.add_section(section)

    # Helper methods (kept for backward compatibility, but use report_helpers where possible)

    def _format_diff_summary(self, diff_groups: Dict[str, List[CriticalDifference]]) -> str:
        """Format difference summary by category."""
        content = ""
        for category, diffs in diff_groups.items():
            critical_count = len([d for d in diffs if d.impact_level == ImpactLevel.CRITICAL])
            high_count = len([d for d in diffs if d.impact_level == ImpactLevel.HIGH])

            content += f"""
### {category.replace('_', ' ').title()}
- **Total Issues**: {len(diffs)}
- **Critical**: {critical_count}
- **High Impact**: {high_count}
- **Average Confidence**: {safe_mean([d.confidence for d in diffs]):.2f}
"""
        return content

    def _format_top_issues(self, differences: List[CriticalDifference]) -> str:
        """Format top critical issues."""
        sorted_diffs = sorted(
            differences,
            key=lambda d: d.calculate_severity_score(),
            reverse=True,
        )

        content = "\n\n### Top Critical Issues\n"
        for i, diff in enumerate(sorted_diffs[:5], 1):
            content += f"""
#### {i}. {diff.description}
- **Category**: {diff.category.value}
- **Impact**: {diff.impact_level.value}
- **Confidence**: {diff.confidence:.2f}
- **Severity Score**: {diff.calculate_severity_score():.1f}/10.0
- **Fix Urgency**: {diff.get_fix_urgency()}
- **Recon Value**: {diff.recon_value}
- **Zapret Value**: {diff.zapret_value}
"""

            if diff.suggested_fix:
                content += f"- **Suggested Fix**: {diff.suggested_fix}\n"

        return content

    def _format_fix_summary(self, fix_groups: Dict[str, List[CodeFix]]) -> str:
        """Format fix summary by type."""
        content = ""
        for fix_type, fixes in fix_groups.items():
            low_risk = len([f for f in fixes if f.risk_level == RiskLevel.LOW])
            medium_risk = len([f for f in fixes if f.risk_level == RiskLevel.MEDIUM])
            high_risk = len([f for f in fixes if f.risk_level == RiskLevel.HIGH])

            content += f"""
### {fix_type.replace('_', ' ').title()}
- **Total Fixes**: {len(fixes)}
- **Low Risk**: {low_risk}
- **Medium Risk**: {medium_risk}
- **High Risk**: {high_risk}
- **Average Confidence**: {safe_mean([f.confidence for f in fixes]):.2f}
"""
        return content

    def _format_fix_order(self, fixes: List[CodeFix]) -> str:
        """Format recommended fix order."""
        sorted_fixes = sorted(
            fixes,
            key=lambda f: (self._risk_order(f.risk_level.value), -f.confidence),
            reverse=False,
        )

        content = "\n\n### Recommended Fix Order\n"
        for i, fix in enumerate(sorted_fixes[:10], 1):
            content += f"""
#### {i}. {fix.description}
- **File**: {fix.file_path}
- **Function**: {fix.function_name or 'N/A'}
- **Fix Type**: {fix.fix_type.value}
- **Risk Level**: {fix.risk_level.value}
- **Confidence**: {fix.confidence:.2f}
- **Impact**: {fix.impact_assessment}
"""

            if fix.test_cases:
                content += f"- **Test Cases**: {len(fix.test_cases)} test cases required\n"

        return content
