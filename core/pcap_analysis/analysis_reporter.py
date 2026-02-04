"""
Comprehensive analysis reporting system for PCAP comparison results.

This module implements detailed report generation with findings, recommendations,
visualizations, and executive summaries for PCAP analysis results.
"""

from typing import List, Dict, Any
import logging
import time
from datetime import datetime
from pathlib import Path

LOG = logging.getLogger(__name__)

from .comparison_result import ComparisonResult
from .critical_difference import CriticalDifference
from .root_cause_analyzer import RootCause
from .fix_generator import CodeFix
from .strategy_validator import ValidationResult
from .packet_info import PacketInfo
from .strategy_config import StrategyConfig
from .report_models import (
    ReportFormat,
    VisualizationType,
    ReportSection,
    ExecutiveSummary,
    AnalysisReport,
)


class AnalysisReporter:
    """
    Comprehensive analysis reporting system.

    Generates detailed reports with findings, recommendations, visualizations,
    and executive summaries for PCAP analysis results.
    """

    def __init__(self, output_dir: str = "reports"):
        """Initialize the reporter."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize helper components (lazy import to avoid circular dependencies)
        self._section_builder = None
        self._visualization_builder = None
        self._summary_calculator = None
        self._priority_calculator = None
        self._formatter = None

    @property
    def section_builder(self):
        """Lazy initialization of section builder."""
        if self._section_builder is None:
            from .report_sections import ReportSectionBuilder

            self._section_builder = ReportSectionBuilder()
        return self._section_builder

    @property
    def visualization_builder(self):
        """Lazy initialization of visualization builder."""
        if self._visualization_builder is None:
            from .visualization_builder import VisualizationBuilder

            self._visualization_builder = VisualizationBuilder()
        return self._visualization_builder

    @property
    def summary_calculator(self):
        """Lazy initialization of summary calculator."""
        if self._summary_calculator is None:
            from .executive_summary_calculator import ExecutiveSummaryCalculator

            self._summary_calculator = ExecutiveSummaryCalculator()
        return self._summary_calculator

    @property
    def priority_calculator(self):
        """Lazy initialization of priority calculator."""
        if self._priority_calculator is None:
            from .priority_calculator import PriorityCalculator

            self._priority_calculator = PriorityCalculator()
        return self._priority_calculator

    @property
    def formatter(self):
        """Lazy initialization of report formatter."""
        if self._formatter is None:
            from .report_formatters import ReportFormatter

            self._formatter = ReportFormatter(str(self.output_dir))
        return self._formatter

    def generate_comprehensive_report(
        self,
        comparison_result: ComparisonResult,
        critical_differences: List[CriticalDifference],
        root_causes: List[RootCause],
        generated_fixes: List[CodeFix],
        validation_results: List[ValidationResult] = None,
        target_domain: str = "unknown",
        strategy_config: StrategyConfig = None,
    ) -> AnalysisReport:
        """
        Generate a comprehensive analysis report.

        Args:
            comparison_result: PCAP comparison results
            critical_differences: List of critical differences found
            root_causes: List of identified root causes
            generated_fixes: List of generated code fixes
            validation_results: Optional validation results
            target_domain: Target domain being analyzed
            strategy_config: Strategy configuration used

        Returns:
            AnalysisReport: Complete analysis report
        """
        start_time = time.time()

        # Ensure lists are not None
        critical_differences = critical_differences or []
        root_causes = root_causes or []
        generated_fixes = generated_fixes or []

        # Create report structure
        report = AnalysisReport(
            report_id=f"pcap_analysis_{int(time.time())}",
            timestamp=datetime.now(),
            analysis_duration=0.0,  # Will be updated at the end
            recon_pcap=comparison_result.recon_file if comparison_result else "unknown",
            zapret_pcap=(comparison_result.zapret_file if comparison_result else "unknown"),
            target_domain=target_domain,
            strategy_used=strategy_config,
            comparison_result=comparison_result,
            critical_differences=critical_differences,
            root_causes=root_causes,
            generated_fixes=generated_fixes,
            validation_results=validation_results or [],
        )

        # Generate executive summary (delegated to summary calculator)
        report.executive_summary = self.summary_calculator.generate_executive_summary(
            comparison_result, critical_differences, root_causes, generated_fixes
        )

        # Generate detailed sections (delegated to section builder)
        self.section_builder.add_overview_section(report)
        self.section_builder.add_comparison_analysis_section(report)
        self.section_builder.add_critical_differences_section(report)
        self.section_builder.add_root_cause_analysis_section(report)
        self.section_builder.add_fix_recommendations_section(report)
        self.section_builder.add_validation_results_section(report)
        self.section_builder.add_technical_details_section(report)

        # Generate visualizations (delegated to visualization builder)
        report.visualizations = self.visualization_builder.generate_visualizations(
            report.comparison_result, report.critical_differences, report.generated_fixes
        )

        # Create priority matrix (delegated to priority calculator)
        report.priority_matrix = self.priority_calculator.create_priority_matrix(
            critical_differences, generated_fixes
        )

        # Update analysis duration
        report.analysis_duration = time.time() - start_time
        LOG.debug("Generated report %s in %.3fs", report.report_id, report.analysis_duration)

        return report

    def _generate_executive_summary(
        self,
        comparison_result: ComparisonResult,
        critical_differences: List[CriticalDifference],
        root_causes: List[RootCause],
        generated_fixes: List[CodeFix],
    ) -> ExecutiveSummary:
        """Backward compatibility wrapper."""
        return self.summary_calculator.generate_executive_summary(
            comparison_result, critical_differences, root_causes, generated_fixes
        )

    # Backward compatibility wrappers for section methods
    def _add_overview_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_overview_section(report)

    def _add_comparison_analysis_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_comparison_analysis_section(report)

    def _add_critical_differences_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_critical_differences_section(report)

    def _add_root_cause_analysis_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_root_cause_analysis_section(report)

    def _add_fix_recommendations_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_fix_recommendations_section(report)

    def _add_validation_results_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_validation_results_section(report)

    def _add_technical_details_section(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        return self.section_builder.add_technical_details_section(report)

    def _generate_visualizations(self, report: AnalysisReport):
        """Backward compatibility wrapper."""
        report.visualizations = self.visualization_builder.generate_visualizations(
            report.comparison_result, report.critical_differences, report.generated_fixes
        )

    def _create_packet_sequence_viz(
        self, recon_packets: List[PacketInfo], zapret_packets: List[PacketInfo]
    ) -> Dict[str, Any]:
        """Backward compatibility wrapper."""
        return self.visualization_builder.create_packet_sequence_viz(recon_packets, zapret_packets)

    def _create_ttl_pattern_viz(self, ttl_differences: List[CriticalDifference]) -> Dict[str, Any]:
        """Backward compatibility wrapper."""
        return self.visualization_builder.create_ttl_pattern_viz(ttl_differences)

    def _create_fix_priority_matrix(self, fixes: List[CodeFix]) -> Dict[str, Any]:
        """Backward compatibility wrapper."""
        return self.visualization_builder.create_fix_priority_matrix(fixes)

    def _create_priority_matrix(
        self,
        critical_differences: List[CriticalDifference],
        generated_fixes: List[CodeFix],
    ) -> Dict[str, Any]:
        """Backward compatibility wrapper."""
        return self.priority_calculator.create_priority_matrix(
            critical_differences, generated_fixes
        )

    def _calculate_recommended_fix_order(
        self, differences: List[CriticalDifference], fixes: List[CodeFix]
    ) -> List[Dict[str, Any]]:
        """Backward compatibility wrapper."""
        return self.priority_calculator.calculate_recommended_fix_order(differences, fixes)

    def _calculate_success_probability(
        self,
        similarity_score: float,
        differences: List[CriticalDifference],
        fixes: List[CodeFix],
    ) -> float:
        """Backward compatibility wrapper."""
        return self.summary_calculator.calculate_success_probability(
            similarity_score, differences, fixes
        )

    def _generate_immediate_actions(
        self, differences: List[CriticalDifference], root_causes: List[RootCause]
    ) -> List[str]:
        """Backward compatibility wrapper."""
        return self.summary_calculator.generate_immediate_actions(differences, root_causes)

    def _generate_fix_recommendations(self, fixes: List[CodeFix]) -> List[str]:
        """Backward compatibility wrapper."""
        return self.summary_calculator.generate_fix_recommendations(fixes)

    def _assess_risk_level(
        self, differences: List[CriticalDifference], fixes: List[CodeFix]
    ) -> str:
        """Backward compatibility wrapper."""
        return self.summary_calculator.assess_risk_level(differences, fixes)

    def _estimate_fix_time(self, fixes: List[CodeFix]) -> str:
        """Backward compatibility wrapper."""
        return self.summary_calculator.estimate_fix_time(fixes)

    # Backward compatibility wrappers for formatting methods
    def _load_report_templates(self) -> Dict[str, str]:
        """Backward compatibility wrapper."""
        return self.formatter.get_report_templates()

    def _load_visualization_config(self) -> Dict[str, Any]:
        """Backward compatibility wrapper."""
        return self.formatter.get_visualization_config()

    def export_report(
        self,
        report: AnalysisReport,
        format: ReportFormat = ReportFormat.JSON,
        filename: str = None,
    ) -> str:
        """Backward compatibility wrapper."""
        return self.formatter.export_report(report, format, filename)

    def _generate_markdown_report(self, report: AnalysisReport) -> str:
        """Backward compatibility wrapper."""
        return self.formatter.generate_markdown_report(report)

    def _generate_html_report(self, report: AnalysisReport) -> str:
        """Backward compatibility wrapper."""
        return self.formatter.generate_html_report(report)

    def _generate_text_report(self, report: AnalysisReport) -> str:
        """Backward compatibility wrapper."""
        return self.formatter.generate_text_report(report)
