#!/usr/bin/env python3
"""
Comprehensive Validation Report Generator

This module generates comprehensive validation reports that combine results from
end-to-end testing, PCAP analysis, and strategy validation to provide a complete
assessment of DPI strategy implementation effectiveness.

Requirements: 5.7
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import statistics

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@dataclass
class ValidationSummary:
    """Summary of validation results."""

    total_tests: int
    successful_tests: int
    failed_tests: int
    success_rate: float
    average_effectiveness: float
    total_strategies_tested: int
    strategies_working: int
    strategies_failing: int
    total_packets_analyzed: int
    total_issues_found: int
    validation_timestamp: str


@dataclass
class StrategyPerformance:
    """Performance metrics for a specific strategy."""

    strategy_name: str
    tests_conducted: int
    successful_tests: int
    success_rate: float
    average_confidence: float
    total_applications: int
    issues_found: List[str]
    recommendations: List[str]


@dataclass
class ComprehensiveValidationReport:
    """Complete validation report structure."""

    report_id: str
    generation_timestamp: str
    validation_summary: ValidationSummary
    strategy_performance: Dict[str, StrategyPerformance]
    test_results: List[Dict[str, Any]]
    pcap_analysis_results: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    issues_and_limitations: List[str]
    recommendations: List[str]
    next_steps: List[str]
    appendices: Dict[str, Any]


class ValidationReportGenerator:
    """
    Generator for comprehensive validation reports.

    This class combines results from multiple testing and analysis tools
    to create comprehensive reports on DPI strategy implementation effectiveness.

    Requirements: 5.7
    """

    def __init__(self, output_dir: str = "validation_reports"):
        """Initialize the report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the report generator."""
        logger = logging.getLogger("validation_report_generator")
        logger.setLevel(logging.INFO)

        # Create file handler
        log_file = (
            self.output_dir
            / f"report_gen_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def generate_comprehensive_report(
        self,
        end_to_end_results: Optional[Dict[str, Any]] = None,
        pcap_analysis_results: Optional[List[Dict[str, Any]]] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> ComprehensiveValidationReport:
        """
        Generate a comprehensive validation report from all available data.

        Args:
            end_to_end_results: Results from end-to-end testing
            pcap_analysis_results: Results from PCAP analysis
            additional_data: Any additional data to include

        Returns:
            Comprehensive validation report

        Requirements: 5.7
        """
        self.logger.info("Generating comprehensive validation report")

        report_id = f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Initialize report structure
        report = ComprehensiveValidationReport(
            report_id=report_id,
            generation_timestamp=datetime.now().isoformat(),
            validation_summary=ValidationSummary(
                total_tests=0,
                successful_tests=0,
                failed_tests=0,
                success_rate=0.0,
                average_effectiveness=0.0,
                total_strategies_tested=0,
                strategies_working=0,
                strategies_failing=0,
                total_packets_analyzed=0,
                total_issues_found=0,
                validation_timestamp=datetime.now().isoformat(),
            ),
            strategy_performance={},
            test_results=[],
            pcap_analysis_results=pcap_analysis_results or [],
            performance_metrics={},
            issues_and_limitations=[],
            recommendations=[],
            next_steps=[],
            appendices={},
        )

        try:
            # Process end-to-end test results
            if end_to_end_results:
                self._process_end_to_end_results(end_to_end_results, report)

            # Process PCAP analysis results
            if pcap_analysis_results:
                self._process_pcap_analysis_results(pcap_analysis_results, report)

            # Process additional data
            if additional_data:
                self._process_additional_data(additional_data, report)

            # Calculate summary statistics
            self._calculate_summary_statistics(report)

            # Analyze strategy performance
            self._analyze_strategy_performance(report)

            # Generate recommendations and next steps
            self._generate_recommendations_and_next_steps(report)

            # Create appendices
            self._create_appendices(report)

            # Save report
            self._save_report(report)

            self.logger.info(f"Comprehensive report generated: {report_id}")

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            report.issues_and_limitations.append(f"Report generation error: {e}")

        return report

    def _process_end_to_end_results(
        self, results: Dict[str, Any], report: ComprehensiveValidationReport
    ) -> None:
        """Process end-to-end test results."""
        self.logger.info("Processing end-to-end test results")

        if "test_results" in results:
            report.test_results = results["test_results"]

        if "validation_summary" in results:
            summary = results["validation_summary"]
            report.validation_summary.total_tests = summary.get("total_tests", 0)
            report.validation_summary.successful_tests = summary.get(
                "successful_tests", 0
            )
            report.validation_summary.failed_tests = summary.get("failed_tests", 0)
            report.validation_summary.success_rate = summary.get("success_rate", 0.0)
            report.validation_summary.total_packets_analyzed = summary.get(
                "total_packets_analyzed", 0
            )

        # Extract performance metrics
        if "performance_analysis" in results:
            report.performance_metrics.update(results["performance_analysis"])

        # Extract issues and recommendations
        if "issues_found" in results:
            report.issues_and_limitations.extend(results["issues_found"])

        if "recommendations" in results:
            report.recommendations.extend(results["recommendations"])

    def _process_pcap_analysis_results(
        self, results: List[Dict[str, Any]], report: ComprehensiveValidationReport
    ) -> None:
        """Process PCAP analysis results."""
        self.logger.info(f"Processing {len(results)} PCAP analysis results")

        total_effectiveness = 0.0
        effectiveness_count = 0

        for analysis in results:
            if "effectiveness_score" in analysis:
                total_effectiveness += analysis["effectiveness_score"]
                effectiveness_count += 1

            if "total_packets" in analysis:
                report.validation_summary.total_packets_analyzed += analysis[
                    "total_packets"
                ]

            if "issues_found" in analysis:
                report.issues_and_limitations.extend(analysis["issues_found"])

            if "recommendations" in analysis:
                report.recommendations.extend(analysis["recommendations"])

        # Calculate average effectiveness
        if effectiveness_count > 0:
            report.validation_summary.average_effectiveness = (
                total_effectiveness / effectiveness_count
            )

    def _process_additional_data(
        self, data: Dict[str, Any], report: ComprehensiveValidationReport
    ) -> None:
        """Process any additional data provided."""
        self.logger.info("Processing additional data")

        # Add to appendices
        report.appendices["additional_data"] = data

        # Extract any relevant metrics
        if "performance_metrics" in data:
            report.performance_metrics.update(data["performance_metrics"])

    def _calculate_summary_statistics(
        self, report: ComprehensiveValidationReport
    ) -> None:
        """Calculate summary statistics from all available data."""
        self.logger.info("Calculating summary statistics")

        # Count strategy tests from test results
        strategy_counts = {}
        strategy_successes = {}

        for test_result in report.test_results:
            if isinstance(test_result, dict) and "config" in test_result:
                config = test_result["config"]
                strategies = config.get("split_positions", []) + config.get(
                    "fooling_methods", []
                )

                for strategy in strategies:
                    strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
                    if test_result.get("success", False):
                        strategy_successes[strategy] = (
                            strategy_successes.get(strategy, 0) + 1
                        )

        report.validation_summary.total_strategies_tested = len(strategy_counts)
        report.validation_summary.strategies_working = len(
            [s for s in strategy_counts if strategy_successes.get(s, 0) > 0]
        )
        report.validation_summary.strategies_failing = (
            report.validation_summary.total_strategies_tested
            - report.validation_summary.strategies_working
        )

        # Count total issues
        report.validation_summary.total_issues_found = len(
            set(report.issues_and_limitations)
        )

    def _analyze_strategy_performance(
        self, report: ComprehensiveValidationReport
    ) -> None:
        """Analyze performance of individual strategies."""
        self.logger.info("Analyzing strategy performance")

        strategy_data = {}

        # Analyze from test results
        for test_result in report.test_results:
            if isinstance(test_result, dict) and "config" in test_result:
                config = test_result["config"]
                strategies = config.get("split_positions", []) + config.get(
                    "fooling_methods", []
                )
                success = test_result.get("success", False)

                for strategy in strategies:
                    if strategy not in strategy_data:
                        strategy_data[strategy] = {
                            "tests": 0,
                            "successes": 0,
                            "applications": 0,
                            "issues": [],
                            "recommendations": [],
                        }

                    strategy_data[strategy]["tests"] += 1
                    if success:
                        strategy_data[strategy]["successes"] += 1

                    # Extract strategy-specific data
                    analysis = test_result.get("analysis_results", {})
                    if f"{strategy}_applications" in analysis:
                        strategy_data[strategy]["applications"] += analysis[
                            f"{strategy}_applications"
                        ]

        # Analyze from PCAP results
        for pcap_result in report.pcap_analysis_results:
            if "strategy_validations" in pcap_result:
                for validation in pcap_result["strategy_validations"]:
                    strategy_name = validation.get("strategy_name", "")
                    if strategy_name in strategy_data:
                        if validation.get("issues"):
                            strategy_data[strategy_name]["issues"].extend(
                                validation["issues"]
                            )

        # Create StrategyPerformance objects
        for strategy_name, data in strategy_data.items():
            performance = StrategyPerformance(
                strategy_name=strategy_name,
                tests_conducted=data["tests"],
                successful_tests=data["successes"],
                success_rate=data["successes"] / max(data["tests"], 1),
                average_confidence=0.8,  # Default confidence
                total_applications=data["applications"],
                issues_found=list(set(data["issues"])),
                recommendations=list(set(data["recommendations"])),
            )

            report.strategy_performance[strategy_name] = performance

    def _generate_recommendations_and_next_steps(
        self, report: ComprehensiveValidationReport
    ) -> None:
        """Generate recommendations and next steps based on analysis."""
        self.logger.info("Generating recommendations and next steps")

        # Deduplicate existing recommendations
        report.recommendations = list(set(report.recommendations))

        # Add general recommendations based on summary
        if report.validation_summary.success_rate >= 0.9:
            report.recommendations.append(
                "✅ Excellent performance - DPI strategies are highly effective"
            )
            report.next_steps.extend(
                [
                    "Deploy to production environment with monitoring",
                    "Conduct periodic validation to ensure continued effectiveness",
                    "Consider optimizing performance for high-traffic scenarios",
                ]
            )
        elif report.validation_summary.success_rate >= 0.7:
            report.recommendations.append(
                "⚠️ Good performance with room for improvement"
            )
            report.next_steps.extend(
                [
                    "Investigate and fix failing test cases",
                    "Optimize strategies with lower success rates",
                    "Conduct additional testing with edge cases",
                ]
            )
        else:
            report.recommendations.append(
                "❌ Poor performance - significant issues need addressing"
            )
            report.next_steps.extend(
                [
                    "Review and fix core implementation issues",
                    "Conduct thorough debugging of failing strategies",
                    "Consider redesigning problematic components",
                    "Increase unit test coverage before retesting",
                ]
            )

        # Strategy-specific recommendations
        for strategy_name, performance in report.strategy_performance.items():
            if performance.success_rate < 0.5:
                report.recommendations.append(
                    f"🔧 {strategy_name} strategy needs significant improvement (success rate: {performance.success_rate:.1%})"
                )
                report.next_steps.append(
                    f"Debug and fix {strategy_name} implementation"
                )

        # Performance recommendations
        if report.validation_summary.total_packets_analyzed > 10000:
            report.recommendations.append(
                "📊 Large-scale testing completed - results are statistically significant"
            )
        elif report.validation_summary.total_packets_analyzed < 100:
            report.recommendations.append(
                "📊 Limited packet analysis - consider more extensive testing"
            )
            report.next_steps.append(
                "Conduct longer capture sessions for more comprehensive analysis"
            )

        # Issue-based recommendations
        if report.validation_summary.total_issues_found > 10:
            report.recommendations.append(
                "⚠️ Multiple issues detected - prioritize fixing critical problems"
            )
            report.next_steps.append("Create issue tracking and prioritization system")

    def _create_appendices(self, report: ComprehensiveValidationReport) -> None:
        """Create appendices with detailed data."""
        self.logger.info("Creating report appendices")

        # Appendix A: Detailed test results
        report.appendices["detailed_test_results"] = {
            "description": "Complete test results with full configuration and analysis data",
            "data": report.test_results,
        }

        # Appendix B: PCAP analysis details
        report.appendices["pcap_analysis_details"] = {
            "description": "Detailed PCAP analysis results including packet-level analysis",
            "data": report.pcap_analysis_results,
        }

        # Appendix C: Strategy performance matrix
        strategy_matrix = {}
        for strategy_name, performance in report.strategy_performance.items():
            strategy_matrix[strategy_name] = {
                "success_rate": performance.success_rate,
                "tests_conducted": performance.tests_conducted,
                "total_applications": performance.total_applications,
                "issues_count": len(performance.issues_found),
            }

        report.appendices["strategy_performance_matrix"] = {
            "description": "Performance matrix showing success rates and metrics for each strategy",
            "data": strategy_matrix,
        }

        # Appendix D: Performance metrics
        report.appendices["performance_metrics"] = {
            "description": "Detailed performance metrics from all tests",
            "data": report.performance_metrics,
        }

    def _save_report(self, report: ComprehensiveValidationReport) -> None:
        """Save the comprehensive report in multiple formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON report
        json_file = self.output_dir / f"{report.report_id}.json"

        # Convert to dict for JSON serialization
        report_dict = {
            "report_id": report.report_id,
            "generation_timestamp": report.generation_timestamp,
            "validation_summary": asdict(report.validation_summary),
            "strategy_performance": {
                k: asdict(v) for k, v in report.strategy_performance.items()
            },
            "test_results": report.test_results,
            "pcap_analysis_results": report.pcap_analysis_results,
            "performance_metrics": report.performance_metrics,
            "issues_and_limitations": report.issues_and_limitations,
            "recommendations": report.recommendations,
            "next_steps": report.next_steps,
            "appendices": report.appendices,
        }

        with open(json_file, "w") as f:
            json.dump(report_dict, f, indent=2)

        self.logger.info(f"JSON report saved: {json_file}")

        # Save human-readable report
        text_file = self.output_dir / f"{report.report_id}.txt"
        text_content = self._generate_text_report(report)

        with open(text_file, "w") as f:
            f.write(text_content)

        self.logger.info(f"Text report saved: {text_file}")

        # Save executive summary
        summary_file = self.output_dir / f"{report.report_id}_executive_summary.txt"
        summary_content = self._generate_executive_summary(report)

        with open(summary_file, "w") as f:
            f.write(summary_content)

        self.logger.info(f"Executive summary saved: {summary_file}")

    def _generate_text_report(self, report: ComprehensiveValidationReport) -> str:
        """Generate human-readable text report."""
        lines = []

        lines.append("=" * 100)
        lines.append("COMPREHENSIVE DPI STRATEGY VALIDATION REPORT")
        lines.append("=" * 100)
        lines.append(f"Report ID: {report.report_id}")
        lines.append(f"Generated: {report.generation_timestamp}")
        lines.append("")

        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 50)
        summary = report.validation_summary
        lines.append(f"Overall Success Rate: {summary.success_rate:.1%}")
        lines.append(f"Average Effectiveness: {summary.average_effectiveness:.2f}/1.00")
        lines.append(f"Total Tests Conducted: {summary.total_tests}")
        lines.append(f"Successful Tests: {summary.successful_tests}")
        lines.append(f"Failed Tests: {summary.failed_tests}")
        lines.append(f"Strategies Tested: {summary.total_strategies_tested}")
        lines.append(f"Working Strategies: {summary.strategies_working}")
        lines.append(f"Failing Strategies: {summary.strategies_failing}")
        lines.append(f"Packets Analyzed: {summary.total_packets_analyzed:,}")
        lines.append(f"Issues Found: {summary.total_issues_found}")
        lines.append("")

        # Strategy Performance
        lines.append("STRATEGY PERFORMANCE ANALYSIS")
        lines.append("-" * 50)

        for strategy_name, performance in report.strategy_performance.items():
            status = (
                "✅"
                if performance.success_rate >= 0.8
                else "⚠️" if performance.success_rate >= 0.5 else "❌"
            )
            lines.append(f"{status} {strategy_name.upper()}")
            lines.append(
                f"  Success Rate: {performance.success_rate:.1%} ({performance.successful_tests}/{performance.tests_conducted})"
            )
            lines.append(f"  Applications: {performance.total_applications}")
            lines.append(f"  Issues: {len(performance.issues_found)}")

            if performance.issues_found:
                lines.append("  Key Issues:")
                for issue in performance.issues_found[:3]:
                    lines.append(f"    - {issue}")
                if len(performance.issues_found) > 3:
                    lines.append(
                        f"    ... and {len(performance.issues_found) - 3} more"
                    )
            lines.append("")

        # Performance Metrics
        if report.performance_metrics:
            lines.append("PERFORMANCE METRICS")
            lines.append("-" * 50)
            for metric, value in report.performance_metrics.items():
                if isinstance(value, float):
                    lines.append(f"{metric}: {value:.3f}")
                else:
                    lines.append(f"{metric}: {value}")
            lines.append("")

        # Issues and Limitations
        if report.issues_and_limitations:
            lines.append("ISSUES AND LIMITATIONS")
            lines.append("-" * 50)
            for i, issue in enumerate(set(report.issues_and_limitations), 1):
                lines.append(f"{i}. {issue}")
            lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 50)
            for i, rec in enumerate(set(report.recommendations), 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Next Steps
        if report.next_steps:
            lines.append("NEXT STEPS")
            lines.append("-" * 50)
            for i, step in enumerate(report.next_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Test Results Summary
        lines.append("TEST RESULTS SUMMARY")
        lines.append("-" * 50)
        lines.append(f"Total Test Sessions: {len(report.test_results)}")

        if report.test_results:
            successful = sum(1 for r in report.test_results if r.get("success", False))
            lines.append(f"Successful Sessions: {successful}")
            lines.append(f"Failed Sessions: {len(report.test_results) - successful}")

            # Show test configurations
            configs = set()
            for result in report.test_results:
                if "config" in result:
                    config = result["config"]
                    config_str = f"Split: {config.get('split_positions', [])}, Fooling: {config.get('fooling_methods', [])}"
                    configs.add(config_str)

            lines.append("\nTest Configurations:")
            for i, config in enumerate(sorted(configs), 1):
                lines.append(f"  {i}. {config}")
        lines.append("")

        # PCAP Analysis Summary
        lines.append("PCAP ANALYSIS SUMMARY")
        lines.append("-" * 50)
        lines.append(f"PCAP Files Analyzed: {len(report.pcap_analysis_results)}")

        if report.pcap_analysis_results:
            total_packets = sum(
                r.get("total_packets", 0) for r in report.pcap_analysis_results
            )
            total_tcp = sum(
                r.get("tcp_packets", 0) for r in report.pcap_analysis_results
            )
            total_tls = sum(
                r.get("tls_packets", 0) for r in report.pcap_analysis_results
            )

            lines.append(f"Total Packets: {total_packets:,}")
            lines.append(f"TCP Packets: {total_tcp:,}")
            lines.append(f"TLS Packets: {total_tls:,}")

            # Average effectiveness
            effectiveness_scores = [
                r.get("effectiveness_score", 0)
                for r in report.pcap_analysis_results
                if "effectiveness_score" in r
            ]
            if effectiveness_scores:
                avg_effectiveness = statistics.mean(effectiveness_scores)
                lines.append(f"Average Effectiveness: {avg_effectiveness:.2f}/1.00")

        lines.append("")
        lines.append("=" * 100)
        lines.append("END OF REPORT")
        lines.append("=" * 100)

        return "\n".join(lines)

    def _generate_executive_summary(self, report: ComprehensiveValidationReport) -> str:
        """Generate executive summary for stakeholders."""
        lines = []

        lines.append("=" * 80)
        lines.append("DPI STRATEGY VALIDATION - EXECUTIVE SUMMARY")
        lines.append("=" * 80)
        lines.append(f"Report ID: {report.report_id}")
        lines.append(
            f"Date: {datetime.fromisoformat(report.generation_timestamp).strftime('%B %d, %Y')}"
        )
        lines.append("")

        # Key Findings
        lines.append("KEY FINDINGS")
        lines.append("-" * 30)

        summary = report.validation_summary

        if summary.success_rate >= 0.9:
            lines.append("🟢 EXCELLENT: DPI strategies are highly effective")
        elif summary.success_rate >= 0.7:
            lines.append(
                "🟡 GOOD: DPI strategies are mostly effective with minor issues"
            )
        else:
            lines.append(
                "🔴 POOR: DPI strategies have significant effectiveness issues"
            )

        lines.append(f"• Overall Success Rate: {summary.success_rate:.1%}")
        lines.append(
            f"• Strategies Working: {summary.strategies_working}/{summary.total_strategies_tested}"
        )
        lines.append(f"• Tests Conducted: {summary.total_tests}")
        lines.append(f"• Packets Analyzed: {summary.total_packets_analyzed:,}")
        lines.append("")

        # Strategy Status
        lines.append("STRATEGY STATUS")
        lines.append("-" * 30)

        for strategy_name, performance in report.strategy_performance.items():
            if performance.success_rate >= 0.8:
                status = "✅ Working Well"
            elif performance.success_rate >= 0.5:
                status = "⚠️ Needs Improvement"
            else:
                status = "❌ Not Working"

            lines.append(
                f"• {strategy_name}: {status} ({performance.success_rate:.1%})"
            )
        lines.append("")

        # Critical Issues
        critical_issues = [
            issue
            for issue in report.issues_and_limitations
            if any(
                word in issue.lower()
                for word in ["critical", "failed", "error", "not working"]
            )
        ]
        if critical_issues:
            lines.append("CRITICAL ISSUES")
            lines.append("-" * 30)
            for issue in critical_issues[:5]:
                lines.append(f"• {issue}")
            if len(critical_issues) > 5:
                lines.append(f"• ... and {len(critical_issues) - 5} more issues")
            lines.append("")

        # Top Recommendations
        lines.append("TOP RECOMMENDATIONS")
        lines.append("-" * 30)
        for i, rec in enumerate(report.recommendations[:5], 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

        # Immediate Actions
        lines.append("IMMEDIATE ACTIONS REQUIRED")
        lines.append("-" * 30)
        for i, step in enumerate(report.next_steps[:3], 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        # Conclusion
        lines.append("CONCLUSION")
        lines.append("-" * 30)

        if summary.success_rate >= 0.9:
            lines.append(
                "The DPI strategy implementation is highly effective and ready for"
            )
            lines.append(
                "production deployment. Continue monitoring and periodic validation."
            )
        elif summary.success_rate >= 0.7:
            lines.append(
                "The DPI strategy implementation shows good results but requires"
            )
            lines.append(
                "addressing identified issues before full production deployment."
            )
        else:
            lines.append(
                "The DPI strategy implementation has significant issues that must"
            )
            lines.append(
                "be resolved before deployment. Recommend thorough review and fixes."
            )

        lines.append("")
        lines.append(f"For detailed analysis, see full report: {report.report_id}.txt")
        lines.append("=" * 80)

        return "\n".join(lines)


def main():
    """Main function for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate comprehensive validation report"
    )
    parser.add_argument(
        "--end-to-end-results", help="JSON file with end-to-end test results"
    )
    parser.add_argument(
        "--pcap-analysis-results",
        nargs="+",
        help="JSON files with PCAP analysis results",
    )
    parser.add_argument(
        "--output-dir", default="validation_reports", help="Output directory"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Load data
    end_to_end_data = None
    if args.end_to_end_results:
        try:
            with open(args.end_to_end_results, "r") as f:
                end_to_end_data = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load end-to-end results: {e}")

    pcap_data = []
    if args.pcap_analysis_results:
        for file_path in args.pcap_analysis_results:
            try:
                with open(file_path, "r") as f:
                    pcap_data.append(json.load(f))
            except Exception as e:
                print(
                    f"Warning: Could not load PCAP analysis results from {file_path}: {e}"
                )

    # Create report generator
    generator = ValidationReportGenerator(args.output_dir)

    print("📊 Generating comprehensive validation report")
    print(f"End-to-end data: {'✅' if end_to_end_data else '❌'}")
    print(f"PCAP analysis files: {len(pcap_data)}")
    print(f"Output directory: {args.output_dir}")
    print()

    try:
        # Generate report
        report = generator.generate_comprehensive_report(
            end_to_end_results=end_to_end_data, pcap_analysis_results=pcap_data
        )

        # Print summary
        print("✅ REPORT GENERATED SUCCESSFULLY")
        print("=" * 50)
        print(f"Report ID: {report.report_id}")
        print(f"Overall Success Rate: {report.validation_summary.success_rate:.1%}")
        print(f"Strategies Tested: {report.validation_summary.total_strategies_tested}")
        print(f"Working Strategies: {report.validation_summary.strategies_working}")
        print(f"Total Issues: {report.validation_summary.total_issues_found}")
        print(f"Recommendations: {len(report.recommendations)}")
        print()
        print(f"📁 Files saved to: {args.output_dir}")
        print(f"  • Full report: {report.report_id}.txt")
        print(f"  • JSON data: {report.report_id}.json")
        print(f"  • Executive summary: {report.report_id}_executive_summary.txt")

    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
