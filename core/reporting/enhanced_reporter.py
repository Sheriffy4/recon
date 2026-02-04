# recon/core/reporting/enhanced_reporter.py
"""
Enhanced Reporting System

Provides comprehensive, informative reports for DPI analysis, strategy effectiveness,
and system performance with confidence levels and actionable insights.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

LOG = logging.getLogger("EnhancedReporter")


class ConfidenceLevel(Enum):
    """Confidence levels for predictions and analysis."""

    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"  # 75-89%
    MEDIUM = "medium"  # 50-74%
    LOW = "low"  # 25-49%
    VERY_LOW = "very_low"  # 0-24%


@dataclass
class DPIAnalysisReport:
    """Comprehensive DPI analysis report."""

    domain: str
    target_ip: str
    vendor_prediction: str
    vendor_confidence: ConfidenceLevel

    # Behavioral characteristics
    blocking_method: str  # "rst", "timeout", "content", "none"
    rst_ttl_distance: Optional[int] = None
    response_timing_pattern: str = "unknown"
    supports_http2: Optional[bool] = None
    supports_quic: Optional[bool] = None
    supports_ech: Optional[bool] = None

    # Key vulnerabilities discovered
    key_vulnerabilities: List[str] = field(default_factory=list)

    # Analysis confidence and notes
    analysis_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    analysis_notes: List[str] = field(default_factory=list)

    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class StrategyEffectivenessReport:
    """Strategy effectiveness analysis."""

    strategy_name: str
    strategy_type: str

    # Effectiveness metrics
    success_rate: float  # 0.0 - 1.0
    avg_latency_ms: float
    total_tests: int
    successful_tests: int
    failed_tests: int

    # Performance characteristics
    best_latency_ms: float
    worst_latency_ms: float
    latency_consistency: str  # "consistent", "variable", "unstable"

    # Reliability assessment
    reliability_score: float  # 0.0 - 1.0
    reliability_confidence: ConfidenceLevel

    # Usage recommendations
    recommended_scenarios: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SystemPerformanceReport:
    """System performance summary."""

    # Overall metrics
    total_domains_tested: int
    total_strategies_tested: int
    overall_success_rate: float
    avg_response_time_ms: float

    # Engine performance
    engine_type: str
    engine_health_status: str
    packets_processed: int = 0
    processing_errors: int = 0

    # Resource usage
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None

    # Time metrics
    total_runtime_seconds: float = 0.0
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ComprehensiveReport:
    """Complete analysis and recommendations report."""

    # Summary information
    target_domain: str
    analysis_duration_seconds: float

    # Analysis results
    dpi_analysis: DPIAnalysisReport
    best_strategies: List[StrategyEffectivenessReport]
    system_performance: SystemPerformanceReport

    # Key findings and recommendations
    key_findings: List[str] = field(default_factory=list)
    recommended_commands: List[str] = field(default_factory=list)
    troubleshooting_tips: List[str] = field(default_factory=list)

    # Confidence assessment
    overall_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    confidence_explanation: str = ""

    timestamp: datetime = field(default_factory=datetime.now)


class EnhancedReporter:
    """
    Enhanced reporting system for comprehensive DPI bypass analysis.

    Provides detailed reports with confidence levels, actionable insights,
    and user-friendly summaries.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = LOG
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def generate_dpi_analysis_report(
        self,
        domain: str,
        target_ip: str,
        fingerprint_data: Dict[str, Any],
        classification_result: Dict[str, Any],
    ) -> DPIAnalysisReport:
        """
        Generate comprehensive DPI analysis report.

        Args:
            domain: Target domain
            target_ip: Target IP address
            fingerprint_data: Fingerprint analysis data
            classification_result: DPI classification results

        Returns:
            DPIAnalysisReport with detailed analysis
        """
        self.logger.debug(f"Generating DPI analysis report for {domain}")

        # Extract vendor prediction and confidence
        vendor_prediction = classification_result.get("predicted_vendor", "unknown")
        confidence_score = classification_result.get("confidence", 0.0)
        vendor_confidence = self._score_to_confidence_level(confidence_score)

        # Analyze blocking method
        blocking_method = fingerprint_data.get("baseline_block_type", "unknown")

        # Extract behavioral characteristics
        rst_ttl_distance = fingerprint_data.get("rst_ttl_distance")
        response_timing_pattern = fingerprint_data.get("response_timing_pattern", "unknown")
        supports_http2 = fingerprint_data.get("http2_support")
        supports_quic = fingerprint_data.get("quic_support")
        supports_ech = fingerprint_data.get("ech_support")

        # Identify key vulnerabilities
        key_vulnerabilities = self._identify_vulnerabilities(fingerprint_data)

        # Determine analysis confidence
        analysis_confidence = self._calculate_analysis_confidence(
            fingerprint_data, classification_result
        )

        # Generate analysis notes
        analysis_notes = self._generate_analysis_notes(fingerprint_data, classification_result)

        return DPIAnalysisReport(
            domain=domain,
            target_ip=target_ip,
            vendor_prediction=vendor_prediction,
            vendor_confidence=vendor_confidence,
            blocking_method=blocking_method,
            rst_ttl_distance=rst_ttl_distance,
            response_timing_pattern=response_timing_pattern,
            supports_http2=supports_http2,
            supports_quic=supports_quic,
            supports_ech=supports_ech,
            key_vulnerabilities=key_vulnerabilities,
            analysis_confidence=analysis_confidence,
            analysis_notes=analysis_notes,
        )

    def generate_strategy_effectiveness_report(
        self, strategy_name: str, strategy_type: str, test_results: List[Dict[str, Any]]
    ) -> StrategyEffectivenessReport:
        """
        Generate strategy effectiveness report.

        Args:
            strategy_name: Name of the strategy
            strategy_type: Type/category of strategy
            test_results: List of test result dictionaries

        Returns:
            StrategyEffectivenessReport with effectiveness analysis
        """
        self.logger.debug(f"Generating effectiveness report for strategy: {strategy_name}")

        if not test_results:
            return StrategyEffectivenessReport(
                strategy_name=strategy_name,
                strategy_type=strategy_type,
                success_rate=0.0,
                avg_latency_ms=0.0,
                total_tests=0,
                successful_tests=0,
                failed_tests=0,
                best_latency_ms=0.0,
                worst_latency_ms=0.0,
                latency_consistency="unknown",
                reliability_score=0.0,
                reliability_confidence=ConfidenceLevel.VERY_LOW,
            )

        # Calculate basic metrics
        total_tests = len(test_results)
        successful_tests = sum(1 for r in test_results if r.get("success", False))
        failed_tests = total_tests - successful_tests
        success_rate = successful_tests / total_tests if total_tests > 0 else 0.0

        # Calculate latency metrics
        latencies = [r.get("latency_ms", 0.0) for r in test_results if r.get("latency_ms")]
        if latencies:
            avg_latency_ms = sum(latencies) / len(latencies)
            best_latency_ms = min(latencies)
            worst_latency_ms = max(latencies)

            # Assess latency consistency
            latency_std = self._calculate_std_dev(latencies)
            if latency_std < avg_latency_ms * 0.1:
                latency_consistency = "consistent"
            elif latency_std < avg_latency_ms * 0.3:
                latency_consistency = "variable"
            else:
                latency_consistency = "unstable"
        else:
            avg_latency_ms = 0.0
            best_latency_ms = 0.0
            worst_latency_ms = 0.0
            latency_consistency = "unknown"

        # Calculate reliability score
        reliability_score = self._calculate_reliability_score(test_results)
        reliability_confidence = self._calculate_reliability_confidence(test_results)

        # Generate recommendations and limitations
        recommended_scenarios = self._generate_strategy_recommendations(
            strategy_type, success_rate, latency_consistency
        )
        limitations = self._identify_strategy_limitations(test_results)

        return StrategyEffectivenessReport(
            strategy_name=strategy_name,
            strategy_type=strategy_type,
            success_rate=success_rate,
            avg_latency_ms=avg_latency_ms,
            total_tests=total_tests,
            successful_tests=successful_tests,
            failed_tests=failed_tests,
            best_latency_ms=best_latency_ms,
            worst_latency_ms=worst_latency_ms,
            latency_consistency=latency_consistency,
            reliability_score=reliability_score,
            reliability_confidence=reliability_confidence,
            recommended_scenarios=recommended_scenarios,
            limitations=limitations,
        )

    def generate_comprehensive_report(
        self,
        target_domain: str,
        analysis_duration: float,
        dpi_analysis: DPIAnalysisReport,
        strategy_reports: List[StrategyEffectivenessReport],
        system_performance: SystemPerformanceReport,
    ) -> ComprehensiveReport:
        """
        Generate comprehensive analysis report with recommendations.

        Args:
            target_domain: Target domain analyzed
            analysis_duration: Total analysis time in seconds
            dpi_analysis: DPI analysis results
            strategy_reports: List of strategy effectiveness reports
            system_performance: System performance metrics

        Returns:
            ComprehensiveReport with complete analysis and recommendations
        """
        self.logger.info(f"Generating comprehensive report for {target_domain}")

        # Select best strategies (top 3)
        best_strategies = sorted(
            strategy_reports,
            key=lambda s: (s.success_rate, -s.avg_latency_ms),
            reverse=True,
        )[:3]

        # Generate key findings
        key_findings = self._generate_key_findings(
            dpi_analysis, best_strategies, system_performance
        )

        # Generate recommended commands
        recommended_commands = self._generate_recommended_commands(target_domain, best_strategies)

        # Generate troubleshooting tips
        troubleshooting_tips = self._generate_troubleshooting_tips(dpi_analysis, system_performance)

        # Calculate overall confidence
        overall_confidence, confidence_explanation = self._calculate_overall_confidence(
            dpi_analysis, best_strategies, system_performance
        )

        return ComprehensiveReport(
            target_domain=target_domain,
            analysis_duration_seconds=analysis_duration,
            dpi_analysis=dpi_analysis,
            best_strategies=best_strategies,
            system_performance=system_performance,
            key_findings=key_findings,
            recommended_commands=recommended_commands,
            troubleshooting_tips=troubleshooting_tips,
            overall_confidence=overall_confidence,
            confidence_explanation=confidence_explanation,
        )

    def print_comprehensive_report(self, report: ComprehensiveReport) -> None:
        """Print comprehensive report to console in user-friendly format."""

        print("\n" + "=" * 80)
        print("🎯 DPI BYPASS ANALYSIS REPORT")
        print("=" * 80)

        # Header information
        print(f"Target Domain: {report.target_domain}")
        print(f"Analysis Duration: {report.analysis_duration_seconds:.1f} seconds")
        print(f"Report Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

        # Overall confidence
        confidence_emoji = {
            ConfidenceLevel.VERY_HIGH: "🟢",
            ConfidenceLevel.HIGH: "🟢",
            ConfidenceLevel.MEDIUM: "🟡",
            ConfidenceLevel.LOW: "🟠",
            ConfidenceLevel.VERY_LOW: "🔴",
        }

        print(
            f"Overall Confidence: {confidence_emoji[report.overall_confidence]} {report.overall_confidence.value.upper()}"
        )
        if report.confidence_explanation:
            print(f"Confidence Explanation: {report.confidence_explanation}")

        print("\n" + "-" * 80)
        print("📊 DPI ANALYSIS")
        print("-" * 80)

        dpi = report.dpi_analysis
        print(f"Target IP: {dpi.target_ip}")
        print(
            f"Predicted DPI Vendor: {dpi.vendor_prediction} ({confidence_emoji[dpi.vendor_confidence]} {dpi.vendor_confidence.value})"
        )
        print(f"Blocking Method: {dpi.blocking_method}")

        if dpi.rst_ttl_distance is not None:
            print(f"RST TTL Distance: {dpi.rst_ttl_distance}")

        print(f"Response Timing Pattern: {dpi.response_timing_pattern}")

        # Protocol support
        protocols = []
        if dpi.supports_http2 is True:
            protocols.append("HTTP/2 ✅")
        elif dpi.supports_http2 is False:
            protocols.append("HTTP/2 ❌")

        if dpi.supports_quic is True:
            protocols.append("QUIC ✅")
        elif dpi.supports_quic is False:
            protocols.append("QUIC ❌")

        if dpi.supports_ech is True:
            protocols.append("ECH ✅")
        elif dpi.supports_ech is False:
            protocols.append("ECH ❌")

        if protocols:
            print(f"Protocol Support: {', '.join(protocols)}")

        # Key vulnerabilities
        if dpi.key_vulnerabilities:
            print("\n🔍 Key Vulnerabilities Identified:")
            for vuln in dpi.key_vulnerabilities:
                print(f"  • {vuln}")

        print("\n" + "-" * 80)
        print("🏆 BEST STRATEGIES")
        print("-" * 80)

        for i, strategy in enumerate(report.best_strategies, 1):
            print(f"\n{i}. {strategy.strategy_name}")
            print(f"   Type: {strategy.strategy_type}")
            print(f"   Success Rate: {strategy.success_rate:.1%}")
            print(f"   Average Latency: {strategy.avg_latency_ms:.0f}ms")
            print(
                f"   Reliability: {confidence_emoji[strategy.reliability_confidence]} {strategy.reliability_score:.1%}"
            )
            print(f"   Tests: {strategy.successful_tests}/{strategy.total_tests}")

            if strategy.recommended_scenarios:
                # Фильтруем None значения
                filtered_scenarios = [s for s in strategy.recommended_scenarios if s is not None]
                if filtered_scenarios:
                    print(f"   Best For: {', '.join(filtered_scenarios)}")

            if strategy.limitations:
                # Фильтруем None значения
                filtered_limitations = [l for l in strategy.limitations if l is not None]
                if filtered_limitations:
                    print(f"   Limitations: {', '.join(filtered_limitations)}")

        print("\n" + "-" * 80)
        print("💻 SYSTEM PERFORMANCE")
        print("-" * 80)

        perf = report.system_performance
        print(f"Engine Type: {perf.engine_type}")
        print(f"Engine Health: {perf.engine_health_status}")
        print(f"Domains Tested: {perf.total_domains_tested}")
        print(f"Strategies Tested: {perf.total_strategies_tested}")
        print(f"Overall Success Rate: {perf.overall_success_rate:.1%}")
        print(f"Average Response Time: {perf.avg_response_time_ms:.0f}ms")

        if perf.packets_processed > 0:
            print(f"Packets Processed: {perf.packets_processed:,}")

        if perf.processing_errors > 0:
            print(f"Processing Errors: {perf.processing_errors}")

        print(f"Total Runtime: {perf.total_runtime_seconds:.1f} seconds")

        print("\n" + "-" * 80)
        print("🔑 KEY FINDINGS")
        print("-" * 80)

        for finding in report.key_findings:
            print(f"• {finding}")

        print("\n" + "-" * 80)
        print("⚡ RECOMMENDED COMMANDS")
        print("-" * 80)

        for cmd in report.recommended_commands:
            print(f"  {cmd}")

        if report.troubleshooting_tips:
            print("\n" + "-" * 80)
            print("🛠️ TROUBLESHOOTING TIPS")
            print("-" * 80)

            for tip in report.troubleshooting_tips:
                print(f"• {tip}")

        print("\n" + "=" * 80)
        print("Report completed successfully! 🎉")
        print("=" * 80 + "\n")

    def save_report_to_file(
        self, report: ComprehensiveReport, filename: Optional[str] = None
    ) -> str:
        """
        Save comprehensive report to JSON file.

        Args:
            report: ComprehensiveReport to save
            filename: Optional filename (auto-generated if not provided)

        Returns:
            Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain_safe = report.target_domain.replace(".", "_")
            filename = f"dpi_analysis_report_{domain_safe}_{timestamp}.json"

        # Convert dataclass to dict for JSON serialization
        report_dict = asdict(report)

        # Convert datetime objects to strings
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: convert_datetime(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetime(item) for item in obj]
            else:
                return obj

        report_dict = convert_datetime(report_dict)

        # Convert enums to strings
        def convert_enums(obj):
            if hasattr(obj, "value"):
                return obj.value
            elif isinstance(obj, dict):
                return {k: convert_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums(item) for item in obj]
            else:
                return obj

        report_dict = convert_enums(report_dict)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Report saved to: {filename}")
        return filename

    # Helper methods

    def _score_to_confidence_level(self, score: float) -> ConfidenceLevel:
        """Convert numeric score to confidence level."""
        if score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.75:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def _identify_vulnerabilities(self, fingerprint_data: Dict[str, Any]) -> List[str]:
        """Identify key vulnerabilities from fingerprint data."""
        vulnerabilities = []

        # Check for timing-based vulnerabilities
        # >>> ИЗМЕНЕНИЕ: Добавляем `or 0` для безопасной обработки None <<<
        if fingerprint_data.get("timing_attack_vulnerable") or 0:
            vulnerabilities.append("Vulnerable to timing-based attacks")

        # Check for fragmentation vulnerabilities
        if fingerprint_data.get("supports_ip_fragmentation"):
            vulnerabilities.append("IP fragmentation bypass possible")

        # Check for protocol-specific vulnerabilities
        if fingerprint_data.get("http2_support"):
            vulnerabilities.append("HTTP/2 frame manipulation possible")

        if fingerprint_data.get("quic_support"):
            vulnerabilities.append("QUIC connection ID manipulation possible")

        # Check for RST injection detection
        # >>> ИЗМЕНЕНИЕ: Добавляем `or 0` для безопасной обработки None <<<
        if (fingerprint_data.get("rst_ttl_distance") or 0) > 0:
            vulnerabilities.append("RST injection detected - TTL manipulation effective")

        return vulnerabilities

    def _calculate_analysis_confidence(
        self, fingerprint_data: Dict[str, Any], classification_result: Dict[str, Any]
    ) -> ConfidenceLevel:
        """Calculate overall analysis confidence."""
        confidence_factors = []

        # Classification confidence
        classification_confidence = classification_result.get("confidence", 0.0)
        confidence_factors.append(classification_confidence)

        # Data completeness
        data_completeness = len([v for v in fingerprint_data.values() if v is not None]) / len(
            fingerprint_data
        )
        confidence_factors.append(data_completeness)

        # Test result consistency
        if fingerprint_data.get("baseline_success") is not None:
            confidence_factors.append(0.8)  # We have baseline data

        avg_confidence = (
            sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
        )
        return self._score_to_confidence_level(avg_confidence)

    def _generate_analysis_notes(
        self, fingerprint_data: Dict[str, Any], classification_result: Dict[str, Any]
    ) -> List[str]:
        """Generate analysis notes."""
        notes = []

        if fingerprint_data.get("baseline_block_type") == "timeout":
            notes.append("Target uses timeout-based blocking - timing attacks recommended")

        if fingerprint_data.get("baseline_block_type") == "rst":
            notes.append("Target uses RST-based blocking - packet manipulation attacks recommended")

        if classification_result.get("confidence", 0.0) < 0.5:
            notes.append(
                "DPI vendor classification has low confidence - multiple attack types recommended"
            )

        return notes

    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance**0.5

    def _calculate_reliability_score(self, test_results: List[Dict[str, Any]]) -> float:
        """Calculate reliability score based on test results."""
        if not test_results:
            return 0.0

        success_rate = sum(1 for r in test_results if r.get("success", False)) / len(test_results)

        # Factor in consistency
        latencies = [r.get("latency_ms", 0.0) for r in test_results if r.get("latency_ms")]
        if latencies and len(latencies) > 1:
            avg_latency = sum(latencies) / len(latencies)
            std_dev = self._calculate_std_dev(latencies)
            consistency_factor = max(0.0, 1.0 - (std_dev / avg_latency)) if avg_latency > 0 else 0.0
        else:
            consistency_factor = 1.0

        return success_rate * 0.7 + consistency_factor * 0.3

    def _calculate_reliability_confidence(
        self, test_results: List[Dict[str, Any]]
    ) -> ConfidenceLevel:
        """Calculate confidence in reliability assessment."""
        test_count = len(test_results)

        if test_count >= 10:
            return ConfidenceLevel.HIGH
        elif test_count >= 5:
            return ConfidenceLevel.MEDIUM
        elif test_count >= 2:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def _generate_strategy_recommendations(
        self, strategy_type: str, success_rate: float, latency_consistency: str
    ) -> List[str]:
        """Generate strategy usage recommendations."""
        recommendations = []

        if success_rate >= 0.8:
            recommendations.append("High-reliability scenarios")

        if latency_consistency == "consistent":
            recommendations.append("Latency-sensitive applications")

        if strategy_type in ["tcp_segmentation", "tcp_manipulation"]:
            recommendations.append("TCP-based protocols")
        elif strategy_type in ["http_header", "http_method"]:
            recommendations.append("HTTP/HTTPS traffic")
        elif strategy_type in ["tls_manipulation", "tls_extension"]:
            recommendations.append("TLS-encrypted connections")

        return recommendations

    def _identify_strategy_limitations(self, test_results: List[Dict[str, Any]]) -> List[str]:
        """Identify strategy limitations."""
        limitations = []

        if not test_results:
            return ["No test data available"]

        success_rate = sum(1 for r in test_results if r.get("success", False)) / len(test_results)

        if success_rate < 0.5:
            limitations.append("Low success rate")

        latencies = [r.get("latency_ms", 0.0) for r in test_results if r.get("latency_ms")]
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            if avg_latency > 5000:  # 5 seconds
                limitations.append("High latency")

        return limitations

    def _generate_key_findings(
        self,
        dpi_analysis: DPIAnalysisReport,
        best_strategies: List[StrategyEffectivenessReport],
        system_performance: SystemPerformanceReport,
    ) -> List[str]:
        """Generate key findings from analysis."""
        findings = []

        # DPI findings
        if dpi_analysis.vendor_confidence in [
            ConfidenceLevel.HIGH,
            ConfidenceLevel.VERY_HIGH,
        ]:
            findings.append(
                f"DPI system identified as {dpi_analysis.vendor_prediction} with high confidence"
            )

        if dpi_analysis.key_vulnerabilities:
            findings.append(
                f"Identified {len(dpi_analysis.key_vulnerabilities)} key vulnerabilities"
            )

        # Strategy findings
        if best_strategies:
            best_strategy = best_strategies[0]
            findings.append(
                f"Best strategy: {best_strategy.strategy_name} ({best_strategy.success_rate:.1%} success rate)"
            )

        # Performance findings
        if system_performance.overall_success_rate >= 0.8:
            findings.append("High overall success rate achieved")
        elif system_performance.overall_success_rate < 0.3:
            findings.append("Low success rate - target may be difficult to bypass")

        return findings

    def _generate_recommended_commands(
        self, target_domain: str, best_strategies: List[StrategyEffectivenessReport]
    ) -> List[str]:
        """Generate recommended commands for users."""
        commands = []

        if best_strategies:
            best_strategy = best_strategies[0]

            # Generate command based on strategy type
            if "zapret" in best_strategy.strategy_name.lower():
                commands.append(
                    f"python recon_service.py  # Use the best strategy found for {target_domain}"
                )
            else:
                commands.append(
                    f"python cli.py {target_domain} --strategy {best_strategy.strategy_name}"
                )

        commands.append("python recon_service.py  # Start persistent bypass service")

        return commands

    def _generate_troubleshooting_tips(
        self,
        dpi_analysis: DPIAnalysisReport,
        system_performance: SystemPerformanceReport,
    ) -> List[str]:
        """Generate troubleshooting tips."""
        tips = []

        if system_performance.processing_errors > 0:
            tips.append("Check system permissions - run as Administrator/root if needed")

        if dpi_analysis.blocking_method == "timeout":
            tips.append("Try strategies with shorter timeouts or faster execution")

        if system_performance.overall_success_rate < 0.3:
            tips.append("Consider using multiple strategies in combination")
            tips.append("Try evolutionary search for better strategy discovery")

        return tips

    def _calculate_overall_confidence(
        self,
        dpi_analysis: DPIAnalysisReport,
        best_strategies: List[StrategyEffectivenessReport],
        system_performance: SystemPerformanceReport,
    ) -> Tuple[ConfidenceLevel, str]:
        """Calculate overall confidence and explanation."""
        confidence_factors = []
        explanations = []

        # DPI analysis confidence
        dpi_confidence_score = {
            ConfidenceLevel.VERY_HIGH: 1.0,
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4,
            ConfidenceLevel.VERY_LOW: 0.2,
        }[dpi_analysis.analysis_confidence]

        confidence_factors.append(dpi_confidence_score)
        explanations.append(f"DPI analysis confidence: {dpi_analysis.analysis_confidence.value}")

        # Strategy effectiveness confidence
        if best_strategies:
            strategy_confidence = sum(
                dpi_confidence_score[s.reliability_confidence] for s in best_strategies[:3]
            ) / min(3, len(best_strategies))
            confidence_factors.append(strategy_confidence)
            explanations.append(f"Strategy reliability: {len(best_strategies)} strategies tested")

        # System performance confidence
        if system_performance.total_domains_tested >= 1:
            perf_confidence = min(1.0, system_performance.overall_success_rate + 0.2)
            confidence_factors.append(perf_confidence)
            explanations.append(
                f"System performance: {system_performance.overall_success_rate:.1%} success rate"
            )

        # Calculate overall
        overall_score = (
            sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.0
        )
        overall_confidence = self._score_to_confidence_level(overall_score)

        explanation = "; ".join(explanations)

        return overall_confidence, explanation
