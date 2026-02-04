"""
Main attack parity analyzer orchestrator.

This module provides the AttackParityAnalyzer class that orchestrates the complete
analysis pipeline from logs and PCAP files to comprehensive reports, handling
error cases and providing comprehensive analysis results.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from datetime import datetime
import json

from .interfaces import LogParser, PCAPAnalyzer, CorrelationEngine, ParityChecker
from .parsers import auto_detect_parser, create_log_parser
from .pcap_analyzer import DefaultPCAPAnalyzer
from .correlation_engine import AttackCorrelationEngine, TimingAnalyzer
from .parity_checker import ParityChecker as DefaultParityChecker
from .report_generator import AttackParityReportGenerator
from .models import (
    AttackEvent,
    AttackSequence,
    PacketModification,
    CorrelationResult,
    ParityResult,
    ExecutionMode,
)

logger = logging.getLogger(__name__)


class AttackParityAnalyzer:
    """
    Main orchestrator for attack parity analysis.

    This class coordinates the complete analysis pipeline from logs and PCAP files
    to comprehensive reports, ensuring universal attack semantics consistency
    across discovery and service modes.
    """

    def __init__(
        self,
        timing_tolerance: float = 0.1,
        log_parser: Optional[LogParser] = None,
        pcap_analyzer: Optional[PCAPAnalyzer] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        parity_checker: Optional[ParityChecker] = None,
        report_generator: Optional[AttackParityReportGenerator] = None,
    ):
        """
        Initialize the attack parity analyzer.

        Args:
            timing_tolerance: Acceptable timing difference for correlation (seconds)
            log_parser: Custom log parser (auto-detected if None)
            pcap_analyzer: Custom PCAP analyzer (default if None)
            correlation_engine: Custom correlation engine (default if None)
            parity_checker: Custom parity checker (default if None)
            report_generator: Custom report generator (default if None)
        """
        self.timing_tolerance = timing_tolerance
        self.logger = logging.getLogger(__name__)

        # Initialize components with defaults if not provided
        self.log_parser = log_parser
        self.pcap_analyzer = pcap_analyzer or DefaultPCAPAnalyzer()
        self.correlation_engine = correlation_engine or AttackCorrelationEngine(timing_tolerance)
        self.parity_checker = parity_checker or DefaultParityChecker(timing_tolerance)
        self.report_generator = report_generator or AttackParityReportGenerator()

        # Initialize timing analyzer for advanced timing analysis
        self.timing_analyzer = TimingAnalyzer(timing_tolerance)

        # Track analysis state
        self.last_analysis_results = None
        self.analysis_metadata = {}

    def analyze_parity(
        self,
        discovery_log_path: Optional[str] = None,
        service_log_path: Optional[str] = None,
        discovery_pcap_path: Optional[str] = None,
        service_pcap_path: Optional[str] = None,
        output_report_path: Optional[str] = None,
        analysis_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive attack parity analysis.

        Args:
            discovery_log_path: Path to discovery mode log file
            service_log_path: Path to service mode log file
            discovery_pcap_path: Path to discovery mode PCAP file
            service_pcap_path: Path to service mode PCAP file
            output_report_path: Path to save analysis report
            analysis_config: Configuration options for analysis

        Returns:
            Dictionary containing comprehensive analysis results
        """
        self.logger.info("Starting comprehensive attack parity analysis")

        try:
            # Initialize analysis metadata
            self._initialize_analysis_metadata(analysis_config)

            # Parse log files
            discovery_attacks, service_attacks = self._parse_log_files(
                discovery_log_path, service_log_path
            )

            # Analyze PCAP files
            discovery_modifications, service_modifications = self._analyze_pcap_files(
                discovery_pcap_path, service_pcap_path
            )

            # Perform correlation analysis
            correlation_results = self._perform_correlation_analysis(
                discovery_attacks, service_attacks, discovery_modifications, service_modifications
            )

            # Perform parity analysis
            parity_result = self._perform_parity_analysis(discovery_attacks, service_attacks)

            # Generate comprehensive report
            report = self._generate_comprehensive_report(correlation_results, parity_result)

            # Save report if output path provided
            if output_report_path:
                self.report_generator.save_report_to_file(report, output_report_path)

            # Store results for future reference
            self.last_analysis_results = {
                "correlation_results": correlation_results,
                "parity_result": parity_result,
                "report": report,
                "metadata": self.analysis_metadata,
            }

            self.logger.info("Attack parity analysis completed successfully")
            return self.last_analysis_results

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}", exc_info=True)
            return self._handle_analysis_error(e)

    def analyze_correlation_only(
        self, log_path: str, pcap_path: str, mode: ExecutionMode = ExecutionMode.DISCOVERY
    ) -> CorrelationResult:
        """
        Perform correlation analysis only (logs vs PCAP).

        Args:
            log_path: Path to log file
            pcap_path: Path to PCAP file
            mode: Execution mode for the analysis

        Returns:
            CorrelationResult containing correlation analysis
        """
        self.logger.info(f"Starting correlation-only analysis for {mode.value} mode")

        try:
            # Parse log file
            attacks = self._parse_single_log_file(log_path, mode)

            # Analyze PCAP file
            modifications = self._analyze_single_pcap_file(pcap_path)

            # Perform correlation
            correlation_result = self.correlation_engine.correlate_logs_with_pcap(
                attacks, modifications
            )

            self.logger.info(
                f"Correlation analysis completed. Accuracy: {correlation_result.semantic_accuracy:.2%}"
            )
            return correlation_result

        except Exception as e:
            self.logger.error(f"Correlation analysis failed: {str(e)}", exc_info=True)
            raise

    def analyze_parity_only(self, discovery_log_path: str, service_log_path: str) -> ParityResult:
        """
        Perform parity analysis only (cross-mode comparison).

        Args:
            discovery_log_path: Path to discovery mode log file
            service_log_path: Path to service mode log file

        Returns:
            ParityResult containing parity analysis
        """
        self.logger.info("Starting parity-only analysis")

        try:
            # Parse log files
            discovery_attacks, service_attacks = self._parse_log_files(
                discovery_log_path, service_log_path
            )

            # Perform parity analysis
            parity_result = self._perform_parity_analysis(discovery_attacks, service_attacks)

            self.logger.info(f"Parity analysis completed. Score: {parity_result.parity_score:.2%}")
            return parity_result

        except Exception as e:
            self.logger.error(f"Parity analysis failed: {str(e)}", exc_info=True)
            raise

    def validate_timing_consistency(
        self, log_path: str, pcap_path: str, detailed_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Perform detailed timing consistency validation.

        Args:
            log_path: Path to log file
            pcap_path: Path to PCAP file
            detailed_analysis: Whether to perform detailed timing analysis

        Returns:
            Dictionary containing timing validation results
        """
        self.logger.info("Starting timing consistency validation")

        try:
            # Parse log and PCAP files
            attacks = self._parse_single_log_file(log_path)
            modifications = self._analyze_single_pcap_file(pcap_path)

            # Perform timing validation
            if detailed_analysis:
                timing_results = self.timing_analyzer.validate_timing_consistency(
                    attacks, modifications
                )
            else:
                timing_results = self.timing_analyzer.validate_timestamp_alignment(
                    attacks, modifications, self.timing_tolerance
                )

            self.logger.info(
                f"Timing validation completed. Consistency score: {timing_results.get('consistency_score', 'N/A')}"
            )
            return timing_results

        except Exception as e:
            self.logger.error(f"Timing validation failed: {str(e)}", exc_info=True)
            raise

    def get_analysis_summary(self) -> Optional[Dict[str, Any]]:
        """
        Get summary of the last analysis performed.

        Returns:
            Dictionary containing analysis summary or None if no analysis performed
        """
        if not self.last_analysis_results:
            return None

        correlation_results = self.last_analysis_results["correlation_results"]
        parity_result = self.last_analysis_results["parity_result"]

        return {
            "analysis_timestamp": self.analysis_metadata.get("analysis_start_time"),
            "semantic_accuracy": correlation_results.get("discovery", {}).get(
                "semantic_accuracy", 0.0
            ),
            "truth_consistency": correlation_results.get("discovery", {}).get(
                "truth_consistency_score", 0.0
            ),
            "parity_score": parity_result.parity_score,
            "total_attacks_analyzed": (
                len(
                    correlation_results.get("discovery", {}).get("semantically_correct_attacks", [])
                )
                + len(
                    correlation_results.get("discovery", {}).get(
                        "semantically_incorrect_attacks", []
                    )
                )
            ),
            "critical_issues": self._identify_critical_issues(correlation_results, parity_result),
        }

    def _initialize_analysis_metadata(self, config: Optional[Dict[str, Any]]):
        """Initialize analysis metadata and configuration."""
        self.analysis_metadata = {
            "analysis_start_time": datetime.now().isoformat(),
            "timing_tolerance": self.timing_tolerance,
            "analyzer_version": "1.0",
            "config": config or {},
        }

    def _parse_log_files(
        self, discovery_log_path: Optional[str], service_log_path: Optional[str]
    ) -> Tuple[List[AttackSequence], List[AttackSequence]]:
        """Parse discovery and service mode log files."""
        discovery_attacks = []
        service_attacks = []

        if discovery_log_path:
            self.logger.info(f"Parsing discovery mode log: {discovery_log_path}")
            discovery_events = self._parse_single_log_file(
                discovery_log_path, ExecutionMode.DISCOVERY
            )
            discovery_attacks = self._group_events_into_sequences(
                discovery_events, ExecutionMode.DISCOVERY
            )

        if service_log_path:
            self.logger.info(f"Parsing service mode log: {service_log_path}")
            service_events = self._parse_single_log_file(service_log_path, ExecutionMode.SERVICE)
            service_attacks = self._group_events_into_sequences(
                service_events, ExecutionMode.SERVICE
            )

        self.logger.info(
            f"Parsed {len(discovery_attacks)} discovery sequences, {len(service_attacks)} service sequences"
        )
        return discovery_attacks, service_attacks

    def _parse_single_log_file(
        self, log_path: str, mode: Optional[ExecutionMode] = None
    ) -> List[AttackEvent]:
        """Parse a single log file and extract attack events."""
        if not Path(log_path).exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        # Auto-detect parser if not provided
        if not self.log_parser:
            self.log_parser = auto_detect_parser(log_path)

        # Parse the log file
        events = self.log_parser.parse_log_file(log_path)

        # Validate mode consistency if specified
        if mode and events:
            detected_mode = events[0].execution_mode
            if detected_mode != mode:
                self.logger.warning(
                    f"Mode mismatch: expected {mode.value}, detected {detected_mode.value}"
                )

        return events

    def _analyze_pcap_files(
        self, discovery_pcap_path: Optional[str], service_pcap_path: Optional[str]
    ) -> Tuple[List[PacketModification], List[PacketModification]]:
        """Analyze discovery and service mode PCAP files."""
        discovery_modifications = []
        service_modifications = []

        if discovery_pcap_path:
            self.logger.info(f"Analyzing discovery mode PCAP: {discovery_pcap_path}")
            discovery_modifications = self._analyze_single_pcap_file(discovery_pcap_path)

        if service_pcap_path:
            self.logger.info(f"Analyzing service mode PCAP: {service_pcap_path}")
            service_modifications = self._analyze_single_pcap_file(service_pcap_path)

        self.logger.info(
            f"Found {len(discovery_modifications)} discovery modifications, "
            f"{len(service_modifications)} service modifications"
        )
        return discovery_modifications, service_modifications

    def _analyze_single_pcap_file(self, pcap_path: str) -> List[PacketModification]:
        """Analyze a single PCAP file and extract packet modifications."""
        if not Path(pcap_path).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        return self.pcap_analyzer.analyze_pcap_file(pcap_path)

    def _group_events_into_sequences(
        self, events: List[AttackEvent], mode: ExecutionMode
    ) -> List[AttackSequence]:
        """Group attack events into logical sequences."""
        if not self.log_parser:
            # Use a default parser for grouping
            self.log_parser = create_log_parser(mode)

        return self.log_parser.extract_attack_sequences(events)

    def _perform_correlation_analysis(
        self,
        discovery_attacks: List[AttackSequence],
        service_attacks: List[AttackSequence],
        discovery_modifications: List[PacketModification],
        service_modifications: List[PacketModification],
    ) -> Dict[str, CorrelationResult]:
        """Perform correlation analysis for both modes."""
        correlation_results = {}

        # Correlate discovery mode
        if discovery_attacks and discovery_modifications:
            self.logger.info("Correlating discovery mode logs with PCAP")
            discovery_events = [event for seq in discovery_attacks for event in seq.attacks]
            correlation_results["discovery"] = self.correlation_engine.correlate_logs_with_pcap(
                discovery_events, discovery_modifications
            )

        # Correlate service mode
        if service_attacks and service_modifications:
            self.logger.info("Correlating service mode logs with PCAP")
            service_events = [event for seq in service_attacks for event in seq.attacks]
            correlation_results["service"] = self.correlation_engine.correlate_logs_with_pcap(
                service_events, service_modifications
            )

        return correlation_results

    def _perform_parity_analysis(
        self, discovery_attacks: List[AttackSequence], service_attacks: List[AttackSequence]
    ) -> ParityResult:
        """Perform parity analysis between modes."""
        self.logger.info("Performing cross-mode parity analysis")

        return self.parity_checker.compare_attack_sequences(discovery_attacks, service_attacks)

    def _generate_comprehensive_report(
        self, correlation_results: Dict[str, CorrelationResult], parity_result: ParityResult
    ) -> Dict[str, Any]:
        """Generate comprehensive analysis report."""
        self.logger.info("Generating comprehensive analysis report")

        # Use the first available correlation result for report generation
        # In practice, you might want to combine results from both modes
        primary_correlation = (
            correlation_results.get("discovery")
            or correlation_results.get("service")
            or CorrelationResult([], [], [], [], 0.0, 0.0)
        )

        return self.report_generator.generate_comprehensive_report(
            primary_correlation, parity_result, self.analysis_metadata
        )

    def _handle_analysis_error(self, error: Exception) -> Dict[str, Any]:
        """Handle analysis errors and return error report."""
        error_report = {
            "success": False,
            "error": str(error),
            "error_type": type(error).__name__,
            "analysis_metadata": self.analysis_metadata,
            "partial_results": None,
            "recommendations": [
                "Check file paths and permissions",
                "Verify log and PCAP file formats",
                "Review timing tolerance settings",
                "Check system resources and dependencies",
            ],
        }

        # Try to include any partial results if available
        if hasattr(self, "last_analysis_results") and self.last_analysis_results:
            error_report["partial_results"] = self.last_analysis_results

        return error_report

    def _identify_critical_issues(
        self, correlation_results: Dict[str, CorrelationResult], parity_result: ParityResult
    ) -> List[str]:
        """Identify critical issues from analysis results."""
        issues = []

        # Check correlation results
        for mode, result in correlation_results.items():
            if result.semantic_accuracy < 0.5:
                issues.append(
                    f"Critical: {mode} mode semantic accuracy very low ({result.semantic_accuracy:.1%})"
                )

            if result.truth_consistency_score < 0.7:
                issues.append(
                    f"Critical: {mode} mode truth consistency issues ({result.truth_consistency_score:.1%})"
                )

        # Check parity results
        if parity_result.parity_score < 0.5:
            issues.append(
                f"Critical: Cross-mode parity very low ({parity_result.parity_score:.1%})"
            )

        return issues


class AnalysisConfiguration:
    """Configuration class for attack parity analysis."""

    def __init__(
        self,
        timing_tolerance: float = 0.1,
        enable_detailed_timing: bool = True,
        enable_semantic_validation: bool = True,
        enable_combination_analysis: bool = True,
        report_format: str = "json",
        output_directory: Optional[str] = None,
    ):
        """
        Initialize analysis configuration.

        Args:
            timing_tolerance: Acceptable timing difference (seconds)
            enable_detailed_timing: Enable detailed timing analysis
            enable_semantic_validation: Enable semantic correctness validation
            enable_combination_analysis: Enable attack combination analysis
            report_format: Output report format ("json", "html", "text")
            output_directory: Directory for output files
        """
        self.timing_tolerance = timing_tolerance
        self.enable_detailed_timing = enable_detailed_timing
        self.enable_semantic_validation = enable_semantic_validation
        self.enable_combination_analysis = enable_combination_analysis
        self.report_format = report_format
        self.output_directory = output_directory

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "timing_tolerance": self.timing_tolerance,
            "enable_detailed_timing": self.enable_detailed_timing,
            "enable_semantic_validation": self.enable_semantic_validation,
            "enable_combination_analysis": self.enable_combination_analysis,
            "report_format": self.report_format,
            "output_directory": self.output_directory,
        }

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "AnalysisConfiguration":
        """Create configuration from dictionary."""
        return cls(**config_dict)

    @classmethod
    def from_file(cls, config_path: str) -> "AnalysisConfiguration":
        """Load configuration from JSON file."""
        with open(config_path, "r") as f:
            config_dict = json.load(f)
        return cls.from_dict(config_dict)
