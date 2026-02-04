"""
Data models for CLI wrapper.

This module contains dataclasses for configuration, metrics, and results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional
import importlib.util


# ============================================================================
# ENUMS
# ============================================================================


class AnalysisMode(str, Enum):
    """Analysis mode options."""

    QUICK = "quick"
    BALANCED = "balanced"
    COMPREHENSIVE = "comprehensive"
    DEEP = "deep"

    @property
    def max_trials(self) -> int:
        """Get max trials for this mode."""
        return {
            self.QUICK: 5,
            self.BALANCED: 10,
            self.COMPREHENSIVE: 15,
            self.DEEP: 25,
        }[self]


class OutputFormat(str, Enum):
    """Output format options."""

    RICH = "rich"
    PLAIN = "plain"
    JSON = "json"
    QUIET = "quiet"


# ============================================================================
# CONFIGURATION
# ============================================================================


@dataclass
class CLIConfig:
    """
    CLI-specific configuration.

    Attributes:
        verbose: Enable verbose output
        quiet: Suppress most output
        no_colors: Disable colored output
        export_file: Path to export results
        save_legacy: Save in legacy format
        show_progress: Show progress indicators
        timeout: Analysis timeout in seconds
        output_format: Output format to use
    """

    verbose: bool = False
    quiet: bool = False
    no_colors: bool = False
    export_file: Optional[str] = None
    save_legacy: bool = True
    show_progress: bool = True
    timeout: float = 300.0
    output_format: OutputFormat = OutputFormat.RICH

    def __post_init__(self):
        """Adjust settings based on environment."""
        # Avoid importing adaptive_cli_wrapper here to prevent circular imports.
        # Detect Rich availability directly.
        if importlib.util.find_spec("rich") is None:
            self.no_colors = True
            self.output_format = OutputFormat.PLAIN

        if self.quiet:
            self.output_format = OutputFormat.QUIET


# ============================================================================
# METRICS
# ============================================================================


@dataclass
class AnalysisMetrics:
    """
    Metrics for analysis execution tracking.

    Tracks timing, success, and other metrics for a single analysis run.
    """

    start_time: float = 0.0
    end_time: float = 0.0
    execution_time: float = 0.0
    trials_count: int = 0
    strategies_tested: int = 0
    success: bool = False
    error_message: Optional[str] = None
    domain: str = ""
    mode: str = ""
    fingerprint_updated: bool = False

    @property
    def duration(self) -> float:
        """
        Get execution duration.

        Returns:
            Duration in seconds
        """
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return self.execution_time


# ============================================================================
# BATCH PROCESSING
# ============================================================================


@dataclass
class BatchResult:
    """
    Result for a single domain in batch processing.

    Attributes:
        domain: Domain name
        success: Whether analysis succeeded
        strategy_name: Name of successful strategy (if any)
        error: Error message (if failed)
        execution_time: Time taken for this domain
    """

    domain: str
    success: bool
    strategy_name: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class BatchSummary:
    """
    Summary of batch processing results.

    Aggregates results from multiple domain analyses.
    """

    total_domains: int = 0
    successful_domains: int = 0
    failed_domains: int = 0
    total_time: float = 0.0
    results: Dict[str, BatchResult] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """
        Get success rate as percentage.

        Returns:
            Success rate (0-100)
        """
        if self.total_domains == 0:
            return 0.0
        return (self.successful_domains / self.total_domains) * 100
