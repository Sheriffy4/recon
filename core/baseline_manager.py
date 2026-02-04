"""
Baseline Manager for Attack Validation Suite

This module provides baseline management functionality for regression detection,
including saving, loading, comparing, and archiving baseline test results.

Author: Attack Validation Suite
Date: 2025-10-06
"""

import json
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum


class RegressionSeverity(Enum):
    """Severity levels for regressions."""

    CRITICAL = "critical"  # Pass -> Fail
    HIGH = "high"  # Validation degradation
    MEDIUM = "medium"  # Performance degradation
    LOW = "low"  # Minor changes


@dataclass
class BaselineResult:
    """Represents a single test result in a baseline."""

    attack_name: str
    passed: bool
    packet_count: int
    validation_passed: bool
    validation_issues: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BaselineReport:
    """Complete baseline test report."""

    name: str
    timestamp: str
    version: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    results: List[BaselineResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "version": self.version,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "results": [asdict(r) for r in self.results],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineReport":
        """Create from dictionary."""
        results = [BaselineResult(**r) for r in data.get("results", [])]
        return cls(
            name=data["name"],
            timestamp=data["timestamp"],
            version=data["version"],
            total_tests=data["total_tests"],
            passed_tests=data["passed_tests"],
            failed_tests=data["failed_tests"],
            results=results,
            metadata=data.get("metadata", {}),
        )


@dataclass
class Regression:
    """Represents a detected regression."""

    attack_name: str
    severity: RegressionSeverity
    baseline_status: str
    current_status: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Improvement:
    """Represents a detected improvement."""

    attack_name: str
    baseline_status: str
    current_status: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComparisonResult:
    """Result of comparing current results with baseline."""

    baseline_name: str
    baseline_timestamp: str
    current_timestamp: str
    total_tests: int
    regressions: List[Regression] = field(default_factory=list)
    improvements: List[Improvement] = field(default_factory=list)
    unchanged: int = 0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "baseline_name": self.baseline_name,
            "baseline_timestamp": self.baseline_timestamp,
            "current_timestamp": self.current_timestamp,
            "total_tests": self.total_tests,
            "regressions": [
                {
                    "attack_name": r.attack_name,
                    "severity": r.severity.value,
                    "baseline_status": r.baseline_status,
                    "current_status": r.current_status,
                    "description": r.description,
                    "details": r.details,
                }
                for r in self.regressions
            ],
            "improvements": [
                {
                    "attack_name": i.attack_name,
                    "baseline_status": i.baseline_status,
                    "current_status": i.current_status,
                    "description": i.description,
                    "details": i.details,
                }
                for i in self.improvements
            ],
            "unchanged": self.unchanged,
            "summary": self.summary,
        }


class BaselineManager:
    """
    Manages baseline test results for regression detection.

    Features:
    - Save baseline results with timestamp and version
    - Load baseline results with version selection
    - Compare current results with baseline
    - Detect regressions and improvements
    - Archive old baselines
    - Caching for frequently accessed baselines (optimization)
    """

    def __init__(self, baselines_dir: Optional[Path] = None, enable_cache: bool = True):
        """
        Initialize baseline manager.

        Args:
            baselines_dir: Directory to store baselines (default: ./baselines)
            enable_cache: Whether to enable baseline caching (default: True)
        """
        if baselines_dir is None:
            baselines_dir = Path(__file__).parent.parent / "baselines"

        self.baselines_dir = Path(baselines_dir)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

        # Archive directory for old baselines
        self.archive_dir = self.baselines_dir / "archive"
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        # Current baseline symlink
        self.current_baseline_link = self.baselines_dir / "current_baseline.json"

        # Baseline cache for performance optimization
        self.enable_cache = enable_cache
        self._baseline_cache: Dict[str, tuple[BaselineReport, float]] = (
            {}
        )  # name -> (report, timestamp)
        self._cache_ttl = 300.0  # 5 minutes cache TTL

    def save_baseline(self, report: BaselineReport, name: Optional[str] = None) -> Path:
        """
        Save baseline test results.

        Args:
            report: Baseline report to save
            name: Optional name for baseline (default: auto-generated)

        Returns:
            Path to saved baseline file
        """
        # Generate name if not provided
        if name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"baseline_{timestamp}"

        # Update report name and timestamp
        report.name = name
        report.timestamp = datetime.now().isoformat()

        # Save to file
        baseline_file = self.baselines_dir / f"{name}.json"
        with open(baseline_file, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        # Update current baseline symlink
        self._update_current_baseline(baseline_file)

        return baseline_file

    def load_baseline(self, name: Optional[str] = None) -> Optional[BaselineReport]:
        """
        Load baseline test results with caching support.

        Args:
            name: Name of baseline to load (default: current baseline)

        Returns:
            Baseline report or None if not found
        """
        # Determine baseline name
        if name is None:
            # Load current baseline
            if self.current_baseline_link.exists():
                baseline_file = self.current_baseline_link
                # Use file stem as cache key
                name = baseline_file.stem if baseline_file.is_file() else "current"
            else:
                # Find most recent baseline
                baseline_file = self._find_latest_baseline()
                if baseline_file is None:
                    return None
                name = baseline_file.stem
        else:
            # Load specific baseline
            baseline_file = self.baselines_dir / f"{name}.json"
            if not baseline_file.exists():
                return None

        # Check cache first
        if self.enable_cache and name in self._baseline_cache:
            cached_report, cache_time = self._baseline_cache[name]

            # Check if cache is still valid
            import time

            if time.time() - cache_time < self._cache_ttl:
                return cached_report
            else:
                # Cache expired, remove entry
                del self._baseline_cache[name]

        # Load from file
        try:
            with open(baseline_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            report = BaselineReport.from_dict(data)

            # Cache the loaded baseline
            if self.enable_cache:
                import time

                self._baseline_cache[name] = (report, time.time())

            return report
        except Exception as e:
            print(f"Error loading baseline: {e}")
            return None

    def compare_with_baseline(
        self,
        current: BaselineReport,
        baseline: Optional[BaselineReport] = None,
        baseline_name: Optional[str] = None,
    ) -> ComparisonResult:
        """
        Compare current results with baseline.

        Args:
            current: Current test results
            baseline: Baseline to compare against (or load by name)
            baseline_name: Name of baseline to load if baseline not provided

        Returns:
            Comparison result with regressions and improvements
        """
        # Load baseline if not provided
        if baseline is None:
            baseline = self.load_baseline(baseline_name)
            if baseline is None:
                raise ValueError("No baseline found to compare against")

        # Create result object
        result = ComparisonResult(
            baseline_name=baseline.name,
            baseline_timestamp=baseline.timestamp,
            current_timestamp=current.timestamp,
            total_tests=current.total_tests,
        )

        # Create lookup for baseline results
        baseline_lookup = {r.attack_name: r for r in baseline.results}

        # Compare each test
        for current_result in current.results:
            attack_name = current_result.attack_name

            if attack_name not in baseline_lookup:
                # New test not in baseline
                continue

            baseline_result = baseline_lookup[attack_name]

            # Detect regressions and improvements
            regression = self._detect_regression(baseline_result, current_result)
            if regression:
                result.regressions.append(regression)
            else:
                improvement = self._detect_improvement(baseline_result, current_result)
                if improvement:
                    result.improvements.append(improvement)
                else:
                    result.unchanged += 1

        # Generate summary
        result.summary = self._generate_comparison_summary(result)

        return result

    def detect_regressions(self, comparison: ComparisonResult) -> List[Regression]:
        """
        Extract regressions from comparison result.

        Args:
            comparison: Comparison result

        Returns:
            List of regressions
        """
        return comparison.regressions

    def archive_baseline(self, name: str) -> bool:
        """
        Archive a baseline (move to archive directory).

        Args:
            name: Name of baseline to archive

        Returns:
            True if successful, False otherwise
        """
        baseline_file = self.baselines_dir / f"{name}.json"
        if not baseline_file.exists():
            return False

        # Move to archive
        archive_file = self.archive_dir / f"{name}.json"
        shutil.move(str(baseline_file), str(archive_file))

        return True

    def list_baselines(self) -> List[str]:
        """
        List all available baselines.

        Returns:
            List of baseline names
        """
        baselines = []
        for file in self.baselines_dir.glob("baseline_*.json"):
            baselines.append(file.stem)
        return sorted(baselines, reverse=True)

    def list_archived_baselines(self) -> List[str]:
        """
        List all archived baselines.

        Returns:
            List of archived baseline names
        """
        archived = []
        for file in self.archive_dir.glob("baseline_*.json"):
            archived.append(file.stem)
        return sorted(archived, reverse=True)

    def clear_cache(self):
        """Clear the baseline cache."""
        self._baseline_cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get baseline cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        import time

        current_time = time.time()

        valid_entries = sum(
            1
            for _, cache_time in self._baseline_cache.values()
            if current_time - cache_time < self._cache_ttl
        )

        return {
            "enabled": self.enable_cache,
            "total_entries": len(self._baseline_cache),
            "valid_entries": valid_entries,
            "expired_entries": len(self._baseline_cache) - valid_entries,
            "cache_ttl": self._cache_ttl,
        }

    def _update_current_baseline(self, baseline_file: Path):
        """Update the current baseline symlink."""
        # Remove old symlink if exists
        if self.current_baseline_link.exists() or self.current_baseline_link.is_symlink():
            self.current_baseline_link.unlink()

        # Create new symlink (or copy on Windows if symlink fails)
        try:
            self.current_baseline_link.symlink_to(baseline_file.name)
        except OSError:
            # Fallback for Windows without admin rights
            shutil.copy(str(baseline_file), str(self.current_baseline_link))

    def _find_latest_baseline(self) -> Optional[Path]:
        """Find the most recent baseline file."""
        baselines = list(self.baselines_dir.glob("baseline_*.json"))
        if not baselines:
            return None
        return max(baselines, key=lambda p: p.stat().st_mtime)

    def _detect_regression(
        self, baseline: BaselineResult, current: BaselineResult
    ) -> Optional[Regression]:
        """
        Detect if current result is a regression from baseline.

        Args:
            baseline: Baseline result
            current: Current result

        Returns:
            Regression object if regression detected, None otherwise
        """
        # Critical: Pass -> Fail
        if baseline.passed and not current.passed:
            return Regression(
                attack_name=current.attack_name,
                severity=RegressionSeverity.CRITICAL,
                baseline_status="PASS",
                current_status="FAIL",
                description=f"Attack {current.attack_name} regressed from PASS to FAIL",
                details={
                    "baseline_packet_count": baseline.packet_count,
                    "current_packet_count": current.packet_count,
                },
            )

        # High: Validation degradation
        if baseline.validation_passed and not current.validation_passed:
            return Regression(
                attack_name=current.attack_name,
                severity=RegressionSeverity.HIGH,
                baseline_status="VALIDATION_PASS",
                current_status="VALIDATION_FAIL",
                description=f"Attack {current.attack_name} validation degraded",
                details={
                    "baseline_issues": baseline.validation_issues,
                    "current_issues": current.validation_issues,
                },
            )

        # Medium: Packet count decreased significantly
        if baseline.packet_count > 0 and current.packet_count < baseline.packet_count * 0.8:
            return Regression(
                attack_name=current.attack_name,
                severity=RegressionSeverity.MEDIUM,
                baseline_status=f"PACKETS_{baseline.packet_count}",
                current_status=f"PACKETS_{current.packet_count}",
                description=f"Attack {current.attack_name} packet count decreased significantly",
                details={
                    "baseline_packet_count": baseline.packet_count,
                    "current_packet_count": current.packet_count,
                    "decrease_percent": (
                        (baseline.packet_count - current.packet_count) / baseline.packet_count
                    )
                    * 100,
                },
            )

        return None

    def _detect_improvement(
        self, baseline: BaselineResult, current: BaselineResult
    ) -> Optional[Improvement]:
        """
        Detect if current result is an improvement from baseline.

        Args:
            baseline: Baseline result
            current: Current result

        Returns:
            Improvement object if improvement detected, None otherwise
        """
        # Fail -> Pass
        if not baseline.passed and current.passed:
            return Improvement(
                attack_name=current.attack_name,
                baseline_status="FAIL",
                current_status="PASS",
                description=f"Attack {current.attack_name} improved from FAIL to PASS",
                details={
                    "baseline_packet_count": baseline.packet_count,
                    "current_packet_count": current.packet_count,
                },
            )

        # Validation improvement
        if not baseline.validation_passed and current.validation_passed:
            return Improvement(
                attack_name=current.attack_name,
                baseline_status="VALIDATION_FAIL",
                current_status="VALIDATION_PASS",
                description=f"Attack {current.attack_name} validation improved",
                details={
                    "baseline_issues": baseline.validation_issues,
                    "current_issues": current.validation_issues,
                },
            )

        return None

    def _generate_comparison_summary(self, result: ComparisonResult) -> str:
        """Generate human-readable comparison summary."""
        lines = []
        lines.append(f"Baseline Comparison: {result.baseline_name}")
        lines.append(f"Baseline Date: {result.baseline_timestamp}")
        lines.append(f"Current Date: {result.current_timestamp}")
        lines.append(f"Total Tests: {result.total_tests}")
        lines.append(f"Regressions: {len(result.regressions)}")
        lines.append(f"Improvements: {len(result.improvements)}")
        lines.append(f"Unchanged: {result.unchanged}")

        if result.regressions:
            lines.append("\nREGRESSIONS:")
            for reg in result.regressions:
                lines.append(
                    f"  [{reg.severity.value.upper()}] {reg.attack_name}: {reg.description}"
                )

        if result.improvements:
            lines.append("\nIMPROVEMENTS:")
            for imp in result.improvements:
                lines.append(f"  [IMPROVEMENT] {imp.attack_name}: {imp.description}")

        return "\n".join(lines)
