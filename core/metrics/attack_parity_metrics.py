"""
Attack Application Parity Metrics System

This module implements comprehensive metrics tracking for:
- Compliance scores from PCAP validation
- Attack detection rates
- Strategy application failures
- PCAP validation errors

Requirements: Task 23 - deployment strategy
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import threading

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMetric:
    """Metric for compliance score tracking."""

    domain: str
    timestamp: datetime
    score: int
    max_score: int
    percentage: float
    issues_count: int
    expected_attacks: List[str]
    detected_attacks: List[str]
    mode: str  # "testing" or "production"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class AttackDetectionMetric:
    """Metric for attack detection rate tracking."""

    attack_type: str
    timestamp: datetime
    total_attempts: int
    successful_detections: int
    failed_detections: int
    detection_rate: float
    average_confidence: float

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class StrategyApplicationMetric:
    """Metric for strategy application tracking."""

    domain: str
    timestamp: datetime
    strategy_id: str
    attacks: List[str]
    success: bool
    error_message: Optional[str]
    application_time_ms: float
    mode: str  # "testing" or "production"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class PCAPValidationMetric:
    """Metric for PCAP validation error tracking."""

    pcap_file: str
    timestamp: datetime
    validation_success: bool
    error_type: Optional[str]
    error_message: Optional[str]
    packets_analyzed: int
    streams_found: int
    clienthello_found: bool
    validation_time_ms: float

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class PCAPReassemblyMetric:
    """
    Metric for TCP/ClientHello reassembly quality tracking.

    Purpose:
    - Track how many exact retransmission duplicates were filtered during reassembly.
    - Helps diagnose noisy captures and prevents false positives in split/disorder detection.
    """

    pcap_file: str
    timestamp: datetime
    stream_key: str
    retransmission_duplicates_filtered: int
    payload_packets_before_dedup: int
    payload_packets_after_dedup: int

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


@dataclass
class MetricsSummary:
    """Summary of all metrics."""

    timestamp: datetime
    time_window_minutes: int

    # Compliance metrics
    total_compliance_checks: int = 0
    average_compliance_score: float = 0.0
    perfect_compliance_count: int = 0
    failed_compliance_count: int = 0

    # Attack detection metrics
    total_attack_detections: int = 0
    successful_detections: int = 0
    failed_detections: int = 0
    overall_detection_rate: float = 0.0
    detection_rates_by_attack: Dict[str, float] = field(default_factory=dict)

    # Strategy application metrics
    total_strategy_applications: int = 0
    successful_applications: int = 0
    failed_applications: int = 0
    application_success_rate: float = 0.0
    failures_by_error_type: Dict[str, int] = field(default_factory=dict)

    # PCAP validation metrics
    total_pcap_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    validation_success_rate: float = 0.0
    errors_by_type: Dict[str, int] = field(default_factory=dict)

    # Performance metrics
    average_validation_time_ms: float = 0.0
    average_application_time_ms: float = 0.0

    # Reassembly quality metrics
    total_pcap_reassemblies: int = 0
    total_retransmission_duplicates_filtered: int = 0
    average_retransmission_duplicates_filtered: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {**asdict(self), "timestamp": self.timestamp.isoformat()}


class AttackParityMetricsCollector:
    """
    Centralized metrics collector for attack application parity system.

    Tracks:
    - Compliance scores from PCAP validation
    - Attack detection rates
    - Strategy application failures
    - PCAP validation errors

    Thread-safe for concurrent metric recording.
    """

    def __init__(
        self, retention_hours: int = 24, auto_save: bool = True, save_path: Optional[str] = None
    ):
        """
        Initialize metrics collector.

        Args:
            retention_hours: How long to keep metrics in memory
            auto_save: Whether to auto-save metrics to disk
            save_path: Path to save metrics (default: metrics/attack_parity_metrics.json)
        """
        self.retention_hours = retention_hours
        self.auto_save = auto_save
        self.save_path = save_path or "metrics/attack_parity_metrics.json"

        # Metric storage
        self.compliance_metrics: List[ComplianceMetric] = []
        self.detection_metrics: List[AttackDetectionMetric] = []
        self.application_metrics: List[StrategyApplicationMetric] = []
        self.validation_metrics: List[PCAPValidationMetric] = []
        self.reassembly_metrics: List[PCAPReassemblyMetric] = []

        # Thread safety
        self._lock = threading.Lock()

        # Load existing metrics if available
        self._load_metrics()

        logger.info(f"AttackParityMetricsCollector initialized with {retention_hours}h retention")

    def record_compliance(
        self,
        domain: str,
        score: int,
        max_score: int,
        issues_count: int,
        expected_attacks: List[str],
        detected_attacks: List[str],
        mode: str = "production",
    ):
        """
        Record a compliance score metric.

        Args:
            domain: Domain being validated
            score: Compliance score achieved
            max_score: Maximum possible score
            issues_count: Number of compliance issues found
            expected_attacks: List of expected attack types
            detected_attacks: List of detected attack types
            mode: "testing" or "production"
        """
        percentage = (score / max_score * 100) if max_score > 0 else 0.0

        metric = ComplianceMetric(
            domain=domain,
            timestamp=datetime.now(),
            score=score,
            max_score=max_score,
            percentage=percentage,
            issues_count=issues_count,
            expected_attacks=expected_attacks,
            detected_attacks=detected_attacks,
            mode=mode,
        )

        with self._lock:
            self.compliance_metrics.append(metric)
            self._cleanup_old_metrics()
            if self.auto_save:
                self._save_metrics()

        logger.info(
            f"Recorded compliance metric: {domain} - {percentage:.1f}% ({score}/{max_score})"
        )

    def record_attack_detection(
        self,
        attack_type: str,
        total_attempts: int,
        successful_detections: int,
        failed_detections: int,
        average_confidence: float = 1.0,
    ):
        """
        Record attack detection rate metric.

        Args:
            attack_type: Type of attack (fake, split, disorder, etc.)
            total_attempts: Total detection attempts
            successful_detections: Number of successful detections
            failed_detections: Number of failed detections
            average_confidence: Average confidence score (0.0-1.0)
        """
        detection_rate = (
            (successful_detections / total_attempts * 100) if total_attempts > 0 else 0.0
        )

        metric = AttackDetectionMetric(
            attack_type=attack_type,
            timestamp=datetime.now(),
            total_attempts=total_attempts,
            successful_detections=successful_detections,
            failed_detections=failed_detections,
            detection_rate=detection_rate,
            average_confidence=average_confidence,
        )

        with self._lock:
            self.detection_metrics.append(metric)
            self._cleanup_old_metrics()
            if self.auto_save:
                self._save_metrics()

        logger.info(f"Recorded detection metric: {attack_type} - {detection_rate:.1f}% rate")

    def record_strategy_application(
        self,
        domain: str,
        strategy_id: str,
        attacks: List[str],
        success: bool,
        error_message: Optional[str],
        application_time_ms: float,
        mode: str = "production",
    ):
        """
        Record strategy application metric.

        Args:
            domain: Domain for which strategy was applied
            strategy_id: Identifier of the strategy
            attacks: List of attacks in the strategy
            success: Whether application succeeded
            error_message: Error message if failed
            application_time_ms: Time taken to apply strategy
            mode: "testing" or "production"
        """
        metric = StrategyApplicationMetric(
            domain=domain,
            timestamp=datetime.now(),
            strategy_id=strategy_id,
            attacks=attacks,
            success=success,
            error_message=error_message,
            application_time_ms=application_time_ms,
            mode=mode,
        )

        with self._lock:
            self.application_metrics.append(metric)
            self._cleanup_old_metrics()
            if self.auto_save:
                self._save_metrics()

        status = "SUCCESS" if success else "FAILED"
        logger.info(
            f"Recorded application metric: {domain} - {status} ({application_time_ms:.1f}ms)"
        )

    def record_pcap_validation(
        self,
        pcap_file: str,
        validation_success: bool,
        error_type: Optional[str],
        error_message: Optional[str],
        packets_analyzed: int,
        streams_found: int,
        clienthello_found: bool,
        validation_time_ms: float,
    ):
        """
        Record PCAP validation metric.

        Args:
            pcap_file: Path to PCAP file
            validation_success: Whether validation succeeded
            error_type: Type of error if failed
            error_message: Error message if failed
            packets_analyzed: Number of packets analyzed
            streams_found: Number of TCP streams found
            clienthello_found: Whether ClientHello was found
            validation_time_ms: Time taken for validation
        """
        metric = PCAPValidationMetric(
            pcap_file=pcap_file,
            timestamp=datetime.now(),
            validation_success=validation_success,
            error_type=error_type,
            error_message=error_message,
            packets_analyzed=packets_analyzed,
            streams_found=streams_found,
            clienthello_found=clienthello_found,
            validation_time_ms=validation_time_ms,
        )

        with self._lock:
            self.validation_metrics.append(metric)
            self._cleanup_old_metrics()
            if self.auto_save:
                self._save_metrics()

        status = "SUCCESS" if validation_success else "FAILED"
        logger.info(
            f"Recorded validation metric: {pcap_file} - {status} ({validation_time_ms:.1f}ms)"
        )

    def record_pcap_reassembly(
        self,
        pcap_file: str,
        stream_key: str,
        retransmission_duplicates_filtered: int,
        payload_packets_before_dedup: int,
        payload_packets_after_dedup: int,
    ) -> None:
        """
        Record TCP/ClientHello reassembly metric.

        This is intentionally separate from record_pcap_validation to keep that API stable.
        """
        metric = PCAPReassemblyMetric(
            pcap_file=pcap_file,
            timestamp=datetime.now(),
            stream_key=stream_key,
            retransmission_duplicates_filtered=int(retransmission_duplicates_filtered),
            payload_packets_before_dedup=int(payload_packets_before_dedup),
            payload_packets_after_dedup=int(payload_packets_after_dedup),
        )

        with self._lock:
            self.reassembly_metrics.append(metric)
            self._cleanup_old_metrics()
            if self.auto_save:
                self._save_metrics()

        logger.debug(
            "Recorded reassembly metric: %s stream=%s dup_filtered=%d (%d->%d)",
            pcap_file,
            stream_key,
            metric.retransmission_duplicates_filtered,
            metric.payload_packets_before_dedup,
            metric.payload_packets_after_dedup,
        )

    def get_summary(self, time_window_minutes: int = 60) -> MetricsSummary:
        """
        Get summary of metrics for specified time window.

        Args:
            time_window_minutes: Time window in minutes

        Returns:
            MetricsSummary with aggregated statistics
        """
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)

        with self._lock:
            # Filter metrics by time window
            recent_compliance = [m for m in self.compliance_metrics if m.timestamp >= cutoff_time]
            recent_detection = [m for m in self.detection_metrics if m.timestamp >= cutoff_time]
            recent_application = [m for m in self.application_metrics if m.timestamp >= cutoff_time]
            recent_validation = [m for m in self.validation_metrics if m.timestamp >= cutoff_time]
            recent_reassembly = [m for m in self.reassembly_metrics if m.timestamp >= cutoff_time]

            summary = MetricsSummary(
                timestamp=datetime.now(), time_window_minutes=time_window_minutes
            )

            # Compliance metrics
            if recent_compliance:
                summary.total_compliance_checks = len(recent_compliance)
                summary.average_compliance_score = sum(
                    m.percentage for m in recent_compliance
                ) / len(recent_compliance)
                summary.perfect_compliance_count = sum(
                    1 for m in recent_compliance if m.percentage == 100.0
                )
                summary.failed_compliance_count = sum(
                    1 for m in recent_compliance if m.percentage < 50.0
                )

            # Attack detection metrics
            if recent_detection:
                summary.total_attack_detections = sum(m.total_attempts for m in recent_detection)
                summary.successful_detections = sum(
                    m.successful_detections for m in recent_detection
                )
                summary.failed_detections = sum(m.failed_detections for m in recent_detection)
                if summary.total_attack_detections > 0:
                    summary.overall_detection_rate = (
                        summary.successful_detections / summary.total_attack_detections * 100
                    )

                # Per-attack detection rates
                attack_stats = defaultdict(lambda: {"total": 0, "success": 0})
                for m in recent_detection:
                    attack_stats[m.attack_type]["total"] += m.total_attempts
                    attack_stats[m.attack_type]["success"] += m.successful_detections

                summary.detection_rates_by_attack = {
                    attack: (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0.0
                    for attack, stats in attack_stats.items()
                }

            # Strategy application metrics
            if recent_application:
                summary.total_strategy_applications = len(recent_application)
                summary.successful_applications = sum(1 for m in recent_application if m.success)
                summary.failed_applications = sum(1 for m in recent_application if not m.success)
                if summary.total_strategy_applications > 0:
                    summary.application_success_rate = (
                        summary.successful_applications / summary.total_strategy_applications * 100
                    )

                # Failures by error type
                for m in recent_application:
                    if not m.success and m.error_message:
                        error_type = (
                            m.error_message.split(":")[0]
                            if ":" in m.error_message
                            else m.error_message
                        )
                        summary.failures_by_error_type[error_type] = (
                            summary.failures_by_error_type.get(error_type, 0) + 1
                        )

                # Average application time
                summary.average_application_time_ms = sum(
                    m.application_time_ms for m in recent_application
                ) / len(recent_application)

            # PCAP validation metrics
            if recent_validation:
                summary.total_pcap_validations = len(recent_validation)
                summary.successful_validations = sum(
                    1 for m in recent_validation if m.validation_success
                )
                summary.failed_validations = sum(
                    1 for m in recent_validation if not m.validation_success
                )
                if summary.total_pcap_validations > 0:
                    summary.validation_success_rate = (
                        summary.successful_validations / summary.total_pcap_validations * 100
                    )

                # Errors by type
                for m in recent_validation:
                    if not m.validation_success and m.error_type:
                        summary.errors_by_type[m.error_type] = (
                            summary.errors_by_type.get(m.error_type, 0) + 1
                        )

                # Average validation time
                summary.average_validation_time_ms = sum(
                    m.validation_time_ms for m in recent_validation
                ) / len(recent_validation)

            # PCAP reassembly metrics
            if recent_reassembly:
                summary.total_pcap_reassemblies = len(recent_reassembly)
                summary.total_retransmission_duplicates_filtered = sum(
                    m.retransmission_duplicates_filtered for m in recent_reassembly
                )
                summary.average_retransmission_duplicates_filtered = (
                    summary.total_retransmission_duplicates_filtered
                    / summary.total_pcap_reassemblies
                )

            return summary

    def get_compliance_history(
        self, domain: Optional[str] = None, limit: int = 100
    ) -> List[ComplianceMetric]:
        """Get compliance history, optionally filtered by domain."""
        with self._lock:
            metrics = self.compliance_metrics
            if domain:
                metrics = [m for m in metrics if m.domain == domain]
            return sorted(metrics, key=lambda m: m.timestamp, reverse=True)[:limit]

    def get_detection_history(
        self, attack_type: Optional[str] = None, limit: int = 100
    ) -> List[AttackDetectionMetric]:
        """Get detection history, optionally filtered by attack type."""
        with self._lock:
            metrics = self.detection_metrics
            if attack_type:
                metrics = [m for m in metrics if m.attack_type == attack_type]
            return sorted(metrics, key=lambda m: m.timestamp, reverse=True)[:limit]

    def get_application_history(
        self, domain: Optional[str] = None, limit: int = 100
    ) -> List[StrategyApplicationMetric]:
        """Get application history, optionally filtered by domain."""
        with self._lock:
            metrics = self.application_metrics
            if domain:
                metrics = [m for m in metrics if m.domain == domain]
            return sorted(metrics, key=lambda m: m.timestamp, reverse=True)[:limit]

    def get_validation_history(self, limit: int = 100) -> List[PCAPValidationMetric]:
        """Get validation history."""
        with self._lock:
            return sorted(self.validation_metrics, key=lambda m: m.timestamp, reverse=True)[:limit]

    def get_reassembly_history(self, limit: int = 100) -> List[PCAPReassemblyMetric]:
        """Get TCP/ClientHello reassembly history."""
        with self._lock:
            return sorted(self.reassembly_metrics, key=lambda m: m.timestamp, reverse=True)[:limit]

    def _cleanup_old_metrics(self):
        """Remove metrics older than retention period."""
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)

        self.compliance_metrics = [m for m in self.compliance_metrics if m.timestamp >= cutoff_time]
        self.detection_metrics = [m for m in self.detection_metrics if m.timestamp >= cutoff_time]
        self.application_metrics = [
            m for m in self.application_metrics if m.timestamp >= cutoff_time
        ]
        self.validation_metrics = [m for m in self.validation_metrics if m.timestamp >= cutoff_time]
        self.reassembly_metrics = [m for m in self.reassembly_metrics if m.timestamp >= cutoff_time]

    def _save_metrics(self):
        """Save metrics to disk."""
        try:
            save_path = Path(self.save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "compliance": [m.to_dict() for m in self.compliance_metrics],
                "detection": [m.to_dict() for m in self.detection_metrics],
                "application": [m.to_dict() for m in self.application_metrics],
                "validation": [m.to_dict() for m in self.validation_metrics],
                "reassembly": [m.to_dict() for m in self.reassembly_metrics],
                "metadata": {
                    "retention_hours": self.retention_hours,
                    "last_saved": datetime.now().isoformat(),
                },
            }

            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.debug(f"Saved metrics to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")

    def _load_metrics(self):
        """Load metrics from disk."""
        try:
            save_path = Path(self.save_path)
            if not save_path.exists():
                return

            with open(save_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Load compliance metrics
            for item in data.get("compliance", []):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
                self.compliance_metrics.append(ComplianceMetric(**item))

            # Load detection metrics
            for item in data.get("detection", []):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
                self.detection_metrics.append(AttackDetectionMetric(**item))

            # Load application metrics
            for item in data.get("application", []):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
                self.application_metrics.append(StrategyApplicationMetric(**item))

            # Load validation metrics
            for item in data.get("validation", []):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
                self.validation_metrics.append(PCAPValidationMetric(**item))

            # Load reassembly metrics (optional, backward-compatible)
            for item in data.get("reassembly", []):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
                self.reassembly_metrics.append(PCAPReassemblyMetric(**item))

            logger.info(
                f"Loaded {len(self.compliance_metrics)} compliance, "
                f"{len(self.detection_metrics)} detection, "
                f"{len(self.application_metrics)} application, "
                f"{len(self.validation_metrics)} validation, "
                f"{len(self.reassembly_metrics)} reassembly metrics"
            )
        except Exception as e:
            logger.warning(f"Failed to load metrics: {e}")

    def export_to_json(self, output_path: str):
        """Export all metrics to JSON file."""
        # Get data without holding lock during file I/O
        with self._lock:
            data = {
                "compliance": [m.to_dict() for m in self.compliance_metrics],
                "detection": [m.to_dict() for m in self.detection_metrics],
                "application": [m.to_dict() for m in self.application_metrics],
                "validation": [m.to_dict() for m in self.validation_metrics],
                "reassembly": [m.to_dict() for m in self.reassembly_metrics],
            }

        # Get summary without lock (it acquires its own lock)
        summary = self.get_summary(time_window_minutes=1440)
        data["summary"] = summary.to_dict()

        # Write to file
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported metrics to {output_path}")

    def clear_all_metrics(self):
        """Clear all metrics from memory."""
        with self._lock:
            self.compliance_metrics.clear()
            self.detection_metrics.clear()
            self.application_metrics.clear()
            self.validation_metrics.clear()
            self.reassembly_metrics.clear()
            logger.info("Cleared all metrics")


# Global metrics collector instance
_global_collector: Optional[AttackParityMetricsCollector] = None


def get_metrics_collector() -> AttackParityMetricsCollector:
    """Get or create global metrics collector instance."""
    global _global_collector
    if _global_collector is None:
        _global_collector = AttackParityMetricsCollector()
    return _global_collector


def set_metrics_collector(collector: AttackParityMetricsCollector):
    """Set global metrics collector instance."""
    global _global_collector
    _global_collector = collector
