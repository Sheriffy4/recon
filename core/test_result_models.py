"""
Test result models for the DPI bypass system.

This module provides data classes for representing test results, PCAP analysis,
validation results, and test sessions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class TestStatus(Enum):
    """Status of a test."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VerdictType(Enum):
    """Types of test verdicts."""

    SUCCESS = "success"
    FAILURE = "failure"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class TestSession:
    """Represents a test session for strategy validation."""

    session_id: str
    domain: str
    strategy_name: str
    pcap_file: str
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: TestStatus = TestStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "domain": self.domain,
            "strategy_name": self.strategy_name,
            "pcap_file": self.pcap_file,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "metadata": self.metadata,
        }


@dataclass
class TestVerdict:
    """Final verdict from a test session."""

    session_id: str
    verdict: VerdictType
    confidence: float = 0.0
    reasoning: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PCAPAnalysisResult:
    """Result of PCAP file analysis."""

    pcap_file: str
    packet_count: int = 0
    detected_attacks: List[str] = field(default_factory=list)
    executed_attacks_from_log: List[str] = field(default_factory=list)
    strategy_type: str = "unknown"
    combo_attacks: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    split_positions: List[int] = field(default_factory=list)
    fake_packets_detected: int = 0
    sni_values: List[str] = field(default_factory=list)
    analysis_time: float = 0.0
    analyzer_version: str = "1.0"
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    domain: str = ""
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pcap_file": self.pcap_file,
            "packet_count": self.packet_count,
            "detected_attacks": self.detected_attacks,
            "executed_attacks_from_log": self.executed_attacks_from_log,
            "strategy_type": self.strategy_type,
            "combo_attacks": self.combo_attacks,
            "parameters": self.parameters,
            "split_positions": self.split_positions,
            "fake_packets_detected": self.fake_packets_detected,
            "sni_values": self.sni_values,
            "analysis_time": self.analysis_time,
            "analyzer_version": self.analyzer_version,
            "errors": self.errors,
            "warnings": self.warnings,
            "domain": self.domain,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ValidationResult:
    """Result of validation operations."""

    test_name: str
    success: bool
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "success": self.success,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class SaveResult:
    """Result of save operations."""

    success: bool
    file_path: str = ""
    message: str = ""
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "file_path": self.file_path,
            "message": self.message,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }
