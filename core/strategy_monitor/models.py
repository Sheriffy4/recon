"""
Data models for strategy monitoring system.

Contains dataclasses representing reports, changes, and strategies used throughout
the monitoring system.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class AttackEffectivenessReport:
    """Report on individual attack effectiveness over time."""

    attack_name: str
    domain: str
    success_rate: float
    avg_latency_ms: float
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    trend: str = "stable"  # improving, degrading, stable
    confidence: float = 0.0
    category: str = "unknown"
    protocol: str = "tcp"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.last_success:
            result["last_success"] = self.last_success.isoformat()
        if self.last_failure:
            result["last_failure"] = self.last_failure.isoformat()
        return result


@dataclass
class EffectivenessReport:
    """Report on strategy effectiveness over time (legacy compatibility)."""

    strategy_id: str
    domain: str
    success_rate: float
    avg_latency_ms: float
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    trend: str = "stable"  # improving, degrading, stable
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.last_success:
            result["last_success"] = self.last_success.isoformat()
        if self.last_failure:
            result["last_failure"] = self.last_failure.isoformat()
        return result


@dataclass
class DPIChange:
    """Detected change in DPI behavior."""

    domain: str
    change_type: str  # behavior_change, new_blocking, technique_failure
    detected_at: datetime
    old_fingerprint_hash: Optional[str] = None
    new_fingerprint_hash: Optional[str] = None
    affected_techniques: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result["detected_at"] = self.detected_at.isoformat()
        return result


@dataclass
class Strategy:
    """Strategy definition compatible with existing format."""

    strategy_id: str
    strategy_string: str  # zapret-compatible strategy string
    technique_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    domains: List[str] = field(default_factory=list)
    fingerprint_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_tested: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result["created_at"] = self.created_at.isoformat()
        if self.last_tested:
            result["last_tested"] = self.last_tested.isoformat()
        return result
