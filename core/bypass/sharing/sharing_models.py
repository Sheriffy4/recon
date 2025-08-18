"""
Data models for strategy sharing and collaboration system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import hashlib
import json


class ShareLevel(Enum):
    """Strategy sharing access levels."""
    PRIVATE = "private"
    TRUSTED = "trusted"
    COMMUNITY = "community"
    PUBLIC = "public"


class ValidationStatus(Enum):
    """Strategy validation status."""
    PENDING = "pending"
    VALIDATED = "validated"
    REJECTED = "rejected"
    SUSPICIOUS = "suspicious"


class TrustLevel(Enum):
    """Source trust levels."""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


@dataclass
class SharedStrategy:
    """Represents a strategy shared in the community."""
    id: str
    name: str
    description: str
    strategy_data: Dict[str, Any]
    author: str
    version: str
    share_level: ShareLevel
    validation_status: ValidationStatus
    trust_score: float
    download_count: int = 0
    success_reports: int = 0
    failure_reports: int = 0
    tags: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    target_isps: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    signature: Optional[str] = None
    
    def calculate_signature(self, private_key: str) -> str:
        """Calculate cryptographic signature for strategy integrity."""
        data = {
            'name': self.name,
            'strategy_data': self.strategy_data,
            'version': self.version,
            'author': self.author
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(f"{content}{private_key}".encode()).hexdigest()
    
    def verify_signature(self, public_key: str) -> bool:
        """Verify strategy signature."""
        if not self.signature:
            return False
        expected = self.calculate_signature(public_key)
        return self.signature == expected
    
    def get_effectiveness_score(self) -> float:
        """Calculate effectiveness score based on community feedback."""
        total_reports = self.success_reports + self.failure_reports
        if total_reports == 0:
            return 0.0
        return self.success_reports / total_reports


@dataclass
class StrategyPackage:
    """Package containing multiple related strategies."""
    id: str
    name: str
    description: str
    strategies: List[SharedStrategy]
    author: str
    version: str
    dependencies: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class TrustedSource:
    """Represents a trusted source for strategy updates."""
    id: str
    name: str
    url: str
    public_key: str
    trust_level: TrustLevel
    auto_update: bool = False
    last_sync: Optional[datetime] = None
    sync_interval: int = 3600  # seconds
    enabled: bool = True
    
    def is_sync_due(self) -> bool:
        """Check if sync is due based on interval."""
        if not self.last_sync:
            return True
        elapsed = (datetime.now() - self.last_sync).total_seconds()
        return elapsed >= self.sync_interval


@dataclass
class ValidationResult:
    """Result of strategy validation."""
    strategy_id: str
    is_valid: bool
    trust_score: float
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    test_results: Dict[str, Any] = field(default_factory=dict)
    validated_at: datetime = field(default_factory=datetime.now)
    validator_id: str = ""


@dataclass
class SharingConfig:
    """Configuration for strategy sharing system."""
    enable_sharing: bool = True
    enable_auto_updates: bool = False
    default_share_level: ShareLevel = ShareLevel.PRIVATE
    min_trust_score: float = 0.7
    max_strategies_per_source: int = 1000
    validation_timeout: int = 300
    community_db_url: str = ""
    private_key: str = ""
    public_key: str = ""


@dataclass
class StrategyFeedback:
    """User feedback on strategy effectiveness."""
    strategy_id: str
    user_id: str
    success: bool
    region: str
    isp: str
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SyncResult:
    """Result of synchronization with trusted source."""
    source_id: str
    success: bool
    strategies_added: int = 0
    strategies_updated: int = 0
    strategies_removed: int = 0
    errors: List[str] = field(default_factory=list)
    sync_time: datetime = field(default_factory=datetime.now)