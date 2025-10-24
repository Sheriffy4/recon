"""
Strategy configuration data models for PCAP analysis.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union
from enum import Enum


class StrategyType(Enum):
    """Strategy types for DPI bypass."""

    FAKE = "fake"
    FAKE_DISORDER = "fakeddisorder"
    SPLIT = "split"
    DISORDER = "disorder"
    MULTISPLIT = "multisplit"
    MULTIDISORDER = "multidisorder"


class FoolingMethod(Enum):
    """Fooling methods for fake packets."""

    BADSUM = "badsum"
    BADSEQ = "badseq"
    MD5SIG = "md5sig"
    HOPBYHOP = "hopbyhop"


@dataclass
class StrategyConfig:
    """Configuration for DPI bypass strategy."""

    # Strategy identification
    name: str = ""
    dpi_desync: str = ""  # e.g., "fake,fakeddisorder"

    # Position and overlap parameters
    split_pos: Optional[int] = None
    split_seqovl: Optional[int] = None

    # TTL parameters
    ttl: Optional[int] = None
    autottl: Optional[int] = None

    # Fooling methods
    fooling: List[str] = field(default_factory=list)

    # Fake packet parameters
    fake_tls: Optional[str] = None
    fake_http: Optional[str] = None
    fake_quic: Optional[str] = None

    # Execution parameters
    repeats: int = 1

    # Additional parameters
    disorder: bool = False
    reverse: bool = False

    # Metadata
    source: str = "unknown"  # "recon", "zapret", "manual"
    confidence: float = 1.0  # 0.0 to 1.0

    def __post_init__(self):
        """Post-initialization processing."""
        # Parse dpi_desync into strategy types
        if self.dpi_desync:
            self.strategy_types = [s.strip() for s in self.dpi_desync.split(",")]
        else:
            self.strategy_types = []

        # Validate fooling methods
        valid_fooling = []
        for method in self.fooling:
            try:
                FoolingMethod(method)
                valid_fooling.append(method)
            except ValueError:
                # Keep the method even if not in enum for flexibility
                valid_fooling.append(method)
        self.fooling = valid_fooling

    @classmethod
    def from_zapret_params(cls, params: Dict[str, Any]) -> "StrategyConfig":
        """Create StrategyConfig from zapret command line parameters."""
        config = cls(source="zapret")

        # Map zapret parameters to config
        if "dpi-desync" in params:
            config.dpi_desync = params["dpi-desync"]

        if "dpi-desync-split-pos" in params:
            config.split_pos = int(params["dpi-desync-split-pos"])

        if "dpi-desync-split-seqovl" in params:
            config.split_seqovl = int(params["dpi-desync-split-seqovl"])

        if "dpi-desync-ttl" in params:
            config.ttl = int(params["dpi-desync-ttl"])

        if "dpi-desync-autottl" in params:
            config.autottl = int(params["dpi-desync-autottl"])

        if "dpi-desync-fooling" in params:
            config.fooling = [
                f.strip() for f in params["dpi-desync-fooling"].split(",")
            ]

        if "dpi-desync-fake-tls" in params:
            config.fake_tls = params["dpi-desync-fake-tls"]

        if "dpi-desync-fake-http" in params:
            config.fake_http = params["dpi-desync-fake-http"]

        if "dpi-desync-fake-quic" in params:
            config.fake_quic = params["dpi-desync-fake-quic"]

        if "dpi-desync-repeats" in params:
            config.repeats = int(params["dpi-desync-repeats"])

        if "dpi-desync-disorder" in params:
            config.disorder = bool(params["dpi-desync-disorder"])

        if "dpi-desync-reverse" in params:
            config.reverse = bool(params["dpi-desync-reverse"])

        # Ensure post-init is called
        config.__post_init__()

        return config

    @classmethod
    def from_recon_config(cls, config_dict: Dict[str, Any]) -> "StrategyConfig":
        """Create StrategyConfig from recon configuration."""
        config = cls(source="recon")

        # Map recon config to StrategyConfig
        config.name = config_dict.get("name", "")
        config.dpi_desync = config_dict.get("strategy", "")
        config.split_pos = config_dict.get("split_pos")
        config.split_seqovl = config_dict.get("split_seqovl")
        config.ttl = config_dict.get("ttl")
        config.autottl = config_dict.get("autottl")
        config.fooling = config_dict.get("fooling", [])
        config.fake_tls = config_dict.get("fake_tls")
        config.fake_http = config_dict.get("fake_http")
        config.fake_quic = config_dict.get("fake_quic")
        config.repeats = config_dict.get("repeats", 1)
        config.disorder = config_dict.get("disorder", False)
        config.reverse = config_dict.get("reverse", False)

        # Ensure post-init is called
        config.__post_init__()

        return config

    def has_strategy(self, strategy_type: Union[str, StrategyType]) -> bool:
        """Check if config contains specific strategy type."""
        if isinstance(strategy_type, StrategyType):
            strategy_type = strategy_type.value

        # Ensure strategy_types is available
        if not hasattr(self, "strategy_types"):
            self.__post_init__()

        return strategy_type in self.strategy_types

    def has_fooling_method(self, method: Union[str, FoolingMethod]) -> bool:
        """Check if config contains specific fooling method."""
        if isinstance(method, FoolingMethod):
            method = method.value

        return method in self.fooling

    def is_fake_disorder_strategy(self) -> bool:
        """Check if this is a fake+disorder strategy."""
        return self.has_strategy("fake") and self.has_strategy("fakeddisorder")

    def get_effective_ttl(self) -> Optional[int]:
        """Get the effective TTL value."""
        return self.ttl or self.autottl

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "dpi_desync": self.dpi_desync,
            "split_pos": self.split_pos,
            "split_seqovl": self.split_seqovl,
            "ttl": self.ttl,
            "autottl": self.autottl,
            "fooling": self.fooling,
            "fake_tls": self.fake_tls,
            "fake_http": self.fake_http,
            "fake_quic": self.fake_quic,
            "repeats": self.repeats,
            "disorder": self.disorder,
            "reverse": self.reverse,
            "source": self.source,
            "confidence": self.confidence,
            "strategy_types": getattr(self, "strategy_types", []),
        }

    def __eq__(self, other) -> bool:
        """Compare two strategy configurations."""
        if not isinstance(other, StrategyConfig):
            return False

        # Compare key parameters
        return (
            self.dpi_desync == other.dpi_desync
            and self.split_pos == other.split_pos
            and self.split_seqovl == other.split_seqovl
            and self.ttl == other.ttl
            and self.autottl == other.autottl
            and self.fooling == other.fooling
            and self.fake_tls == other.fake_tls
            and self.fake_http == other.fake_http
            and self.fake_quic == other.fake_quic
            and self.repeats == other.repeats
            and self.disorder == other.disorder
            and self.reverse == other.reverse
        )


@dataclass
class StrategyDifference:
    """Represents a difference between two strategy configurations."""

    parameter: str
    recon_value: Any
    zapret_value: Any
    impact_level: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    description: str
    fix_suggestion: str = ""

    def __post_init__(self):
        """Post-initialization processing."""
        if not self.fix_suggestion:
            self.fix_suggestion = f"Change {self.parameter} from {self.recon_value} to {self.zapret_value}"


@dataclass
class StrategyComparison:
    """Result of comparing two strategy configurations."""

    recon_config: StrategyConfig
    zapret_config: StrategyConfig
    differences: List[StrategyDifference] = field(default_factory=list)
    similarity_score: float = 0.0
    is_compatible: bool = False

    def __post_init__(self):
        """Calculate similarity score and compatibility."""
        if not self.differences:
            self.similarity_score = 1.0
            self.is_compatible = True
        else:
            # Calculate similarity based on number and severity of differences
            critical_count = sum(
                1 for d in self.differences if d.impact_level == "CRITICAL"
            )
            high_count = sum(1 for d in self.differences if d.impact_level == "HIGH")
            medium_count = sum(
                1 for d in self.differences if d.impact_level == "MEDIUM"
            )
            low_count = sum(1 for d in self.differences if d.impact_level == "LOW")

            # Weight differences by severity
            penalty = (
                critical_count * 0.4
                + high_count * 0.3
                + medium_count * 0.2
                + low_count * 0.1
            )
            self.similarity_score = max(0.0, 1.0 - penalty)

            # Compatible if no critical differences
            self.is_compatible = critical_count == 0

    def get_critical_differences(self) -> List[StrategyDifference]:
        """Get only critical differences."""
        return [d for d in self.differences if d.impact_level == "CRITICAL"]

    def get_high_priority_differences(self) -> List[StrategyDifference]:
        """Get critical and high priority differences."""
        return [d for d in self.differences if d.impact_level in ["CRITICAL", "HIGH"]]
