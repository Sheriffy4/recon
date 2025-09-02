# recon/core/fingerprint/advanced_models.py
"""
Advanced DPI Fingerprinting Models - Task 1 Implementation
Enhanced data models with 20+ detailed metrics, ML classification, and robust error handling.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import time
import json
import hashlib


class DPIType(Enum):
    """DPI system types for classification"""

    UNKNOWN = "unknown"
    ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
    ROSKOMNADZOR_DPI = "roskomnadzor_dpi"
    COMMERCIAL_DPI = "commercial_dpi"
    FIREWALL_BASED = "firewall_based"
    ISP_TRANSPARENT_PROXY = "isp_proxy"
    CLOUDFLARE_PROTECTION = "cloudflare"
    GOVERNMENT_CENSORSHIP = "government"


class ConfidenceLevel(Enum):
    """Confidence levels for DPI classification"""

    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.9


# Exception Hierarchy
class FingerprintingError(Exception):
    """Base exception for fingerprinting system"""

    pass


class NetworkAnalysisError(FingerprintingError):
    """Network analysis related errors"""

    pass


class MLClassificationError(FingerprintingError):
    """ML classification related errors"""

    pass


class CacheError(FingerprintingError):
    """Cache system related errors"""

    pass


class MetricsCollectionError(FingerprintingError):
    """Metrics collection related errors"""

    pass


@dataclass
class DPIFingerprint:
    """
    Advanced DPI fingerprint with 20+ detailed metrics and ML classification.
    Implements requirements 1.1, 2.1, 7.1 from the specification.
    """

    # Basic Information
    target: str
    timestamp: float = field(default_factory=time.time)
    analysis_duration: float = 0.0

    # ML Classification Results
    dpi_type: DPIType = DPIType.UNKNOWN
    confidence: float = 0.0
    alternative_types: List[Tuple[DPIType, float]] = field(default_factory=list)

    # Coherent Fingerprint Features
    cipher_suites_order: Optional[List[int]] = None
    extensions_order: Optional[List[int]] = None
    supported_groups: Optional[List[int]] = None
    signature_algorithms: Optional[List[int]] = None
    ec_point_formats: Optional[List[int]] = None
    alpn_protocols: Optional[List[str]] = None
    tcp_window_size: Optional[int] = None
    tcp_mss: Optional[int] = None
    tcp_sack_permitted: bool = False
    tcp_timestamps_enabled: bool = False
    syn_ack_to_client_hello_delta: Optional[float] = None

    # TCP Behavior Metrics (11 metrics)
    rst_injection_detected: bool = False
    rst_ttl: Optional[int] = None  # TTL of detected RST packet
    rst_source_analysis: str = "unknown"  # 'server', 'middlebox', 'unknown'
    tcp_window_manipulation: bool = False
    sequence_number_anomalies: bool = False
    tcp_options_filtering: bool = False
    connection_reset_timing: float = 0.0
    handshake_anomalies: List[str] = field(default_factory=list)
    fragmentation_handling: str = "unknown"  # 'allowed', 'blocked', 'modified'
    mss_clamping_detected: bool = False
    tcp_timestamp_manipulation: bool = False

    # HTTP Behavior Metrics (10 metrics)
    http_header_filtering: bool = False
    content_inspection_depth: int = 0
    user_agent_filtering: bool = False
    host_header_manipulation: bool = False
    http_method_restrictions: List[str] = field(default_factory=list)
    content_type_filtering: bool = False
    redirect_injection: bool = False
    http_response_modification: bool = False
    keep_alive_manipulation: bool = False
    chunked_encoding_handling: str = "unknown"  # 'supported', 'blocked', 'modified'

    # DNS Behavior Metrics (10 metrics)
    dns_hijacking_detected: bool = False
    dns_response_modification: bool = False
    dns_query_filtering: bool = False
    doh_blocking: bool = False
    dot_blocking: bool = False
    dns_cache_poisoning: bool = False
    dns_timeout_manipulation: bool = False
    recursive_resolver_blocking: bool = False
    dns_over_tcp_blocking: bool = False
    edns_support: bool = False

    # Additional Advanced Metrics (6+ metrics)
    supports_ipv6: bool = False
    ip_fragmentation_handling: str = "unknown"  # 'allowed', 'blocked', 'reassembled'
    packet_size_limitations: Optional[int] = None
    protocol_whitelist: List[str] = field(default_factory=list)
    geographic_restrictions: bool = False
    time_based_filtering: bool = False

    # Metadata and Analysis Context
    raw_metrics: Dict[str, Any] = field(default_factory=dict)
    analysis_methods_used: List[str] = field(default_factory=list)
    reliability_score: float = 0.0

    # >>>>> НОВЫЙ КОД: Поле для хранения типа блокировки <<<<<
    block_type: str = (
        "unknown"  # 'rst', 'timeout', 'ssl_block', 'dns_hijack', 'content_block', 'none'
    )
    # >>>>> КОНЕЦ НОВОГО КОДА <<<<<

    # Behavioral Vulnerabilities
    vulnerable_to_fragmentation: bool = False
    vulnerable_to_sni_case: bool = False
    vulnerable_to_bad_checksum_race: bool = False
    is_stateful: bool = False

    def short_hash(self) -> str:
        """
        Generates a short, unique hash based on key, quickly determined
        characteristics of the DPI fingerprint.
        """
        # >>>>> ЭКСПЕРТНОЕ ИСПРАВЛЕНИЕ: Используем новые быстрые метрики для хэша <<<<<
        key_features = (
            ("bt", self.block_type),
            ("rst", self.rst_injection_detected),
            ("ttl", self.rst_ttl),
            ("tcp_opts", self.tcp_options_filtering),
        )
        # Create a stable string representation
        feature_string = ";".join(f"{k}:{v}" for k, v in key_features)

        return hashlib.sha1(feature_string.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Convert fingerprint to dictionary for serialization"""
        result = {}

        for field_name, field_value in self.__dict__.items():
            if isinstance(field_value, Enum):
                result[field_name] = field_value.value
            elif (
                isinstance(field_value, list)
                and field_value
                and isinstance(field_value[0], tuple)
            ):
                # Handle alternative_types list of tuples with enums
                result[field_name] = [
                    (item[0].value if isinstance(item[0], Enum) else item[0], item[1])
                    for item in field_value
                ]
            else:
                result[field_name] = field_value

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DPIFingerprint":
        """Create fingerprint from dictionary"""
        # Convert enum values back to enums
        if "dpi_type" in data and isinstance(data["dpi_type"], str):
            data["dpi_type"] = DPIType(data["dpi_type"])

        if "alternative_types" in data:
            data["alternative_types"] = [
                (DPIType(item[0]) if isinstance(item[0], str) else item[0], item[1])
                for item in data["alternative_types"]
            ]

        return cls(**data)

    def get_recommended_strategies(self) -> List[str]:
        """Get recommended bypass strategies based on DPI type and characteristics"""
        strategies = []

        # Base strategies by DPI type
        type_strategies = {
            DPIType.ROSKOMNADZOR_TSPU: [
                "tcp_fragmentation",
                "http_host_header_case",
                "tls_sni_fragmentation",
            ],
            DPIType.ROSKOMNADZOR_DPI: [
                "tcp_window_scaling",
                "http_method_override",
                "dns_over_https",
            ],
            DPIType.COMMERCIAL_DPI: [
                "tcp_options_manipulation",
                "http_chunked_encoding",
                "tls_version_downgrade",
            ],
            DPIType.FIREWALL_BASED: [
                "port_hopping",
                "protocol_tunneling",
                "packet_timing_manipulation",
            ],
            DPIType.ISP_TRANSPARENT_PROXY: [
                "http_proxy_bypass",
                "https_upgrade",
                "alternative_dns",
            ],
            DPIType.CLOUDFLARE_PROTECTION: [
                "user_agent_rotation",
                "request_header_randomization",
                "connection_pooling",
            ],
            DPIType.GOVERNMENT_CENSORSHIP: [
                "domain_fronting",
                "encrypted_sni",
                "traffic_obfuscation",
            ],
        }

        strategies.extend(type_strategies.get(self.dpi_type, []))

        # Add strategies based on specific characteristics
        if not self.supports_ipv6:
            strategies.append("ipv6_tunneling")

        if self.dns_hijacking_detected:
            strategies.extend(
                ["dns_over_tls", "dns_over_https", "alternative_dns_servers"]
            )

        if self.http_header_filtering:
            strategies.extend(
                ["header_case_manipulation", "header_order_randomization"]
            )

        if self.rst_injection_detected:
            strategies.extend(["tcp_sequence_manipulation", "connection_multiplexing"])

        if self.fragmentation_handling == "blocked":
            strategies.append("large_packet_avoidance")
        elif self.fragmentation_handling == "allowed":
            strategies.append("aggressive_fragmentation")

        return list(set(strategies))  # Remove duplicates

    def get_confidence_level(self) -> ConfidenceLevel:
        """Get confidence level enum based on confidence score"""
        if self.confidence >= ConfidenceLevel.VERY_HIGH.value:
            return ConfidenceLevel.VERY_HIGH
        elif self.confidence >= ConfidenceLevel.HIGH.value:
            return ConfidenceLevel.HIGH
        elif self.confidence >= ConfidenceLevel.MEDIUM.value:
            return ConfidenceLevel.MEDIUM
        elif self.confidence >= ConfidenceLevel.LOW.value:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def calculate_evasion_difficulty(self) -> float:
        """Calculate difficulty score for evading this DPI (0.0 = easy, 1.0 = very hard)"""
        difficulty_factors = []

        # TCP-based difficulty factors
        if self.rst_injection_detected:
            difficulty_factors.append(0.15)
        if self.tcp_window_manipulation:
            difficulty_factors.append(0.10)
        if self.sequence_number_anomalies:
            difficulty_factors.append(0.12)
        if self.tcp_options_filtering:
            difficulty_factors.append(0.08)

        # HTTP-based difficulty factors
        if self.http_header_filtering:
            difficulty_factors.append(0.10)
        if self.content_inspection_depth > 1000:
            difficulty_factors.append(0.15)
        if self.user_agent_filtering:
            difficulty_factors.append(0.05)
        if self.http_response_modification:
            difficulty_factors.append(0.12)

        # DNS-based difficulty factors
        if self.dns_hijacking_detected:
            difficulty_factors.append(0.10)
        if self.doh_blocking and self.dot_blocking:
            difficulty_factors.append(0.15)
        if self.dns_cache_poisoning:
            difficulty_factors.append(0.08)

        # Advanced factors
        if self.geographic_restrictions:
            difficulty_factors.append(0.10)
        if self.time_based_filtering:
            difficulty_factors.append(0.05)
        if self.packet_size_limitations and self.packet_size_limitations < 1000:
            difficulty_factors.append(0.08)

        return min(sum(difficulty_factors), 1.0)

    def get_summary(self) -> str:
        """Get human-readable summary of the fingerprint"""
        confidence_level = self.get_confidence_level()
        difficulty = self.calculate_evasion_difficulty()

        return (
            f"{self.dpi_type.value.replace('_', ' ').title()} "
            f"(Confidence: {confidence_level.name}, "
            f"Difficulty: {difficulty:.1f}/1.0)"
        )

    def merge_with(self, other: "DPIFingerprint") -> "DPIFingerprint":
        """Merge this fingerprint with another, keeping the most reliable data"""
        if other.confidence > self.confidence:
            # Use the more confident classification
            self.dpi_type = other.dpi_type
            self.confidence = other.confidence
            self.alternative_types = other.alternative_types

        # Merge boolean flags (OR operation for detected features)
        bool_fields = [
            "rst_injection_detected",
            "tcp_window_manipulation",
            "sequence_number_anomalies",
            "tcp_options_filtering",
            "mss_clamping_detected",
            "tcp_timestamp_manipulation",
            "http_header_filtering",
            "user_agent_filtering",
            "host_header_manipulation",
            "content_type_filtering",
            "redirect_injection",
            "http_response_modification",
            "keep_alive_manipulation",
            "dns_hijacking_detected",
            "dns_response_modification",
            "dns_query_filtering",
            "doh_blocking",
            "dot_blocking",
            "dns_cache_poisoning",
            "dns_timeout_manipulation",
            "recursive_resolver_blocking",
            "dns_over_tcp_blocking",
            "edns_support",
            "supports_ipv6",
            "geographic_restrictions",
            "time_based_filtering",
        ]

        for field in bool_fields:
            if hasattr(other, field):
                setattr(self, field, getattr(self, field) or getattr(other, field))

        # Merge numeric fields (take maximum for inspection depth, minimum for timing)
        if other.content_inspection_depth > self.content_inspection_depth:
            self.content_inspection_depth = other.content_inspection_depth

        if other.connection_reset_timing > 0 and (
            self.connection_reset_timing == 0
            or other.connection_reset_timing < self.connection_reset_timing
        ):
            self.connection_reset_timing = other.connection_reset_timing

        # Merge lists (union)
        self.handshake_anomalies = list(
            set(self.handshake_anomalies + other.handshake_anomalies)
        )
        self.http_method_restrictions = list(
            set(self.http_method_restrictions + other.http_method_restrictions)
        )
        self.protocol_whitelist = list(
            set(self.protocol_whitelist + other.protocol_whitelist)
        )
        self.analysis_methods_used = list(
            set(self.analysis_methods_used + other.analysis_methods_used)
        )

        # Update reliability score (weighted average)
        total_weight = self.reliability_score + other.reliability_score
        if total_weight > 0:
            self.reliability_score = (
                self.reliability_score * self.reliability_score
                + other.reliability_score * other.reliability_score
            ) / total_weight

        # Merge raw metrics
        self.raw_metrics.update(other.raw_metrics)

        # Update timestamp to most recent
        if other.timestamp > self.timestamp:
            self.timestamp = other.timestamp

        return self

    def to_json(self) -> str:
        """Serialize fingerprint to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "DPIFingerprint":
        """Deserialize fingerprint from JSON string"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> List[str]:
        """Validate fingerprint data and return list of validation errors"""
        errors = []

        if not self.target:
            errors.append("Target cannot be empty")

        if self.confidence < 0.0 or self.confidence > 1.0:
            errors.append("Confidence must be between 0.0 and 1.0")

        if self.reliability_score < 0.0 or self.reliability_score > 1.0:
            errors.append("Reliability score must be between 0.0 and 1.0")

        if self.content_inspection_depth < 0:
            errors.append("Content inspection depth cannot be negative")

        if self.connection_reset_timing < 0:
            errors.append("Connection reset timing cannot be negative")

        if (
            self.packet_size_limitations is not None
            and self.packet_size_limitations <= 0
        ):
            errors.append("Packet size limitations must be positive")

        # Validate enum values in alternative_types
        for alt_type, alt_confidence in self.alternative_types:
            if not isinstance(alt_type, DPIType):
                errors.append(f"Invalid DPI type in alternatives: {alt_type}")
            if alt_confidence < 0.0 or alt_confidence > 1.0:
                errors.append(f"Invalid confidence in alternatives: {alt_confidence}")

        return errors
