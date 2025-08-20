# recon/core/fingerprint/models.py
"""
Ultimate data models combining all expert ideas with enhanced capabilities
"""
import hashlib
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Tuple, Any, Optional, Set
from enum import Enum


class DPIFamily(Enum):
    """DPI system families for classification"""

    INLINE_FAST = "Inline_Fast"
    MIDDLEBOX_HEAVY = "Middlebox_Heavy"
    CLOUD_BASED = "Cloud_Based"
    ENTERPRISE = "Enterprise"
    NATIONAL = "National"
    OPEN_SOURCE = "Open_Source"
    NGFW = "Next_Gen_Firewall"
    CDN_EDGE = "CDN_Edge"
    CLOUD_SECURITY = "Cloud_Security"
    UNKNOWN = "Unknown"


@dataclass
class ProbeResult:
    """Detailed result from a single probe test"""

    name: str
    value: Any
    timestamp: datetime = field(default_factory=datetime.now)
    latency_ms: float = 0.0
    confidence: float = 1.0
    raw_response: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        if self.raw_response:
            data["raw_response"] = self.raw_response.hex()
        return data


# FIX: Added the missing DPIClassification dataclass here, where it belongs.
@dataclass
class DPIClassification:
    """Result of a DPI classification process."""

    dpi_type: str
    vendor: str
    family: str
    confidence: float
    classification_method: str
    classification_reasons: List[str] = field(default_factory=list)
    alternative_classifications: List[Tuple[str, float]] = field(default_factory=list)
    recommended_techniques: List[str] = field(default_factory=list)
    ml_features: Optional[Dict[str, float]] = None


@dataclass
class Fingerprint:
    """Ultimate DPI fingerprint with all possible metrics"""

    # === Basic Identification ===
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    fingerprint_version: str = "3.0"

    # === Passive Analysis Results ===
    rst_ttl: Optional[int] = None
    rst_from_target: bool = False
    icmp_ttl_exceeded: bool = False
    tcp_options: Tuple[str, ...] = ()
    rst_latency_ms: Optional[float] = None
    rst_distance: Optional[int] = None
    timestamp_in_rst: Optional[bool] = None
    window_size_in_rst: Optional[int] = None

    # === Core Probing Results (All Experts) ===
    # From Expert 2 & 3
    supports_ip_frag: Optional[bool] = None
    checksum_validation: Optional[bool] = None
    tcp_option_len_limit: Optional[int] = None
    quic_udp_blocked: Optional[bool] = None
    sni_case_sensitive: Optional[bool] = None
    ech_grease_blocked: Optional[bool] = None
    stateful_inspection: Optional[bool] = None
    rate_limiting_detected: Optional[bool] = None
    ml_detection_blocked: Optional[bool] = None
    ip_level_blocked: Optional[bool] = None
    ech_blocked: Optional[bool] = None
    dpi_hop_distance: Optional[int] = None
    tcp_option_splicing: Optional[bool] = None
    large_payload_bypass: Optional[bool] = None
    ecn_support: Optional[bool] = None
    mptcp_support: Optional[bool] = None

    # From Expert 1
    quic_version_negotiation: Optional[bool] = None
    http3_support: Optional[bool] = None
    dns_over_https_blocked: Optional[bool] = None
    dns_over_tls_blocked: Optional[bool] = None  # Added for completeness
    ipv6_handling: Optional[str] = None  # 'blocked', 'allowed', 'throttled'
    payload_entropy_sensitivity: Optional[float] = None

    # From Expert 3
    http2_detection: Optional[bool] = None
    zero_rtt_blocked: Optional[bool] = None
    tls_version_sensitivity: Optional[str] = None

    # === Additional Advanced Metrics ===
    tcp_fast_open_support: Optional[bool] = None
    tcp_keepalive_handling: Optional[str] = None  # 'strip', 'forward', 'reset'
    esni_support: Optional[bool] = None
    tls13_downgrade: Optional[bool] = None
    tcp_timestamps_modified: Optional[bool] = None
    ipv6_extension_headers: Dict[str, bool] = field(default_factory=dict)
    congestion_control_algo: Optional[str] = None
    websocket_blocked: Optional[bool] = None
    grpc_blocked: Optional[bool] = None
    ssh_blocked: Optional[bool] = None
    vpn_detection: Dict[str, bool] = field(
        default_factory=dict
    )  # openvpn, wireguard, ipsec
    certificate_validation: Optional[bool] = None  # Added for completeness

    # === Classification Results ===
    dpi_type: Optional[str] = None
    dpi_family: Optional[DPIFamily] = None
    dpi_vendor: Optional[str] = None
    dpi_version: Optional[str] = None
    confidence: float = 0.0
    classification_method: str = "signature"  # signature, ml, hybrid
    classification_reasons: List[str] = field(default_factory=list)
    alternative_classifications: List[Tuple[str, float]] = field(default_factory=list)

    # === ML Features ===
    ml_features: Dict[str, float] = field(default_factory=dict)
    anomaly_score: float = 0.0
    cluster_id: Optional[int] = None
    ml_confidence: float = 0.0

    # === Session Tracking ===
    session_history: Dict[str, int] = field(default_factory=dict)
    probe_results: List[ProbeResult] = field(default_factory=list)

    def update_from_result(self, result_status: str):
        """Update fingerprint based on attack result"""
        self.session_history[result_status] = (
            self.session_history.get(result_status, 0) + 1
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        if self.dpi_family:
            data["dpi_family"] = self.dpi_family.value
        data["probe_results"] = [pr.to_dict() for pr in self.probe_results]
        return data

    def calculate_evasion_difficulty(self) -> float:
        """Calculate how difficult this DPI is to evade (0-1)"""
        difficulty_factors = [
            (self.stateful_inspection, 0.15),
            (self.checksum_validation, 0.10),
            (self.rate_limiting_detected, 0.15),
            (self.ml_detection_blocked, 0.20),
            (not self.supports_ip_frag, 0.10),
            (self.tcp_option_splicing, 0.10),
            (not self.large_payload_bypass, 0.10),
            (self.zero_rtt_blocked, 0.05),
            (self.websocket_blocked, 0.05),
        ]

        difficulty = sum(weight for enabled, weight in difficulty_factors if enabled)
        return min(difficulty, 1.0)

    def get_summary(self) -> str:
        # Handle both string and enum values for dpi_family
        if isinstance(self.dpi_family, str):
            family_str = self.dpi_family
        elif self.dpi_family:
            family_str = self.dpi_family.value
        else:
            family_str = "Unknown"

        return f"{self.dpi_type or 'Unknown'} ({family_str}) [{self.confidence:.0%}]"

    def short_hash(self) -> str:
        """Generate unique hash for this fingerprint"""
        key_fields = [
            self.dpi_type,
            self.dpi_vendor,
            str(self.rst_ttl),
            str(self.supports_ip_frag),
            str(self.checksum_validation),
            str(self.stateful_inspection),
            str(self.ml_detection_blocked),
        ]
        hash_str = "|".join([str(f) for f in key_fields if f is not None])
        return hashlib.sha256(hash_str.encode()).hexdigest()[:16]


@dataclass
class EnhancedFingerprint(Fingerprint):
    """Extended fingerprint with comprehensive analysis data"""

    # === Temporal Metrics ===
    connection_latency: float = 0.0
    connection_jitter: float = 0.0
    packet_loss_rate: float = 0.0
    timeout_behavior: str = "unknown"

    # === Behavioral Patterns ===
    technique_success_rates: Dict[str, float] = field(default_factory=dict)
    optimal_parameters: Dict[str, Any] = field(default_factory=dict)
    packet_processing_stats: Dict[str, int] = field(default_factory=dict)

    # === Deep Analysis Results ===
    payload_analysis: Dict[str, Any] = field(default_factory=dict)
    header_manipulation_sensitivity: Dict[str, bool] = field(default_factory=dict)
    timing_sensitivity: Dict[str, float] = field(default_factory=dict)

    # === Protocol Analysis ===
    protocol_behaviors: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    supported_cipher_suites: List[str] = field(default_factory=list)
    tls_fingerprint: Optional[str] = None
    http_fingerprint: Optional[str] = None

    # === Historical Data ===
    technique_history: Dict[str, List[Tuple[datetime, bool]]] = field(
        default_factory=dict
    )
    performance_metrics: Dict[str, List[float]] = field(default_factory=dict)

    # === Network Topology ===
    network_path: List[str] = field(default_factory=list)
    asn_info: Dict[str, Any] = field(default_factory=dict)
    geo_location: Dict[str, Any] = field(default_factory=dict)

    # === ML Predictions ===
    predicted_weaknesses: List[str] = field(default_factory=list)
    recommended_attacks: List[Tuple[str, float]] = field(default_factory=list)

    # === NEW: Extended DPI Analysis Features (Requirements 6.1, 6.2) ===
    # RST TTL distance analysis
    rst_ttl_distance: Optional[int] = (
        None  # Difference between response TTL and RST TTL
    )
    baseline_block_type: Optional[str] = (
        None  # 'RST', 'TIMEOUT', 'CONTENT', 'CONNECTION_REFUSED'
    )

    # SNI consistency analysis
    sni_consistency_blocked: Optional[bool] = (
        None  # Whether SNI consistency checks block traffic
    )

    # Response timing patterns for behavioral analysis
    response_timing_patterns: Dict[str, List[float]] = field(
        default_factory=dict
    )  # Pattern name -> timing measurements

    # Content filtering indicators
    content_filtering_indicators: Dict[str, bool] = field(
        default_factory=dict
    )  # Filter type -> detected

    # === NEW: Modern Protocol Support Features ===
    # HTTP/2 specific features
    http2_support: Optional[bool] = None  # Whether HTTP/2 is supported
    http2_frame_analysis: Dict[str, Any] = field(
        default_factory=dict
    )  # Frame-level analysis results
    http2_hpack_sensitivity: Optional[bool] = (
        None  # Sensitivity to HPACK header compression
    )

    # QUIC/HTTP3 specific features
    quic_support: Optional[bool] = None  # Whether QUIC is supported
    quic_version_support: List[str] = field(
        default_factory=list
    )  # Supported QUIC versions
    quic_connection_id_handling: Optional[str] = None  # How Connection IDs are handled
    quic_packet_coalescing_support: Optional[bool] = (
        None  # Support for packet coalescing
    )

    # TLS 1.3 ECH (Encrypted Client Hello) features
    ech_support: Optional[bool] = None  # Whether ECH is supported
    ech_grease_handling: Optional[str] = None  # How GREASE values are handled
    ech_fragmentation_sensitivity: Optional[bool] = (
        None  # Sensitivity to ECH fragmentation
    )

    # === NEW: Advanced Behavioral Indicators ===
    # Primary blocking method classification
    primary_block_method: Optional[str] = None  # 'rst', 'timeout', 'content', 'mixed'

    # Connection timeout patterns
    connection_timeout_ms: Optional[int] = None  # Typical connection timeout

    # Timing attack sensitivity
    timing_attack_vulnerable: Optional[bool] = (
        None  # Vulnerable to timing-based attacks
    )

    reassembly_buffer_size: Optional[int] = None
    reassembly_timeout_ms: Optional[int] = None
    protocol_parser_strictness: Dict[str, str] = field(
        default_factory=dict
    )  # {'tls': 'strict', 'http': 'loose'}
    cache_poisoning_vulnerability: Optional[str] = None  # 'ttl', 'checksum', 'none'
    flow_correlation_sensitivity: Optional[float] = None  # 0.0-1.0

    def merge_with(self, other: "EnhancedFingerprint") -> "EnhancedFingerprint":
        """Merge with another fingerprint, keeping the most recent/confident data"""
        if other.confidence > self.confidence:
            # Use other's classification
            self.dpi_type = other.dpi_type
            self.dpi_vendor = other.dpi_vendor
            self.dpi_family = other.dpi_family
            self.confidence = other.confidence
            self.classification_reasons = other.classification_reasons

        # Merge success rates (weighted average)
        for technique, rate in other.technique_success_rates.items():
            if technique in self.technique_success_rates:
                self.technique_success_rates[technique] = (
                    self.technique_success_rates[technique] * 0.7 + rate * 0.3
                )
            else:
                self.technique_success_rates[technique] = rate

        # Merge new extended features
        if other.rst_ttl_distance is not None:
            self.rst_ttl_distance = other.rst_ttl_distance
        if other.baseline_block_type is not None:
            self.baseline_block_type = other.baseline_block_type
        if other.sni_consistency_blocked is not None:
            self.sni_consistency_blocked = other.sni_consistency_blocked
        if other.primary_block_method is not None:
            self.primary_block_method = other.primary_block_method

        # Merge timing patterns
        for pattern_name, timings in other.response_timing_patterns.items():
            if pattern_name in self.response_timing_patterns:
                self.response_timing_patterns[pattern_name].extend(timings)
            else:
                self.response_timing_patterns[pattern_name] = timings.copy()

        # Merge protocol support indicators
        if other.http2_support is not None:
            self.http2_support = other.http2_support
        if other.quic_support is not None:
            self.quic_support = other.quic_support
        if other.ech_support is not None:
            self.ech_support = other.ech_support

        # Update timestamps
        if other.timestamp > self.timestamp:
            self.timestamp = other.timestamp

        return self

    def short_hash(self) -> str:
        """Generate unique hash for this enhanced fingerprint including new features"""
        key_fields = [
            self.dpi_type,
            self.dpi_vendor,
            str(self.rst_ttl),
            str(self.supports_ip_frag),
            str(self.checksum_validation),
            str(self.stateful_inspection),
            str(self.ml_detection_blocked),
            # Include new extended features in hash
            str(self.rst_ttl_distance),
            self.baseline_block_type,
            str(self.sni_consistency_blocked),
            self.primary_block_method,
            str(self.http2_support),
            str(self.quic_support),
            str(self.ech_support),
        ]
        hash_str = "|".join([str(f) for f in key_fields if f is not None])
        return hashlib.sha256(hash_str.encode()).hexdigest()[:16]


@dataclass
class DPIBehaviorProfile:
    """Ultimate behavioral profile combining all expert insights with enhanced behavioral analysis"""

    dpi_system_id: str
    creation_time: datetime = field(default_factory=datetime.now)

    # === Detection Patterns ===
    detection_patterns: Dict[str, Any] = field(default_factory=dict)
    signature_based_detection: bool = False
    behavioral_analysis: bool = False
    ml_detection: bool = False
    statistical_analysis: bool = False

    # === Evasion Analysis ===
    evasion_effectiveness: Dict[str, float] = field(default_factory=dict)
    technique_rankings: List[Tuple[str, float]] = field(default_factory=list)

    # === Temporal Patterns ===
    temporal_patterns: Dict[str, List[float]] = field(default_factory=dict)
    peak_hours: List[int] = field(default_factory=list)
    maintenance_windows: List[Tuple[int, int]] = field(default_factory=list)

    # === Traffic Analysis ===
    packet_size_sensitivity: Dict[int, float] = field(default_factory=dict)
    protocol_handling: Dict[str, str] = field(default_factory=dict)
    traffic_shaping_detected: bool = False
    qos_manipulation: Dict[str, Any] = field(default_factory=dict)

    # === Advanced Behavioral Metrics ===
    connection_state_tracking: Dict[str, bool] = field(default_factory=dict)
    application_layer_inspection: Dict[str, float] = field(default_factory=dict)
    ssl_interception_indicators: List[str] = field(default_factory=list)
    anomaly_detection_triggers: List[str] = field(default_factory=list)

    # === NEW: Enhanced Behavioral Analysis (Requirements 6.1, 6.2) ===
    # Core DPI capabilities
    supports_ip_frag: Optional[bool] = None  # IP fragmentation support
    checksum_validation: Optional[bool] = None  # Checksum validation strictness
    rst_latency_ms: Optional[float] = None  # Average RST response latency
    ech_support: Optional[bool] = None  # ECH (Encrypted Client Hello) support

    # Timing sensitivity analysis
    timing_sensitivity_profile: Dict[str, float] = field(
        default_factory=dict
    )  # Delay type -> sensitivity score
    connection_timeout_patterns: Dict[str, int] = field(
        default_factory=dict
    )  # Protocol -> timeout ms
    burst_tolerance: Optional[float] = None  # Tolerance to traffic bursts (0-1)

    # Protocol-specific behavioral patterns
    tcp_state_tracking_depth: Optional[int] = None  # How deep TCP state tracking goes
    tls_inspection_level: Optional[str] = None  # 'none', 'basic', 'deep', 'full'
    http_parsing_strictness: Optional[str] = None  # 'loose', 'standard', 'strict'

    # Advanced DPI behavioral indicators
    stateful_connection_limit: Optional[int] = None  # Max tracked connections
    packet_reordering_tolerance: Optional[bool] = None  # Handles out-of-order packets
    fragmentation_reassembly_timeout: Optional[int] = (
        None  # Fragment reassembly timeout
    )

    # Content analysis capabilities
    deep_packet_inspection_depth: Optional[int] = (
        None  # How deep into payload DPI looks
    )
    pattern_matching_engine: Optional[str] = (
        None  # 'regex', 'aho-corasick', 'hyperscan', 'custom'
    )
    content_caching_behavior: Optional[str] = (
        None  # 'none', 'headers', 'partial', 'full'
    )

    # Evasion resistance patterns
    anti_evasion_techniques: List[str] = field(
        default_factory=list
    )  # Known anti-evasion methods
    learning_adaptation_detected: Optional[bool] = (
        None  # Whether DPI adapts to evasion attempts
    )
    honeypot_detection: Optional[bool] = None  # Whether DPI uses honeypot techniques

    # === Weakness Analysis ===
    identified_weaknesses: List[str] = field(default_factory=list)
    exploit_recommendations: List[Dict[str, Any]] = field(default_factory=list)

    def analyze_weakness_patterns(self) -> List[str]:
        """Comprehensive weakness analysis"""
        weaknesses = []

        # Technique effectiveness analysis
        for technique, effectiveness in self.evasion_effectiveness.items():
            if effectiveness > 0.8:
                weaknesses.append(
                    f"Highly vulnerable to {technique} ({effectiveness:.0%})"
                )
            elif effectiveness > 0.6:
                weaknesses.append(
                    f"Moderately vulnerable to {technique} ({effectiveness:.0%})"
                )

        # Packet size vulnerability
        if self.packet_size_sensitivity:
            size_groups = {
                "tiny": (0, 100),
                "small": (100, 500),
                "medium": (500, 1000),
                "large": (1000, 1400),
                "jumbo": (1400, 9000),
            }

            for group_name, (min_size, max_size) in size_groups.items():
                group_rates = [
                    rate
                    for size, rate in self.packet_size_sensitivity.items()
                    if min_size <= size < max_size
                ]
                if group_rates and sum(group_rates) / len(group_rates) > 0.7:
                    weaknesses.append(f"Weak against {group_name} packets")

        # Temporal vulnerabilities
        if self.temporal_patterns.get("burst_tolerance"):
            burst_scores = self.temporal_patterns["burst_tolerance"]
            if burst_scores and max(burst_scores) > 0.8:
                weaknesses.append("Vulnerable to traffic bursts")

        # Protocol weaknesses
        weak_protocols = [
            protocol
            for protocol, handling in self.protocol_handling.items()
            if handling in ["basic_inspection", "passthrough", "no_inspection"]
        ]
        if weak_protocols:
            weaknesses.append(f"Weak protocol inspection: {', '.join(weak_protocols)}")

        # Traffic shaping vulnerability
        if not self.traffic_shaping_detected:
            weaknesses.append("No traffic shaping detected - vulnerable to flooding")

        self.identified_weaknesses = weaknesses
        return weaknesses

    def generate_exploit_strategy(self) -> Dict[str, Any]:
        """Generate comprehensive exploitation strategy"""
        strategy = {
            "primary_techniques": [],
            "secondary_techniques": [],
            "timing_recommendations": {},
            "parameter_tuning": {},
            "success_probability": 0.0,
        }

        # Select primary techniques based on effectiveness
        sorted_techniques = sorted(
            self.evasion_effectiveness.items(), key=lambda x: x[1], reverse=True
        )

        strategy["primary_techniques"] = [
            t[0] for t in sorted_techniques[:3] if t[1] > 0.6
        ]
        strategy["secondary_techniques"] = [
            t[0] for t in sorted_techniques[3:6] if t[1] > 0.4
        ]

        # Timing recommendations
        if self.peak_hours:
            off_peak = [h for h in range(24) if h not in self.peak_hours]
            strategy["timing_recommendations"]["preferred_hours"] = off_peak[:3]

        # Parameter tuning based on sensitivities
        if self.packet_size_sensitivity:
            optimal_sizes = [
                size
                for size, rate in self.packet_size_sensitivity.items()
                if rate > 0.7
            ]
            if optimal_sizes:
                strategy["parameter_tuning"]["optimal_packet_size"] = optimal_sizes[0]

        # Calculate overall success probability
        if strategy["primary_techniques"]:
            primary_rates = [
                self.evasion_effectiveness.get(t, 0)
                for t in strategy["primary_techniques"]
            ]
            strategy["success_probability"] = max(primary_rates)

        return strategy


@dataclass
class ProbeConfig:
    """Configuration for probing operations"""

    target_ip: str
    port: int = 443
    family: str = "IPv4"
    timeout: float = 2.0
    max_workers: int = 10
    cache_file: str = "data/probe_cache.json"
    cache_ttl: int = 3600

    # Probe selection
    probe_categories: List[str] = field(default_factory=lambda: ["all"])
    excluded_probes: Set[str] = field(default_factory=set)

    # Advanced options
    stealth_mode: bool = False
    randomize_order: bool = True
    inter_probe_delay: float = 0.1
    retry_failed: bool = True
    max_retries: int = 2
