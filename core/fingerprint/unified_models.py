# path: core/fingerprint/unified_models.py

import time
import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

# ==============================================================================
# Enums and Basic Types
# ==============================================================================


class AnalysisStatus(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class DPIType(Enum):
    UNKNOWN = "unknown"
    ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
    ROSKOMNADZOR_DPI = "roskomnadzor_dpi"
    COMMERCIAL_DPI = "commercial_dpi"
    FIREWALL_BASED = "firewall_based"
    ISP_TRANSPARENT_PROXY = "isp_transparent_proxy"


class HTTPBlockingMethod(Enum):
    NONE = "none"
    CONNECTION_RESET = "connection_reset"
    TIMEOUT = "timeout"
    REDIRECT = "redirect"
    CONTENT_MODIFICATION = "content_modification"
    HEADER_FILTERING = "header_filtering"
    STATUS_CODE_INJECTION = "status_code_injection"


@dataclass
class ProbeResult:
    name: str
    success: bool
    value: Any
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StrategyRecommendation:
    strategy_name: str
    predicted_effectiveness: float
    confidence: float
    reasoning: List[str]


@dataclass
class AnalyzerError:
    """Error from analyzer"""

    analyzer_name: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TCPAnalysisResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    rst_injection_detected: bool = False
    tcp_window_manipulation: bool = False
    sequence_tracking: bool = False
    fragmentation_vulnerable: bool = False
    fragmentation_handling: str = "unknown"
    tcp_options_filtering: List[str] = field(default_factory=list)
    window_size: Optional[int] = None
    mss: Optional[int] = None
    sack_permitted: bool = False
    timestamps_enabled: bool = False
    syn_ack_to_client_hello_delta: Optional[float] = None
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPRequest:
    """Data structure for tracking HTTP requests"""

    timestamp: float
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    host_header: str = ""
    content_type: str = ""
    body: Optional[str] = None
    success: bool = False
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_time_ms: float = 0.0
    blocking_method: HTTPBlockingMethod = HTTPBlockingMethod.NONE
    error_message: Optional[str] = None
    redirect_url: Optional[str] = None
    content_modified: bool = False


@dataclass
class HTTPAnalysisResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    http_blocking_detected: bool = False
    http2_support: bool = False
    header_filtering: List[str] = field(default_factory=list)
    user_agent_blocking: bool = False
    host_header_inspection: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None
    http_requests: List[HTTPRequest] = field(default_factory=list)
    analysis_errors: List[str] = field(default_factory=list)

    # Добавляем недостающие атрибуты
    http_header_filtering: bool = False
    filtered_headers: List[str] = field(default_factory=list)
    user_agent_filtering: bool = False
    blocked_user_agents: List[str] = field(default_factory=list)
    user_agent_whitelist_detected: bool = False
    host_header_manipulation: bool = False
    host_header_validation: bool = False
    sni_host_mismatch_blocking: bool = False
    http_method_restrictions: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=list)
    method_based_blocking: bool = False
    content_type_filtering: bool = False
    blocked_content_types: List[str] = field(default_factory=list)
    content_type_validation: bool = False
    content_based_blocking: bool = False
    content_inspection_depth: int = 0
    keyword_filtering: List[str] = field(default_factory=list)
    redirect_injection: bool = False
    redirect_status_codes: List[int] = field(default_factory=list)
    redirect_patterns: List[str] = field(default_factory=list)
    http_response_modification: bool = False
    injected_content: List[str] = field(default_factory=list)
    response_modification_patterns: List[str] = field(default_factory=list)
    keep_alive_manipulation: bool = False
    connection_header_filtering: bool = False
    persistent_connection_blocking: bool = False
    chunked_encoding_handling: str = "unknown"
    transfer_encoding_filtering: bool = False
    compression_handling: str = "unknown"
    header_case_sensitivity: bool = False
    custom_header_blocking: bool = False
    reliability_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSAnalysisResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    sni_blocking_detected: bool = False
    ech_support: bool = False
    certificate_swapping: bool = False
    cipher_suite_filtering: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class DNSAnalysisResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    dns_blocking_detected: bool = False
    doh_support: bool = False
    dns_spoofing_detected: bool = False
    response_manipulation: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class MLClassificationResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    predicted_dpi_type: DPIType = DPIType.UNKNOWN
    confidence: float = 0.0
    alternative_predictions: List[Tuple[DPIType, float]] = field(default_factory=list)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_version: Optional[str] = None
    error_message: Optional[str] = None


# Advanced Probe Results - Task 23 Implementation (moved before UnifiedFingerprint)


@dataclass
class AdvancedTCPProbeResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    target: str = ""
    port: int = 0
    timestamp: float = field(default_factory=time.time)
    packet_reordering_tolerance: bool = False
    reordering_window_size: Optional[int] = None
    ip_fragmentation_overlap_handling: str = "unknown"
    fragment_reassembly_timeout: Optional[float] = None
    exotic_tcp_flags_response: Dict[str, str] = field(default_factory=dict)
    tcp_options_filtering: List[str] = field(default_factory=list)
    dpi_distance_hops: Optional[int] = None
    ttl_manipulation_detected: bool = False
    error_message: Optional[str] = None


@dataclass
class AdvancedTLSProbeResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    target: str = ""
    port: int = 0
    timestamp: float = field(default_factory=time.time)
    clienthello_size_sensitivity: Dict[int, Any] = field(default_factory=dict)
    max_clienthello_size: Optional[int] = None
    min_clienthello_size: Optional[int] = None
    ech_support_detected: bool = False
    ech_blocking_detected: bool = False
    ech_config_available: bool = False
    http2_support: bool = False
    http2_blocking_detected: bool = False
    http3_support: bool = False
    quic_blocking_detected: bool = False
    dirty_http_tolerance: Dict[str, str] = field(default_factory=dict)
    http_header_filtering: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class BehavioralProbeResult:
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    target: str = ""
    port: int = 0
    timestamp: float = field(default_factory=time.time)
    connection_timing_patterns: Dict[str, Any] = field(default_factory=dict)
    dpi_processing_delay: Optional[float] = None
    timing_variance_detected: bool = False
    session_tracking_detected: bool = False
    connection_correlation_detected: bool = False
    ip_based_tracking: bool = False
    port_based_tracking: bool = False
    dpi_learning_detected: bool = False
    adaptation_time_window: Optional[float] = None
    bypass_degradation_detected: bool = False
    concurrent_connection_limit: Optional[int] = None
    rate_limiting_detected: bool = False
    connection_fingerprinting: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass
class UnifiedFingerprint:
    target: str
    port: int
    fingerprint_version: str = "1.0"
    timestamp: float = field(default_factory=time.time)
    ip_addresses: List[str] = field(default_factory=list)
    dpi_type: DPIType = DPIType.UNKNOWN
    reliability_score: float = 0.0
    analysis_duration: float = 0.0
    cache_keys: List[str] = field(default_factory=list)
    tcp_analysis: TCPAnalysisResult = field(default_factory=TCPAnalysisResult)
    http_analysis: HTTPAnalysisResult = field(default_factory=HTTPAnalysisResult)
    tls_analysis: TLSAnalysisResult = field(default_factory=TLSAnalysisResult)
    dns_analysis: DNSAnalysisResult = field(default_factory=DNSAnalysisResult)
    ml_classification: MLClassificationResult = field(default_factory=MLClassificationResult)
    advanced_tcp_probes: AdvancedTCPProbeResult = field(default_factory=AdvancedTCPProbeResult)
    advanced_tls_probes: AdvancedTLSProbeResult = field(default_factory=AdvancedTLSProbeResult)
    behavioral_probes: BehavioralProbeResult = field(default_factory=BehavioralProbeResult)
    recommended_strategies: List[StrategyRecommendation] = field(default_factory=list)
    errors: List["AnalyzerError"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # backward-compat alias
        d["confidence"] = self.confidence
        return d

    @property
    def confidence(self) -> float:
        try:
            return float(self.ml_classification.confidence)
        except Exception:
            return 0.0

    def get_cache_key(self, strategy: str = "domain") -> str:
        """Generate cache key based on strategy"""
        if strategy == "domain":
            return f"domain:{self.target}:{self.port}"
        elif strategy == "dpi_hash":
            return self.calculate_dpi_hash()
        else:
            return f"fingerprint:{self.target}:{self.port}"

    def calculate_dpi_hash(self) -> str:
        """Calculate hash based on DPI characteristics"""
        characteristics = {
            "dpi_type": (self.dpi_type.value if isinstance(self.dpi_type, Enum) else self.dpi_type),
            "tcp_rst_injection": self.tcp_analysis.rst_injection_detected,
            "tcp_window_manipulation": self.tcp_analysis.tcp_window_manipulation,
            "sni_blocking": self.tls_analysis.sni_blocking_detected,
            "http_blocking": self.http_analysis.http_blocking_detected,
            "dns_blocking": self.dns_analysis.dns_blocking_detected,
        }

        data = json.dumps(characteristics, sort_keys=True)
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def calculate_reliability_score(self) -> float:
        """Calculate overall reliability score"""
        scores = []
        weights = []

        # TCP analysis weight
        if self.tcp_analysis.status == AnalysisStatus.COMPLETED:
            tcp_score = len([r for r in self.tcp_analysis.probe_results if r.success]) / max(
                1, len(self.tcp_analysis.probe_results)
            )
            scores.append(tcp_score)
            weights.append(0.3)

        # HTTP analysis weight
        if self.http_analysis.status == AnalysisStatus.COMPLETED:
            http_score = len([r for r in self.http_analysis.probe_results if r.success]) / max(
                1, len(self.http_analysis.probe_results)
            )
            scores.append(http_score)
            weights.append(0.2)

        # TLS analysis weight
        if self.tls_analysis.status == AnalysisStatus.COMPLETED:
            tls_score = len([r for r in self.tls_analysis.probe_results if r.success]) / max(
                1, len(self.tls_analysis.probe_results)
            )
            scores.append(tls_score)
            weights.append(0.3)

        # ML classification weight
        if self.ml_classification.status == AnalysisStatus.COMPLETED:
            scores.append(self.ml_classification.confidence)
            weights.append(0.15)

        # Advanced probes weights - Task 23
        if self.advanced_tcp_probes.status == AnalysisStatus.COMPLETED:
            # Score based on successful probe detection
            tcp_probe_score = 0.0
            if self.advanced_tcp_probes.packet_reordering_tolerance:
                tcp_probe_score += 0.3
            if self.advanced_tcp_probes.ip_fragmentation_overlap_handling == "vulnerable":
                tcp_probe_score += 0.4
            if self.advanced_tcp_probes.dpi_distance_hops:
                tcp_probe_score += 0.3
            scores.append(tcp_probe_score)
            weights.append(0.1)

        if self.advanced_tls_probes.status == AnalysisStatus.COMPLETED:
            # Score based on TLS probe results
            tls_probe_score = 0.0
            if self.advanced_tls_probes.ech_support_detected:
                tls_probe_score += 0.3
            if self.advanced_tls_probes.http2_support:
                tls_probe_score += 0.2
            if self.advanced_tls_probes.clienthello_size_sensitivity:
                tls_probe_score += 0.5
            scores.append(tls_probe_score)
            weights.append(0.1)

        if self.behavioral_probes.status == AnalysisStatus.COMPLETED:
            # Score based on behavioral detection
            behavioral_score = 0.0
            if self.behavioral_probes.dpi_processing_delay:
                behavioral_score += 0.4
            if self.behavioral_probes.session_tracking_detected:
                behavioral_score += 0.3
            if self.behavioral_probes.dpi_learning_detected:
                behavioral_score += 0.3
            scores.append(behavioral_score)
            weights.append(0.05)

        if not scores:
            return 0.0

        # Weighted average
        total_weight = sum(weights)
        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        return weighted_sum / total_weight

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of analysis results"""
        return {
            "target": f"{self.target}:{self.port}",
            "dpi_type": (self.dpi_type.value if isinstance(self.dpi_type, Enum) else self.dpi_type),
            "confidence": self.ml_classification.confidence,
            "reliability_score": self.reliability_score,
            "analysis_duration": self.analysis_duration,
            "components_completed": [
                name
                for name, result in [
                    ("tcp", self.tcp_analysis),
                    ("http", self.http_analysis),
                    ("tls", self.tls_analysis),
                    ("dns", self.dns_analysis),
                    ("ml", self.ml_classification),
                    ("advanced_tcp", self.advanced_tcp_probes),
                    ("advanced_tls", self.advanced_tls_probes),
                    ("behavioral", self.behavioral_probes),
                ]
                if result.status == AnalysisStatus.COMPLETED
            ],
            "recommended_strategies": [r.strategy_name for r in self.recommended_strategies],
            "cache_key": self.get_cache_key(),
        }


# Exception hierarchy for unified error handling
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


class AnalyzerError(FingerprintingError):
    """Analyzer component related errors"""

    pass


class ValidationError(FingerprintingError):
    """Data validation related errors"""

    pass
