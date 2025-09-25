"""
Unified Fingerprinting Data Models - Task 22 Implementation
Standardizes all fingerprinting data models into a single, coherent structure.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum
import time
import hashlib
import json
from datetime import datetime


class DPIType(Enum):
    """Standardized DPI system types"""
    UNKNOWN = "unknown"
    ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
    ROSKOMNADZOR_DPI = "roskomnadzor_dpi"
    COMMERCIAL_DPI = "commercial_dpi"
    FIREWALL_BASED = "firewall_based"
    ISP_TRANSPARENT_PROXY = "isp_proxy"
    CLOUDFLARE_PROTECTION = "cloudflare"
    GOVERNMENT_CENSORSHIP = "government"
    CDN_EDGE_PROTECTION = "cdn_edge"
    ENTERPRISE_FIREWALL = "enterprise_fw"


class ConfidenceLevel(Enum):
    """Standardized confidence levels"""
    VERY_LOW = 0.2
    LOW = 0.4
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.9


class AnalysisStatus(Enum):
    """Status of analysis components"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ProbeResult:
    """Standardized result from a single probe"""
    name: str
    success: bool
    value: Any = None
    timestamp: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    confidence: float = 1.0
    error_message: Optional[str] = None
    raw_data: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "name": self.name,
            "success": self.success,
            "value": self.value,
            "timestamp": self.timestamp,
            "latency_ms": self.latency_ms,
            "confidence": self.confidence,
            "error_message": self.error_message,
            "metadata": self.metadata
        }
        if self.raw_data:
            result["raw_data"] = self.raw_data.hex()
        return result


@dataclass
class TCPAnalysisResult:
    """Standardized TCP analysis results"""
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    rst_injection_detected: bool = False
    tcp_window_manipulation: bool = False
    sequence_tracking: bool = False
    fragmentation_vulnerable: bool = False
    tcp_options_filtering: List[str] = field(default_factory=list)
    window_size: Optional[int] = None
    mss: Optional[int] = None
    sack_permitted: bool = False
    timestamps_enabled: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class HTTPAnalysisResult:
    """Standardized HTTP analysis results"""
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    http_blocking_detected: bool = False
    http2_support: bool = False
    header_filtering: List[str] = field(default_factory=list)
    user_agent_blocking: bool = False
    host_header_inspection: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class TLSAnalysisResult:
    """Standardized TLS analysis results"""
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    sni_blocking_detected: bool = False
    cipher_suite_filtering: bool = False
    extension_filtering: List[str] = field(default_factory=list)
    ech_support: bool = False
    ja3_fingerprint: Optional[str] = None
    supported_versions: List[str] = field(default_factory=list)
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class DNSAnalysisResult:
    """Standardized DNS analysis results"""
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    dns_blocking_detected: bool = False
    doh_support: bool = False
    dns_spoofing_detected: bool = False
    response_manipulation: bool = False
    probe_results: List[ProbeResult] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class MLClassificationResult:
    """Standardized ML classification results"""
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    predicted_dpi_type: DPIType = DPIType.UNKNOWN
    confidence: float = 0.0
    alternative_predictions: List[Tuple[DPIType, float]] = field(default_factory=list)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_version: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class StrategyRecommendation:
    """Standardized strategy recommendation"""
    strategy_name: str
    predicted_effectiveness: float
    confidence: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)


# Advanced Probe Results - Task 23 Implementation (moved before UnifiedFingerprint)

@dataclass
class AdvancedTCPProbeResult:
    """Results from advanced TCP/IP probing - Task 23"""
    
    target: str = ""
    port: int = 443
    timestamp: float = field(default_factory=time.time)
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    error_message: Optional[str] = None
    
    # Packet Reordering Tests
    packet_reordering_tolerance: bool = False
    reordering_window_size: Optional[int] = None
    
    # IP Fragmentation Tests
    ip_fragmentation_overlap_handling: str = "unknown"  # "vulnerable", "blocked", "unknown"
    fragment_reassembly_timeout: Optional[float] = None
    
    # Exotic TCP Flags and Options
    exotic_tcp_flags_response: Dict[str, str] = field(default_factory=dict)
    tcp_options_filtering: List[str] = field(default_factory=list)
    
    # TTL Distance Analysis
    dpi_distance_hops: Optional[int] = None
    ttl_manipulation_detected: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


@dataclass
class AdvancedTLSProbeResult:
    """Results from advanced TLS/HTTP probing - Task 23"""
    
    target: str = ""
    port: int = 443
    timestamp: float = field(default_factory=time.time)
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    error_message: Optional[str] = None
    
    # TLS ClientHello Size Tests
    clienthello_size_sensitivity: Dict[str, Any] = field(default_factory=dict)
    max_clienthello_size: Optional[int] = None
    min_clienthello_size: Optional[int] = None
    
    # ECH (Encrypted Client Hello) Tests
    ech_support_detected: bool = False
    ech_blocking_detected: bool = False
    ech_config_available: bool = False
    
    # HTTP/2 and HTTP/3 Tests
    http2_support: bool = False
    http2_blocking_detected: bool = False
    http3_support: bool = False
    quic_blocking_detected: bool = False
    
    # "Dirty" HTTP Traffic Tests
    dirty_http_tolerance: Dict[str, str] = field(default_factory=dict)
    http_header_filtering: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


@dataclass
class BehavioralProbeResult:
    """Results from behavioral and timing probing - Task 23"""
    
    target: str = ""
    port: int = 443
    timestamp: float = field(default_factory=time.time)
    status: AnalysisStatus = AnalysisStatus.NOT_STARTED
    error_message: Optional[str] = None
    
    # Timing Analysis
    connection_timing_patterns: Dict[str, Any] = field(default_factory=dict)
    dpi_processing_delay: Optional[float] = None
    timing_variance_detected: bool = False
    
    # Session Fingerprinting
    session_tracking_detected: bool = False
    connection_correlation_detected: bool = False
    ip_based_tracking: bool = False
    port_based_tracking: bool = False
    
    # DPI Adaptation Testing
    dpi_learning_detected: bool = False
    adaptation_time_window: Optional[float] = None
    bypass_degradation_detected: bool = False
    
    # Connection Pattern Analysis
    concurrent_connection_limit: Optional[int] = None
    rate_limiting_detected: bool = False
    connection_fingerprinting: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


@dataclass
class UnifiedFingerprint:
    """
    Unified fingerprint structure combining all analysis results.
    This replaces the fragmented DPIFingerprint, EnhancedFingerprint, etc.
    """
    # Basic identification
    target: str
    port: int = 443
    timestamp: float = field(default_factory=time.time)
    analysis_duration: float = 0.0
    fingerprint_version: str = "4.0"
    
    # Overall classification
    dpi_type: DPIType = DPIType.UNKNOWN
    confidence: float = 0.0
    reliability_score: float = 0.0
    
    # Component analysis results
    tcp_analysis: TCPAnalysisResult = field(default_factory=TCPAnalysisResult)
    http_analysis: HTTPAnalysisResult = field(default_factory=HTTPAnalysisResult)
    tls_analysis: TLSAnalysisResult = field(default_factory=TLSAnalysisResult)
    dns_analysis: DNSAnalysisResult = field(default_factory=DNSAnalysisResult)
    ml_classification: MLClassificationResult = field(default_factory=MLClassificationResult)
    
    # Advanced probe results - Task 23
    advanced_tcp_probes: AdvancedTCPProbeResult = field(default_factory=AdvancedTCPProbeResult)
    advanced_tls_probes: AdvancedTLSProbeResult = field(default_factory=AdvancedTLSProbeResult)
    behavioral_probes: BehavioralProbeResult = field(default_factory=BehavioralProbeResult)
    
    # Strategy recommendations
    recommended_strategies: List[StrategyRecommendation] = field(default_factory=list)
    
    # Network information
    ip_addresses: List[str] = field(default_factory=list)
    cdn_provider: Optional[str] = None
    asn: Optional[int] = None
    
    # Performance metrics
    connection_latency_ms: float = 0.0
    analysis_success_rate: float = 0.0
    
    # Raw data for debugging
    raw_metrics: Dict[str, Any] = field(default_factory=dict)
    cache_keys: List[str] = field(default_factory=list)
    
    def get_cache_key(self, strategy: str = "domain") -> str:
        """Generate cache key based on strategy"""
        if strategy == "domain":
            return f"domain:{self.target}:{self.port}"
        elif strategy == "cdn" and self.cdn_provider:
            return f"cdn:{self.cdn_provider}:{self.port}"
        elif strategy == "dpi_hash":
            return self.calculate_dpi_hash()
        else:
            return f"fingerprint:{self.target}:{self.port}"
    
    def calculate_dpi_hash(self) -> str:
        """Calculate hash based on DPI characteristics"""
        characteristics = {
            "dpi_type": self.dpi_type.value,
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
            tcp_score = len([r for r in self.tcp_analysis.probe_results if r.success]) / max(1, len(self.tcp_analysis.probe_results))
            scores.append(tcp_score)
            weights.append(0.3)
        
        # HTTP analysis weight
        if self.http_analysis.status == AnalysisStatus.COMPLETED:
            http_score = len([r for r in self.http_analysis.probe_results if r.success]) / max(1, len(self.http_analysis.probe_results))
            scores.append(http_score)
            weights.append(0.2)
        
        # TLS analysis weight
        if self.tls_analysis.status == AnalysisStatus.COMPLETED:
            tls_score = len([r for r in self.tls_analysis.probe_results if r.success]) / max(1, len(self.tls_analysis.probe_results))
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
            "dpi_type": self.dpi_type.value,
            "confidence": self.confidence,
            "reliability_score": self.reliability_score,
            "analysis_duration": self.analysis_duration,
            "components_completed": [
                name for name, result in [
                    ("tcp", self.tcp_analysis),
                    ("http", self.http_analysis),
                    ("tls", self.tls_analysis),
                    ("dns", self.dns_analysis),
                    ("ml", self.ml_classification),
                    ("advanced_tcp", self.advanced_tcp_probes),
                    ("advanced_tls", self.advanced_tls_probes),
                    ("behavioral", self.behavioral_probes)
                ] if result.status == AnalysisStatus.COMPLETED
            ],
            "recommended_strategies": [r.strategy_name for r in self.recommended_strategies],
            "cache_key": self.get_cache_key()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "target": self.target,
            "port": self.port,
            "timestamp": self.timestamp,
            "analysis_duration": self.analysis_duration,
            "fingerprint_version": self.fingerprint_version,
            "dpi_type": self.dpi_type.value,
            "confidence": self.confidence,
            "reliability_score": self.reliability_score,
            "tcp_analysis": {
                "status": self.tcp_analysis.status.value,
                "rst_injection_detected": self.tcp_analysis.rst_injection_detected,
                "tcp_window_manipulation": self.tcp_analysis.tcp_window_manipulation,
                "sequence_tracking": self.tcp_analysis.sequence_tracking,
                "fragmentation_vulnerable": self.tcp_analysis.fragmentation_vulnerable,
                "probe_results": [r.to_dict() for r in self.tcp_analysis.probe_results]
            },
            "http_analysis": {
                "status": self.http_analysis.status.value,
                "http_blocking_detected": self.http_analysis.http_blocking_detected,
                "http2_support": self.http_analysis.http2_support,
                "probe_results": [r.to_dict() for r in self.http_analysis.probe_results]
            },
            "tls_analysis": {
                "status": self.tls_analysis.status.value,
                "sni_blocking_detected": self.tls_analysis.sni_blocking_detected,
                "cipher_suite_filtering": self.tls_analysis.cipher_suite_filtering,
                "probe_results": [r.to_dict() for r in self.tls_analysis.probe_results]
            },
            "dns_analysis": {
                "status": self.dns_analysis.status.value,
                "dns_blocking_detected": self.dns_analysis.dns_blocking_detected,
                "doh_support": self.dns_analysis.doh_support,
                "probe_results": [r.to_dict() for r in self.dns_analysis.probe_results]
            },
            "ml_classification": {
                "status": self.ml_classification.status.value,
                "predicted_dpi_type": self.ml_classification.predicted_dpi_type.value,
                "confidence": self.ml_classification.confidence,
                "alternative_predictions": [(t.value, c) for t, c in self.ml_classification.alternative_predictions]
            },
            "recommended_strategies": [
                {
                    "strategy_name": r.strategy_name,
                    "predicted_effectiveness": r.predicted_effectiveness,
                    "confidence": r.confidence,
                    "parameters": r.parameters,
                    "reasoning": r.reasoning
                } for r in self.recommended_strategies
            ],
            "ip_addresses": self.ip_addresses,
            "cdn_provider": self.cdn_provider,
            "asn": self.asn,
            "connection_latency_ms": self.connection_latency_ms,
            "analysis_success_rate": self.analysis_success_rate,
            "raw_metrics": self.raw_metrics
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