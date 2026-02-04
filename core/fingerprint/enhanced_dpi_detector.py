#!/usr/bin/env python3
"""
Enhanced DPI Pattern Detector - Task 19 Implementation
Adds new DPI markers and improves detection algorithms for modern DPI systems.

Requirements: 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4
"""

import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

LOG = logging.getLogger("enhanced_dpi_detector")


class ModernDPIType(Enum):
    """Extended DPI types including modern systems"""

    # Traditional systems
    ROSKOMNADZOR_TSPU = "roskomnadzor_tspu"
    ROSKOMNADZOR_DPI = "roskomnadzor_dpi"
    SANDVINE = "sandvine"
    GFW = "gfw"

    # Modern cloud-based systems
    CLOUDFLARE_SECURITY = "cloudflare_security"
    AWS_WAF = "aws_waf"
    AZURE_FIREWALL = "azure_firewall"
    GOOGLE_CLOUD_ARMOR = "google_cloud_armor"

    # Enterprise systems
    FORTIGATE_DPI = "fortigate_dpi"
    PALO_ALTO_DPI = "palo_alto_dpi"
    CHECKPOINT_DPI = "checkpoint_dpi"
    CISCO_FIREPOWER = "cisco_firepower"

    # ISP systems
    NOKIA_DEEPFIELD = "nokia_deepfield"
    HUAWEI_DPI = "huawei_dpi"
    ERICSSON_DPI = "ericsson_dpi"

    # AI-powered systems
    ML_BASED_DPI = "ml_based_dpi"
    BEHAVIORAL_DPI = "behavioral_dpi"

    # Unknown/Generic
    UNKNOWN = "unknown"


@dataclass
class EnhancedDPISignature:
    """Enhanced DPI signature with modern detection markers"""

    # Basic identification
    signature_id: str
    dpi_type: ModernDPIType
    confidence: float
    detection_timestamp: datetime

    # Traditional markers
    rst_ttl: Optional[int] = None
    rst_from_target: bool = False
    icmp_ttl_exceeded: bool = False
    tcp_options: List[int] = field(default_factory=list)
    rst_latency_ms: float = 0.0
    rst_distance: int = 0

    # Modern DPI markers
    tls_fingerprint_blocking: bool = False
    ja3_fingerprint_detected: bool = False
    ja3s_fingerprint_detected: bool = False
    http2_frame_analysis: bool = False
    quic_connection_id_tracking: bool = False
    encrypted_sni_blocking: bool = False
    certificate_transparency_monitoring: bool = False

    # Advanced behavioral markers
    connection_pattern_analysis: bool = False
    timing_correlation_detection: bool = False
    traffic_flow_analysis: bool = False
    statistical_anomaly_detection: bool = False
    machine_learning_classification: bool = False

    # Cloud-specific markers
    cdn_edge_detection: bool = False
    load_balancer_fingerprinting: bool = False
    geo_blocking_patterns: bool = False
    rate_limiting_sophistication: int = 0

    # Enterprise markers
    application_layer_inspection: bool = False
    protocol_anomaly_detection: bool = False
    threat_intelligence_integration: bool = False
    zero_day_detection_capability: bool = False

    # Performance markers
    processing_latency_ms: float = 0.0
    throughput_impact_percentage: float = 0.0
    cpu_usage_correlation: float = 0.0

    # Evasion resistance markers
    obfuscation_detection: bool = False
    tunnel_detection_capability: bool = False
    encryption_analysis_depth: int = 0
    steganography_detection: bool = False


@dataclass
class DPIDetectionRule:
    """Rule for detecting specific DPI systems"""

    rule_id: str
    dpi_type: ModernDPIType
    conditions: List[Tuple[str, Any, float]]  # (field, expected_value, weight)
    minimum_confidence: float
    description: str


class EnhancedDPIDetector:
    """
    Enhanced DPI detector with modern pattern recognition and AI-powered detection.

    Features:
    - Detection of modern cloud-based DPI systems
    - AI/ML-powered DPI identification
    - Advanced behavioral pattern analysis
    - Enterprise DPI system recognition
    - Evasion technique detection
    """

    def __init__(self):
        self.detection_rules = self._initialize_detection_rules()
        self.signature_cache: Dict[str, EnhancedDPISignature] = {}
        self.pattern_history: List[EnhancedDPISignature] = []
        self.detection_stats = {
            "total_detections": 0,
            "successful_identifications": 0,
            "new_patterns_discovered": 0,
            "confidence_improvements": 0,
        }

    def _initialize_detection_rules(self) -> List[DPIDetectionRule]:
        """Initialize comprehensive DPI detection rules"""
        rules = []

        # Roskomnadzor TSPU (Enhanced detection)
        rules.append(
            DPIDetectionRule(
                rule_id="roskomnadzor_tspu_v2",
                dpi_type=ModernDPIType.ROSKOMNADZOR_TSPU,
                conditions=[
                    ("rst_ttl", (60, 64), 0.15),
                    ("rst_from_target", False, 0.10),
                    ("tls_fingerprint_blocking", True, 0.12),
                    ("connection_pattern_analysis", True, 0.10),
                    ("timing_correlation_detection", True, 0.08),
                    ("encrypted_sni_blocking", True, 0.15),
                    ("statistical_anomaly_detection", True, 0.10),
                    ("processing_latency_ms", (10, 50), 0.08),
                    ("obfuscation_detection", True, 0.12),
                ],
                minimum_confidence=0.85,
                description="Enhanced Roskomnadzor TSPU detection with modern markers",
            )
        )

        # Sandvine (Modern version)
        rules.append(
            DPIDetectionRule(
                rule_id="sandvine_modern",
                dpi_type=ModernDPIType.SANDVINE,
                conditions=[
                    ("rst_ttl", 128, 0.12),
                    ("tcp_options", [2, 4, 8], 0.10),
                    ("application_layer_inspection", True, 0.15),
                    ("protocol_anomaly_detection", True, 0.12),
                    ("traffic_flow_analysis", True, 0.10),
                    ("rate_limiting_sophistication", (3, 5), 0.08),
                    ("throughput_impact_percentage", (5, 15), 0.08),
                    ("tunnel_detection_capability", True, 0.15),
                    ("threat_intelligence_integration", True, 0.10),
                ],
                minimum_confidence=0.80,
                description="Modern Sandvine DPI with advanced capabilities",
            )
        )

        # Great Firewall (Enhanced)
        rules.append(
            DPIDetectionRule(
                rule_id="gfw_enhanced",
                dpi_type=ModernDPIType.GFW,
                conditions=[
                    ("rst_from_target", False, 0.12),
                    ("icmp_ttl_exceeded", True, 0.10),
                    ("ja3_fingerprint_detected", True, 0.15),
                    ("certificate_transparency_monitoring", True, 0.12),
                    ("machine_learning_classification", True, 0.10),
                    ("geo_blocking_patterns", True, 0.08),
                    ("encryption_analysis_depth", (2, 4), 0.08),
                    ("steganography_detection", True, 0.15),
                    ("zero_day_detection_capability", True, 0.10),
                ],
                minimum_confidence=0.78,
                description="Enhanced Great Firewall with AI capabilities",
            )
        )

        # Cloudflare Security
        rules.append(
            DPIDetectionRule(
                rule_id="cloudflare_security",
                dpi_type=ModernDPIType.CLOUDFLARE_SECURITY,
                conditions=[
                    ("cdn_edge_detection", True, 0.20),
                    ("load_balancer_fingerprinting", True, 0.15),
                    ("http2_frame_analysis", True, 0.12),
                    ("quic_connection_id_tracking", True, 0.10),
                    ("rate_limiting_sophistication", (4, 5), 0.10),
                    ("processing_latency_ms", (1, 10), 0.08),
                    ("threat_intelligence_integration", True, 0.15),
                    ("machine_learning_classification", True, 0.10),
                ],
                minimum_confidence=0.82,
                description="Cloudflare edge security detection",
            )
        )

        # AWS WAF
        rules.append(
            DPIDetectionRule(
                rule_id="aws_waf",
                dpi_type=ModernDPIType.AWS_WAF,
                conditions=[
                    ("application_layer_inspection", True, 0.18),
                    ("machine_learning_classification", True, 0.15),
                    ("geo_blocking_patterns", True, 0.12),
                    ("rate_limiting_sophistication", (3, 5), 0.10),
                    ("threat_intelligence_integration", True, 0.15),
                    ("statistical_anomaly_detection", True, 0.10),
                    ("processing_latency_ms", (5, 25), 0.08),
                    ("cdn_edge_detection", True, 0.12),
                ],
                minimum_confidence=0.80,
                description="AWS WAF detection with cloud markers",
            )
        )

        # Palo Alto DPI
        rules.append(
            DPIDetectionRule(
                rule_id="palo_alto_dpi",
                dpi_type=ModernDPIType.PALO_ALTO_DPI,
                conditions=[
                    ("application_layer_inspection", True, 0.20),
                    ("protocol_anomaly_detection", True, 0.15),
                    ("threat_intelligence_integration", True, 0.12),
                    ("zero_day_detection_capability", True, 0.10),
                    ("tunnel_detection_capability", True, 0.10),
                    ("behavioral_dpi", True, 0.08),
                    ("encryption_analysis_depth", (3, 5), 0.08),
                    ("traffic_flow_analysis", True, 0.12),
                    ("obfuscation_detection", True, 0.05),
                ],
                minimum_confidence=0.75,
                description="Palo Alto Networks DPI detection",
            )
        )

        # ML-based DPI (Generic AI-powered)
        rules.append(
            DPIDetectionRule(
                rule_id="ml_based_dpi",
                dpi_type=ModernDPIType.ML_BASED_DPI,
                conditions=[
                    ("machine_learning_classification", True, 0.25),
                    ("behavioral_dpi", True, 0.20),
                    ("statistical_anomaly_detection", True, 0.15),
                    ("timing_correlation_detection", True, 0.10),
                    ("traffic_flow_analysis", True, 0.10),
                    ("connection_pattern_analysis", True, 0.08),
                    ("processing_latency_ms", (20, 100), 0.07),
                    ("cpu_usage_correlation", (0.3, 0.8), 0.05),
                ],
                minimum_confidence=0.70,
                description="AI/ML-powered DPI system detection",
            )
        )

        return rules

    def detect_dpi_system(self, network_data: Dict[str, Any]) -> Optional[EnhancedDPISignature]:
        """
        Detect DPI system from network analysis data.

        Args:
            network_data: Dictionary containing network analysis results

        Returns:
            Enhanced DPI signature if detected, None otherwise
        """
        LOG.info("Starting enhanced DPI detection analysis")

        # Extract signature from network data
        signature = self._extract_enhanced_signature(network_data)

        # Apply detection rules
        best_match = None
        highest_confidence = 0.0

        for rule in self.detection_rules:
            confidence = self._evaluate_detection_rule(signature, rule)

            if confidence >= rule.minimum_confidence and confidence > highest_confidence:
                highest_confidence = confidence
                best_match = rule

        if best_match:
            # Update signature with detection results
            signature.dpi_type = best_match.dpi_type
            signature.confidence = highest_confidence
            signature.signature_id = self._generate_signature_id(signature)

            # Cache the signature
            self.signature_cache[signature.signature_id] = signature
            self.pattern_history.append(signature)

            # Update statistics
            self.detection_stats["total_detections"] += 1
            self.detection_stats["successful_identifications"] += 1

            LOG.info(
                f"DPI system detected: {best_match.dpi_type.value} (confidence: {highest_confidence:.2f})"
            )

            return signature

        # No match found - might be a new pattern
        signature.dpi_type = ModernDPIType.UNKNOWN
        signature.confidence = 0.0
        signature.signature_id = self._generate_signature_id(signature)

        # Check if this is a potentially new pattern
        if self._is_potential_new_pattern(signature):
            self.detection_stats["new_patterns_discovered"] += 1
            LOG.info("Potential new DPI pattern discovered")

        self.detection_stats["total_detections"] += 1

        return signature

    def _extract_enhanced_signature(self, network_data: Dict[str, Any]) -> EnhancedDPISignature:
        """Extract enhanced DPI signature from network data"""

        signature = EnhancedDPISignature(
            signature_id="",  # Will be generated later
            dpi_type=ModernDPIType.UNKNOWN,
            confidence=0.0,
            detection_timestamp=datetime.now(),
        )

        # Extract traditional markers
        signature.rst_ttl = network_data.get("rst_ttl")
        signature.rst_from_target = network_data.get("rst_from_target", False)
        signature.icmp_ttl_exceeded = network_data.get("icmp_ttl_exceeded", False)
        signature.tcp_options = network_data.get("tcp_options", [])
        signature.rst_latency_ms = network_data.get("rst_latency_ms", 0.0)
        signature.rst_distance = network_data.get("rst_distance", 0)

        # Extract modern markers
        signature.tls_fingerprint_blocking = self._detect_tls_fingerprint_blocking(network_data)
        signature.ja3_fingerprint_detected = self._detect_ja3_fingerprinting(network_data)
        signature.ja3s_fingerprint_detected = self._detect_ja3s_fingerprinting(network_data)
        signature.http2_frame_analysis = self._detect_http2_analysis(network_data)
        signature.quic_connection_id_tracking = self._detect_quic_tracking(network_data)
        signature.encrypted_sni_blocking = self._detect_encrypted_sni_blocking(network_data)
        signature.certificate_transparency_monitoring = self._detect_ct_monitoring(network_data)

        # Extract behavioral markers
        signature.connection_pattern_analysis = self._detect_connection_patterns(network_data)
        signature.timing_correlation_detection = self._detect_timing_correlation(network_data)
        signature.traffic_flow_analysis = self._detect_traffic_flow_analysis(network_data)
        signature.statistical_anomaly_detection = self._detect_statistical_anomalies(network_data)
        signature.machine_learning_classification = self._detect_ml_classification(network_data)

        # Extract cloud-specific markers
        signature.cdn_edge_detection = self._detect_cdn_edge(network_data)
        signature.load_balancer_fingerprinting = self._detect_load_balancer(network_data)
        signature.geo_blocking_patterns = self._detect_geo_blocking(network_data)
        signature.rate_limiting_sophistication = self._assess_rate_limiting(network_data)

        # Extract enterprise markers
        signature.application_layer_inspection = self._detect_app_layer_inspection(network_data)
        signature.protocol_anomaly_detection = self._detect_protocol_anomalies(network_data)
        signature.threat_intelligence_integration = self._detect_threat_intel(network_data)
        signature.zero_day_detection_capability = self._detect_zero_day_capability(network_data)

        # Extract performance markers
        signature.processing_latency_ms = network_data.get("processing_latency_ms", 0.0)
        signature.throughput_impact_percentage = network_data.get("throughput_impact", 0.0)
        signature.cpu_usage_correlation = network_data.get("cpu_correlation", 0.0)

        # Extract evasion resistance markers
        signature.obfuscation_detection = self._detect_obfuscation_resistance(network_data)
        signature.tunnel_detection_capability = self._detect_tunnel_detection(network_data)
        signature.encryption_analysis_depth = self._assess_encryption_analysis(network_data)
        signature.steganography_detection = self._detect_steganography_capability(network_data)

        return signature

    def _evaluate_detection_rule(
        self, signature: EnhancedDPISignature, rule: DPIDetectionRule
    ) -> float:
        """Evaluate a detection rule against a signature"""
        total_weight = 0.0
        matched_weight = 0.0

        for field_name, expected_value, weight in rule.conditions:
            total_weight += weight

            # Get actual value from signature
            actual_value = getattr(signature, field_name, None)

            if actual_value is None:
                continue

            # Check if condition matches
            if self._condition_matches(actual_value, expected_value):
                matched_weight += weight

        if total_weight == 0:
            return 0.0

        confidence = matched_weight / total_weight
        return confidence

    def _condition_matches(self, actual_value: Any, expected_value: Any) -> bool:
        """Check if actual value matches expected condition"""

        if isinstance(expected_value, tuple) and len(expected_value) == 2:
            # Range check
            min_val, max_val = expected_value
            if isinstance(actual_value, (int, float)):
                return min_val <= actual_value <= max_val
            return False

        elif isinstance(expected_value, list):
            # List membership check
            if isinstance(actual_value, list):
                return any(item in actual_value for item in expected_value)
            return actual_value in expected_value

        else:
            # Exact match
            return actual_value == expected_value

    def _generate_signature_id(self, signature: EnhancedDPISignature) -> str:
        """Generate unique signature ID"""
        # Create hash from key signature elements
        key_elements = [
            str(signature.rst_ttl),
            str(signature.rst_from_target),
            str(signature.tls_fingerprint_blocking),
            str(signature.machine_learning_classification),
            str(signature.application_layer_inspection),
            str(signature.cdn_edge_detection),
        ]

        signature_str = "|".join(key_elements)
        return hashlib.md5(signature_str.encode()).hexdigest()[:10]

    def _is_potential_new_pattern(self, signature: EnhancedDPISignature) -> bool:
        """Check if signature represents a potential new DPI pattern"""

        # Check for unique combination of modern markers
        modern_markers = [
            signature.tls_fingerprint_blocking,
            signature.ja3_fingerprint_detected,
            signature.http2_frame_analysis,
            signature.quic_connection_id_tracking,
            signature.machine_learning_classification,
            signature.behavioral_dpi,
        ]

        # If multiple modern markers are present, it might be a new system
        active_markers = sum(1 for marker in modern_markers if marker)

        return active_markers >= 3

    # Detection helper methods for modern DPI markers

    def _detect_tls_fingerprint_blocking(self, data: Dict[str, Any]) -> bool:
        """Detect TLS fingerprint-based blocking"""
        return data.get("tls_fingerprint_analysis", False) or data.get("ja3_blocking", False)

    def _detect_ja3_fingerprinting(self, data: Dict[str, Any]) -> bool:
        """Detect JA3 fingerprinting"""
        return data.get("ja3_detected", False) or "ja3" in str(data.get("tls_analysis", "")).lower()

    def _detect_ja3s_fingerprinting(self, data: Dict[str, Any]) -> bool:
        """Detect JA3S fingerprinting"""
        return (
            data.get("ja3s_detected", False) or "ja3s" in str(data.get("tls_analysis", "")).lower()
        )

    def _detect_http2_analysis(self, data: Dict[str, Any]) -> bool:
        """Detect HTTP/2 frame analysis"""
        return data.get("http2_inspection", False) or data.get("h2_frame_analysis", False)

    def _detect_quic_tracking(self, data: Dict[str, Any]) -> bool:
        """Detect QUIC connection ID tracking"""
        return data.get("quic_tracking", False) or data.get("quic_connection_analysis", False)

    def _detect_encrypted_sni_blocking(self, data: Dict[str, Any]) -> bool:
        """Detect encrypted SNI blocking"""
        return data.get("esni_blocked", False) or data.get("ech_blocked", False)

    def _detect_ct_monitoring(self, data: Dict[str, Any]) -> bool:
        """Detect Certificate Transparency monitoring"""
        return data.get("ct_monitoring", False) or data.get("certificate_analysis", False)

    def _detect_connection_patterns(self, data: Dict[str, Any]) -> bool:
        """Detect connection pattern analysis"""
        return data.get("pattern_analysis", False) or data.get("behavioral_analysis", False)

    def _detect_timing_correlation(self, data: Dict[str, Any]) -> bool:
        """Detect timing correlation analysis"""
        return data.get("timing_analysis", False) or data.get("latency_correlation", False)

    def _detect_traffic_flow_analysis(self, data: Dict[str, Any]) -> bool:
        """Detect traffic flow analysis"""
        return data.get("flow_analysis", False) or data.get("netflow_inspection", False)

    def _detect_statistical_anomalies(self, data: Dict[str, Any]) -> bool:
        """Detect statistical anomaly detection"""
        return data.get("anomaly_detection", False) or data.get("statistical_analysis", False)

    def _detect_ml_classification(self, data: Dict[str, Any]) -> bool:
        """Detect machine learning classification"""
        ml_indicators = ["ml_", "ai_", "neural_", "learning_", "classification_"]
        return any(indicator in str(data).lower() for indicator in ml_indicators)

    def _detect_cdn_edge(self, data: Dict[str, Any]) -> bool:
        """Detect CDN edge detection"""
        return data.get("cdn_detected", False) or data.get("edge_server", False)

    def _detect_load_balancer(self, data: Dict[str, Any]) -> bool:
        """Detect load balancer fingerprinting"""
        return data.get("load_balancer", False) or data.get("lb_detected", False)

    def _detect_geo_blocking(self, data: Dict[str, Any]) -> bool:
        """Detect geo-blocking patterns"""
        return data.get("geo_blocking", False) or data.get("location_based_blocking", False)

    def _assess_rate_limiting(self, data: Dict[str, Any]) -> int:
        """Assess rate limiting sophistication (0-5 scale)"""
        rate_limit_features = [
            data.get("rate_limiting", False),
            data.get("adaptive_rate_limiting", False),
            data.get("per_ip_limiting", False),
            data.get("per_session_limiting", False),
            data.get("burst_detection", False),
        ]
        return sum(1 for feature in rate_limit_features if feature)

    def _detect_app_layer_inspection(self, data: Dict[str, Any]) -> bool:
        """Detect application layer inspection"""
        return data.get("app_inspection", False) or data.get("l7_analysis", False)

    def _detect_protocol_anomalies(self, data: Dict[str, Any]) -> bool:
        """Detect protocol anomaly detection"""
        return data.get("protocol_anomalies", False) or data.get("protocol_validation", False)

    def _detect_threat_intel(self, data: Dict[str, Any]) -> bool:
        """Detect threat intelligence integration"""
        return data.get("threat_intel", False) or data.get("reputation_analysis", False)

    def _detect_zero_day_capability(self, data: Dict[str, Any]) -> bool:
        """Detect zero-day detection capability"""
        return data.get("zero_day_detection", False) or data.get("unknown_threat_detection", False)

    def _detect_obfuscation_resistance(self, data: Dict[str, Any]) -> bool:
        """Detect obfuscation detection capability"""
        return data.get("obfuscation_detection", False) or data.get("evasion_detection", False)

    def _detect_tunnel_detection(self, data: Dict[str, Any]) -> bool:
        """Detect tunnel detection capability"""
        return data.get("tunnel_detection", False) or data.get("vpn_detection", False)

    def _assess_encryption_analysis(self, data: Dict[str, Any]) -> int:
        """Assess encryption analysis depth (0-5 scale)"""
        encryption_features = [
            data.get("tls_analysis", False),
            data.get("certificate_analysis", False),
            data.get("cipher_analysis", False),
            data.get("key_exchange_analysis", False),
            data.get("encryption_metadata_analysis", False),
        ]
        return sum(1 for feature in encryption_features if feature)

    def _detect_steganography_capability(self, data: Dict[str, Any]) -> bool:
        """Detect steganography detection capability"""
        return data.get("steganography_detection", False) or data.get(
            "hidden_data_detection", False
        )

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        stats = self.detection_stats.copy()

        if stats["total_detections"] > 0:
            stats["success_rate"] = stats["successful_identifications"] / stats["total_detections"]
        else:
            stats["success_rate"] = 0.0

        stats["cached_signatures"] = len(self.signature_cache)
        stats["pattern_history_size"] = len(self.pattern_history)

        return stats

    def get_signature_by_id(self, signature_id: str) -> Optional[EnhancedDPISignature]:
        """Get cached signature by ID"""
        return self.signature_cache.get(signature_id)

    def export_new_patterns(self) -> List[Dict[str, Any]]:
        """Export discovered new patterns for integration"""
        new_patterns = []

        for signature in self.pattern_history:
            if signature.dpi_type == ModernDPIType.UNKNOWN and signature.confidence == 0.0:
                if self._is_potential_new_pattern(signature):
                    pattern_data = {
                        "signature_id": signature.signature_id,
                        "detection_timestamp": signature.detection_timestamp.isoformat(),
                        "modern_markers": {
                            "tls_fingerprint_blocking": signature.tls_fingerprint_blocking,
                            "ja3_fingerprint_detected": signature.ja3_fingerprint_detected,
                            "machine_learning_classification": signature.machine_learning_classification,
                            "behavioral_analysis": signature.connection_pattern_analysis,
                            "advanced_evasion_detection": signature.obfuscation_detection,
                        },
                        "suggested_classification": self._suggest_classification(signature),
                        "recommended_strategies": self._recommend_strategies_for_pattern(signature),
                    }
                    new_patterns.append(pattern_data)

        return new_patterns

    def _suggest_classification(self, signature: EnhancedDPISignature) -> str:
        """Suggest classification for unknown pattern"""

        if signature.cdn_edge_detection and signature.load_balancer_fingerprinting:
            return "cloud_based_dpi"
        elif signature.machine_learning_classification and signature.statistical_anomaly_detection:
            return "ai_powered_dpi"
        elif signature.application_layer_inspection and signature.threat_intelligence_integration:
            return "enterprise_dpi"
        elif signature.geo_blocking_patterns:
            return "national_dpi"
        else:
            return "unknown_advanced_dpi"

    def _recommend_strategies_for_pattern(self, signature: EnhancedDPISignature) -> List[str]:
        """Recommend bypass strategies for detected pattern"""
        strategies = []

        # Base strategies
        strategies.append("--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum")

        # Add specific strategies based on detected capabilities
        if signature.tls_fingerprint_blocking:
            strategies.append(
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum"
            )

        if signature.machine_learning_classification:
            strategies.append(
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=random --dpi-desync-fooling=badseq"
            )

        if signature.timing_correlation_detection:
            strategies.append("--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-delay=random")

        if signature.obfuscation_detection:
            strategies.append(
                "--dpi-desync=disorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=md5sig"
            )

        return strategies


# Example usage and testing
async def test_enhanced_dpi_detector():
    """Test the enhanced DPI detector"""

    detector = EnhancedDPIDetector()

    # Test data simulating various DPI systems
    test_cases = [
        {
            "name": "Roskomnadzor TSPU",
            "data": {
                "rst_ttl": 62,
                "rst_from_target": False,
                "tls_fingerprint_analysis": True,
                "timing_analysis": True,
                "esni_blocked": True,
                "anomaly_detection": True,
                "processing_latency_ms": 25,
                "obfuscation_detection": True,
            },
        },
        {
            "name": "Cloudflare Security",
            "data": {
                "cdn_detected": True,
                "load_balancer": True,
                "http2_inspection": True,
                "quic_tracking": True,
                "rate_limiting": True,
                "processing_latency_ms": 5,
                "threat_intel": True,
                "ml_classification": True,
            },
        },
        {
            "name": "Unknown AI-powered DPI",
            "data": {
                "ml_classification": True,
                "behavioral_analysis": True,
                "anomaly_detection": True,
                "timing_analysis": True,
                "flow_analysis": True,
                "pattern_analysis": True,
                "processing_latency_ms": 45,
                "cpu_correlation": 0.6,
            },
        },
    ]

    LOG.info("Testing Enhanced DPI Detector")

    for test_case in test_cases:
        LOG.info(f"\nTesting: {test_case['name']}")

        signature = detector.detect_dpi_system(test_case["data"])

        if signature:
            LOG.info(f"  Detected: {signature.dpi_type.value}")
            LOG.info(f"  Confidence: {signature.confidence:.2f}")
            LOG.info(f"  Signature ID: {signature.signature_id}")

            if signature.dpi_type == ModernDPIType.UNKNOWN:
                LOG.info("  -> Potential new pattern discovered!")
        else:
            LOG.info("  No DPI system detected")

    # Display statistics
    stats = detector.get_detection_statistics()
    LOG.info("\nDetection Statistics:")
    LOG.info(f"  Total detections: {stats['total_detections']}")
    LOG.info(f"  Successful identifications: {stats['successful_identifications']}")
    LOG.info(f"  New patterns discovered: {stats['new_patterns_discovered']}")
    LOG.info(f"  Success rate: {stats['success_rate']:.2f}")

    # Export new patterns
    new_patterns = detector.export_new_patterns()
    if new_patterns:
        LOG.info(f"\nNew patterns found: {len(new_patterns)}")
        for pattern in new_patterns:
            LOG.info(f"  Pattern ID: {pattern['signature_id']}")
            LOG.info(f"  Suggested classification: {pattern['suggested_classification']}")


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    asyncio.run(test_enhanced_dpi_detector())
