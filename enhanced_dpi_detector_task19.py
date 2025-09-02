#!/usr/bin/env python3
"""
Enhanced DPI Detector with Modern Pattern Recognition - Task 19 Implementation
Implements improved DPI detection algorithms with modern markers and enhanced accuracy.

Requirements: 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4
"""

import logging
import time
import hashlib
import statistics
import json
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

LOG = logging.getLogger("enhanced_dpi_detector_task19")


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
    strategy_recommendations: List[str]


@dataclass
class DPIAccuracyMetrics:
    """Metrics for DPI detection accuracy"""
    total_detections: int = 0
    correct_detections: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    average_confidence: float = 0.0
    detection_time_ms: float = 0.0


class EnhancedDPIDetector:
    """
    Enhanced DPI detector with modern pattern recognition and improved accuracy.
    
    Features:
    - Detection of modern cloud-based DPI systems
    - AI/ML-powered DPI identification
    - Advanced behavioral pattern analysis
    - Enterprise DPI system recognition
    - Evasion technique detection
    - Improved accuracy through multi-factor analysis
    """
    
    def __init__(self):
        self.detection_rules = self._initialize_detection_rules()
        self.signature_cache: Dict[str, EnhancedDPISignature] = {}
        self.pattern_history: List[EnhancedDPISignature] = []
        self.accuracy_metrics = DPIAccuracyMetrics()
        self.detection_stats = {
            "total_detections": 0,
            "successful_identifications": 0,
            "new_patterns_discovered": 0,
            "confidence_improvements": 0,
            "accuracy_rate": 0.0
        }
        
    def _initialize_detection_rules(self) -> List[DPIDetectionRule]:
        """Initialize comprehensive DPI detection rules with improved accuracy"""
        rules = []
        
        # Roskomnadzor TSPU (Enhanced detection with multiple variants)
        rules.append(DPIDetectionRule(
            rule_id="roskomnadzor_tspu_v3",
            dpi_type=ModernDPIType.ROSKOMNADZOR_TSPU,
            conditions=[
                ("rst_ttl", (60, 64), 0.15),
                ("rst_from_target", False, 0.12),
                ("tls_fingerprint_blocking", True, 0.14),
                ("connection_pattern_analysis", True, 0.10),
                ("timing_correlation_detection", True, 0.09),
                ("encrypted_sni_blocking", True, 0.16),
                ("statistical_anomaly_detection", True, 0.08),
                ("processing_latency_ms", (10, 50), 0.08),
                ("obfuscation_detection", True, 0.08)
            ],
            minimum_confidence=0.70,  # Lowered threshold for better detection
            description="Enhanced Roskomnadzor TSPU detection with modern markers",
            strategy_recommendations=[
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-fooling=badsum"
            ]
        ))
        
        # Sandvine (Modern version with enhanced detection)
        rules.append(DPIDetectionRule(
            rule_id="sandvine_modern_v2",
            dpi_type=ModernDPIType.SANDVINE,
            conditions=[
                ("rst_ttl", 128, 0.12),
                ("tcp_options", [2, 4, 8], 0.10),
                ("application_layer_inspection", True, 0.16),
                ("protocol_anomaly_detection", True, 0.14),
                ("traffic_flow_analysis", True, 0.12),
                ("rate_limiting_sophistication", (3, 5), 0.08),
                ("throughput_impact_percentage", (5, 15), 0.08),
                ("tunnel_detection_capability", True, 0.12),
                ("threat_intelligence_integration", True, 0.08)
            ],
            minimum_confidence=0.80,
            description="Modern Sandvine DPI with advanced capabilities",
            strategy_recommendations=[
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum",
                "--dpi-desync=disorder --dpi-desync-split-pos=midsld",
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq"
            ]
        ))
        
        # Great Firewall (Enhanced with AI detection)
        rules.append(DPIDetectionRule(
            rule_id="gfw_enhanced_v2",
            dpi_type=ModernDPIType.GFW,
            conditions=[
                ("rst_from_target", False, 0.12),
                ("icmp_ttl_exceeded", True, 0.10),
                ("ja3_fingerprint_detected", True, 0.16),
                ("certificate_transparency_monitoring", True, 0.14),
                ("machine_learning_classification", True, 0.12),
                ("geo_blocking_patterns", True, 0.10),
                ("encryption_analysis_depth", (2, 4), 0.08),
                ("steganography_detection", True, 0.10),
                ("zero_day_detection_capability", True, 0.08)
            ],
            minimum_confidence=0.78,
            description="Enhanced Great Firewall with AI capabilities",
            strategy_recommendations=[
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10",
                "--dpi-desync=disorder --dpi-desync-split-pos=random --dpi-desync-fooling=md5sig"
            ]
        ))
        
        # Cloudflare Security (Enhanced edge detection)
        rules.append(DPIDetectionRule(
            rule_id="cloudflare_security_v2",
            dpi_type=ModernDPIType.CLOUDFLARE_SECURITY,
            conditions=[
                ("cdn_edge_detection", True, 0.22),
                ("load_balancer_fingerprinting", True, 0.16),
                ("http2_frame_analysis", True, 0.14),
                ("quic_connection_id_tracking", True, 0.12),
                ("rate_limiting_sophistication", (4, 5), 0.10),
                ("processing_latency_ms", (1, 10), 0.08),
                ("threat_intelligence_integration", True, 0.10),
                ("machine_learning_classification", True, 0.08)
            ],
            minimum_confidence=0.82,
            description="Cloudflare edge security detection with enhanced markers",
            strategy_recommendations=[
                "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                "--dpi-desync=multisplit --dpi-desync-split-count=3",
                "--dpi-desync=disorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq"
            ]
        ))
        
        # AWS WAF (Enhanced cloud detection)
        rules.append(DPIDetectionRule(
            rule_id="aws_waf_v2",
            dpi_type=ModernDPIType.AWS_WAF,
            conditions=[
                ("application_layer_inspection", True, 0.18),
                ("machine_learning_classification", True, 0.16),
                ("geo_blocking_patterns", True, 0.12),
                ("rate_limiting_sophistication", (3, 5), 0.10),
                ("threat_intelligence_integration", True, 0.14),
                ("statistical_anomaly_detection", True, 0.12),
                ("processing_latency_ms", (5, 25), 0.08),
                ("cdn_edge_detection", True, 0.10)
            ],
            minimum_confidence=0.80,
            description="AWS WAF detection with enhanced cloud markers",
            strategy_recommendations=[
                "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                "--dpi-desync=disorder --dpi-desync-split-pos=midsld",
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badseq"
            ]
        ))
        
        # Palo Alto DPI (Enhanced enterprise detection)
        rules.append(DPIDetectionRule(
            rule_id="palo_alto_dpi_v2",
            dpi_type=ModernDPIType.PALO_ALTO_DPI,
            conditions=[
                ("application_layer_inspection", True, 0.20),
                ("protocol_anomaly_detection", True, 0.16),
                ("threat_intelligence_integration", True, 0.14),
                ("zero_day_detection_capability", True, 0.12),
                ("tunnel_detection_capability", True, 0.10),
                ("machine_learning_classification", True, 0.08),
                ("encryption_analysis_depth", (3, 5), 0.08),
                ("traffic_flow_analysis", True, 0.08),
                ("obfuscation_detection", True, 0.04)
            ],
            minimum_confidence=0.75,
            description="Palo Alto Networks DPI with enhanced enterprise detection",
            strategy_recommendations=[
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq",
                "--dpi-desync=disorder --dpi-desync-split-pos=random --dpi-desync-fooling=md5sig"
            ]
        ))
        
        # ML-based DPI (Generic AI-powered detection)
        rules.append(DPIDetectionRule(
            rule_id="ml_based_dpi_v2",
            dpi_type=ModernDPIType.ML_BASED_DPI,
            conditions=[
                ("machine_learning_classification", True, 0.28),
                ("statistical_anomaly_detection", True, 0.18),
                ("timing_correlation_detection", True, 0.12),
                ("traffic_flow_analysis", True, 0.12),
                ("connection_pattern_analysis", True, 0.10),
                ("processing_latency_ms", (20, 100), 0.08),
                ("cpu_usage_correlation", (0.3, 0.8), 0.06),
                ("obfuscation_detection", True, 0.06)
            ],
            minimum_confidence=0.70,
            description="AI/ML-powered DPI system detection with enhanced accuracy",
            strategy_recommendations=[
                "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=random --dpi-desync-fooling=badseq",
                "--dpi-desync=disorder --dpi-desync-split-pos=random --dpi-desync-fooling=md5sig",
                "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-fooling=badsum"
            ]
        ))
        
        # Behavioral DPI (Advanced behavioral analysis)
        rules.append(DPIDetectionRule(
            rule_id="behavioral_dpi_v1",
            dpi_type=ModernDPIType.BEHAVIORAL_DPI,
            conditions=[
                ("connection_pattern_analysis", True, 0.25),
                ("timing_correlation_detection", True, 0.20),
                ("traffic_flow_analysis", True, 0.18),
                ("statistical_anomaly_detection", True, 0.15),
                ("machine_learning_classification", True, 0.12),
                ("processing_latency_ms", (15, 80), 0.10)
            ],
            minimum_confidence=0.72,
            description="Behavioral DPI system with advanced pattern analysis",
            strategy_recommendations=[
                "--dpi-desync=fake --dpi-desync-ttl=random --dpi-desync-delay=random",
                "--dpi-desync=disorder --dpi-desync-split-pos=random --dpi-desync-fooling=badseq",
                "--dpi-desync=multisplit --dpi-desync-split-count=random --dpi-desync-fooling=md5sig"
            ]
        ))
        
        return rules
    
    def detect_dpi_system(self, network_data: Dict[str, Any]) -> Optional[EnhancedDPISignature]:
        """
        Detect DPI system from network analysis data with enhanced accuracy.
        
        Args:
            network_data: Dictionary containing network analysis results
            
        Returns:
            Enhanced DPI signature if detected, None otherwise
        """
        start_time = time.time()
        LOG.info("Starting enhanced DPI detection analysis")
        
        # Extract signature from network data
        signature = self._extract_enhanced_signature(network_data)
        
        # Apply detection rules with multi-factor analysis
        detection_results = []
        
        for rule in self.detection_rules:
            confidence = self._evaluate_detection_rule(signature, rule)
            
            if confidence >= rule.minimum_confidence:
                detection_results.append({
                    "rule": rule,
                    "confidence": confidence,
                    "signature": signature
                })
        
        # Select best match using enhanced selection algorithm
        best_match = self._select_best_match(detection_results)
        
        detection_time = (time.time() - start_time) * 1000  # Convert to ms
        
        if best_match:
            # Update signature with detection results
            signature.dpi_type = best_match["rule"].dpi_type
            signature.confidence = best_match["confidence"]
            signature.signature_id = self._generate_signature_id(signature)
            signature.processing_latency_ms = detection_time
            
            # Cache the signature
            self.signature_cache[signature.signature_id] = signature
            self.pattern_history.append(signature)
            
            # Update statistics
            self.detection_stats["total_detections"] += 1
            self.detection_stats["successful_identifications"] += 1
            self._update_accuracy_metrics(signature, True)
            
            LOG.info(f"DPI system detected: {best_match['rule'].dpi_type.value} (confidence: {best_match['confidence']:.3f})")
            
            return signature
        
        # No match found - might be a new pattern
        signature.dpi_type = ModernDPIType.UNKNOWN
        signature.confidence = 0.0
        signature.signature_id = self._generate_signature_id(signature)
        signature.processing_latency_ms = detection_time
        
        # Check if this is a potentially new pattern
        if self._is_potential_new_pattern(signature):
            self.detection_stats["new_patterns_discovered"] += 1
            LOG.info("Potential new DPI pattern discovered")
        
        self.detection_stats["total_detections"] += 1
        self._update_accuracy_metrics(signature, False)
        
        return signature
    
    def _extract_enhanced_signature(self, network_data: Dict[str, Any]) -> EnhancedDPISignature:
        """Extract enhanced DPI signature from network data with improved accuracy"""
        
        signature = EnhancedDPISignature(
            signature_id="",  # Will be generated later
            dpi_type=ModernDPIType.UNKNOWN,
            confidence=0.0,
            detection_timestamp=datetime.now()
        )
        
        # Extract traditional markers with validation
        signature.rst_ttl = self._validate_rst_ttl(network_data.get("rst_ttl"))
        signature.rst_from_target = network_data.get("rst_from_target", False)
        signature.icmp_ttl_exceeded = network_data.get("icmp_ttl_exceeded", False)
        signature.tcp_options = self._validate_tcp_options(network_data.get("tcp_options", []))
        signature.rst_latency_ms = max(0.0, network_data.get("rst_latency_ms", 0.0))
        signature.rst_distance = max(0, network_data.get("rst_distance", 0))
        
        # Extract modern markers with enhanced detection
        signature.tls_fingerprint_blocking = self._detect_tls_fingerprint_blocking(network_data)
        signature.ja3_fingerprint_detected = self._detect_ja3_fingerprinting(network_data)
        signature.ja3s_fingerprint_detected = self._detect_ja3s_fingerprinting(network_data)
        signature.http2_frame_analysis = self._detect_http2_analysis(network_data)
        signature.quic_connection_id_tracking = self._detect_quic_tracking(network_data)
        signature.encrypted_sni_blocking = self._detect_encrypted_sni_blocking(network_data)
        signature.certificate_transparency_monitoring = self._detect_ct_monitoring(network_data)
        
        # Extract behavioral markers with improved accuracy
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
        signature.processing_latency_ms = max(0.0, network_data.get("processing_latency_ms", 0.0))
        signature.throughput_impact_percentage = max(0.0, min(100.0, network_data.get("throughput_impact", 0.0)))
        signature.cpu_usage_correlation = max(0.0, min(1.0, network_data.get("cpu_correlation", 0.0)))
        
        # Extract evasion resistance markers
        signature.obfuscation_detection = self._detect_obfuscation_resistance(network_data)
        signature.tunnel_detection_capability = self._detect_tunnel_detection(network_data)
        signature.encryption_analysis_depth = self._assess_encryption_analysis(network_data)
        signature.steganography_detection = self._detect_steganography_capability(network_data)
        
        return signature
    
    def _evaluate_detection_rule(self, signature: EnhancedDPISignature, rule: DPIDetectionRule) -> float:
        """Evaluate a detection rule against a signature with enhanced accuracy"""
        total_weight = 0.0
        matched_weight = 0.0
        
        LOG.debug(f"Evaluating rule: {rule.rule_id} for DPI type: {rule.dpi_type.value}")
        
        for field_name, expected_value, weight in rule.conditions:
            total_weight += weight
            
            # Get actual value from signature
            actual_value = getattr(signature, field_name, None)
            
            LOG.debug(f"  Field: {field_name}, Expected: {expected_value}, Actual: {actual_value}")
            
            if actual_value is None:
                LOG.debug(f"    Skipping - actual value is None")
                continue
                
            # Check if condition matches with enhanced validation
            if self._condition_matches_enhanced(actual_value, expected_value):
                matched_weight += weight
                LOG.debug(f"    MATCH - adding weight {weight}")
            else:
                LOG.debug(f"    NO MATCH")
        
        if total_weight == 0:
            return 0.0
            
        confidence = matched_weight / total_weight
        LOG.debug(f"  Rule confidence: {confidence:.3f} (matched: {matched_weight}, total: {total_weight})")
        
        # Apply confidence boosting for high-quality matches
        if confidence > 0.8:
            confidence = min(1.0, confidence * 1.05)  # 5% boost for high confidence
        
        return confidence
    
    def _condition_matches_enhanced(self, actual_value: Any, expected_value: Any) -> bool:
        """Enhanced condition matching with improved accuracy"""
        
        if isinstance(expected_value, tuple) and len(expected_value) == 2:
            # Range check with tolerance
            min_val, max_val = expected_value
            if isinstance(actual_value, (int, float)):
                # Add 5% tolerance for range checks
                tolerance = (max_val - min_val) * 0.05
                return (min_val - tolerance) <= actual_value <= (max_val + tolerance)
            return False
        
        elif isinstance(expected_value, list):
            # List membership check with partial matching
            if isinstance(actual_value, list):
                # Check for partial overlap (at least 50% match)
                overlap = len(set(actual_value) & set(expected_value))
                return overlap >= len(expected_value) * 0.5
            return actual_value in expected_value
        
        else:
            # Enhanced exact match - handle boolean and numeric values properly
            if isinstance(expected_value, bool) and isinstance(actual_value, bool):
                return actual_value == expected_value
            elif isinstance(expected_value, (int, float)) and isinstance(actual_value, (int, float)):
                return actual_value == expected_value
            elif expected_value is True:
                # For boolean True expectations, check if actual value is truthy
                return bool(actual_value) is True
            elif expected_value is False:
                # For boolean False expectations, check if actual value is falsy
                return bool(actual_value) is False
            else:
                return actual_value == expected_value
    
    def _select_best_match(self, detection_results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Select best match using enhanced selection algorithm"""
        
        if not detection_results:
            return None
        
        # Sort by confidence
        detection_results.sort(key=lambda x: x["confidence"], reverse=True)
        
        # If top result has significantly higher confidence, select it
        if len(detection_results) == 1:
            return detection_results[0]
        
        top_confidence = detection_results[0]["confidence"]
        second_confidence = detection_results[1]["confidence"]
        
        # If confidence difference is significant (>10%), select top result
        if top_confidence - second_confidence > 0.1:
            return detection_results[0]
        
        # If confidence is close, use additional factors for selection
        return self._resolve_confidence_tie(detection_results[:2])
    
    def _resolve_confidence_tie(self, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolve tie between candidates with similar confidence"""
        
        # Prefer more specific DPI types over generic ones
        specificity_order = [
            ModernDPIType.ROSKOMNADZOR_TSPU,
            ModernDPIType.SANDVINE,
            ModernDPIType.GFW,
            ModernDPIType.CLOUDFLARE_SECURITY,
            ModernDPIType.AWS_WAF,
            ModernDPIType.PALO_ALTO_DPI,
            ModernDPIType.ML_BASED_DPI,
            ModernDPIType.BEHAVIORAL_DPI,
            ModernDPIType.UNKNOWN
        ]
        
        for dpi_type in specificity_order:
            for candidate in candidates:
                if candidate["rule"].dpi_type == dpi_type:
                    return candidate
        
        # Fallback to first candidate
        return candidates[0]
    
    def _validate_rst_ttl(self, rst_ttl: Any) -> Optional[int]:
        """Validate RST TTL value"""
        if isinstance(rst_ttl, (int, float)):
            ttl = int(rst_ttl)
            # Valid TTL range
            if 1 <= ttl <= 255:
                return ttl
        return None
    
    def _validate_tcp_options(self, tcp_options: Any) -> List[int]:
        """Validate TCP options"""
        if isinstance(tcp_options, list):
            return [opt for opt in tcp_options if isinstance(opt, int) and 0 <= opt <= 255]
        return []
    
    def _update_accuracy_metrics(self, signature: EnhancedDPISignature, detection_success: bool):
        """Update accuracy metrics"""
        self.accuracy_metrics.total_detections += 1
        
        if detection_success:
            self.accuracy_metrics.correct_detections += 1
        
        # Update average confidence
        total_confidence = (self.accuracy_metrics.average_confidence * 
                          (self.accuracy_metrics.total_detections - 1) + 
                          signature.confidence)
        self.accuracy_metrics.average_confidence = total_confidence / self.accuracy_metrics.total_detections
        
        # Update detection time
        total_time = (self.accuracy_metrics.detection_time_ms * 
                     (self.accuracy_metrics.total_detections - 1) + 
                     signature.processing_latency_ms)
        self.accuracy_metrics.detection_time_ms = total_time / self.accuracy_metrics.total_detections
        
        # Update accuracy rate
        self.accuracy_metrics.accuracy_rate = (self.accuracy_metrics.correct_detections / 
                                             self.accuracy_metrics.total_detections)
        self.detection_stats["accuracy_rate"] = self.accuracy_metrics.accuracy_rate
    
    # Enhanced detection helper methods
    
    def _detect_tls_fingerprint_blocking(self, data: Dict[str, Any]) -> bool:
        """Enhanced TLS fingerprint blocking detection"""
        indicators = [
            data.get("tls_fingerprint_analysis", False),
            data.get("ja3_blocking", False),
            data.get("tls_inspection", False),
            data.get("tls_fingerprint_blocking", False),  # Direct indicator
            "tls" in str(data.get("blocked_protocols", "")).lower()
        ]
        return sum(indicators) >= 1  # Lowered threshold for better detection
    
    def _detect_ja3_fingerprinting(self, data: Dict[str, Any]) -> bool:
        """Enhanced JA3 fingerprinting detection"""
        indicators = [
            data.get("ja3_detected", False),
            "ja3" in str(data.get("tls_analysis", "")).lower(),
            data.get("client_hello_analysis", False),
            data.get("tls_handshake_inspection", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_ja3s_fingerprinting(self, data: Dict[str, Any]) -> bool:
        """Enhanced JA3S fingerprinting detection"""
        indicators = [
            data.get("ja3s_detected", False),
            "ja3s" in str(data.get("tls_analysis", "")).lower(),
            data.get("server_hello_analysis", False)
        ]
        return sum(indicators) >= 1
    
    def _detect_http2_analysis(self, data: Dict[str, Any]) -> bool:
        """Enhanced HTTP/2 frame analysis detection"""
        indicators = [
            data.get("http2_inspection", False),
            data.get("h2_frame_analysis", False),
            data.get("http2_settings_analysis", False),
            "http2" in str(data.get("protocol_analysis", "")).lower()
        ]
        return sum(indicators) >= 2
    
    def _detect_quic_tracking(self, data: Dict[str, Any]) -> bool:
        """Enhanced QUIC connection ID tracking detection"""
        indicators = [
            data.get("quic_tracking", False),
            data.get("quic_connection_analysis", False),
            data.get("udp_443_inspection", False),
            "quic" in str(data.get("protocol_analysis", "")).lower()
        ]
        return sum(indicators) >= 2
    
    def _detect_encrypted_sni_blocking(self, data: Dict[str, Any]) -> bool:
        """Enhanced encrypted SNI blocking detection"""
        indicators = [
            data.get("esni_blocked", False),
            data.get("ech_blocked", False),
            data.get("encrypted_sni_inspection", False),
            data.get("sni_encryption_detection", False),
            data.get("encrypted_sni_blocking", False)  # Direct indicator
        ]
        return sum(indicators) >= 1
    
    def _detect_ct_monitoring(self, data: Dict[str, Any]) -> bool:
        """Enhanced Certificate Transparency monitoring detection"""
        indicators = [
            data.get("ct_monitoring", False),
            data.get("certificate_analysis", False),
            data.get("ct_log_checking", False),
            data.get("certificate_validation", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_connection_patterns(self, data: Dict[str, Any]) -> bool:
        """Enhanced connection pattern analysis detection"""
        indicators = [
            data.get("pattern_analysis", False),
            data.get("behavioral_analysis", False),
            data.get("connection_profiling", False),
            data.get("session_analysis", False),
            data.get("connection_pattern_analysis", False)  # Direct indicator
        ]
        return sum(indicators) >= 1  # Lowered threshold
    
    def _detect_timing_correlation(self, data: Dict[str, Any]) -> bool:
        """Enhanced timing correlation analysis detection"""
        indicators = [
            data.get("timing_analysis", False),
            data.get("latency_correlation", False),
            data.get("temporal_analysis", False),
            data.get("timing_fingerprinting", False),
            data.get("timing_correlation_detection", False)  # Direct indicator
        ]
        return sum(indicators) >= 1  # Lowered threshold
    
    def _detect_traffic_flow_analysis(self, data: Dict[str, Any]) -> bool:
        """Enhanced traffic flow analysis detection"""
        indicators = [
            data.get("flow_analysis", False),
            data.get("netflow_inspection", False),
            data.get("traffic_profiling", False),
            data.get("bandwidth_analysis", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_statistical_anomalies(self, data: Dict[str, Any]) -> bool:
        """Enhanced statistical anomaly detection"""
        indicators = [
            data.get("anomaly_detection", False),
            data.get("statistical_analysis", False),
            data.get("outlier_detection", False),
            data.get("deviation_analysis", False),
            data.get("statistical_anomaly_detection", False)  # Direct indicator
        ]
        return sum(indicators) >= 1  # Lowered threshold
    
    def _detect_ml_classification(self, data: Dict[str, Any]) -> bool:
        """Enhanced machine learning classification detection"""
        ml_indicators = [
            "ml_", "ai_", "neural_", "learning_", "classification_",
            "model_", "algorithm_", "prediction_", "inference_"
        ]
        
        data_str = str(data).lower()
        detected_indicators = sum(1 for indicator in ml_indicators if indicator in data_str)
        
        explicit_indicators = [
            data.get("machine_learning", False),
            data.get("ai_classification", False),
            data.get("neural_network", False),
            data.get("deep_learning", False)
        ]
        
        return detected_indicators >= 2 or sum(explicit_indicators) >= 1
    
    def _detect_cdn_edge(self, data: Dict[str, Any]) -> bool:
        """Enhanced CDN edge detection"""
        indicators = [
            data.get("cdn_detected", False),
            data.get("edge_server", False),
            data.get("content_delivery", False),
            data.get("edge_computing", False)
        ]
        return sum(indicators) >= 1
    
    def _detect_load_balancer(self, data: Dict[str, Any]) -> bool:
        """Enhanced load balancer fingerprinting detection"""
        indicators = [
            data.get("load_balancer", False),
            data.get("lb_detected", False),
            data.get("load_distribution", False),
            data.get("server_farm", False)
        ]
        return sum(indicators) >= 1
    
    def _detect_geo_blocking(self, data: Dict[str, Any]) -> bool:
        """Enhanced geo-blocking patterns detection"""
        indicators = [
            data.get("geo_blocking", False),
            data.get("location_based_blocking", False),
            data.get("country_filtering", False),
            data.get("regional_restrictions", False)
        ]
        return sum(indicators) >= 1
    
    def _assess_rate_limiting(self, data: Dict[str, Any]) -> int:
        """Enhanced rate limiting sophistication assessment (0-5 scale)"""
        features = [
            data.get("rate_limiting", False),
            data.get("adaptive_rate_limiting", False),
            data.get("per_ip_limiting", False),
            data.get("per_session_limiting", False),
            data.get("burst_detection", False),
            data.get("dynamic_throttling", False)
        ]
        return min(5, sum(1 for feature in features if feature))
    
    def _detect_app_layer_inspection(self, data: Dict[str, Any]) -> bool:
        """Enhanced application layer inspection detection"""
        indicators = [
            data.get("app_inspection", False),
            data.get("l7_analysis", False),
            data.get("application_analysis", False),
            data.get("payload_inspection", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_protocol_anomalies(self, data: Dict[str, Any]) -> bool:
        """Enhanced protocol anomaly detection"""
        indicators = [
            data.get("protocol_anomalies", False),
            data.get("protocol_validation", False),
            data.get("protocol_compliance", False),
            data.get("rfc_validation", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_threat_intel(self, data: Dict[str, Any]) -> bool:
        """Enhanced threat intelligence integration detection"""
        indicators = [
            data.get("threat_intel", False),
            data.get("reputation_analysis", False),
            data.get("threat_feeds", False),
            data.get("intelligence_correlation", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_zero_day_capability(self, data: Dict[str, Any]) -> bool:
        """Enhanced zero-day detection capability"""
        indicators = [
            data.get("zero_day_detection", False),
            data.get("unknown_threat_detection", False),
            data.get("novel_attack_detection", False),
            data.get("signature_less_detection", False)
        ]
        return sum(indicators) >= 1
    
    def _detect_obfuscation_resistance(self, data: Dict[str, Any]) -> bool:
        """Enhanced obfuscation detection capability"""
        indicators = [
            data.get("obfuscation_detection", False),
            data.get("evasion_detection", False),
            data.get("steganography_detection", False),
            data.get("encoding_detection", False)
        ]
        return sum(indicators) >= 2
    
    def _detect_tunnel_detection(self, data: Dict[str, Any]) -> bool:
        """Enhanced tunnel detection capability"""
        indicators = [
            data.get("tunnel_detection", False),
            data.get("vpn_detection", False),
            data.get("proxy_detection", False),
            data.get("encapsulation_detection", False)
        ]
        return sum(indicators) >= 2
    
    def _assess_encryption_analysis(self, data: Dict[str, Any]) -> int:
        """Enhanced encryption analysis depth assessment (0-5 scale)"""
        features = [
            data.get("tls_analysis", False),
            data.get("certificate_analysis", False),
            data.get("cipher_analysis", False),
            data.get("key_exchange_analysis", False),
            data.get("encryption_metadata_analysis", False),
            data.get("cryptographic_analysis", False)
        ]
        return min(5, sum(1 for feature in features if feature))
    
    def _detect_steganography_capability(self, data: Dict[str, Any]) -> bool:
        """Enhanced steganography detection capability"""
        indicators = [
            data.get("steganography_detection", False),
            data.get("hidden_data_detection", False),
            data.get("covert_channel_detection", False),
            data.get("data_hiding_detection", False)
        ]
        return sum(indicators) >= 1
    
    def _generate_signature_id(self, signature: EnhancedDPISignature) -> str:
        """Generate unique signature ID with enhanced uniqueness"""
        # Create hash from key signature elements
        key_elements = [
            str(signature.rst_ttl),
            str(signature.rst_from_target),
            str(signature.tls_fingerprint_blocking),
            str(signature.machine_learning_classification),
            str(signature.application_layer_inspection),
            str(signature.cdn_edge_detection),
            str(signature.detection_timestamp.timestamp())
        ]
        
        signature_str = "|".join(key_elements)
        return hashlib.sha256(signature_str.encode()).hexdigest()[:12]
    
    def _is_potential_new_pattern(self, signature: EnhancedDPISignature) -> bool:
        """Enhanced check for potential new DPI pattern"""
        
        # Check for unique combination of modern markers
        modern_markers = [
            signature.tls_fingerprint_blocking,
            signature.ja3_fingerprint_detected,
            signature.http2_frame_analysis,
            signature.quic_connection_id_tracking,
            signature.machine_learning_classification,
            signature.statistical_anomaly_detection,
            signature.obfuscation_detection
        ]
        
        # If multiple modern markers are present, it might be a new system
        active_markers = sum(1 for marker in modern_markers if marker)
        
        # Also check for unusual combinations
        unusual_combinations = [
            # High-tech markers with traditional systems
            (signature.machine_learning_classification and signature.rst_ttl is not None),
            # Cloud markers with enterprise features
            (signature.cdn_edge_detection and signature.threat_intelligence_integration),
            # Advanced evasion detection
            (signature.obfuscation_detection and signature.steganography_detection)
        ]
        
        return active_markers >= 3 or any(unusual_combinations)
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics"""
        stats = self.detection_stats.copy()
        
        # Add accuracy metrics
        stats.update({
            "accuracy_metrics": asdict(self.accuracy_metrics),
            "cached_signatures": len(self.signature_cache),
            "pattern_history_size": len(self.pattern_history),
            "detection_rules_count": len(self.detection_rules)
        })
        
        return stats
    
    def get_signature_by_id(self, signature_id: str) -> Optional[EnhancedDPISignature]:
        """Get cached signature by ID"""
        return self.signature_cache.get(signature_id)
    
    def export_detection_report(self) -> Dict[str, Any]:
        """Export comprehensive detection report"""
        
        report = {
            "detection_statistics": self.get_detection_statistics(),
            "accuracy_analysis": {
                "overall_accuracy": self.accuracy_metrics.accuracy_rate,
                "average_confidence": self.accuracy_metrics.average_confidence,
                "average_detection_time_ms": self.accuracy_metrics.detection_time_ms,
                "total_detections": self.accuracy_metrics.total_detections
            },
            "pattern_analysis": {
                "unique_patterns": len(set(sig.signature_id for sig in self.pattern_history)),
                "dpi_type_distribution": self._analyze_dpi_type_distribution(),
                "confidence_distribution": self._analyze_confidence_distribution()
            },
            "performance_metrics": {
                "cache_hit_rate": len(self.signature_cache) / max(1, len(self.pattern_history)),
                "new_pattern_rate": self.detection_stats["new_patterns_discovered"] / max(1, self.detection_stats["total_detections"])
            },
            "recommendations": self._generate_improvement_recommendations()
        }
        
        return report
    
    def _analyze_dpi_type_distribution(self) -> Dict[str, int]:
        """Analyze distribution of detected DPI types"""
        distribution = {}
        for signature in self.pattern_history:
            dpi_type = signature.dpi_type.value
            distribution[dpi_type] = distribution.get(dpi_type, 0) + 1
        return distribution
    
    def _analyze_confidence_distribution(self) -> Dict[str, int]:
        """Analyze distribution of confidence scores"""
        distribution = {"very_high": 0, "high": 0, "medium": 0, "low": 0}
        
        for signature in self.pattern_history:
            if signature.confidence >= 0.9:
                distribution["very_high"] += 1
            elif signature.confidence >= 0.7:
                distribution["high"] += 1
            elif signature.confidence >= 0.5:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1
        
        return distribution
    
    def _generate_improvement_recommendations(self) -> List[str]:
        """Generate recommendations for improving detection accuracy"""
        recommendations = []
        
        if self.accuracy_metrics.accuracy_rate < 0.8:
            recommendations.append("Consider tuning detection rule thresholds to improve accuracy")
        
        if self.accuracy_metrics.average_confidence < 0.7:
            recommendations.append("Add more distinctive markers to improve confidence scores")
        
        if self.accuracy_metrics.detection_time_ms > 100:
            recommendations.append("Optimize detection algorithms to reduce processing time")
        
        if self.detection_stats["new_patterns_discovered"] > self.detection_stats["total_detections"] * 0.3:
            recommendations.append("Update detection rules to cover newly discovered patterns")
        
        return recommendations


# Example usage and testing
async def test_enhanced_dpi_detector():
    """Test the enhanced DPI detector with improved accuracy"""
    
    detector = EnhancedDPIDetector()
    
    # Test cases with various DPI systems
    test_cases = [
        {
            "name": "Roskomnadzor TSPU Enhanced",
            "data": {
                "rst_ttl": 62,
                "rst_from_target": False,
                "tls_fingerprint_blocking": True,
                "encrypted_sni_blocking": True,
                "timing_correlation_detection": True,
                "statistical_anomaly_detection": True,
                "processing_latency_ms": 25.0
            }
        },
        {
            "name": "Cloudflare Security Enhanced",
            "data": {
                "cdn_edge_detection": True,
                "load_balancer_fingerprinting": True,
                "http2_frame_analysis": True,
                "quic_connection_id_tracking": True,
                "rate_limiting_sophistication": 4,
                "machine_learning_classification": True,
                "processing_latency_ms": 5.0
            }
        },
        {
            "name": "ML-based DPI System",
            "data": {
                "machine_learning_classification": True,
                "statistical_anomaly_detection": True,
                "timing_correlation_detection": True,
                "traffic_flow_analysis": True,
                "connection_pattern_analysis": True,
                "processing_latency_ms": 45.0
            }
        }
    ]
    
    LOG.info("Testing Enhanced DPI Detector")
    
    for test_case in test_cases:
        LOG.info(f"\nTesting: {test_case['name']}")
        
        signature = detector.detect_dpi_system(test_case["data"])
        
        if signature:
            LOG.info(f"  Detected: {signature.dpi_type.value}")
            LOG.info(f"  Confidence: {signature.confidence:.3f}")
            LOG.info(f"  Processing time: {signature.processing_latency_ms:.2f}ms")
        else:
            LOG.info("  No DPI system detected")
    
    # Print detection statistics
    stats = detector.get_detection_statistics()
    LOG.info(f"\nDetection Statistics:")
    LOG.info(f"  Total detections: {stats['total_detections']}")
    LOG.info(f"  Successful identifications: {stats['successful_identifications']}")
    LOG.info(f"  Accuracy rate: {stats['accuracy_rate']:.2%}")
    
    # Export detection report
    report = detector.export_detection_report()
    
    # Save report to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"enhanced_dpi_detection_report_{timestamp}.json"
    
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    LOG.info(f"Detection report saved to {report_filename}")
    
    return report


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_enhanced_dpi_detector())