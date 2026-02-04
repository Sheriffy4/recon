"""
Advanced Traffic Profiler for Traffic Mimicry

Implements sophisticated traffic pattern analysis and generation
for creating highly realistic application traffic profiles.
"""

import time
from io import BytesIO
import logging
import hashlib
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from collections import defaultdict
from core.bypass.attacks.combo.traffic_mimicry import TrafficPattern
from core.bypass.attacks.combo.steganographic_engine import (
    SteganographicManager,
    SteganographicConfig,
)

try:
    from scapy.utils import PcapReader

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
LOG = logging.getLogger(__name__)


class ApplicationCategory(Enum):
    """Categories of applications for traffic profiling."""

    VIDEO_CONFERENCING = "video_conferencing"
    MESSAGING = "messaging"
    SOCIAL_MEDIA = "social_media"
    STREAMING = "streaming"
    GAMING = "gaming"
    FILE_SHARING = "file_sharing"
    BROWSING = "browsing"
    EMAIL = "email"
    VPN = "vpn"
    CLOUD_STORAGE = "cloud_storage"


@dataclass
class TrafficSignature:
    """Signature of traffic pattern for a specific application."""

    application_name: str
    category: ApplicationCategory
    domain_patterns: List[str]
    port_patterns: List[int]
    protocol_patterns: List[str]
    avg_packet_size: int
    packet_size_variance: float
    packet_size_distribution: Dict[str, float]
    avg_inter_packet_delay: float
    delay_variance: float
    burst_patterns: List[Tuple[int, float]]
    session_duration_range: Tuple[float, float]
    idle_periods: List[Tuple[float, float]]
    bidirectional_ratio: float
    keep_alive_pattern: Optional[Tuple[float, int]]
    http_headers: Dict[str, str]
    tls_patterns: Dict[str, Any]
    udp_patterns: Dict[str, Any]
    steganographic_support: bool
    embedding_capacity: float
    detection_resistance: float


@dataclass
class ProfilingResult:
    """Result of traffic profiling analysis."""

    success: bool
    detected_applications: List[str]
    confidence_scores: Dict[str, float]
    traffic_signatures: List[TrafficSignature]
    recommended_profiles: List[str]
    steganographic_opportunities: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    pcap_file: Optional[str] = None
    error_message: Optional[str] = None

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)


class TrafficAnalyzer(ABC):
    """
    Abstract base class for traffic analysis engines.

    Each analyzer implements specific techniques for detecting
    and analyzing application traffic patterns.
    """

    def __init__(self):
        self._analysis_cache = {}
        self._signature_database = {}
        self._load_signature_database()

    @abstractmethod
    def analyze_packet_sequence(
        self, packet_sequence: List[Tuple[bytes, float]], context: Dict[str, Any]
    ) -> ProfilingResult:
        """Analyze packet sequence to detect application patterns."""
        pass

    @abstractmethod
    def extract_signatures(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> List[TrafficSignature]:
        """Extract traffic signatures from packet sequence."""
        pass

    def _load_signature_database(self):
        """Load pre-defined traffic signatures."""
        self._signature_database["zoom"] = TrafficSignature(
            application_name="Zoom",
            category=ApplicationCategory.VIDEO_CONFERENCING,
            domain_patterns=[".*zoom\\.us", ".*zoomgov\\.com"],
            port_patterns=[443, 8801, 8802],
            protocol_patterns=["tcp", "udp"],
            avg_packet_size=900,
            packet_size_variance=0.4,
            packet_size_distribution={"small": 0.2, "medium": 0.5, "large": 0.3},
            avg_inter_packet_delay=25.0,
            delay_variance=0.3,
            burst_patterns=[(5, 40.0), (3, 30.0)],
            session_duration_range=(300.0, 3600.0),
            idle_periods=[(0.5, 2.0)],
            bidirectional_ratio=0.85,
            keep_alive_pattern=(15.0, 64),
            http_headers={
                "user_agent": "Zoom/5.0",
                "content_type": "application/octet-stream",
            },
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_256_GCM_SHA384"]},
            udp_patterns={"ports": [8801, 8802]},
            steganographic_support=True,
            embedding_capacity=0.15,
            detection_resistance=0.8,
        )
        self._signature_database["telegram"] = TrafficSignature(
            application_name="Telegram",
            category=ApplicationCategory.MESSAGING,
            domain_patterns=[".*telegram\\.org", ".*t\\.me"],
            port_patterns=[443, 80],
            protocol_patterns=["tcp"],
            avg_packet_size=600,
            packet_size_variance=0.6,
            packet_size_distribution={"small": 0.4, "medium": 0.4, "large": 0.2},
            avg_inter_packet_delay=50.0,
            delay_variance=0.5,
            burst_patterns=[(2, 100.0), (1, 200.0)],
            session_duration_range=(60.0, 1800.0),
            idle_periods=[(1.0, 5.0)],
            bidirectional_ratio=0.7,
            keep_alive_pattern=(30.0, 32),
            http_headers={"user_agent": "Telegram/2.0", "accept": "application/json"},
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_128_GCM_SHA256"]},
            udp_patterns={},
            steganographic_support=True,
            embedding_capacity=0.12,
            detection_resistance=0.7,
        )
        self._signature_database["chrome"] = TrafficSignature(
            application_name="Chrome",
            category=ApplicationCategory.BROWSING,
            domain_patterns=[".*"],
            port_patterns=[443, 80],
            protocol_patterns=["tcp"],
            avg_packet_size=800,
            packet_size_variance=0.7,
            packet_size_distribution={"small": 0.3, "medium": 0.5, "large": 0.2},
            avg_inter_packet_delay=40.0,
            delay_variance=0.8,
            burst_patterns=[(3, 50.0), (1, 150.0)],
            session_duration_range=(30.0, 600.0),
            idle_periods=[(0.5, 3.0)],
            bidirectional_ratio=0.6,
            keep_alive_pattern=None,
            http_headers={
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_128_GCM_SHA256"]},
            udp_patterns={},
            steganographic_support=True,
            embedding_capacity=0.1,
            detection_resistance=0.6,
        )

    def get_signature(self, application_name: str) -> Optional[TrafficSignature]:
        """Get traffic signature for application."""
        return self._signature_database.get(application_name.lower())


class StatisticalTrafficAnalyzer(TrafficAnalyzer):
    """
    Statistical traffic analyzer using machine learning techniques
    to detect application patterns based on statistical characteristics.
    """

    def __init__(self):
        super().__init__()
        self._feature_extractors = {
            "packet_size_stats": self._extract_packet_size_statistics,
            "timing_stats": self._extract_timing_statistics,
            "burst_patterns": self._extract_burst_patterns,
            "protocol_features": self._extract_protocol_features,
            "behavioral_features": self._extract_behavioral_features,
        }

    def analyze_packet_sequence(
        self, packet_sequence: List[Tuple[bytes, float]], context: Dict[str, Any]
    ) -> ProfilingResult:
        """Analyze packet sequence using statistical methods."""
        try:
            if not packet_sequence:
                return ProfilingResult(
                    success=False,
                    detected_applications=[],
                    confidence_scores={},
                    traffic_signatures=[],
                    recommended_profiles=[],
                    steganographic_opportunities={},
                )
            features = self._extract_all_features(packet_sequence)
            matches = self._match_signatures(features)
            confidence_scores = self._calculate_confidence_scores(features, matches)
            steganographic_opportunities = self._identify_steganographic_opportunities(
                packet_sequence, features
            )
            recommended_profiles = self._generate_recommendations(matches, confidence_scores)
            return ProfilingResult(
                success=True,
                detected_applications=list(matches.keys()),
                confidence_scores=confidence_scores,
                traffic_signatures=[self._signature_database[app] for app in matches.keys()],
                recommended_profiles=recommended_profiles,
                steganographic_opportunities=steganographic_opportunities,
                metadata={
                    "features_extracted": features,
                    "analysis_method": "statistical",
                    "sequence_length": len(packet_sequence),
                },
            )
        except Exception as e:
            LOG.error(f"Statistical traffic analysis failed: {e}")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={},
            )

    def extract_signatures(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> List[TrafficSignature]:
        """Extract traffic signatures from packet sequence."""
        try:
            features = self._extract_all_features(packet_sequence)
            signature = TrafficSignature(
                application_name="extracted",
                category=ApplicationCategory.BROWSING,
                domain_patterns=[],
                port_patterns=[],
                protocol_patterns=[],
                avg_packet_size=features.get("avg_packet_size", 800),
                packet_size_variance=features.get("packet_size_variance", 0.5),
                packet_size_distribution=features.get("packet_size_distribution", {}),
                avg_inter_packet_delay=features.get("avg_inter_packet_delay", 50.0),
                delay_variance=features.get("delay_variance", 0.5),
                burst_patterns=features.get("burst_patterns", []),
                session_duration_range=(30.0, 300.0),
                idle_periods=features.get("idle_periods", []),
                bidirectional_ratio=features.get("bidirectional_ratio", 0.6),
                keep_alive_pattern=None,
                http_headers={},
                tls_patterns={},
                udp_patterns={},
                steganographic_support=True,
                embedding_capacity=0.1,
                detection_resistance=0.6,
            )
            return [signature]
        except Exception as e:
            LOG.error(f"Signature extraction failed: {e}")
            return []

    def _extract_all_features(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract all features from packet sequence."""
        features = {}
        for feature_name, extractor in self._feature_extractors.items():
            try:
                features[feature_name] = extractor(packet_sequence)
            except Exception as e:
                LOG.warning(f"Feature extraction failed for {feature_name}: {e}")
                features[feature_name] = {}
        return features

    def _extract_packet_size_statistics(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> Dict[str, Any]:
        """Extract packet size statistics."""
        packet_sizes = [len(packet) for packet, _ in packet_sequence]
        if not packet_sizes:
            return {}
        avg_size = sum(packet_sizes) / len(packet_sizes)
        variance = sum(((size - avg_size) ** 2 for size in packet_sizes)) / len(packet_sizes)
        small_count = sum((1 for size in packet_sizes if size < 500))
        medium_count = sum((1 for size in packet_sizes if 500 <= size < 1000))
        large_count = sum((1 for size in packet_sizes if size >= 1000))
        total = len(packet_sizes)
        return {
            "avg_packet_size": avg_size,
            "packet_size_variance": variance / avg_size**2 if avg_size > 0 else 0,
            "packet_size_distribution": {
                "small": small_count / total if total > 0 else 0,
                "medium": medium_count / total if total > 0 else 0,
                "large": large_count / total if total > 0 else 0,
            },
            "min_size": min(packet_sizes),
            "max_size": max(packet_sizes),
        }

    def _extract_timing_statistics(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> Dict[str, Any]:
        """Extract timing statistics."""
        if len(packet_sequence) < 2:
            return {}
        delays = [delay for _, delay in packet_sequence[1:]]
        if not delays:
            return {}
        avg_delay = sum(delays) / len(delays)
        variance = sum(((delay - avg_delay) ** 2 for delay in delays)) / len(delays)
        return {
            "avg_inter_packet_delay": avg_delay,
            "delay_variance": variance / avg_delay**2 if avg_delay > 0 else 0,
            "min_delay": min(delays),
            "max_delay": max(delays),
        }

    def _extract_burst_patterns(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract burst patterns."""
        if len(packet_sequence) < 3:
            return {}
        bursts = []
        current_burst = 1
        burst_start_time = 0
        for i, (_, delay) in enumerate(packet_sequence[1:], 1):
            if delay < 20.0:
                current_burst += 1
            else:
                if current_burst > 1:
                    bursts.append((current_burst, delay))
                current_burst = 1
        if current_burst > 1:
            bursts.append((current_burst, 0))
        return {
            "burst_patterns": bursts,
            "avg_burst_size": (sum((size for size, _ in bursts)) / len(bursts) if bursts else 1),
            "burst_count": len(bursts),
        }

    def _extract_protocol_features(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> Dict[str, Any]:
        """Extract protocol-specific features."""
        if not packet_sequence:
            return {}
        http_count = 0
        tls_count = 0
        udp_count = 0
        for packet, _ in packet_sequence:
            if not packet:
                continue
            try:
                packet_str = packet.decode("utf-8", errors="ignore")
                if "HTTP/" in packet_str or "GET " in packet_str or "POST " in packet_str:
                    http_count += 1
            except:
                pass
            if len(packet) > 5 and packet[0:2] == b"\x16\x03":
                tls_count += 1
            elif len(packet) < 100 and len(packet) > 0:
                udp_count += 1
        total = len(packet_sequence)
        return {
            "http_ratio": http_count / total if total > 0 else 0,
            "tls_ratio": tls_count / total if total > 0 else 0,
            "udp_ratio": udp_count / total if total > 0 else 0,
        }

    def _extract_behavioral_features(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> Dict[str, Any]:
        """Extract behavioral features."""
        if len(packet_sequence) < 2:
            return {}
        bidirectional_ratio = 0.6
        idle_periods = []
        for _, delay in packet_sequence[1:]:
            if delay > 100.0:
                idle_periods.append((delay - 100.0, delay))
        return {
            "bidirectional_ratio": bidirectional_ratio,
            "idle_periods": idle_periods,
            "total_idle_time": sum((start for start, _ in idle_periods)),
        }

    def _match_signatures(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Match features against known signatures."""
        matches = {}
        for app_name, signature in self._signature_database.items():
            score = 0.0
            if "packet_size_stats" in features:
                size_stats = features["packet_size_stats"]
                if "avg_packet_size" in size_stats:
                    size_diff = abs(size_stats["avg_packet_size"] - signature.avg_packet_size)
                    size_score = max(0, 1.0 - size_diff / signature.avg_packet_size)
                    score += size_score * 0.3
            if "timing_stats" in features:
                timing_stats = features["timing_stats"]
                if "avg_inter_packet_delay" in timing_stats:
                    delay_diff = abs(
                        timing_stats["avg_inter_packet_delay"] - signature.avg_inter_packet_delay
                    )
                    delay_score = max(0, 1.0 - delay_diff / signature.avg_inter_packet_delay)
                    score += delay_score * 0.3
            if "protocol_features" in features:
                protocol_features = features["protocol_features"]
                if signature.category == ApplicationCategory.VIDEO_CONFERENCING:
                    if protocol_features.get("udp_ratio", 0) > 0.1:
                        score += 0.2
                elif signature.category == ApplicationCategory.BROWSING:
                    if protocol_features.get("http_ratio", 0) > 0.3:
                        score += 0.2
            if score > 0.3:
                matches[app_name] = score
        return matches

    def _calculate_confidence_scores(
        self, features: Dict[str, Any], matches: Dict[str, float]
    ) -> Dict[str, float]:
        """Calculate confidence scores for matches."""
        confidence_scores = {}
        for app_name, base_score in matches.items():
            feature_completeness = len(features) / len(self._feature_extractors)
            confidence = base_score * feature_completeness
            confidence_scores[app_name] = min(confidence, 1.0)
        return confidence_scores

    def _identify_steganographic_opportunities(
        self, packet_sequence: List[Tuple[bytes, float]], features: Dict[str, Any]
    ) -> Dict[str, float]:
        """Identify opportunities for steganographic embedding."""
        opportunities = {}
        if "packet_size_stats" in features:
            size_stats = features["packet_size_stats"]
            avg_size = size_stats.get("avg_packet_size", 800)
            if avg_size > 1000:
                opportunities["lsb_embedding"] = 0.8
            elif avg_size > 500:
                opportunities["lsb_embedding"] = 0.6
            else:
                opportunities["lsb_embedding"] = 0.3
        if "timing_stats" in features:
            timing_stats = features["timing_stats"]
            avg_delay = timing_stats.get("avg_inter_packet_delay", 50.0)
            if 20.0 <= avg_delay <= 100.0:
                opportunities["timing_channel"] = 0.7
            else:
                opportunities["timing_channel"] = 0.4
        if "protocol_features" in features:
            protocol_features = features["protocol_features"]
            http_ratio = protocol_features.get("http_ratio", 0)
            if http_ratio > 0.3:
                opportunities["header_modification"] = 0.8
            else:
                opportunities["header_modification"] = 0.3
        return opportunities

    def _generate_recommendations(
        self, matches: Dict[str, float], confidence_scores: Dict[str, float]
    ) -> List[str]:
        """Generate profile recommendations."""
        recommendations = []
        sorted_matches = sorted(matches.items(), key=lambda x: x[1], reverse=True)
        for app_name, score in sorted_matches[:3]:
            if score > 0.5:
                recommendations.append(app_name)
        if not recommendations:
            recommendations = ["chrome", "telegram", "zoom"]
        return recommendations


class AdvancedTrafficProfiler:
    """
    Advanced traffic profiler that combines multiple analysis techniques
    to create highly realistic traffic profiles for mimicry.
    """

    def __init__(self):
        self.analyzer = StatisticalTrafficAnalyzer()
        self.steganographic_manager = SteganographicManager()
        self._profile_cache = {}
        self._analysis_history = []
        self.feature_extractors = self.analyzer._feature_extractors

    def analyze_pcap_file(self, filepath: str, **kwargs) -> ProfilingResult:
        if not SCAPY_AVAILABLE:
            LOG.error("Scapy is not installed. Cannot analyze pcap files.")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={},
                metadata={"error": "Scapy not installed"},
                pcap_file=filepath,
                error_message="Scapy not installed",
            )
        LOG.info(f"Analyzing pcap file: {filepath}")
        try:
            pm = {}
            with open(filepath, "rb") as f:
                file_bytes = f.read()
            packets = []
            from scapy.utils import PcapReader

            bio = BytesIO(file_bytes)
            try:
                with PcapReader(bio) as reader:
                    for pkt in reader:
                        packets.append(pkt)
            finally:
                try:
                    bio.close()
                except Exception:
                    pass
            if not packets:
                LOG.warning(f"No packets found in pcap file: {filepath}")
                return ProfilingResult(
                    success=False,
                    detected_applications=[],
                    confidence_scores={},
                    traffic_signatures=[],
                    recommended_profiles=[],
                    steganographic_opportunities={},
                    metadata={"error": "No packets found in file"},
                    pcap_file=filepath,
                    error_message="No packets found in file",
                )
            real_time = kwargs.get("real_time", False)
            behavioral_analysis = kwargs.get("behavioral_analysis", True)
            steganographic_analysis = kwargs.get("steganographic_analysis", True)
            protocol_options = kwargs.get("protocol_specific", {})
            packet_sequence = []
            flow_stats = defaultdict(int)
            last_timestamp = None
            current_flow = None
            tls_client_hello_count = 0
            for packet in packets:
                timestamp = float(getattr(packet, "time", time.time()))
                delay = (
                    0.0 if last_timestamp is None else max(0.0, (timestamp - last_timestamp) * 1000)
                )
                last_timestamp = timestamp
                packet_info = self._extract_packet_info(packet)
                if not packet_info:
                    packet_info = self._extract_packet_info_fallback(packet)
                    if not packet_info:
                        continue
                payload, ip_info, transport_info = packet_info
                if len(payload) > 5 and payload[0] == 22 and (payload[1] == 3):
                    if len(payload) > 5 and payload[5] == 1:
                        tls_client_hello_count += 1
                flow_key = self._get_flow_key(ip_info, transport_info)
                # Count packets per flow (not only flow transitions).
                flow_stats[flow_key] += 1
                if real_time:
                    self._process_realtime_feedback(packet_info)
                packet_entry = {
                    "payload": payload,
                    "delay": delay,
                    "timestamp": timestamp,
                    "ip": ip_info,
                    "transport": transport_info,
                    "flow_key": flow_key,
                    "size": len(payload),
                }
                packet_sequence.append((packet_entry, delay))
            if not packet_sequence:
                LOG.warning(f"Could not extract a valid packet sequence from {filepath}")
                return ProfilingResult(
                    success=False,
                    detected_applications=[],
                    confidence_scores={},
                    traffic_signatures=[],
                    recommended_profiles=[],
                    steganographic_opportunities={},
                    metadata={"error": "Could not extract packet sequence"},
                    pcap_file=filepath,
                    error_message="Could not extract packet sequence",
                )
            analysis_context = {
                "context": kwargs.get("context", {}),
                "flow_statistics": dict(flow_stats),
                "behavioral_patterns": (
                    self._extract_behavioral_patterns(packet_sequence)
                    if behavioral_analysis
                    else None
                ),
                "protocol_metrics": self._analyze_protocol_patterns(
                    packet_sequence, protocol_options
                ),
                "steganographic_opportunities": (
                    self._identify_steganographic_channels(packet_sequence)
                    if steganographic_analysis
                    else None
                ),
            }
            pm = analysis_context.get("protocol_metrics", {})
            simple_sequence = [(entry["payload"], delay) for entry, delay in packet_sequence]
            result = self.analyzer.analyze_packet_sequence(simple_sequence, analysis_context)
            result.pcap_file = filepath
            ip_packets = sum(
                (1 for entry, _ in packet_sequence if entry.get("ip", {}).get("version") in (4, 6))
            )
            tcp_packets = sum(
                (1 for entry, _ in packet_sequence if entry.get("ip", {}).get("proto") == 6)
            )
            udp_packets = sum(
                (1 for entry, _ in packet_sequence if entry.get("ip", {}).get("proto") == 17)
            )
            if result and behavioral_analysis:
                result.metadata.update(
                    {
                        "flow_analysis": self._analyze_flow_patterns(flow_stats),
                        "behavioral_markers": analysis_context["behavioral_patterns"],
                        "protocol_insights": pm,
                        "context": {
                            "total_packets": len(packet_sequence),
                            "ip_packets": ip_packets,
                            "tcp_packets": tcp_packets,
                            "udp_packets": udp_packets,
                            "tls_client_hello": pm.get("tls", {}).get(
                                "client_hello", tls_client_hello_count
                            ),
                        },
                    }
                )
            detected_protocols = []
            try:
                if pm.get("tls", {}).get("handshakes", 0) + pm.get("tls", {}).get("data", 0) > 0:
                    detected_protocols.append("TLS")
                if (
                    pm.get("http", {}).get("requests", 0) + pm.get("http", {}).get("responses", 0)
                    > 0
                ):
                    detected_protocols.append("HTTP")
                if pm.get("dns", {}).get("packets", 0) > 0:
                    detected_protocols.append("DNS")
                elif pm.get("udp", {}).get("packets", 0) > 0:
                    detected_protocols.append("UDP")
            except Exception:
                pass
            existing = set(result.detected_applications)
            for proto in detected_protocols:
                if proto not in existing:
                    result.detected_applications.append(proto)
                    result.confidence_scores[proto] = max(
                        result.confidence_scores.get(proto, 0.0), 1.0
                    )
            stego_ctx = analysis_context.get("steganographic_opportunities")
            if isinstance(stego_ctx, dict):
                result.steganographic_opportunities.update(stego_ctx)
            dns_pkts = pm.get("dns", {}).get("packets", 0)
            if dns_pkts > 0 and "dns_tunneling" not in result.steganographic_opportunities:
                total = len(packet_sequence) if packet_sequence else 1
                score = min(0.9, 0.4 + dns_pkts / total * 0.5)
                result.steganographic_opportunities["dns_tunneling"] = score
            tls_pkts = pm.get("tls", {}).get("handshakes", 0) + pm.get("tls", {}).get("data", 0)
            if tls_pkts > 0 and "tls_padding" not in result.steganographic_opportunities:
                total = len(packet_sequence) if packet_sequence else 1
                score = min(0.9, 0.4 + tls_pkts / total * 0.5)
                result.steganographic_opportunities["tls_padding"] = score
            if result.success is False and packet_sequence:
                result.success = True
            return result
        except Exception as e:
            error_msg = str(e)
            if "[Errno 2]" in error_msg or "No such file" in error_msg:
                error_msg = "File not found"
            LOG.error(f"Failed to analyze pcap file {filepath}: {e}")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={},
                metadata={"error": error_msg},
                pcap_file=filepath,
                error_message=error_msg,
            )

    def _extract_packet_info(self, packet) -> Optional[Tuple[bytes, Dict, Dict]]:
        """Extract enriched packet information."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.packet import Raw

            if IP in packet:
                ip_layer = packet[IP]
                ip_info = {
                    "version": getattr(ip_layer, "version", 4),
                    "src": getattr(ip_layer, "src", "0.0.0.0"),
                    "dst": getattr(ip_layer, "dst", "0.0.0.0"),
                    "proto": getattr(ip_layer, "proto", 6),
                }
                transport_info = {"sport": 0, "dport": 0, "flags": 0}
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    transport_info = {
                        "sport": getattr(tcp_layer, "sport", 0),
                        "dport": getattr(tcp_layer, "dport", 0),
                        "flags": getattr(tcp_layer, "flags", 0),
                    }
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    transport_info = {
                        "sport": getattr(udp_layer, "sport", 0),
                        "dport": getattr(udp_layer, "dport", 0),
                        "flags": 0,
                    }
                payload = b""
                if Raw in packet:
                    payload = bytes(packet[Raw])
                elif TCP in packet and hasattr(packet[TCP], "payload"):
                    tcp_payload = packet[TCP].payload
                    if tcp_payload and (not isinstance(tcp_payload, type(None))):
                        payload = bytes(tcp_payload)
                elif UDP in packet and hasattr(packet[UDP], "payload"):
                    udp_payload = packet[UDP].payload
                    if udp_payload and (not isinstance(udp_payload, type(None))):
                        payload = bytes(udp_payload)
                if not payload and hasattr(packet, "load"):
                    payload = bytes(packet.load)
                return (payload, ip_info, transport_info)
            return self._extract_packet_info_fallback(packet)
        except Exception as e:
            LOG.debug(f"Could not extract packet info: {e}")
            return self._extract_packet_info_fallback(packet)

    def _extract_packet_info_fallback(self, packet) -> Optional[Tuple[bytes, Dict, Dict]]:
        """Fallback method to extract packet information from simpler packet structures."""
        try:
            try:
                from scapy.packet import Raw

                if Raw in packet:
                    payload = bytes(packet[Raw])
                elif hasattr(packet, "load"):
                    payload = bytes(packet.load)
                elif hasattr(packet, "__bytes__"):
                    full_packet = bytes(packet)
                    payload = full_packet[40:] if len(full_packet) > 40 else full_packet
                else:
                    payload = b""
            except:
                if isinstance(packet, bytes):
                    payload = packet
                else:
                    payload = bytes(packet) if packet else b""
            ip_info = {"version": 4, "src": "0.0.0.0", "dst": "0.0.0.0", "proto": 6}
            transport_info = {"sport": 0, "dport": 0, "flags": 0}
            return (payload, ip_info, transport_info)
        except Exception as e:
            LOG.debug(f"Fallback packet extraction failed: {e}")
            return None

    def _get_flow_key(self, ip_info: Dict, transport_info: Dict) -> str:
        """Generate unique flow identifier."""
        return (
            f"{ip_info['src']}:{transport_info['sport']}-{ip_info['dst']}:{transport_info['dport']}"
        )

    def _process_realtime_feedback(self, packet_info: Tuple[bytes, Dict, Dict]):
        """Process packet for real-time analysis feedback."""
        payload, ip_info, transport_info = packet_info
        flow_key = self._get_flow_key(ip_info, transport_info)
        anomaly_score = self._quick_anomaly_check(payload, transport_info)
        if anomaly_score > 0.8:
            LOG.warning(f"Potential anomaly detected in flow {flow_key}")

    def _quick_anomaly_check(self, payload: bytes, transport_info: Dict) -> float:
        """Quick real-time anomaly detection."""
        score = 0.0
        if len(payload) > 1500 or len(payload) < 20:
            score += 0.3
        if transport_info["dport"] in [22, 23, 3389]:
            score += 0.2
        if b"\x00" * 8 in payload:
            score += 0.3
        return min(score, 1.0)

    def _extract_behavioral_patterns(
        self, packet_sequence: List[Tuple[Dict, float]]
    ) -> Dict[str, Any]:
        """Extract complex behavioral patterns from packet sequence."""
        patterns = {
            "burst_patterns": [],
            "timing_patterns": [],
            "size_patterns": [],
            "direction_patterns": [],
        }
        current_burst = []
        last_direction = None
        for packet, delay in packet_sequence:
            if delay < 50.0:
                current_burst.append(packet)
            else:
                if current_burst:
                    patterns["burst_patterns"].append(
                        {
                            "size": len(current_burst),
                            "avg_packet_size": sum((p["size"] for p in current_burst))
                            / len(current_burst),
                            "duration": sum((p["delay"] for p in current_burst)),
                        }
                    )
                current_burst = [packet]
            patterns["timing_patterns"].append(
                {
                    "delay": delay,
                    "size": packet["size"],
                    "timestamp": packet["timestamp"],
                }
            )
            patterns["size_patterns"].append(packet["size"])
            current_direction = (packet.get("ip") or {}).get("src")
            if last_direction and current_direction and current_direction != last_direction:
                patterns["direction_patterns"].append(
                    {
                        "timestamp": packet["timestamp"],
                        "previous": last_direction,
                        "current": current_direction,
                    }
                )
            if current_direction:
                last_direction = current_direction
        return patterns

    def _analyze_protocol_patterns(
        self, packet_sequence: List[Tuple[Dict, float]], options: Dict
    ) -> Dict[str, Any]:
        protocol_metrics = {
            "http": {"requests": 0, "responses": 0},
            "tls": {"handshakes": 0, "data": 0, "client_hello": 0},
            "udp": {"packets": 0},
            "tcp": {"syn": 0, "synack": 0, "established": 0, "fin": 0},
            "dns": {"packets": 0, "queries": 0, "responses": 0},
        }
        for packet, _ in packet_sequence:
            payload = packet["payload"]
            transport = packet["transport"]
            if b"HTTP/" in payload or payload.startswith(b"GET ") or payload.startswith(b"POST "):
                protocol_metrics["http"]["requests"] += 1
            elif b" 200 OK" in payload or b" 404 Not Found" in payload:
                protocol_metrics["http"]["responses"] += 1
            if len(payload) > 2 and payload[0] in (22, 23) and (payload[1] == 3):
                if payload[0] == 22:
                    protocol_metrics["tls"]["handshakes"] += 1
                    if len(payload) > 5 and payload[5] == 1:
                        protocol_metrics["tls"]["client_hello"] += 1
                else:
                    protocol_metrics["tls"]["data"] += 1
            if transport.get("flags"):
                flags = transport["flags"]
                if flags & 2:
                    protocol_metrics["tcp"]["syn"] += 1
                if flags & 18:
                    protocol_metrics["tcp"]["synack"] += 1
                if flags & 1:
                    protocol_metrics["tcp"]["fin"] += 1
            if packet["ip"].get("proto") == 17:
                protocol_metrics["udp"]["packets"] += 1
                dport = transport.get("dport", 0)
                sport = transport.get("sport", 0)
                if dport == 53 or sport == 53:
                    protocol_metrics["dns"]["packets"] += 1
                    if dport == 53:
                        protocol_metrics["dns"]["queries"] += 1
                    if sport == 53:
                        protocol_metrics["dns"]["responses"] += 1
        return protocol_metrics

    def _identify_steganographic_channels(
        self, packet_sequence: List[Tuple[Dict, float]]
    ) -> Dict[str, float]:
        """Identify potential steganographic channels in the traffic."""
        opportunities = {}
        total_packets = len(packet_sequence)
        payload_sizes = [p["size"] for p, _ in packet_sequence]
        if len(payload_sizes) > 10:
            avg_size = sum(payload_sizes) / len(payload_sizes)
            if avg_size > 500:
                opportunities["lsb_embedding"] = min(avg_size / 1500, 0.9)
        delays = [delay for _, delay in packet_sequence]
        if len(delays) > 10:
            delay_variance = sum(((d - sum(delays) / len(delays)) ** 2 for d in delays)) / len(
                delays
            )
            if 10 < delay_variance < 1000:
                opportunities["timing_channel"] = 0.7
        http_count = sum((1 for p, _ in packet_sequence if b"HTTP/" in p["payload"]))
        if http_count > total_packets * 0.3:
            opportunities["header_modification"] = 0.8
        dns_packets = 0
        for pkt, _ in packet_sequence:
            ip = pkt.get("ip", {})
            transport = pkt.get("transport", {})
            if ip.get("proto") == 17 and (
                transport.get("sport") == 53 or transport.get("dport") == 53
            ):
                dns_packets += 1
        if dns_packets > 0:
            score = min(0.9, 0.4 + dns_packets / max(1, total_packets) * 0.5)
            opportunities["dns_tunneling"] = score
        tls_packets = 0
        for pkt, _ in packet_sequence:
            payload = pkt.get("payload", b"")
            if len(payload) > 2 and payload[0] in (22, 23) and (payload[1] == 3):
                tls_packets += 1
        if tls_packets > 0:
            score = min(0.9, 0.4 + tls_packets / max(1, total_packets) * 0.5)
            opportunities["tls_padding"] = score
        return opportunities

    def _analyze_flow_patterns(self, flow_stats: Dict[str, int]) -> Dict[str, Any]:
        """Analyze flow patterns for behavioral insights."""
        flow_analysis = {
            "total_flows": len(flow_stats),
            "flow_distribution": {},
            "flow_entropy": 0.0,
            "dominant_flows": [],
        }
        total_packets = sum(flow_stats.values())
        if total_packets <= 0:
            return flow_analysis
        for flow, count in flow_stats.items():
            percentage = count / total_packets
            flow_analysis["flow_distribution"][flow] = percentage
            if percentage > 0:
                flow_analysis["flow_entropy"] -= percentage * math.log2(percentage)
        dominant_flows = sorted(flow_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        flow_analysis["dominant_flows"] = [
            {"flow": flow, "packet_count": count, "percentage": count / total_packets}
            for flow, count in dominant_flows
        ]
        return flow_analysis

    def analyze_traffic(
        self, packet_sequence: List[Tuple[bytes, float]], context: Dict[str, Any]
    ) -> ProfilingResult:
        """Analyze traffic and generate profiling results."""
        try:
            cache_key = self._generate_cache_key(packet_sequence)
            if cache_key in self._profile_cache:
                return self._profile_cache[cache_key]
            result = self.analyzer.analyze_packet_sequence(packet_sequence, context)
            self._profile_cache[cache_key] = result
            self._analysis_history.append(
                {
                    "timestamp": time.time(),
                    "sequence_length": len(packet_sequence),
                    "detected_applications": result.detected_applications,
                    "confidence_scores": result.confidence_scores,
                }
            )
            return result
        except Exception as e:
            LOG.error(f"Advanced traffic profiling failed: {e}")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={},
                metadata={"error": str(e)},
            )

    def create_enhanced_profile(
        self,
        base_profile_name: str,
        steganographic_config: Optional[SteganographicConfig] = None,
    ) -> Dict[str, Any]:
        """Create enhanced traffic profile with steganographic capabilities."""
        try:
            signature = self.analyzer.get_signature(base_profile_name)
            if not signature:
                LOG.warning(f"No signature found for {base_profile_name}")
                return {}
            enhanced_profile = {
                "name": f"{base_profile_name}_enhanced",
                "base_profile": base_profile_name,
                "signature": signature,
                "steganographic_config": steganographic_config or SteganographicConfig(),
                "embedding_capacity": signature.embedding_capacity,
                "detection_resistance": signature.detection_resistance,
                "recommended_methods": self._get_recommended_steganographic_methods(signature),
                "traffic_pattern": self._create_traffic_pattern_from_signature(signature),
                "metadata": {
                    "created_at": time.time(),
                    "enhancement_level": "advanced",
                    "steganographic_support": signature.steganographic_support,
                },
            }
            return enhanced_profile
        except Exception as e:
            LOG.error(f"Enhanced profile creation failed: {e}")
            return {}

    def _generate_cache_key(self, packet_sequence: List[Tuple[bytes, float]]) -> str:
        """Generate cache key for packet sequence."""
        data = []
        for packet, delay in packet_sequence:
            data.extend([len(packet), int(delay * 1000)])
        return hashlib.md5(str(data).encode()).hexdigest()

    def _get_recommended_steganographic_methods(self, signature: TrafficSignature) -> List[str]:
        """Get recommended steganographic methods for signature."""
        methods = []
        if signature.steganographic_support:
            if signature.embedding_capacity > 0.1:
                methods.append("lsb_payload")
            if signature.avg_inter_packet_delay > 20.0:
                methods.append("timing_channel")
            if signature.category in [
                ApplicationCategory.BROWSING,
                ApplicationCategory.MESSAGING,
            ]:
                methods.append("header_modification")
            if len(methods) > 1:
                methods.append("multi_layer")
        return methods

    def _create_traffic_pattern_from_signature(self, signature: TrafficSignature) -> TrafficPattern:
        """Create TrafficPattern from signature."""
        return TrafficPattern(
            packet_sizes=(
                int(signature.avg_packet_size * 0.5),
                int(signature.avg_packet_size * 1.5),
                signature.avg_packet_size,
            ),
            inter_packet_delays=(
                signature.avg_inter_packet_delay * 0.5,
                signature.avg_inter_packet_delay * 1.5,
                signature.avg_inter_packet_delay,
            ),
            burst_size_range=(1, max(1, int(signature.avg_packet_size / 200))),
            burst_interval_range=(
                signature.avg_inter_packet_delay * 2,
                signature.avg_inter_packet_delay * 4,
            ),
            session_duration_range=signature.session_duration_range,
            idle_periods=signature.idle_periods,
            bidirectional_ratio=signature.bidirectional_ratio,
            keep_alive_interval=(
                signature.keep_alive_pattern[0] if signature.keep_alive_pattern else 30.0
            ),
            protocol_headers=signature.http_headers,
            content_patterns=[],
        )

    def get_profiling_stats(self) -> Dict[str, Any]:
        """Get profiling statistics."""
        return {
            "cache_size": len(self._profile_cache),
            "analysis_count": len(self._analysis_history),
            "recent_analyses": (self._analysis_history[-10:] if self._analysis_history else []),
            "steganographic_stats": self.steganographic_manager.get_engine_stats(),
        }

    def create_enhanced_traffic_profile(
        self, packet_sequence: List[Tuple[bytes, float]], app_name: str, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Create an enhanced traffic profile from packet sequence analysis.

        This method analyzes a packet sequence and creates a detailed profile
        that can be used for highly realistic traffic mimicry.

        Args:
            packet_sequence: List of (packet_data, delay) tuples
            app_name: Name of the application to profile
            **kwargs: Additional options:
                - behavioral_analysis: Enable deep behavioral analysis
                - steganographic_hints: Include steganographic embedding hints
                - ml_classification: Use ML for pattern classification

        Returns:
            Enhanced traffic profile dictionary or None if analysis fails
        """
        try:
            if not packet_sequence:
                LOG.error("Cannot create profile from empty packet sequence")
                return None
            behavioral_patterns = self._extract_behavioral_patterns(
                [
                    (
                        {
                            "payload": p,
                            "size": len(p),
                            "timestamp": time.time(),
                            "ip": {},
                            "transport": {},
                        },
                        d,
                    )
                    for p, d in packet_sequence
                ]
            )
            packet_sizes = [len(p) for p, _ in packet_sequence]
            delays = [d for _, d in packet_sequence]
            profile = {
                "name": f"{app_name}_enhanced",
                "version": "2.0",
                "created_at": time.time(),
                "packet_metrics": {
                    "min_size": min(packet_sizes),
                    "max_size": max(packet_sizes),
                    "avg_size": sum(packet_sizes) / len(packet_sizes),
                    "size_stddev": math.sqrt(
                        sum(
                            ((x - sum(packet_sizes) / len(packet_sizes)) ** 2 for x in packet_sizes)
                        )
                        / len(packet_sizes)
                    ),
                },
                "timing_metrics": {
                    "min_delay": min(delays),
                    "max_delay": max(delays),
                    "avg_delay": sum(delays) / len(delays),
                    "delay_stddev": math.sqrt(
                        sum(((x - sum(delays) / len(delays)) ** 2 for x in delays)) / len(delays)
                    ),
                },
                "behavioral_patterns": behavioral_patterns,
                "burst_characteristics": {
                    "patterns": behavioral_patterns["burst_patterns"],
                    "typical_burst_size": (
                        sum((p["size"] for p in behavioral_patterns["burst_patterns"]))
                        / len(behavioral_patterns["burst_patterns"])
                        if behavioral_patterns["burst_patterns"]
                        else 0
                    ),
                },
                "direction_analysis": {
                    "patterns": behavioral_patterns["direction_patterns"],
                    "changes": len(behavioral_patterns["direction_patterns"]),
                },
            }
            if kwargs.get("ml_classification"):
                profile["ml_patterns"] = self._classify_traffic_patterns(packet_sequence)
            if kwargs.get("steganographic_hints"):
                profile["steganographic_hints"] = self._identify_steganographic_channels(
                    [({"payload": p, "size": len(p)}, d) for p, d in packet_sequence]
                )
            profile["quality_metrics"] = {
                "pattern_stability": self._calculate_pattern_stability(behavioral_patterns),
                "mimicry_effectiveness": self._estimate_mimicry_effectiveness(profile),
                "detection_resistance": self._estimate_detection_resistance(profile),
            }
            return profile
        except Exception as e:
            LOG.error(f"Failed to create enhanced traffic profile: {e}")
            return None

    def _calculate_pattern_stability(self, patterns: Dict[str, Any]) -> float:
        """Calculate stability score for behavioral patterns."""
        stability_score = 0.0
        total_metrics = 0
        if patterns["burst_patterns"]:
            burst_sizes = [p["size"] for p in patterns["burst_patterns"]]
            if burst_sizes:
                mean_size = sum(burst_sizes) / len(burst_sizes)
                variance = sum(((x - mean_size) ** 2 for x in burst_sizes)) / len(burst_sizes)
                stability_score += max(0, 1 - (variance / mean_size if mean_size > 0 else 1))
                total_metrics += 1
        if patterns["timing_patterns"]:
            delays = [p["delay"] for p in patterns["timing_patterns"]]
            if delays:
                mean_delay = sum(delays) / len(delays)
                variance = sum(((x - mean_delay) ** 2 for x in delays)) / len(delays)
                stability_score += max(0, 1 - min(variance / 1000.0, 1.0))
                total_metrics += 1
        if patterns["direction_patterns"]:
            changes = len(patterns["direction_patterns"])
            total_packets = len(patterns["timing_patterns"])
            if total_packets > 0:
                change_rate = changes / total_packets
                stability_score += max(0, 1 - min(change_rate * 2, 1.0))
                total_metrics += 1
        return stability_score / total_metrics if total_metrics > 0 else 0.0

    def _estimate_mimicry_effectiveness(self, profile: Dict[str, Any]) -> float:
        """Estimate how effectively the profile can be used for mimicry."""
        effectiveness = 0.0
        total_factors = 0
        metrics = profile["packet_metrics"]
        if metrics["max_size"] > 0:
            size_variability = metrics["size_stddev"] / metrics["avg_size"]
            effectiveness += max(0, 1 - min(size_variability, 1.0))
            total_factors += 1
        timing = profile["timing_metrics"]
        if timing["max_delay"] > 0:
            timing_consistency = timing["delay_stddev"] / timing["avg_delay"]
            effectiveness += max(0, 1 - min(timing_consistency, 1.0))
            total_factors += 1
        if profile["burst_characteristics"]["patterns"]:
            effectiveness += 0.8
            total_factors += 1
        return effectiveness / total_factors if total_factors > 0 else 0.0

    def _estimate_detection_resistance(self, profile: Dict[str, Any]) -> float:
        """Estimate how resistant the profile is to DPI detection."""
        resistance_score = 0.0
        total_factors = 0
        metrics = profile["packet_metrics"]
        if 200 <= metrics["avg_size"] <= 1400:
            resistance_score += 0.8
        else:
            resistance_score += 0.4
        total_factors += 1
        timing = profile["timing_metrics"]
        if 10 <= timing["avg_delay"] <= 1000:
            resistance_score += 0.9
        else:
            resistance_score += 0.3
        total_factors += 1
        patterns = profile["behavioral_patterns"]
        if patterns["burst_patterns"]:
            if len(patterns["burst_patterns"]) >= 3:
                resistance_score += 0.7
            else:
                resistance_score += 0.4
            total_factors += 1
        return resistance_score / total_factors if total_factors > 0 else 0.0

    def _classify_traffic_patterns(
        self, packet_sequence: List[Tuple[bytes, float]]
    ) -> Dict[str, Any]:
        """Use ML techniques to classify traffic patterns."""
        patterns = {
            "likely_protocols": [],
            "behavioral_class": None,
            "confidence_scores": {},
        }
        features = self._extract_ml_features(packet_sequence)
        protocols = ["HTTP", "TLS", "DNS", "Unknown"]
        scores = self._calculate_protocol_scores(features)
        patterns["confidence_scores"] = {proto: score for proto, score in zip(protocols, scores)}
        patterns["likely_protocols"] = [
            proto for proto, score in patterns["confidence_scores"].items() if score > 0.6
        ]
        behavior_score = self._classify_behavioral_pattern(features)
        patterns["behavioral_class"] = {
            "type": self._get_behavior_class(behavior_score),
            "confidence": behavior_score,
        }
        return patterns

    def _extract_ml_features(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, float]:
        """Extract features for ML classification."""
        features = {}
        sizes = [len(p) for p, _ in packet_sequence]
        delays = [d for _, d in packet_sequence]
        avg_size = sum(sizes) / len(sizes) if sizes else 0.0
        avg_delay = sum(delays) / len(delays) if delays else 0.0
        features.update(
            {
                "avg_size": avg_size,
                "size_variance": (
                    sum(((x - avg_size) ** 2 for x in sizes)) / len(sizes) if sizes else 0.0
                ),
                "avg_delay": avg_delay,
                "delay_variance": (
                    sum(((x - avg_delay) ** 2 for x in delays)) / len(delays) if delays else 0.0
                ),
                "packet_count": len(packet_sequence),
            }
        )
        http_count = sum(
            (
                1
                for p, _ in packet_sequence
                if b"HTTP/" in p or p.startswith(b"GET ") or p.startswith(b"POST ")
            )
        )
        tls_count = sum(
            (1 for p, _ in packet_sequence if len(p) > 2 and p[0] in (22, 23) and (p[1] == 3))
        )
        total = len(packet_sequence) if packet_sequence else 1
        features.update({"http_ratio": http_count / total, "tls_ratio": tls_count / total})
        return features

    def _calculate_protocol_scores(self, features: Dict[str, float]) -> List[float]:
        """Calculate confidence scores for each protocol."""
        scores = [0.0] * 4
        if features["http_ratio"] > 0.3:
            scores[0] = min(features["http_ratio"] * 2, 1.0)
        if features["tls_ratio"] > 0.3:
            scores[1] = min(features["tls_ratio"] * 2, 1.0)
        if features["avg_size"] < 100 and features["size_variance"] < 1000:
            scores[2] = 0.7
        scores[3] = 1.0 - max(scores[0], scores[1], scores[2])
        return scores

    def _classify_behavioral_pattern(self, features: Dict[str, float]) -> float:
        """Classify behavioral pattern confidence."""
        score = 0.0
        if 200 <= features["avg_size"] <= 1400:
            score += 0.3
        if 10 <= features["avg_delay"] <= 1000:
            score += 0.3
        if features["http_ratio"] > 0.3 or features["tls_ratio"] > 0.3:
            score += 0.4
        return min(score, 1.0)

    def _get_behavior_class(self, score: float) -> str:
        """Convert behavior score to class label."""
        if score > 0.8:
            return "Natural"
        elif score > 0.6:
            return "Semi-Natural"
        elif score > 0.4:
            return "Synthetic"
        else:
            return "Anomalous"
