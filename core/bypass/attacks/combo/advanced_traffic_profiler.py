# recon/core/bypass/attacks/combo/advanced_traffic_profiler.py
"""
Advanced Traffic Profiler for Traffic Mimicry

Implements sophisticated traffic pattern analysis and generation
for creating highly realistic application traffic profiles.
"""

import time
import random
import logging
import hashlib
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set, Union, DefaultDict
from enum import Enum
from collections import defaultdict, Counter

from .traffic_mimicry import TrafficPattern, TrafficType
from .steganographic_engine import SteganographicManager, SteganographicConfig

try:
    from scapy.all import rdpcap
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
    
    # Packet characteristics
    avg_packet_size: int
    packet_size_variance: float
    packet_size_distribution: Dict[str, float]  # "small", "medium", "large" percentages
    
    # Timing characteristics
    avg_inter_packet_delay: float
    delay_variance: float
    burst_patterns: List[Tuple[int, float]]  # (packets_per_burst, burst_interval)
    
    # Behavioral characteristics
    session_duration_range: Tuple[float, float]
    idle_periods: List[Tuple[float, float]]
    bidirectional_ratio: float
    keep_alive_pattern: Optional[Tuple[float, int]]  # (interval, packet_size)
    
    # Protocol-specific patterns
    http_headers: Dict[str, str]
    tls_patterns: Dict[str, Any]
    udp_patterns: Dict[str, Any]
    
    # Steganographic compatibility
    steganographic_support: bool
    embedding_capacity: float  # Percentage of payload suitable for embedding
    detection_resistance: float  # 0.0 = easily detectable, 1.0 = highly resistant


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
        self, 
        packet_sequence: List[Tuple[bytes, float]], 
        context: Dict[str, Any]
    ) -> ProfilingResult:
        """Analyze packet sequence to detect application patterns."""
        pass
    
    @abstractmethod
    def extract_signatures(
        self, 
        packet_sequence: List[Tuple[bytes, float]]
    ) -> List[TrafficSignature]:
        """Extract traffic signatures from packet sequence."""
        pass
    
    def _load_signature_database(self):
        """Load pre-defined traffic signatures."""
        # Video conferencing signatures
        self._signature_database["zoom"] = TrafficSignature(
            application_name="Zoom",
            category=ApplicationCategory.VIDEO_CONFERENCING,
            domain_patterns=[r".*zoom\.us", r".*zoomgov\.com"],
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
                "content_type": "application/octet-stream"
            },
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_256_GCM_SHA384"]},
            udp_patterns={"ports": [8801, 8802]},
            steganographic_support=True,
            embedding_capacity=0.15,
            detection_resistance=0.8
        )
        
        # Messaging signatures
        self._signature_database["telegram"] = TrafficSignature(
            application_name="Telegram",
            category=ApplicationCategory.MESSAGING,
            domain_patterns=[r".*telegram\.org", r".*t\.me"],
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
            http_headers={
                "user_agent": "Telegram/2.0",
                "accept": "application/json"
            },
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_128_GCM_SHA256"]},
            udp_patterns={},
            steganographic_support=True,
            embedding_capacity=0.12,
            detection_resistance=0.7
        )
        
        # Browsing signatures
        self._signature_database["chrome"] = TrafficSignature(
            application_name="Chrome",
            category=ApplicationCategory.BROWSING,
            domain_patterns=[r".*"],
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
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            },
            tls_patterns={"version": "1.3", "ciphers": ["TLS_AES_128_GCM_SHA256"]},
            udp_patterns={},
            steganographic_support=True,
            embedding_capacity=0.10,
            detection_resistance=0.6
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
            'packet_size_stats': self._extract_packet_size_statistics,
            'timing_stats': self._extract_timing_statistics,
            'burst_patterns': self._extract_burst_patterns,
            'protocol_features': self._extract_protocol_features,
            'behavioral_features': self._extract_behavioral_features
        }
    
    def analyze_packet_sequence(
        self, 
        packet_sequence: List[Tuple[bytes, float]], 
        context: Dict[str, Any]
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
                    steganographic_opportunities={}
                )
            
            # Extract features
            features = self._extract_all_features(packet_sequence)
            
            # Match against known signatures
            matches = self._match_signatures(features)
            
            # Calculate confidence scores
            confidence_scores = self._calculate_confidence_scores(features, matches)
            
            # Identify steganographic opportunities
            steganographic_opportunities = self._identify_steganographic_opportunities(
                packet_sequence, features
            )
            
            # Generate recommendations
            recommended_profiles = self._generate_recommendations(matches, confidence_scores)
            
            return ProfilingResult(
                success=True,
                detected_applications=list(matches.keys()),
                confidence_scores=confidence_scores,
                traffic_signatures=[self._signature_database[app] for app in matches.keys()],
                recommended_profiles=recommended_profiles,
                steganographic_opportunities=steganographic_opportunities,
                metadata={
                    'features_extracted': features,
                    'analysis_method': 'statistical',
                    'sequence_length': len(packet_sequence)
                }
            )
            
        except Exception as e:
            LOG.error(f"Statistical traffic analysis failed: {e}")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={}
            )
    
    def extract_signatures(
        self, 
        packet_sequence: List[Tuple[bytes, float]]
    ) -> List[TrafficSignature]:
        """Extract traffic signatures from packet sequence."""
        try:
            features = self._extract_all_features(packet_sequence)
            
            # Create signature from extracted features
            signature = TrafficSignature(
                application_name="extracted",
                category=ApplicationCategory.BROWSING,  # Default
                domain_patterns=[],
                port_patterns=[],
                protocol_patterns=[],
                avg_packet_size=features.get('avg_packet_size', 800),
                packet_size_variance=features.get('packet_size_variance', 0.5),
                packet_size_distribution=features.get('packet_size_distribution', {}),
                avg_inter_packet_delay=features.get('avg_inter_packet_delay', 50.0),
                delay_variance=features.get('delay_variance', 0.5),
                burst_patterns=features.get('burst_patterns', []),
                session_duration_range=(30.0, 300.0),
                idle_periods=features.get('idle_periods', []),
                bidirectional_ratio=features.get('bidirectional_ratio', 0.6),
                keep_alive_pattern=None,
                http_headers={},
                tls_patterns={},
                udp_patterns={},
                steganographic_support=True,
                embedding_capacity=0.1,
                detection_resistance=0.6
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
    
    def _extract_packet_size_statistics(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract packet size statistics."""
        packet_sizes = [len(packet) for packet, _ in packet_sequence]
        
        if not packet_sizes:
            return {}
        
        avg_size = sum(packet_sizes) / len(packet_sizes)
        variance = sum((size - avg_size) ** 2 for size in packet_sizes) / len(packet_sizes)
        
        # Size distribution
        small_count = sum(1 for size in packet_sizes if size < 500)
        medium_count = sum(1 for size in packet_sizes if 500 <= size < 1000)
        large_count = sum(1 for size in packet_sizes if size >= 1000)
        total = len(packet_sizes)
        
        return {
            'avg_packet_size': avg_size,
            'packet_size_variance': variance / (avg_size ** 2) if avg_size > 0 else 0,
            'packet_size_distribution': {
                'small': small_count / total if total > 0 else 0,
                'medium': medium_count / total if total > 0 else 0,
                'large': large_count / total if total > 0 else 0
            },
            'min_size': min(packet_sizes),
            'max_size': max(packet_sizes)
        }
    
    def _extract_timing_statistics(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract timing statistics."""
        if len(packet_sequence) < 2:
            return {}
        
        delays = [delay for _, delay in packet_sequence[1:]]  # Skip first packet
        
        if not delays:
            return {}
        
        avg_delay = sum(delays) / len(delays)
        variance = sum((delay - avg_delay) ** 2 for delay in delays) / len(delays)
        
        return {
            'avg_inter_packet_delay': avg_delay,
            'delay_variance': variance / (avg_delay ** 2) if avg_delay > 0 else 0,
            'min_delay': min(delays),
            'max_delay': max(delays)
        }
    
    def _extract_burst_patterns(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract burst patterns."""
        if len(packet_sequence) < 3:
            return {}
        
        bursts = []
        current_burst = 1
        burst_start_time = 0
        
        for i, (_, delay) in enumerate(packet_sequence[1:], 1):
            if delay < 20.0:  # Consider packets within 20ms as part of same burst
                current_burst += 1
            else:
                if current_burst > 1:
                    bursts.append((current_burst, delay))
                current_burst = 1
        
        # Add final burst
        if current_burst > 1:
            bursts.append((current_burst, 0))
        
        return {
            'burst_patterns': bursts,
            'avg_burst_size': sum(size for size, _ in bursts) / len(bursts) if bursts else 1,
            'burst_count': len(bursts)
        }
    
    def _extract_protocol_features(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract protocol-specific features."""
        if not packet_sequence:
            return {}
        
        http_count = 0
        tls_count = 0
        udp_count = 0
        
        for packet, _ in packet_sequence:
            packet_str = packet.decode('utf-8', errors='ignore')
            if 'HTTP/' in packet_str or 'GET ' in packet_str or 'POST ' in packet_str:
                http_count += 1
            elif b'\x16\x03' in packet:  # TLS handshake
                tls_count += 1
            elif len(packet) < 100:  # Likely UDP
                udp_count += 1
        
        total = len(packet_sequence)
        return {
            'http_ratio': http_count / total if total > 0 else 0,
            'tls_ratio': tls_count / total if total > 0 else 0,
            'udp_ratio': udp_count / total if total > 0 else 0
        }
    
    def _extract_behavioral_features(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Extract behavioral features."""
        if len(packet_sequence) < 2:
            return {}
        
        # Calculate bidirectional ratio (simplified)
        bidirectional_ratio = 0.6  # Default assumption
        
        # Calculate idle periods
        idle_periods = []
        for _, delay in packet_sequence[1:]:
            if delay > 100.0:  # Consider delays > 100ms as idle periods
                idle_periods.append((delay - 100.0, delay))
        
        return {
            'bidirectional_ratio': bidirectional_ratio,
            'idle_periods': idle_periods,
            'total_idle_time': sum(start for start, _ in idle_periods)
        }
    
    def _match_signatures(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Match features against known signatures."""
        matches = {}
        
        for app_name, signature in self._signature_database.items():
            score = 0.0
            
            # Match packet size characteristics
            if 'packet_size_stats' in features:
                size_stats = features['packet_size_stats']
                if 'avg_packet_size' in size_stats:
                    size_diff = abs(size_stats['avg_packet_size'] - signature.avg_packet_size)
                    size_score = max(0, 1.0 - size_diff / signature.avg_packet_size)
                    score += size_score * 0.3
            
            # Match timing characteristics
            if 'timing_stats' in features:
                timing_stats = features['timing_stats']
                if 'avg_inter_packet_delay' in timing_stats:
                    delay_diff = abs(timing_stats['avg_inter_packet_delay'] - signature.avg_inter_packet_delay)
                    delay_score = max(0, 1.0 - delay_diff / signature.avg_inter_packet_delay)
                    score += delay_score * 0.3
            
            # Match protocol characteristics
            if 'protocol_features' in features:
                protocol_features = features['protocol_features']
                if signature.category == ApplicationCategory.VIDEO_CONFERENCING:
                    if protocol_features.get('udp_ratio', 0) > 0.1:
                        score += 0.2
                elif signature.category == ApplicationCategory.BROWSING:
                    if protocol_features.get('http_ratio', 0) > 0.3:
                        score += 0.2
            
            if score > 0.3:  # Minimum threshold for matching
                matches[app_name] = score
        
        return matches
    
    def _calculate_confidence_scores(self, features: Dict[str, Any], matches: Dict[str, float]) -> Dict[str, float]:
        """Calculate confidence scores for matches."""
        confidence_scores = {}
        
        for app_name, base_score in matches.items():
            # Adjust confidence based on feature completeness
            feature_completeness = len(features) / len(self._feature_extractors)
            confidence = base_score * feature_completeness
            
            # Normalize to 0-1 range
            confidence_scores[app_name] = min(confidence, 1.0)
        
        return confidence_scores
    
    def _identify_steganographic_opportunities(
        self, 
        packet_sequence: List[Tuple[bytes, float]], 
        features: Dict[str, Any]
    ) -> Dict[str, float]:
        """Identify opportunities for steganographic embedding."""
        opportunities = {}
        
        # Analyze packet sizes for embedding capacity
        if 'packet_size_stats' in features:
            size_stats = features['packet_size_stats']
            avg_size = size_stats.get('avg_packet_size', 800)
            
            # Larger packets have more embedding capacity
            if avg_size > 1000:
                opportunities['lsb_embedding'] = 0.8
            elif avg_size > 500:
                opportunities['lsb_embedding'] = 0.6
            else:
                opportunities['lsb_embedding'] = 0.3
        
        # Analyze timing for timing channel opportunities
        if 'timing_stats' in features:
            timing_stats = features['timing_stats']
            avg_delay = timing_stats.get('avg_inter_packet_delay', 50.0)
            
            # Moderate delays are good for timing channels
            if 20.0 <= avg_delay <= 100.0:
                opportunities['timing_channel'] = 0.7
            else:
                opportunities['timing_channel'] = 0.4
        
        # Analyze protocol features for header modification opportunities
        if 'protocol_features' in features:
            protocol_features = features['protocol_features']
            http_ratio = protocol_features.get('http_ratio', 0)
            
            if http_ratio > 0.3:
                opportunities['header_modification'] = 0.8
            else:
                opportunities['header_modification'] = 0.3
        
        return opportunities
    
    def _generate_recommendations(
        self, 
        matches: Dict[str, float], 
        confidence_scores: Dict[str, float]
    ) -> List[str]:
        """Generate profile recommendations."""
        recommendations = []
        
        # Sort matches by confidence
        sorted_matches = sorted(matches.items(), key=lambda x: x[1], reverse=True)
        
        for app_name, score in sorted_matches[:3]:  # Top 3 matches
            if score > 0.5:  # High confidence threshold
                recommendations.append(app_name)
        
        # Add fallback recommendations
        if not recommendations:
            recommendations = ['chrome', 'telegram', 'zoom']
        
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
    
    def analyze_pcap_file(self, filepath: str, **kwargs) -> Optional[ProfilingResult]:
        """
        Analyze a pcap file to extract traffic patterns and signatures.

        Args:
            filepath: Path to the pcap or pcapng file.
            **kwargs: Additional context for analysis:
                - real_time: Enable real-time analysis mode
                - behavioral_analysis: Enable deep behavioral analysis
                - steganographic_analysis: Check for potential steganographic channels
                - protocol_specific: Protocol-specific analysis options

        Returns:
            ProfilingResult object or None if analysis fails.
        """
        if not SCAPY_AVAILABLE:
            LOG.error("Scapy is not installed. Cannot analyze pcap files.")
            return None

        LOG.info(f"Analyzing pcap file: {filepath}")

        try:
            packets = rdpcap(filepath)

            if not packets:
                LOG.warning(f"No packets found in pcap file: {filepath}")
                return None

            # Configuration from kwargs
            real_time = kwargs.get('real_time', False)
            behavioral_analysis = kwargs.get('behavioral_analysis', True)
            steganographic_analysis = kwargs.get('steganographic_analysis', True)
            protocol_options = kwargs.get('protocol_specific', {})

            # Convert scapy packets to enriched packet sequence format
            packet_sequence = []
            flow_stats = defaultdict(int)
            last_timestamp = None
            current_flow = None

            for packet in packets:
                if not hasattr(packet, 'time') or not hasattr(packet, 'payload'):
                    continue

                timestamp = float(packet.time)
                delay = 0.0 if last_timestamp is None else (timestamp - last_timestamp) * 1000
                last_timestamp = timestamp

                # Extract enriched packet information
                packet_info = self._extract_packet_info(packet)
                if not packet_info:
                    continue

                payload, ip_info, transport_info = packet_info

                # Flow tracking
                flow_key = self._get_flow_key(ip_info, transport_info)
                if flow_key != current_flow:
                    if current_flow:
                        flow_stats[current_flow] += 1
                    current_flow = flow_key

                # Real-time analysis feedback
                if real_time:
                    self._process_realtime_feedback(packet_info)

                # Build enriched packet entry
                packet_entry = {
                    'payload': payload,
                    'delay': delay,
                    'timestamp': timestamp,
                    'ip': ip_info,
                    'transport': transport_info,
                    'flow_key': flow_key,
                    'size': len(payload)
                }

                packet_sequence.append((packet_entry, delay))

            if not packet_sequence:
                LOG.warning(f"Could not extract a valid packet sequence from {filepath}")
                return None

            # Build enhanced analysis context
            analysis_context = {
                'context': kwargs.get('context', {}),
                'flow_statistics': dict(flow_stats),
                'behavioral_patterns': self._extract_behavioral_patterns(packet_sequence) if behavioral_analysis else None,
                'protocol_metrics': self._analyze_protocol_patterns(packet_sequence, protocol_options),
                'steganographic_opportunities': (
                    self._identify_steganographic_channels(packet_sequence) 
                    if steganographic_analysis else None
                )
            }

            # Perform comprehensive analysis
            result = self.analyze_traffic(
                [entry for entry, _ in packet_sequence], 
                analysis_context
            )

            if result and behavioral_analysis:
                # Enrich result with behavioral insights
                result.metadata.update({
                    'flow_analysis': self._analyze_flow_patterns(flow_stats),
                    'behavioral_markers': analysis_context['behavioral_patterns'],
                    'protocol_insights': analysis_context['protocol_metrics']
                })

            return result

        except Exception as e:
            LOG.error(f"Failed to analyze pcap file {filepath}: {e}")
            return None
            
    def _extract_packet_info(self, packet) -> Optional[Tuple[bytes, Dict, Dict]]:
        """Extract enriched packet information."""
        try:
            # Extract IP layer info
            ip_layer = packet.payload
            ip_info = {
                'version': ip_layer.version,
                'src': ip_layer.src,
                'dst': ip_layer.dst,
                'proto': ip_layer.proto
            }

            # Extract transport layer info
            transport_layer = ip_layer.payload
            transport_info = {
                'sport': getattr(transport_layer, 'sport', 0),
                'dport': getattr(transport_layer, 'dport', 0),
                'flags': getattr(transport_layer, 'flags', 0)
            }

            # Get application payload
            payload = bytes(transport_layer.payload)

            return payload, ip_info, transport_info

        except Exception as e:
            LOG.debug(f"Could not extract packet info: {e}")
            return None

    def _get_flow_key(self, ip_info: Dict, transport_info: Dict) -> str:
        """Generate unique flow identifier."""
        return f"{ip_info['src']}:{transport_info['sport']}-{ip_info['dst']}:{transport_info['dport']}"

    def _process_realtime_feedback(self, packet_info: Tuple[bytes, Dict, Dict]):
        """Process packet for real-time analysis feedback."""
        payload, ip_info, transport_info = packet_info
        
        # Update flow statistics in real-time
        flow_key = self._get_flow_key(ip_info, transport_info)
        
        # Quick pattern matching for anomaly detection
        anomaly_score = self._quick_anomaly_check(payload, transport_info)
        if anomaly_score > 0.8:  # High anomaly threshold
            LOG.warning(f"Potential anomaly detected in flow {flow_key}")

    def _quick_anomaly_check(self, payload: bytes, transport_info: Dict) -> float:
        """Quick real-time anomaly detection."""
        score = 0.0
        
        # Size-based checks
        if len(payload) > 1500 or len(payload) < 20:
            score += 0.3
            
        # Port-based checks
        if transport_info['dport'] in [22, 23, 3389]:  # Suspicious ports
            score += 0.2
            
        # Pattern-based checks
        if b'\x00' * 8 in payload:  # Repeated null bytes
            score += 0.3
            
        return min(score, 1.0)

    def _extract_behavioral_patterns(self, packet_sequence: List[Tuple[Dict, float]]) -> Dict[str, Any]:
        """Extract complex behavioral patterns from packet sequence."""
        patterns = {
            'burst_patterns': [],
            'timing_patterns': [],
            'size_patterns': [],
            'direction_patterns': []
        }
        
        current_burst = []
        last_direction = None
        
        for packet, delay in packet_sequence:
            # Analyze bursts
            if delay < 50.0:  # Packets within 50ms are considered a burst
                current_burst.append(packet)
            else:
                if current_burst:
                    patterns['burst_patterns'].append({
                        'size': len(current_burst),
                        'avg_packet_size': sum(p['size'] for p in current_burst) / len(current_burst),
                        'duration': sum(p['delay'] for p in current_burst)
                    })
                current_burst = [packet]
            
            # Analyze timing
            patterns['timing_patterns'].append({
                'delay': delay,
                'size': packet['size'],
                'timestamp': packet['timestamp']
            })
            
            # Analyze packet sizes
            patterns['size_patterns'].append(packet['size'])
            
            # Analyze direction changes
            current_direction = packet['ip']['src']
            if last_direction and current_direction != last_direction:
                patterns['direction_patterns'].append({
                    'timestamp': packet['timestamp'],
                    'previous': last_direction,
                    'current': current_direction
                })
            last_direction = current_direction
        
        return patterns

    def _analyze_protocol_patterns(self, packet_sequence: List[Tuple[Dict, float]], options: Dict) -> Dict[str, Any]:
        """Analyze protocol-specific patterns."""
        protocol_metrics = {
            'http': {'requests': 0, 'responses': 0},
            'tls': {'handshakes': 0, 'data': 0},
            'udp': {'packets': 0},
            'tcp': {
                'syn': 0,
                'synack': 0,
                'established': 0,
                'fin': 0
            }
        }
        
        for packet, _ in packet_sequence:
            payload = packet['payload']
            transport = packet['transport']
            
            # HTTP detection
            if b'HTTP/' in payload or b'GET ' in payload or b'POST ' in payload:
                protocol_metrics['http']['requests'] += 1
            elif b'200 OK' in payload or b'404 Not Found' in payload:
                protocol_metrics['http']['responses'] += 1
                
            # TLS detection
            if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                protocol_metrics['tls']['handshakes'] += 1
            elif len(payload) > 5 and payload[0] == 0x17:  # TLS Application Data
                protocol_metrics['tls']['data'] += 1
                
            # TCP flags analysis
            if transport['flags']:
                if transport['flags'] & 0x02:  # SYN
                    protocol_metrics['tcp']['syn'] += 1
                if transport['flags'] & 0x12:  # SYN-ACK
                    protocol_metrics['tcp']['synack'] += 1
                if transport['flags'] & 0x01:  # FIN
                    protocol_metrics['tcp']['fin'] += 1
                    
            # UDP tracking
            if packet['ip']['proto'] == 17:  # UDP
                protocol_metrics['udp']['packets'] += 1
                
        return protocol_metrics

    def _identify_steganographic_channels(self, packet_sequence: List[Tuple[Dict, float]]) -> Dict[str, float]:
        """Identify potential steganographic channels in the traffic."""
        opportunities = {}
        total_packets = len(packet_sequence)
        
        # Analyze LSB embedding potential
        payload_sizes = [p['size'] for p, _ in packet_sequence]
        if len(payload_sizes) > 10:
            avg_size = sum(payload_sizes) / len(payload_sizes)
            if avg_size > 500:  # Large packets good for LSB
                opportunities['lsb_embedding'] = min(avg_size / 1500, 0.9)
                
        # Analyze timing channel potential
        delays = [delay for _, delay in packet_sequence]
        if len(delays) > 10:
            delay_variance = sum((d - sum(delays)/len(delays))**2 for d in delays) / len(delays)
            if 10 < delay_variance < 1000:  # Good timing variance for covert channel
                opportunities['timing_channel'] = 0.7
                
        # Analyze protocol extension potential
        http_count = sum(1 for p, _ in packet_sequence if b'HTTP/' in p['payload'])
        if http_count > total_packets * 0.3:  # Significant HTTP traffic
            opportunities['header_modification'] = 0.8
            
        return opportunities

    def _analyze_flow_patterns(self, flow_stats: Dict[str, int]) -> Dict[str, Any]:
        """Analyze flow patterns for behavioral insights."""
        flow_analysis = {
            'total_flows': len(flow_stats),
            'flow_distribution': {},
            'flow_entropy': 0.0,
            'dominant_flows': []
        }
        
        # Calculate flow distribution
        total_packets = sum(flow_stats.values())
        for flow, count in flow_stats.items():
            percentage = count / total_packets
            flow_analysis['flow_distribution'][flow] = percentage
            
            # Calculate entropy
            if percentage > 0:
                flow_analysis['flow_entropy'] -= percentage * math.log2(percentage)
                
        # Find dominant flows
        dominant_flows = sorted(flow_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        flow_analysis['dominant_flows'] = [
            {'flow': flow, 'packet_count': count, 'percentage': count/total_packets}
            for flow, count in dominant_flows
        ]
        
        return flow_analysis

    def analyze_traffic(
        self, 
        packet_sequence: List[Tuple[bytes, float]], 
        context: Dict[str, Any]
    ) -> ProfilingResult:
        """Analyze traffic and generate profiling results."""
        try:
            # Check cache first
            cache_key = self._generate_cache_key(packet_sequence)
            if cache_key in self._profile_cache:
                return self._profile_cache[cache_key]
            
            # Perform analysis
            result = self.analyzer.analyze_packet_sequence(packet_sequence, context)
            
            # Cache result
            self._profile_cache[cache_key] = result
            
            # Store in history
            self._analysis_history.append({
                'timestamp': time.time(),
                'sequence_length': len(packet_sequence),
                'detected_applications': result.detected_applications,
                'confidence_scores': result.confidence_scores
            })
            
            return result
            
        except Exception as e:
            LOG.error(f"Advanced traffic profiling failed: {e}")
            return ProfilingResult(
                success=False,
                detected_applications=[],
                confidence_scores={},
                traffic_signatures=[],
                recommended_profiles=[],
                steganographic_opportunities={}
            )
    
    def create_enhanced_profile(
        self, 
        base_profile_name: str, 
        steganographic_config: Optional[SteganographicConfig] = None
    ) -> Dict[str, Any]:
        """Create enhanced traffic profile with steganographic capabilities."""
        try:
            # Get base signature
            signature = self.analyzer.get_signature(base_profile_name)
            if not signature:
                LOG.warning(f"No signature found for {base_profile_name}")
                return {}
            
            # Create enhanced profile
            enhanced_profile = {
                'name': f"{base_profile_name}_enhanced",
                'base_profile': base_profile_name,
                'signature': signature,
                'steganographic_config': steganographic_config or SteganographicConfig(),
                'embedding_capacity': signature.embedding_capacity,
                'detection_resistance': signature.detection_resistance,
                'recommended_methods': self._get_recommended_steganographic_methods(signature),
                'traffic_pattern': self._create_traffic_pattern_from_signature(signature),
                'metadata': {
                    'created_at': time.time(),
                    'enhancement_level': 'advanced',
                    'steganographic_support': signature.steganographic_support
                }
            }
            
            return enhanced_profile
            
        except Exception as e:
            LOG.error(f"Enhanced profile creation failed: {e}")
            return {}
    
    def _generate_cache_key(self, packet_sequence: List[Tuple[bytes, float]]) -> str:
        """Generate cache key for packet sequence."""
        # Create hash of packet sizes and timing
        data = []
        for packet, delay in packet_sequence:
            data.extend([len(packet), int(delay * 1000)])  # Convert delay to milliseconds
        
        return hashlib.md5(str(data).encode()).hexdigest()
    
    def _get_recommended_steganographic_methods(self, signature: TrafficSignature) -> List[str]:
        """Get recommended steganographic methods for signature."""
        methods = []
        
        if signature.steganographic_support:
            if signature.embedding_capacity > 0.1:
                methods.append('lsb_payload')
            
            if signature.avg_inter_packet_delay > 20.0:
                methods.append('timing_channel')
            
            if signature.category in [ApplicationCategory.BROWSING, ApplicationCategory.MESSAGING]:
                methods.append('header_modification')
            
            if len(methods) > 1:
                methods.append('multi_layer')
        
        return methods
    
    def _create_traffic_pattern_from_signature(self, signature: TrafficSignature) -> TrafficPattern:
        """Create TrafficPattern from signature."""
        return TrafficPattern(
            packet_sizes=(
                int(signature.avg_packet_size * 0.5),
                int(signature.avg_packet_size * 1.5),
                signature.avg_packet_size
            ),
            inter_packet_delays=(
                signature.avg_inter_packet_delay * 0.5,
                signature.avg_inter_packet_delay * 1.5,
                signature.avg_inter_packet_delay
            ),
            burst_size_range=(1, max(1, int(signature.avg_packet_size / 200))),
            burst_interval_range=(
                signature.avg_inter_packet_delay * 2,
                signature.avg_inter_packet_delay * 4
            ),
            session_duration_range=signature.session_duration_range,
            idle_periods=signature.idle_periods,
            bidirectional_ratio=signature.bidirectional_ratio,
            keep_alive_interval=signature.keep_alive_pattern[0] if signature.keep_alive_pattern else 30.0,
            protocol_headers=signature.http_headers,
            content_patterns=[]
        )
    
    def get_profiling_stats(self) -> Dict[str, Any]:
        """Get profiling statistics."""
        return {
            'cache_size': len(self._profile_cache),
            'analysis_count': len(self._analysis_history),
            'recent_analyses': self._analysis_history[-10:] if self._analysis_history else [],
            'steganographic_stats': self.steganographic_manager.get_engine_stats()
        }

    def create_enhanced_traffic_profile(
        self,
        packet_sequence: List[Tuple[bytes, float]],
        app_name: str,
        **kwargs
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

            # Extract behavioral patterns
            behavioral_patterns = self._extract_behavioral_patterns(
                [({"payload": p, "size": len(p), "timestamp": time.time(), 
                   "ip": {}, "transport": {}}, d) for p, d in packet_sequence]
            )

            # Calculate basic metrics
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
                        sum((x - sum(packet_sizes)/len(packet_sizes))**2 
                            for x in packet_sizes) / len(packet_sizes)
                    )
                },
                "timing_metrics": {
                    "min_delay": min(delays),
                    "max_delay": max(delays),
                    "avg_delay": sum(delays) / len(delays),
                    "delay_stddev": math.sqrt(
                        sum((x - sum(delays)/len(delays))**2 
                            for x in delays) / len(delays)
                    )
                },
                "behavioral_patterns": behavioral_patterns,
                "burst_characteristics": {
                    "patterns": behavioral_patterns["burst_patterns"],
                    "typical_burst_size": sum(p["size"] for p in behavioral_patterns["burst_patterns"]) / len(behavioral_patterns["burst_patterns"])
                        if behavioral_patterns["burst_patterns"] else 0
                },
                "direction_analysis": {
                    "patterns": behavioral_patterns["direction_patterns"],
                    "changes": len(behavioral_patterns["direction_patterns"])
                }
            }

            # Add ML-based pattern classification if requested
            if kwargs.get("ml_classification"):
                profile["ml_patterns"] = self._classify_traffic_patterns(packet_sequence)

            # Add steganographic hints if requested
            if kwargs.get("steganographic_hints"):
                profile["steganographic_hints"] = self._identify_steganographic_channels(
                    [({"payload": p, "size": len(p)}, d) for p, d in packet_sequence]
                )

            # Calculate profile quality metrics
            profile["quality_metrics"] = {
                "pattern_stability": self._calculate_pattern_stability(behavioral_patterns),
                "mimicry_effectiveness": self._estimate_mimicry_effectiveness(profile),
                "detection_resistance": self._estimate_detection_resistance(profile)
            }

            return profile

        except Exception as e:
            LOG.error(f"Failed to create enhanced traffic profile: {e}")
            return None

    def _calculate_pattern_stability(self, patterns: Dict[str, Any]) -> float:
        """Calculate stability score for behavioral patterns."""
        stability_score = 0.0
        total_metrics = 0

        # Check burst pattern stability
        if patterns["burst_patterns"]:
            burst_sizes = [p["size"] for p in patterns["burst_patterns"]]
            if burst_sizes:
                mean_size = sum(burst_sizes) / len(burst_sizes)
                variance = sum((x - mean_size)**2 for x in burst_sizes) / len(burst_sizes)
                stability_score += max(0, 1 - (variance / mean_size if mean_size > 0 else 1))
                total_metrics += 1

        # Check timing pattern stability
        if patterns["timing_patterns"]:
            delays = [p["delay"] for p in patterns["timing_patterns"]]
            if delays:
                mean_delay = sum(delays) / len(delays)
                variance = sum((x - mean_delay)**2 for x in delays) / len(delays)
                stability_score += max(0, 1 - min(variance / 1000.0, 1.0))
                total_metrics += 1

        # Check direction pattern stability
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

        # Check packet size distribution
        metrics = profile["packet_metrics"]
        if metrics["max_size"] > 0:
            size_variability = metrics["size_stddev"] / metrics["avg_size"]
            effectiveness += max(0, 1 - min(size_variability, 1.0))
            total_factors += 1

        # Check timing characteristics
        timing = profile["timing_metrics"]
        if timing["max_delay"] > 0:
            timing_consistency = timing["delay_stddev"] / timing["avg_delay"]
            effectiveness += max(0, 1 - min(timing_consistency, 1.0))
            total_factors += 1

        # Check burst characteristics
        if profile["burst_characteristics"]["patterns"]:
            effectiveness += 0.8  # Good burst patterns improve mimicry
            total_factors += 1

        return effectiveness / total_factors if total_factors > 0 else 0.0

    def _estimate_detection_resistance(self, profile: Dict[str, Any]) -> float:
        """Estimate how resistant the profile is to DPI detection."""
        resistance_score = 0.0
        total_factors = 0

        # Size-based resistance
        metrics = profile["packet_metrics"]
        if 200 <= metrics["avg_size"] <= 1400:  # Good size range
            resistance_score += 0.8
        else:
            resistance_score += 0.4
        total_factors += 1

        # Timing-based resistance
        timing = profile["timing_metrics"]
        if 10 <= timing["avg_delay"] <= 1000:  # Good timing range
            resistance_score += 0.9
        else:
            resistance_score += 0.3
        total_factors += 1

        # Pattern-based resistance
        patterns = profile["behavioral_patterns"]
        if patterns["burst_patterns"]:
            if len(patterns["burst_patterns"]) >= 3:  # Good variety of bursts
                resistance_score += 0.7
            else:
                resistance_score += 0.4
            total_factors += 1

        return resistance_score / total_factors if total_factors > 0 else 0.0

    def _classify_traffic_patterns(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, Any]:
        """Use ML techniques to classify traffic patterns."""
        patterns = {
            "likely_protocols": [],
            "behavioral_class": None,
            "confidence_scores": {}
        }

        # Extract ML features
        features = self._extract_ml_features(packet_sequence)

        # Protocol classification
        protocols = ["HTTP", "TLS", "DNS", "Unknown"]
        scores = self._calculate_protocol_scores(features)
        patterns["confidence_scores"] = {
            proto: score for proto, score in zip(protocols, scores)
        }
        patterns["likely_protocols"] = [
            proto for proto, score in patterns["confidence_scores"].items()
            if score > 0.6
        ]

        # Behavioral classification
        behavior_score = self._classify_behavioral_pattern(features)
        patterns["behavioral_class"] = {
            "type": self._get_behavior_class(behavior_score),
            "confidence": behavior_score
        }

        return patterns

    def _extract_ml_features(self, packet_sequence: List[Tuple[bytes, float]]) -> Dict[str, float]:
        """Extract features for ML classification."""
        features = {}

        # Basic statistical features
        sizes = [len(p) for p, _ in packet_sequence]
        delays = [d for _, d in packet_sequence]

        features.update({
            "avg_size": sum(sizes) / len(sizes) if sizes else 0,
            "size_variance": sum((x - features["avg_size"])**2 for x in sizes) / len(sizes) if sizes else 0,
            "avg_delay": sum(delays) / len(delays) if delays else 0,
            "delay_variance": sum((x - features["avg_delay"])**2 for x in delays) / len(delays) if delays else 0,
            "packet_count": len(packet_sequence)
        })

        # Protocol indicators
        http_count = sum(1 for p, _ in packet_sequence if b"HTTP/" in p[0])
        tls_count = sum(1 for p, _ in packet_sequence if len(p[0]) > 5 and p[0][0] == 0x16)
        features.update({
            "http_ratio": http_count / len(packet_sequence) if packet_sequence else 0,
            "tls_ratio": tls_count / len(packet_sequence) if packet_sequence else 0
        })

        return features

    def _calculate_protocol_scores(self, features: Dict[str, float]) -> List[float]:
        """Calculate confidence scores for each protocol."""
        scores = [0.0] * 4  # HTTP, TLS, DNS, Unknown

        # HTTP score
        if features["http_ratio"] > 0.3:
            scores[0] = min(features["http_ratio"] * 2, 1.0)

        # TLS score
        if features["tls_ratio"] > 0.3:
            scores[1] = min(features["tls_ratio"] * 2, 1.0)

        # DNS score
        if features["avg_size"] < 100 and features["size_variance"] < 1000:
            scores[2] = 0.7

        # Unknown score (fallback)
        scores[3] = 1.0 - max(scores[0], scores[1], scores[2])

        return scores

    def _classify_behavioral_pattern(self, features: Dict[str, float]) -> float:
        """Classify behavioral pattern confidence."""
        score = 0.0

        # Size-based scoring
        if 200 <= features["avg_size"] <= 1400:
            score += 0.3

        # Timing-based scoring
        if 10 <= features["avg_delay"] <= 1000:
            score += 0.3

        # Protocol-based scoring
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
