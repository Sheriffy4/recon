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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from enum import Enum
from collections import defaultdict, Counter

from .traffic_mimicry import TrafficPattern, TrafficType
from .steganographic_engine import SteganographicManager, SteganographicConfig

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
