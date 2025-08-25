"""
Traffic Mimicry Attack System

Implements traffic pattern mimicry to blend bypass attempts with legitimate application traffic.
This helps evade behavioral DPI analysis by making bypass traffic look like popular applications.
"""
import asyncio
import time
import random
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack
LOG = logging.getLogger(__name__)

class TrafficType(Enum):
    """Types of traffic patterns that can be mimicked."""
    VIDEO_CALL = 'video_call'
    MESSAGING = 'messaging'
    FILE_TRANSFER = 'file_transfer'
    STREAMING = 'streaming'
    BROWSING = 'browsing'
    GAMING = 'gaming'

@dataclass
class TrafficPattern:
    """Represents a traffic pattern with timing and size characteristics."""
    packet_sizes: Tuple[int, int, int] = (64, 1500, 800)
    inter_packet_delays: Tuple[float, float, float] = (10.0, 100.0, 50.0)
    burst_size_range: Tuple[int, int] = (1, 5)
    burst_interval_range: Tuple[float, float] = (100.0, 500.0)
    session_duration_range: Tuple[float, float] = (30.0, 300.0)
    idle_periods: List[Tuple[float, float]] = field(default_factory=lambda: [(1.0, 5.0)])
    bidirectional_ratio: float = 0.7
    keep_alive_interval: float = 30.0
    protocol_headers: Dict[str, bytes] = field(default_factory=dict)
    content_patterns: List[bytes] = field(default_factory=list)

class TrafficProfile(ABC):
    """
    Abstract base class for application traffic profiles.

    Each profile defines the traffic characteristics of a specific application
    to enable realistic traffic mimicry.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Profile name (e.g., 'zoom', 'telegram')."""
        pass

    @property
    @abstractmethod
    def traffic_type(self) -> TrafficType:
        """Type of traffic this profile represents."""
        pass

    @property
    @abstractmethod
    def pattern(self) -> TrafficPattern:
        """Traffic pattern for this profile."""
        pass

    @abstractmethod
    def should_use_for_domain(self, domain: str) -> bool:
        """
        Determine if this profile should be used for a specific domain.

        Args:
            domain: Target domain name

        Returns:
            True if this profile is suitable for the domain
        """
        pass

    @abstractmethod
    async def generate_packet_sequence(self, payload: bytes, context: AttackContext) -> List[Tuple[bytes, float]]:
        """
        Generate a sequence of packets with timing that mimics the application.

        Args:
            payload: Original payload to disguise
            context: Attack context

        Returns:
            List of (packet_data, delay_before_send) tuples
        """
        pass

    def get_random_packet_size(self) -> int:
        """Get a random packet size based on the profile's distribution."""
        min_size, max_size, avg_size = self.pattern.packet_sizes
        size = random.normalvariate(avg_size, (max_size - min_size) / 6)
        return max(min_size, min(max_size, int(size)))

    def get_random_delay(self) -> float:
        """Get a random inter-packet delay based on the profile."""
        min_delay, max_delay, avg_delay = self.pattern.inter_packet_delays
        delay = random.expovariate(1.0 / avg_delay)
        return max(min_delay, min(max_delay, delay))

    def create_padding(self, target_size: int, current_size: int) -> bytes:
        """Create padding to reach target packet size."""
        if target_size <= current_size:
            return b''
        padding_size = target_size - current_size
        padding_patterns = [b'\x00' * padding_size, bytes([random.randint(0, 255) for _ in range(padding_size)]), (b'PADDING' * (padding_size // 7 + 1))[:padding_size]]
        return random.choice(padding_patterns)

@register_attack
class TrafficMimicryAttack(BaseAttack):
    """
    Traffic Mimicry Attack that disguises bypass attempts as legitimate application traffic.

    This attack analyzes the target domain and selects an appropriate traffic profile
    to mimic, then generates packet sequences that match the behavioral patterns
    of popular applications.
    """

    def __init__(self):
        super().__init__()
        self._profiles: Dict[str, TrafficProfile] = {}
        self._domain_profile_cache: Dict[str, str] = {}
        self._register_default_profiles()

    @property
    def name(self) -> str:
        return 'traffic_mimicry'

    @property
    def description(self) -> str:
        return 'Mimics traffic patterns of popular applications to evade behavioral DPI analysis'

    @property
    def category(self) -> str:
        return 'combo'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp', 'udp']

    def register_profile(self, profile: TrafficProfile):
        """
        Register a new traffic profile.

        Args:
            profile: Traffic profile to register
        """
        self._profiles[profile.name] = profile
        LOG.debug(f'Registered traffic profile: {profile.name}')

    def get_profile(self, name: str) -> Optional[TrafficProfile]:
        """
        Get a traffic profile by name.

        Args:
            name: Profile name

        Returns:
            Traffic profile or None if not found
        """
        return self._profiles.get(name)

    def select_profile_for_domain(self, domain: str, fingerprint: Optional[Any]=None) -> Optional[TrafficProfile]:
        """
        Select the most appropriate traffic profile for a domain.

        Args:
            domain: Target domain name
            fingerprint: Optional DPI fingerprint for intelligent selection

        Returns:
            Selected traffic profile or None if no suitable profile found
        """
        cache_key = f"{domain}_{(fingerprint.short_hash() if fingerprint else 'no_fp')}"
        if cache_key in self._domain_profile_cache:
            cached_profile_name = self._domain_profile_cache[cache_key]
            if cached_profile_name in self._profiles:
                return self._profiles[cached_profile_name]
        if fingerprint:
            selected = self._select_profile_by_fingerprint(domain, fingerprint)
            if selected:
                self._domain_profile_cache[cache_key] = selected.name
                LOG.debug(f"Selected profile '{selected.name}' for domain '{domain}' based on fingerprint")
                return selected
        suitable_profiles = []
        for profile in self._profiles.values():
            if profile.should_use_for_domain(domain):
                suitable_profiles.append(profile)
        if not suitable_profiles:
            if 'generic_browsing' in self._profiles:
                selected = self._profiles['generic_browsing']
            else:
                selected = next(iter(self._profiles.values())) if self._profiles else None
        else:
            selected = random.choice(suitable_profiles)
        if selected:
            self._domain_profile_cache[cache_key] = selected.name
            LOG.debug(f"Selected profile '{selected.name}' for domain '{domain}'")
        return selected

    def _select_profile_by_fingerprint(self, domain: str, fingerprint: Any) -> Optional[TrafficProfile]:
        """
        Select profile based on DPI fingerprint characteristics.

        Args:
            domain: Target domain
            fingerprint: DPI fingerprint with behavioral data

        Returns:
            Best matching profile or None
        """
        profile_scores = {}
        for profile_name, profile in self._profiles.items():
            score = 0.0
            if hasattr(fingerprint, 'ml_detection_blocked') and fingerprint.ml_detection_blocked:
                if profile.traffic_type in [TrafficType.VIDEO_CALL, TrafficType.MESSAGING]:
                    score += 0.3
                else:
                    score += 0.1
            if hasattr(fingerprint, 'stateful_inspection') and fingerprint.stateful_inspection:
                if profile.traffic_type == TrafficType.VIDEO_CALL:
                    score += 0.2
                elif profile.traffic_type == TrafficType.MESSAGING:
                    score += 0.15
            if hasattr(fingerprint, 'payload_entropy_sensitivity') and fingerprint.payload_entropy_sensitivity:
                if profile.traffic_type in [TrafficType.MESSAGING, TrafficType.BROWSING]:
                    score += 0.25
            if hasattr(fingerprint, 'http2_detection') and fingerprint.http2_detection:
                if profile.traffic_type == TrafficType.BROWSING:
                    score += 0.2
            if hasattr(fingerprint, 'quic_udp_blocked') and fingerprint.quic_udp_blocked:
                if profile.traffic_type == TrafficType.VIDEO_CALL:
                    score -= 0.1
            if hasattr(fingerprint, 'rate_limiting_detected') and fingerprint.rate_limiting_detected:
                if profile.traffic_type == TrafficType.MESSAGING:
                    score += 0.2
            if profile.should_use_for_domain(domain):
                score += 0.3
            profile_scores[profile_name] = score
        if profile_scores:
            best_profile_name = max(profile_scores.items(), key=lambda x: x[1])[0]
            best_score = profile_scores[best_profile_name]
            if best_score > 0.4:
                LOG.debug(f'Fingerprint-based selection: {best_profile_name} (score: {best_score:.2f})')
                return self._profiles[best_profile_name]
        return None

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute traffic mimicry attack.

        Args:
            context: Attack execution context

        Returns:
            Attack result with mimicry details
        """
        start_time = time.time()
        try:
            fingerprint = context.params.get('fingerprint') if context.params else None
            domain = context.domain or f'{context.dst_ip}:{context.dst_port}'
            profile = self.select_profile_for_domain(domain, fingerprint)
            if not profile:
                return AttackResult(status=AttackStatus.ERROR, error_message='No suitable traffic profile found', latency_ms=(time.time() - start_time) * 1000)
            packet_sequence = await profile.generate_packet_sequence(context.payload, context)
            if not packet_sequence:
                return AttackResult(status=AttackStatus.ERROR, error_message='Failed to generate packet sequence', latency_ms=(time.time() - start_time) * 1000)
            total_bytes_sent = 0
            packets_sent = 0
            for packet_data, delay in packet_sequence:
                if delay > 0:
                    await asyncio.sleep(delay / 1000.0)
                total_bytes_sent += len(packet_data)
                packets_sent += 1
                if time.time() - start_time > context.timeout:
                    break
            execution_time = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=execution_time, packets_sent=packets_sent, bytes_sent=total_bytes_sent, connection_established=True, data_transmitted=packets_sent > 0, metadata={'profile_used': profile.name, 'traffic_type': profile.traffic_type.value, 'sequence_length': len(packet_sequence), 'total_delay_ms': sum((delay for _, delay in packet_sequence)), 'fingerprint_based_selection': fingerprint is not None})
        except Exception as e:
            LOG.error(f'Traffic mimicry execution failed: {e}')
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _register_default_profiles(self):
        """Register default traffic profiles."""

        def _register_default_profiles(self):
            """Register default traffic profiles."""
            from core.bypass.attacks.combo.traffic_profiles import ZoomTrafficProfile, TelegramTrafficProfile, WhatsAppTrafficProfile, GenericBrowsingProfile
            profiles = [ZoomTrafficProfile(), TelegramTrafficProfile(), WhatsAppTrafficProfile(), GenericBrowsingProfile()]
            for profile in profiles:
                self.register_profile(profile)
            LOG.info(f'Registered {len(profiles)} default traffic profiles')

    def get_available_profiles(self) -> List[str]:
        """Get list of available profile names."""
        return list(self._profiles.keys())

    def get_profile_stats(self) -> Dict[str, Any]:
        """Get statistics about registered profiles."""
        stats = {'total_profiles': len(self._profiles), 'profiles_by_type': {}, 'domain_cache_size': len(self._domain_profile_cache)}
        for profile in self._profiles.values():
            traffic_type = profile.traffic_type.value
            if traffic_type not in stats['profiles_by_type']:
                stats['profiles_by_type'][traffic_type] = 0
            stats['profiles_by_type'][traffic_type] += 1
        return stats