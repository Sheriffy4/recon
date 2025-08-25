"""
MultisplitAttack implementation using segments architecture.

This attack splits the payload into multiple small segments with configurable
overlap and timing variations. This technique confuses DPI systems that expect
contiguous data streams and can't properly reassemble fragmented content.

Attack Strategy:
1. Split payload into N configurable segments
2. Add optional overlap between segments for redundancy
3. Send segments with varying delays to confuse timing analysis
4. Use different TCP options for each segment to avoid pattern detection
"""
import asyncio
import logging
import random
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from core.bypass.attacks.base import BaseAttack, AttackResult, AttackStatus, AttackContext

@dataclass
class MultisplitConfig:
    """Configuration for MultisplitAttack."""
    split_count: int = 5
    min_segment_size: int = 10
    max_segment_size: int = 0
    overlap_bytes: int = 0
    base_delay_ms: float = 5.0
    delay_variation_ms: float = 3.0
    randomize_order: bool = False
    vary_ttl: bool = False
    ttl_range: Tuple[int, int] = (60, 64)
    vary_tcp_flags: bool = False
    vary_window_size: bool = False
    window_size_range: Tuple[int, int] = (32768, 65535)
    add_padding: bool = False
    padding_range: Tuple[int, int] = (1, 5)
    corrupt_some_checksums: bool = False
    checksum_corruption_probability: float = 0.2
    exponential_backoff: bool = False
    backoff_multiplier: float = 1.5

class MultisplitAttack(BaseAttack):
    """
    MultisplitAttack using segments architecture.

    This attack implements payload fragmentation with configurable overlap,
    timing variations, and TCP option diversity to bypass DPI systems that
    rely on contiguous data analysis.
    """

    def __init__(self, name: str='multisplit', config: Optional[MultisplitConfig]=None):
        super().__init__(name)
        self.config = config or MultisplitConfig()
        self.logger = logging.getLogger(f'MultisplitAttack.{name}')
        self._validate_config()

    def _validate_config(self):
        """Validate attack configuration."""
        if not 2 <= self.config.split_count <= 20:
            raise ValueError(f'split_count must be between 2 and 20, got {self.config.split_count}')
        if self.config.min_segment_size < 1:
            raise ValueError(f'min_segment_size must be at least 1, got {self.config.min_segment_size}')
        if self.config.max_segment_size > 0 and self.config.max_segment_size < self.config.min_segment_size:
            raise ValueError(f'max_segment_size ({self.config.max_segment_size}) must be >= min_segment_size ({self.config.min_segment_size})')
        if self.config.overlap_bytes < 0:
            raise ValueError(f'overlap_bytes must be non-negative, got {self.config.overlap_bytes}')
        if self.config.base_delay_ms < 0:
            raise ValueError(f'base_delay_ms must be non-negative, got {self.config.base_delay_ms}')
        if self.config.delay_variation_ms < 0:
            raise ValueError(f'delay_variation_ms must be non-negative, got {self.config.delay_variation_ms}')
        if not 0.0 <= self.config.checksum_corruption_probability <= 1.0:
            raise ValueError(f'checksum_corruption_probability must be between 0.0 and 1.0, got {self.config.checksum_corruption_probability}')
        if self.config.ttl_range[0] > self.config.ttl_range[1]:
            raise ValueError(f'Invalid TTL range: {self.config.ttl_range}')
        if self.config.window_size_range[0] > self.config.window_size_range[1]:
            raise ValueError(f'Invalid window size range: {self.config.window_size_range}')
        if self.config.padding_range[0] > self.config.padding_range[1]:
            raise ValueError(f'Invalid padding range: {self.config.padding_range}')

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute MultisplitAttack.

        Args:
            context: Attack context containing payload and connection info

        Returns:
            AttackResult with segments for multisplit payload
        """
        try:
            self.logger.info(f'Executing MultisplitAttack on {context.connection_id}')
            if not context.payload:
                return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': 'Empty payload provided'})
            min_required_size = self.config.min_segment_size * self.config.split_count
            if len(context.payload) < min_required_size:
                return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': f'Payload too small for {self.config.split_count} segments. Required: {min_required_size}, got: {len(context.payload)}'})
            segments = await self._create_segments(context.payload)
            if self.config.randomize_order:
                segments = self._randomize_segment_order(segments)
            result = AttackResult(status=AttackStatus.SUCCESS, modified_payload=None, metadata={'attack_type': 'multisplit', 'segments': segments, 'total_segments': len(segments), 'original_payload_size': len(context.payload), 'config': {'split_count': self.config.split_count, 'min_segment_size': self.config.min_segment_size, 'max_segment_size': self.config.max_segment_size, 'overlap_bytes': self.config.overlap_bytes, 'base_delay_ms': self.config.base_delay_ms, 'delay_variation_ms': self.config.delay_variation_ms, 'randomize_order': self.config.randomize_order, 'vary_ttl': self.config.vary_ttl, 'vary_tcp_flags': self.config.vary_tcp_flags, 'vary_window_size': self.config.vary_window_size, 'add_padding': self.config.add_padding, 'corrupt_some_checksums': self.config.corrupt_some_checksums}})
            result._segments = segments
            self.logger.info(f'MultisplitAttack created {len(segments)} segments from {len(context.payload)}-byte payload')
            return result
        except Exception as e:
            self.logger.error(f'MultisplitAttack failed: {e}')
            return AttackResult(status=AttackStatus.FAILED, modified_payload=None, metadata={'error': str(e), 'attack_type': 'multisplit'})

    async def _create_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create segments from payload with configured options.

        Args:
            payload: Original payload to split

        Returns:
            List of segment tuples (payload, seq_offset, options)
        """
        segments = []
        payload_len = len(payload)
        segment_boundaries = self._calculate_segment_boundaries(payload_len)
        for i, (start_pos, end_pos) in enumerate(segment_boundaries):
            segment_data = payload[start_pos:end_pos]
            if self.config.add_padding:
                segment_data = self._add_padding(segment_data)
            seq_offset = start_pos
            options = await self._create_segment_options(i, len(segment_boundaries))
            segments.append((segment_data, seq_offset, options))
        return segments

    def _calculate_segment_boundaries(self, payload_len: int) -> List[Tuple[int, int]]:
        """
        Calculate segment boundaries with optional overlap.

        Args:
            payload_len: Length of payload to split

        Returns:
            List of (start_pos, end_pos) tuples
        """
        boundaries = []
        if self.config.max_segment_size > 0:
            boundaries = self._calculate_size_based_boundaries(payload_len)
        else:
            boundaries = self._calculate_count_based_boundaries(payload_len)
        if self.config.overlap_bytes > 0:
            boundaries = self._add_overlap_to_boundaries(boundaries, payload_len)
        return boundaries

    def _calculate_count_based_boundaries(self, payload_len: int) -> List[Tuple[int, int]]:
        """Calculate boundaries based on split count."""
        boundaries = []
        base_segment_size = payload_len // self.config.split_count
        remainder = payload_len % self.config.split_count
        current_pos = 0
        for i in range(self.config.split_count):
            segment_size = base_segment_size + (1 if i < remainder else 0)
            segment_size = max(segment_size, self.config.min_segment_size)
            end_pos = min(current_pos + segment_size, payload_len)
            if current_pos < payload_len:
                boundaries.append((current_pos, end_pos))
                current_pos = end_pos
            else:
                break
        return boundaries

    def _calculate_size_based_boundaries(self, payload_len: int) -> List[Tuple[int, int]]:
        """Calculate boundaries based on max segment size."""
        boundaries = []
        current_pos = 0
        while current_pos < payload_len:
            if self.config.delay_variation_ms > 0:
                size_variation = random.randint(-self.config.min_segment_size // 2, self.config.min_segment_size // 2)
                segment_size = self.config.max_segment_size + size_variation
            else:
                segment_size = self.config.max_segment_size
            segment_size = max(segment_size, self.config.min_segment_size)
            segment_size = min(segment_size, payload_len - current_pos)
            end_pos = current_pos + segment_size
            boundaries.append((current_pos, end_pos))
            current_pos = end_pos
        return boundaries

    def _add_overlap_to_boundaries(self, boundaries: List[Tuple[int, int]], payload_len: int) -> List[Tuple[int, int]]:
        """Add overlap between segments."""
        if not boundaries or self.config.overlap_bytes == 0:
            return boundaries
        overlapped_boundaries = []
        for i, (start_pos, end_pos) in enumerate(boundaries):
            new_start = start_pos
            new_end = end_pos
            if i < len(boundaries) - 1:
                new_end = min(end_pos + self.config.overlap_bytes, payload_len)
            if i > 0:
                new_start = max(start_pos - self.config.overlap_bytes, 0)
            overlapped_boundaries.append((new_start, new_end))
        return overlapped_boundaries

    async def _create_segment_options(self, segment_index: int, total_segments: int) -> Dict[str, Any]:
        """
        Create options for a segment.

        Args:
            segment_index: Index of current segment
            total_segments: Total number of segments

        Returns:
            Dictionary of segment options
        """
        options = {}
        delay = await self._calculate_segment_delay(segment_index, total_segments)
        options['delay_ms'] = delay
        if self.config.vary_ttl:
            ttl = random.randint(self.config.ttl_range[0], self.config.ttl_range[1])
            options['ttl'] = ttl
        else:
            options['ttl'] = 64
        if self.config.vary_tcp_flags:
            flag_options = [24, 16, 8]
            options['flags'] = random.choice(flag_options)
        else:
            options['flags'] = 24
        if self.config.vary_window_size:
            window_size = random.randint(self.config.window_size_range[0], self.config.window_size_range[1])
            options['window_size'] = window_size
        if self.config.corrupt_some_checksums:
            if random.random() < self.config.checksum_corruption_probability:
                options['bad_checksum'] = True
        return options

    async def _calculate_segment_delay(self, segment_index: int, total_segments: int) -> float:
        """
        Calculate delay for a segment.

        Args:
            segment_index: Index of current segment
            total_segments: Total number of segments

        Returns:
            Delay in milliseconds
        """
        base_delay = self.config.base_delay_ms
        if self.config.exponential_backoff:
            delay = base_delay * self.config.backoff_multiplier ** segment_index
        else:
            delay = base_delay
        if self.config.delay_variation_ms > 0:
            variation = random.uniform(-self.config.delay_variation_ms, self.config.delay_variation_ms)
            delay += variation

        delay = max(0.0, delay)
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
        return delay

    def _add_padding(self, segment_data: bytes) -> bytes:
        """
        Add padding to segment data.

        Args:
            segment_data: Original segment data

        Returns:
            Segment data with padding
        """
        if not self.config.add_padding:
            return segment_data
        padding_size = random.randint(self.config.padding_range[0], self.config.padding_range[1])
        padding = b'\\x00' * padding_size
        return segment_data + padding

    def _randomize_segment_order(self, segments: List[Tuple[bytes, int, Dict[str, Any]]]) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Randomize the order of segments while preserving sequence offsets.

        Args:
            segments: Original segments list

        Returns:
            Randomized segments list
        """
        if not self.config.randomize_order or len(segments) <= 1:
            return segments
        randomized_segments = segments.copy()
        random.shuffle(randomized_segments)
        return randomized_segments

    def get_attack_info(self) -> Dict[str, Any]:
        """
        Get information about this attack.

        Returns:
            Dictionary with attack information
        """
        return {'name': self.name, 'type': 'multisplit', 'description': 'Splits payload into multiple segments with configurable overlap and timing', 'technique': 'payload_fragmentation', 'effectiveness': 'high_against_contiguous_analysis_dpi', 'config': {'split_count': self.config.split_count, 'min_segment_size': self.config.min_segment_size, 'max_segment_size': self.config.max_segment_size, 'overlap_bytes': self.config.overlap_bytes, 'base_delay_ms': self.config.base_delay_ms, 'delay_variation_ms': self.config.delay_variation_ms, 'randomize_order': self.config.randomize_order, 'vary_ttl': self.config.vary_ttl, 'vary_tcp_flags': self.config.vary_tcp_flags, 'vary_window_size': self.config.vary_window_size, 'add_padding': self.config.add_padding, 'corrupt_some_checksums': self.config.corrupt_some_checksums, 'exponential_backoff': self.config.exponential_backoff}, 'segments_created': 'configurable', 'advantages': ['Confuses contiguous data analysis', 'Configurable overlap for redundancy', 'Variable timing to avoid patterns', 'TCP option diversity', 'Scalable segment count']}

    def estimate_effectiveness(self, context: AttackContext) -> float:
        """
        Estimate attack effectiveness for given context.

        Args:
            context: Attack context

        Returns:
            Effectiveness score (0.0 to 1.0)
        """
        effectiveness = 0.6
        if context.payload:
            payload_len = len(context.payload)
            if payload_len > 500:
                effectiveness += 0.1
            if payload_len > 1000:
                effectiveness += 0.1
        if self.config.split_count >= 7:
            effectiveness += 0.1
        if self.config.overlap_bytes > 0:
            effectiveness += 0.05
        if self.config.randomize_order:
            effectiveness += 0.05
        if self.config.vary_ttl or self.config.vary_tcp_flags or self.config.vary_window_size:
            effectiveness += 0.05
        if self.config.corrupt_some_checksums:
            effectiveness += 0.05
        if self.config.exponential_backoff:
            effectiveness += 0.05
        return min(1.0, max(0.0, effectiveness))

    def get_required_capabilities(self) -> List[str]:
        """
        Get list of required capabilities for this attack.

        Returns:
            List of required capability names
        """
        capabilities = ['packet_construction', 'timing_control', 'sequence_manipulation']
        if self.config.vary_ttl:
            capabilities.append('ttl_modification')
        if self.config.vary_tcp_flags:
            capabilities.append('tcp_flags_modification')
        if self.config.vary_window_size:
            capabilities.append('window_size_modification')
        if self.config.corrupt_some_checksums:
            capabilities.append('checksum_corruption')
        return capabilities

    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """
        Validate if attack can be executed with given context.

        Args:
            context: Attack context to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not context.payload:
            return (False, 'Empty payload provided')
        min_required_size = self.config.min_segment_size * self.config.split_count
        if len(context.payload) < min_required_size:
            return (False, f'Payload too small for {self.config.split_count} segments. Required: {min_required_size}, got: {len(context.payload)}')
        if hasattr(context, 'tcp_seq') and context.tcp_seq is not None:
            if context.tcp_seq < 0:
                return (False, f'Invalid TCP sequence number: {context.tcp_seq}')
        return (True, None)

def create_multisplit_attack(name: str='multisplit', split_count: int=5, min_segment_size: int=10, max_segment_size: int=0, overlap_bytes: int=0, base_delay_ms: float=5.0, delay_variation_ms: float=3.0, randomize_order: bool=False, vary_ttl: bool=False, vary_tcp_flags: bool=False, vary_window_size: bool=False, add_padding: bool=False, corrupt_some_checksums: bool=False, exponential_backoff: bool=False) -> MultisplitAttack:
    """
    Factory function to create MultisplitAttack with custom configuration.

    Args:
        name: Attack name
        split_count: Number of segments to create
        min_segment_size: Minimum segment size in bytes
        max_segment_size: Maximum segment size in bytes (0 = no limit)
        overlap_bytes: Overlap between segments in bytes
        base_delay_ms: Base delay between segments
        delay_variation_ms: Random delay variation
        randomize_order: Whether to randomize segment order
        vary_ttl: Whether to use different TTL values
        vary_tcp_flags: Whether to vary TCP flags
        vary_window_size: Whether to vary window sizes
        add_padding: Whether to add padding to segments
        corrupt_some_checksums: Whether to corrupt some checksums
        exponential_backoff: Whether to use exponential backoff for delays

    Returns:
        Configured MultisplitAttack instance
    """
    config = MultisplitConfig(split_count=split_count, min_segment_size=min_segment_size, max_segment_size=max_segment_size, overlap_bytes=overlap_bytes, base_delay_ms=base_delay_ms, delay_variation_ms=delay_variation_ms, randomize_order=randomize_order, vary_ttl=vary_ttl, vary_tcp_flags=vary_tcp_flags, vary_window_size=vary_window_size, add_padding=add_padding, corrupt_some_checksums=corrupt_some_checksums, exponential_backoff=exponential_backoff)
    return MultisplitAttack(name=name, config=config)

def create_aggressive_multisplit() -> MultisplitAttack:
    """Create aggressive variant with maximum fragmentation."""
    return create_multisplit_attack(name='aggressive_multisplit', split_count=10, min_segment_size=8, overlap_bytes=3, base_delay_ms=8.0, delay_variation_ms=5.0, randomize_order=True, vary_ttl=True, vary_tcp_flags=True, vary_window_size=True, add_padding=True, corrupt_some_checksums=True, exponential_backoff=True)

def create_subtle_multisplit() -> MultisplitAttack:
    """Create subtle variant with minimal fragmentation."""
    return create_multisplit_attack(name='subtle_multisplit', split_count=3, min_segment_size=20, overlap_bytes=0, base_delay_ms=2.0, delay_variation_ms=1.0, randomize_order=False, vary_ttl=False, vary_tcp_flags=False, vary_window_size=False, add_padding=False, corrupt_some_checksums=False, exponential_backoff=False)

def create_overlap_multisplit() -> MultisplitAttack:
    """Create variant optimized for overlap-based confusion."""
    return create_multisplit_attack(name='overlap_multisplit', split_count=6, min_segment_size=15, overlap_bytes=5, base_delay_ms=6.0, delay_variation_ms=3.0, randomize_order=True, vary_ttl=True, vary_tcp_flags=False, vary_window_size=False, add_padding=False, corrupt_some_checksums=True, exponential_backoff=False)

def create_timing_multisplit() -> MultisplitAttack:
    """Create variant optimized for timing-based confusion."""
    return create_multisplit_attack(name='timing_multisplit', split_count=7, min_segment_size=12, overlap_bytes=2, base_delay_ms=3.0, delay_variation_ms=8.0, randomize_order=True, vary_ttl=False, vary_tcp_flags=True, vary_window_size=True, add_padding=True, corrupt_some_checksums=False, exponential_backoff=True)