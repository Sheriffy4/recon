# recon/core/bypass/attacks/obfuscation/traffic_obfuscation.py
"""
Traffic Pattern Obfuscation Attacks

Advanced traffic pattern obfuscation techniques that modify packet timing,
sizes, and flow characteristics to evade behavioral DPI analysis.
"""

import time
import random
import math
from typing import List, Dict, Any, Optional, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@register_attack
class TrafficPatternObfuscationAttack(BaseAttack):
    """
    Traffic Pattern Obfuscation Attack.
    
    Modifies traffic patterns to break behavioral fingerprinting by
    altering packet timing, sizes, and flow characteristics.
    """

    @property
    def name(self) -> str:
        return "traffic_pattern_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies traffic patterns to evade behavioral DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute traffic pattern obfuscation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            obfuscation_strategy = context.params.get("obfuscation_strategy", "mixed")
            intensity_level = context.params.get("intensity_level", "medium")
            mimic_application = context.params.get("mimic_application", "web_browsing")

            # Apply traffic pattern obfuscation
            obfuscated_segments = self._apply_pattern_obfuscation(
                payload, obfuscation_strategy, intensity_level, mimic_application
            )

            # Calculate metrics
            packets_sent = len(obfuscated_segments)
            bytes_sent = sum(len(seg[0]) for seg in obfuscated_segments)
            total_delay = sum(seg[1] for seg in obfuscated_segments)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="traffic_pattern_obfuscation",
                metadata={
                    "obfuscation_strategy": obfuscation_strategy,
                    "intensity_level": intensity_level,
                    "mimic_application": mimic_application,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "total_delay_ms": total_delay,
                    "expansion_ratio": bytes_sent / len(payload) if payload else 1.0,
                    "segments": obfuscated_segments
                }
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="traffic_pattern_obfuscation"
            )

    def _apply_pattern_obfuscation(self, payload: bytes, strategy: str, intensity: str, mimic_app: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply traffic pattern obfuscation based on strategy."""
        if strategy == "timing_randomization":
            return self._apply_timing_randomization(payload, intensity)
        elif strategy == "size_padding":
            return self._apply_size_padding(payload, intensity)
        elif strategy == "burst_shaping":
            return self._apply_burst_shaping(payload, intensity)
        elif strategy == "flow_mimicry":
            return self._apply_flow_mimicry(payload, mimic_app, intensity)
        elif strategy == "mixed":
            return self._apply_mixed_obfuscation(payload, intensity, mimic_app)
        else:
            raise ValueError(f"Invalid obfuscation_strategy: {strategy}")

    def _apply_timing_randomization(self, payload: bytes, intensity: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing randomization obfuscation."""
        segments = []
        chunk_size = self._get_chunk_size(intensity)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Calculate randomized delay
            base_delay = self._get_base_delay(intensity)
            jitter = self._calculate_jitter(intensity)
            delay = max(1, int(base_delay + jitter))
            
            segments.append((chunk, delay, {
                "obfuscation_type": "timing_randomization",
                "base_delay": base_delay,
                "jitter": jitter,
                "chunk_index": i // chunk_size
            }))
        
        return segments

    def _apply_size_padding(self, payload: bytes, intensity: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size padding obfuscation."""
        segments = []
        chunk_size = self._get_chunk_size(intensity)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Add padding to obfuscate size patterns
            padding_size = self._calculate_padding_size(len(chunk), intensity)
            padding = self._generate_realistic_padding(padding_size)
            
            padded_chunk = chunk + padding
            delay = random.randint(10, 50)
            
            segments.append((padded_chunk, delay, {
                "obfuscation_type": "size_padding",
                "original_size": len(chunk),
                "padding_size": padding_size,
                "padded_size": len(padded_chunk)
            }))
        
        return segments

    def _apply_burst_shaping(self, payload: bytes, intensity: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply burst shaping obfuscation."""
        segments = []
        
        # Create burst patterns
        burst_config = self._get_burst_config(intensity)
        burst_size = burst_config["burst_size"]
        burst_interval = burst_config["burst_interval"]
        inter_burst_delay = burst_config["inter_burst_delay"]
        
        chunk_size = len(payload) // burst_size if len(payload) > burst_size else len(payload)
        
        for burst_index in range(burst_size):
            start_pos = burst_index * chunk_size
            end_pos = min(start_pos + chunk_size, len(payload))
            
            if start_pos >= len(payload):
                break
                
            chunk = payload[start_pos:end_pos]
            
            # Delay between bursts
            if burst_index == 0:
                delay = 0
            else:
                delay = inter_burst_delay + random.randint(-10, 10)
            
            segments.append((chunk, delay, {
                "obfuscation_type": "burst_shaping",
                "burst_index": burst_index,
                "burst_size": burst_size,
                "inter_burst_delay": inter_burst_delay
            }))
        
        return segments

    def _apply_flow_mimicry(self, payload: bytes, mimic_app: str, intensity: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow mimicry obfuscation."""
        flow_pattern = self._get_flow_pattern(mimic_app)
        segments = []
        
        # Split payload according to flow pattern
        pattern_chunks = flow_pattern["chunk_sizes"]
        pattern_delays = flow_pattern["delays"]
        
        payload_pos = 0
        for i, (chunk_size, delay) in enumerate(zip(pattern_chunks, pattern_delays)):
            if payload_pos >= len(payload):
                break
            
            # Extract chunk
            actual_chunk_size = min(chunk_size, len(payload) - payload_pos)
            chunk = payload[payload_pos:payload_pos + actual_chunk_size]
            
            # Add padding to match expected size
            if len(chunk) < chunk_size:
                padding = self._generate_realistic_padding(chunk_size - len(chunk))
                chunk = chunk + padding
            
            # Apply delay with some randomization
            actual_delay = delay + random.randint(-delay//4, delay//4)
            
            segments.append((chunk, actual_delay, {
                "obfuscation_type": "flow_mimicry",
                "mimic_application": mimic_app,
                "pattern_index": i,
                "expected_size": chunk_size,
                "actual_size": len(chunk)
            }))
            
            payload_pos += actual_chunk_size
        
        # Handle remaining payload
        if payload_pos < len(payload):
            remaining = payload[payload_pos:]
            segments.append((remaining, random.randint(50, 200), {
                "obfuscation_type": "flow_mimicry",
                "mimic_application": mimic_app,
                "pattern_index": "overflow",
                "remaining_data": True
            }))
        
        return segments

    def _apply_mixed_obfuscation(self, payload: bytes, intensity: str, mimic_app: str) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply mixed obfuscation techniques."""
        segments = []
        
        # Combine multiple techniques
        techniques = ["timing", "padding", "burst"]
        chunk_size = self._get_chunk_size(intensity)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            technique = random.choice(techniques)
            
            if technique == "timing":
                # Apply timing randomization
                delay = self._get_base_delay(intensity) + self._calculate_jitter(intensity)
                obfuscated_chunk = chunk
                
            elif technique == "padding":
                # Apply size padding
                padding_size = self._calculate_padding_size(len(chunk), intensity)
                padding = self._generate_realistic_padding(padding_size)
                obfuscated_chunk = chunk + padding
                delay = random.randint(20, 80)
                
            else:  # burst
                # Apply burst characteristics
                obfuscated_chunk = chunk
                if i == 0:
                    delay = 0
                else:
                    delay = random.randint(100, 300)  # Burst interval
            
            segments.append((obfuscated_chunk, delay, {
                "obfuscation_type": "mixed",
                "technique_used": technique,
                "chunk_index": i // chunk_size,
                "intensity": intensity
            }))
        
        return segments

    def _get_chunk_size(self, intensity: str) -> int:
        """Get chunk size based on intensity."""
        sizes = {
            "low": random.randint(200, 500),
            "medium": random.randint(100, 300),
            "high": random.randint(50, 150)
        }
        return sizes.get(intensity, 200)

    def _get_base_delay(self, intensity: str) -> int:
        """Get base delay based on intensity."""
        delays = {
            "low": random.randint(10, 50),
            "medium": random.randint(20, 100),
            "high": random.randint(50, 200)
        }
        return delays.get(intensity, 50)

    def _calculate_jitter(self, intensity: str) -> int:
        """Calculate timing jitter."""
        jitter_ranges = {
            "low": (-5, 5),
            "medium": (-20, 20),
            "high": (-50, 50)
        }
        min_jitter, max_jitter = jitter_ranges.get(intensity, (-10, 10))
        return random.randint(min_jitter, max_jitter)

    def _calculate_padding_size(self, original_size: int, intensity: str) -> int:
        """Calculate padding size."""
        padding_ratios = {
            "low": 0.1,
            "medium": 0.3,
            "high": 0.5
        }
        ratio = padding_ratios.get(intensity, 0.2)
        return int(original_size * ratio) + random.randint(10, 50)

    def _generate_realistic_padding(self, size: int) -> bytes:
        """Generate realistic padding data."""
        if size <= 0:
            return b""
        
        # Mix of different padding patterns
        patterns = [
            b"\x00" * size,  # Null padding
            bytes([random.randint(0, 255) for _ in range(size)]),  # Random padding
            (b"PADDING" * (size // 7 + 1))[:size],  # Pattern padding
            b"\x20" * size,  # Space padding
        ]
        
        return random.choice(patterns)

    def _get_burst_config(self, intensity: str) -> Dict[str, int]:
        """Get burst configuration."""
        configs = {
            "low": {
                "burst_size": 3,
                "burst_interval": 50,
                "inter_burst_delay": 200
            },
            "medium": {
                "burst_size": 5,
                "burst_interval": 30,
                "inter_burst_delay": 150
            },
            "high": {
                "burst_size": 8,
                "burst_interval": 20,
                "inter_burst_delay": 100
            }
        }
        return configs.get(intensity, configs["medium"])

    def _get_flow_pattern(self, mimic_app: str) -> Dict[str, List[int]]:
        """Get flow pattern for application mimicry."""
        patterns = {
            "web_browsing": {
                "chunk_sizes": [1200, 800, 1500, 600, 1000],
                "delays": [0, 50, 100, 30, 80]
            },
            "video_streaming": {
                "chunk_sizes": [2000, 2000, 2000, 1500, 1800],
                "delays": [0, 33, 33, 33, 33]  # ~30 FPS
            },
            "file_transfer": {
                "chunk_sizes": [1400, 1400, 1400, 1400, 1400],
                "delays": [0, 10, 10, 10, 10]
            },
            "messaging": {
                "chunk_sizes": [200, 150, 300, 100, 250],
                "delays": [0, 200, 500, 100, 300]
            }
        }
        return patterns.get(mimic_app, patterns["web_browsing"])


@register_attack
class PacketSizeObfuscationAttack(BaseAttack):
    """
    Packet Size Obfuscation Attack.
    
    Modifies packet sizes to break size-based fingerprinting by
    adding padding, fragmentation, or size normalization.
    """

    @property
    def name(self) -> str:
        return "packet_size_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies packet sizes to evade size-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute packet size obfuscation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            size_strategy = context.params.get("size_strategy", "normalize")
            target_size = context.params.get("target_size", 1200)
            size_variance = context.params.get("size_variance", 0.1)

            # Apply size obfuscation
            obfuscated_segments = self._apply_size_obfuscation(
                payload, size_strategy, target_size, size_variance
            )

            packets_sent = len(obfuscated_segments)
            bytes_sent = sum(len(seg[0]) for seg in obfuscated_segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="packet_size_obfuscation",
                metadata={
                    "size_strategy": size_strategy,
                    "target_size": target_size,
                    "size_variance": size_variance,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "size_expansion": bytes_sent / len(payload) if payload else 1.0,
                    "segments": obfuscated_segments
                }
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="packet_size_obfuscation"
            )

    def _apply_size_obfuscation(self, payload: bytes, strategy: str, target_size: int, variance: float) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply size obfuscation based on strategy."""
        if strategy == "normalize":
            return self._normalize_packet_sizes(payload, target_size, variance)
        elif strategy == "randomize":
            return self._randomize_packet_sizes(payload, target_size, variance)
        elif strategy == "fragment":
            return self._fragment_packets(payload, target_size)
        elif strategy == "pad_to_mtu":
            return self._pad_to_mtu(payload)
        else:
            return self._normalize_packet_sizes(payload, target_size, variance)

    def _normalize_packet_sizes(self, payload: bytes, target_size: int, variance: float) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Normalize all packets to similar sizes."""
        segments = []
        
        for i in range(0, len(payload), target_size):
            chunk = payload[i:i + target_size]
            
            # Calculate actual target size with variance
            size_variation = int(target_size * variance * (random.random() - 0.5) * 2)
            actual_target = target_size + size_variation
            
            if len(chunk) < actual_target:
                # Pad to target size
                padding_size = actual_target - len(chunk)
                padding = self._generate_size_padding(padding_size)
                normalized_chunk = chunk + padding
            else:
                # Chunk is already at or above target size
                normalized_chunk = chunk
            
            segments.append((normalized_chunk, random.randint(10, 50), {
                "obfuscation_type": "normalize",
                "original_size": len(chunk),
                "target_size": actual_target,
                "final_size": len(normalized_chunk),
                "padding_added": len(normalized_chunk) - len(chunk)
            }))
        
        return segments

    def _randomize_packet_sizes(self, payload: bytes, base_size: int, variance: float) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Randomize packet sizes within a range."""
        segments = []
        min_size = int(base_size * (1 - variance))
        max_size = int(base_size * (1 + variance))
        
        pos = 0
        while pos < len(payload):
            # Random chunk size
            chunk_size = random.randint(min_size, max_size)
            chunk = payload[pos:pos + chunk_size]
            
            # If chunk is smaller than expected, pad it
            if len(chunk) < chunk_size and pos + len(chunk) == len(payload):
                # Last chunk - pad to random size
                padding_size = random.randint(0, chunk_size - len(chunk))
                padding = self._generate_size_padding(padding_size)
                randomized_chunk = chunk + padding
            else:
                randomized_chunk = chunk
            
            segments.append((randomized_chunk, random.randint(5, 30), {
                "obfuscation_type": "randomize",
                "expected_size": chunk_size,
                "actual_size": len(randomized_chunk),
                "position": pos
            }))
            
            pos += len(chunk)
        
        return segments

    def _fragment_packets(self, payload: bytes, fragment_size: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Fragment packets into smaller sizes."""
        segments = []
        
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i:i + fragment_size]
            
            segments.append((fragment, random.randint(1, 10), {
                "obfuscation_type": "fragment",
                "fragment_index": i // fragment_size,
                "fragment_size": len(fragment),
                "is_last_fragment": i + fragment_size >= len(payload)
            }))
        
        return segments

    def _pad_to_mtu(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Pad packets to MTU size."""
        mtu_size = 1500  # Standard Ethernet MTU
        segments = []
        
        for i in range(0, len(payload), mtu_size):
            chunk = payload[i:i + mtu_size]
            
            if len(chunk) < mtu_size:
                # Pad to MTU size
                padding_size = mtu_size - len(chunk)
                padding = self._generate_size_padding(padding_size)
                mtu_chunk = chunk + padding
            else:
                mtu_chunk = chunk
            
            segments.append((mtu_chunk, random.randint(15, 40), {
                "obfuscation_type": "pad_to_mtu",
                "original_size": len(chunk),
                "mtu_size": mtu_size,
                "padding_added": len(mtu_chunk) - len(chunk)
            }))
        
        return segments

    def _generate_size_padding(self, size: int) -> bytes:
        """Generate padding for size obfuscation."""
        if size <= 0:
            return b""
        
        # Use different padding strategies
        strategies = ["zero", "random", "pattern", "http_like"]
        strategy = random.choice(strategies)
        
        if strategy == "zero":
            return b"\x00" * size
        elif strategy == "random":
            return bytes([random.randint(0, 255) for _ in range(size)])
        elif strategy == "pattern":
            pattern = b"ABCDEFGH"
            return (pattern * (size // len(pattern) + 1))[:size]
        else:  # http_like
            # Generate HTTP-like padding
            http_padding = b"X-Padding: " + b"x" * (size - 11) if size > 11 else b"x" * size
            return http_padding[:size]


@register_attack
class TimingObfuscationAttack(BaseAttack):
    """
    Timing Obfuscation Attack.
    
    Modifies packet timing patterns to evade timing-based fingerprinting
    through jitter injection, delay randomization, and rhythm breaking.
    """

    @property
    def name(self) -> str:
        return "timing_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies packet timing to evade timing-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute timing obfuscation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            timing_strategy = context.params.get("timing_strategy", "jitter")
            base_delay = context.params.get("base_delay", 50)
            jitter_range = context.params.get("jitter_range", 20)

            # Apply timing obfuscation
            obfuscated_segments = self._apply_timing_obfuscation(
                payload, timing_strategy, base_delay, jitter_range
            )

            packets_sent = len(obfuscated_segments)
            bytes_sent = sum(len(seg[0]) for seg in obfuscated_segments)
            total_delay = sum(seg[1] for seg in obfuscated_segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="timing_obfuscation",
                metadata={
                    "timing_strategy": timing_strategy,
                    "base_delay": base_delay,
                    "jitter_range": jitter_range,
                    "total_delay_ms": total_delay,
                    "average_delay": total_delay / packets_sent if packets_sent > 0 else 0,
                    "segments": obfuscated_segments
                }
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="timing_obfuscation"
            )

    def _apply_timing_obfuscation(self, payload: bytes, strategy: str, base_delay: int, jitter_range: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply timing obfuscation based on strategy."""
        if strategy == "jitter":
            return self._apply_jitter_timing(payload, base_delay, jitter_range)
        elif strategy == "exponential":
            return self._apply_exponential_timing(payload, base_delay)
        elif strategy == "burst":
            return self._apply_burst_timing(payload, base_delay)
        elif strategy == "rhythm_break":
            return self._apply_rhythm_breaking(payload, base_delay, jitter_range)
        else:
            return self._apply_jitter_timing(payload, base_delay, jitter_range)

    def _apply_jitter_timing(self, payload: bytes, base_delay: int, jitter_range: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply jitter-based timing obfuscation."""
        segments = []
        chunk_size = random.randint(100, 300)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Calculate jittered delay
            jitter = random.randint(-jitter_range, jitter_range)
            delay = max(1, base_delay + jitter)
            
            segments.append((chunk, delay, {
                "timing_type": "jitter",
                "base_delay": base_delay,
                "jitter": jitter,
                "final_delay": delay
            }))
        
        return segments

    def _apply_exponential_timing(self, payload: bytes, base_delay: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply exponential timing distribution."""
        segments = []
        chunk_size = random.randint(150, 400)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Exponential distribution for more realistic timing
            delay = int(random.expovariate(1.0 / base_delay))
            delay = max(1, min(delay, base_delay * 5))  # Cap at 5x base delay
            
            segments.append((chunk, delay, {
                "timing_type": "exponential",
                "base_delay": base_delay,
                "calculated_delay": delay
            }))
        
        return segments

    def _apply_burst_timing(self, payload: bytes, base_delay: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply burst timing patterns."""
        segments = []
        burst_size = random.randint(3, 6)
        burst_delay = base_delay * 3
        
        chunk_size = len(payload) // burst_size if len(payload) > burst_size else len(payload)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            burst_index = i // chunk_size
            
            if burst_index % burst_size == 0:
                # Start of burst - longer delay
                delay = burst_delay + random.randint(-10, 10)
            else:
                # Within burst - short delay
                delay = random.randint(5, 15)
            
            segments.append((chunk, delay, {
                "timing_type": "burst",
                "burst_index": burst_index,
                "burst_size": burst_size,
                "is_burst_start": burst_index % burst_size == 0
            }))
        
        return segments

    def _apply_rhythm_breaking(self, payload: bytes, base_delay: int, jitter_range: int) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply rhythm-breaking timing patterns."""
        segments = []
        chunk_size = random.randint(80, 250)
        
        # Create irregular rhythm
        rhythm_pattern = [1.0, 0.5, 2.0, 0.3, 1.5, 0.8, 2.5]
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            pattern_index = (i // chunk_size) % len(rhythm_pattern)
            
            # Apply rhythm multiplier with jitter
            rhythm_multiplier = rhythm_pattern[pattern_index]
            jitter = random.randint(-jitter_range//2, jitter_range//2)
            delay = max(1, int(base_delay * rhythm_multiplier) + jitter)
            
            segments.append((chunk, delay, {
                "timing_type": "rhythm_break",
                "pattern_index": pattern_index,
                "rhythm_multiplier": rhythm_multiplier,
                "jitter": jitter,
                "final_delay": delay
            }))
        
        return segments


@register_attack
class FlowObfuscationAttack(BaseAttack):
    """
    Flow Obfuscation Attack.
    
    Modifies traffic flow characteristics to evade flow-based fingerprinting
    by altering bidirectional patterns, connection behavior, and session structure.
    """

    @property
    def name(self) -> str:
        return "flow_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies traffic flow characteristics to evade flow-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute flow obfuscation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            flow_strategy = context.params.get("flow_strategy", "bidirectional")
            connection_pattern = context.params.get("connection_pattern", "persistent")
            fake_responses = context.params.get("fake_responses", True)

            # Apply flow obfuscation
            obfuscated_segments = self._apply_flow_obfuscation(
                payload, flow_strategy, connection_pattern, fake_responses, context
            )

            packets_sent = len(obfuscated_segments)
            bytes_sent = sum(len(seg[0]) for seg in obfuscated_segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="flow_obfuscation",
                metadata={
                    "flow_strategy": flow_strategy,
                    "connection_pattern": connection_pattern,
                    "fake_responses": fake_responses,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": obfuscated_segments
                }
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="flow_obfuscation"
            )

    def _apply_flow_obfuscation(self, payload: bytes, strategy: str, pattern: str, fake_responses: bool, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow obfuscation based on strategy."""
        if strategy == "bidirectional":
            return self._create_bidirectional_flow(payload, fake_responses, context)
        elif strategy == "multi_connection":
            return self._create_multi_connection_flow(payload, pattern, context)
        elif strategy == "session_splitting":
            return self._create_session_splitting_flow(payload, context)
        else:
            return self._create_bidirectional_flow(payload, fake_responses, context)

    def _create_bidirectional_flow(self, payload: bytes, fake_responses: bool, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create bidirectional flow pattern."""
        segments = []
        chunk_size = random.randint(200, 500)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Send client data
            segments.append((chunk, random.randint(10, 50), {
                "flow_type": "bidirectional",
                "direction": "client_to_server",
                "chunk_index": i // chunk_size
            }))
            
            # Generate fake server response if requested
            if fake_responses:
                response_size = random.randint(50, 200)
                fake_response = self._generate_fake_server_response(response_size)
                
                segments.append((fake_response, random.randint(20, 100), {
                    "flow_type": "bidirectional",
                    "direction": "server_to_client",
                    "is_fake_response": True,
                    "response_size": response_size
                }))
        
        return segments

    def _create_multi_connection_flow(self, payload: bytes, pattern: str, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create multi-connection flow pattern."""
        segments = []
        num_connections = random.randint(2, 4)
        
        # Split payload across multiple "connections"
        connection_chunks = []
        chunk_size = len(payload) // num_connections
        
        for i in range(num_connections):
            start = i * chunk_size
            end = start + chunk_size if i < num_connections - 1 else len(payload)
            connection_chunks.append(payload[start:end])
        
        # Interleave data from different connections
        max_chunks = max(len(chunk) // 100 + 1 for chunk in connection_chunks)
        
        for chunk_index in range(max_chunks):
            for conn_id, conn_data in enumerate(connection_chunks):
                start_pos = chunk_index * 100
                if start_pos < len(conn_data):
                    end_pos = min(start_pos + 100, len(conn_data))
                    data_chunk = conn_data[start_pos:end_pos]
                    
                    segments.append((data_chunk, random.randint(5, 30), {
                        "flow_type": "multi_connection",
                        "connection_id": conn_id,
                        "chunk_index": chunk_index,
                        "total_connections": num_connections
                    }))
        
        return segments

    def _create_session_splitting_flow(self, payload: bytes, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create session splitting flow pattern."""
        segments = []
        
        # Split into multiple sessions with gaps
        num_sessions = random.randint(2, 3)
        session_size = len(payload) // num_sessions
        
        for session_id in range(num_sessions):
            start = session_id * session_size
            end = start + session_size if session_id < num_sessions - 1 else len(payload)
            session_data = payload[start:end]
            
            # Add session start marker
            if session_id > 0:
                # Gap between sessions
                gap_delay = random.randint(200, 500)
                segments.append((b"", gap_delay, {
                    "flow_type": "session_splitting",
                    "is_session_gap": True,
                    "session_id": session_id
                }))
            
            # Send session data in chunks
            chunk_size = random.randint(150, 300)
            for i in range(0, len(session_data), chunk_size):
                chunk = session_data[i:i + chunk_size]
                
                segments.append((chunk, random.randint(10, 40), {
                    "flow_type": "session_splitting",
                    "session_id": session_id,
                    "chunk_in_session": i // chunk_size,
                    "is_session_data": True
                }))
        
        return segments

    def _generate_fake_server_response(self, size: int) -> bytes:
        """Generate fake server response data."""
        # Generate realistic server response patterns
        response_types = ["http_ok", "json_response", "binary_data"]
        response_type = random.choice(response_types)
        
        if response_type == "http_ok":
            response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(size - 50).encode() + b"\r\n\r\n"
            response += b"x" * (size - len(response))
        elif response_type == "json_response":
            response = b'{"status":"ok","data":"' + b"x" * (size - 20) + b'"}'
        else:  # binary_data
            response = bytes([random.randint(0, 255) for _ in range(size)])
        
        return response[:size]


@register_attack
class FlowObfuscationAttack(BaseAttack):
    """
    Flow Obfuscation Attack.
    
    Modifies traffic flow characteristics to evade flow-based fingerprinting
    through bidirectional traffic simulation and fake responses.
    """

    @property
    def name(self) -> str:
        return "flow_obfuscation"

    @property
    def category(self) -> str:
        return "protocol_obfuscation"

    @property
    def description(self) -> str:
        return "Modifies traffic flow to evade flow-based fingerprinting"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute flow obfuscation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            flow_strategy = context.params.get("flow_strategy", "bidirectional")
            fake_responses = context.params.get("fake_responses", True)
            response_ratio = context.params.get("response_ratio", 0.7)

            # Apply flow obfuscation
            obfuscated_segments = self._apply_flow_obfuscation(
                payload, flow_strategy, fake_responses, response_ratio
            )

            packets_sent = len(obfuscated_segments)
            bytes_sent = sum(len(seg[0]) for seg in obfuscated_segments)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="flow_obfuscation",
                metadata={
                    "flow_strategy": flow_strategy,
                    "fake_responses": fake_responses,
                    "response_ratio": response_ratio,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": obfuscated_segments
                }
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="flow_obfuscation"
            )

    def _apply_flow_obfuscation(self, payload: bytes, strategy: str, fake_responses: bool, response_ratio: float) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Apply flow obfuscation based on strategy."""
        if strategy == "bidirectional":
            return self._create_bidirectional_flow(payload, fake_responses, response_ratio)
        elif strategy == "burst_response":
            return self._create_burst_response_flow(payload, fake_responses)
        elif strategy == "interactive":
            return self._create_interactive_flow(payload, fake_responses)
        else:
            return self._create_bidirectional_flow(payload, fake_responses, response_ratio)

    def _create_bidirectional_flow(self, payload: bytes, fake_responses: bool, response_ratio: float) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create bidirectional traffic flow."""
        segments = []
        chunk_size = random.randint(200, 800)
        
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            
            # Send request
            segments.append((chunk, random.randint(10, 50), {
                "flow_type": "bidirectional",
                "direction": "outbound",
                "chunk_index": i // chunk_size,
                "is_response": False
            }))
            
            # Add fake response if enabled
            if fake_responses and random.random() < response_ratio:
                response_size = int(len(chunk) * random.uniform(0.5, 1.5))
                fake_response = self._generate_fake_response(response_size)
                
                response_delay = random.randint(20, 100)
                segments.append((fake_response, response_delay, {
                    "flow_type": "bidirectional",
                    "direction": "inbound",
                    "chunk_index": i // chunk_size,
                    "is_response": True,
                    "response_size": response_size
                }))
        
        return segments

    def _create_burst_response_flow(self, payload: bytes, fake_responses: bool) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create burst response flow pattern."""
        segments = []
        
        # Send all data in bursts
        burst_size = len(payload) // 3 if len(payload) > 300 else len(payload)
        
        for i in range(0, len(payload), burst_size):
            chunk = payload[i:i + burst_size]
            
            # Send burst
            segments.append((chunk, 0 if i == 0 else random.randint(200, 500), {
                "flow_type": "burst_response",
                "direction": "outbound",
                "burst_index": i // burst_size,
                "is_response": False
            }))
        
        # Add burst of fake responses
        if fake_responses:
            for i in range(random.randint(2, 5)):
                response_size = random.randint(100, 500)
                fake_response = self._generate_fake_response(response_size)
                
                segments.append((fake_response, random.randint(50, 150), {
                    "flow_type": "burst_response",
                    "direction": "inbound",
                    "burst_index": i,
                    "is_response": True,
                    "response_size": response_size
                }))
        
        return segments

    def _create_interactive_flow(self, payload: bytes, fake_responses: bool) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create interactive flow pattern."""
        segments = []
        small_chunk_size = random.randint(50, 150)
        
        for i in range(0, len(payload), small_chunk_size):
            chunk = payload[i:i + small_chunk_size]
            
            # Send small chunk (simulating interactive input)
            segments.append((chunk, random.randint(100, 1000), {
                "flow_type": "interactive",
                "direction": "outbound",
                "chunk_index": i // small_chunk_size,
                "is_response": False,
                "interactive": True
            }))
            
            # Add immediate response if enabled
            if fake_responses:
                # Small acknowledgment response
                ack_size = random.randint(10, 50)
                ack_response = self._generate_fake_response(ack_size)
                
                segments.append((ack_response, random.randint(10, 50), {
                    "flow_type": "interactive",
                    "direction": "inbound",
                    "chunk_index": i // small_chunk_size,
                    "is_response": True,
                    "response_type": "acknowledgment",
                    "response_size": ack_size
                }))
        
        return segments

    def _generate_fake_response(self, size: int) -> bytes:
        """Generate fake response data."""
        if size <= 0:
            return b""
        
        # Generate realistic-looking response data
        response_types = ["json", "html", "binary", "text"]
        response_type = random.choice(response_types)
        
        if response_type == "json":
            # JSON-like response
            json_template = b'{"status":"ok","data":"' + b"x" * (size - 30) + b'","time":123}'
            return json_template[:size]
        
        elif response_type == "html":
            # HTML-like response
            html_template = b'<html><body><p>' + b"content" * (size // 7) + b'</p></body></html>'
            return html_template[:size]
        
        elif response_type == "binary":
            # Binary response
            return random.randbytes(size)
        
        else:  # text
            # Text response
            text_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n"
            return bytes([random.choice(text_chars) for _ in range(size)])