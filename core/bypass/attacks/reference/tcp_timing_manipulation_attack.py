#!/usr/bin/env python3
"""
TCPTimingManipulationAttack implementation using segments architecture.

This attack manipulates TCP timing patterns to confuse DPI systems that
rely on timing analysis for traffic classification and blocking decisions.
Uses variable delays, burst patterns, and timing obfuscation techniques.
"""

import logging
import random
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext
from ..registry import register_attack


class TimingPattern(Enum):
    """Different timing patterns for manipulation."""
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    RANDOM = "random"
    BURST = "burst"
    SAWTOOTH = "sawtooth"
    FIBONACCI = "fibonacci"


@dataclass
class TCPTimingConfig:
    """Configuration for TCPTimingManipulationAttack."""
    
    # Timing pattern to use
    timing_pattern: TimingPattern = TimingPattern.RANDOM
    
    # Base delay in milliseconds
    base_delay_ms: float = 10.0
    
    # Maximum delay in milliseconds
    max_delay_ms: float = 100.0
    
    # Minimum delay in milliseconds
    min_delay_ms: float = 1.0
    
    # Number of segments to create
    segment_count: int = 4
    
    # Whether to add jitter to delays
    add_jitter: bool = True
    
    # Jitter amount (±ms)
    jitter_ms: float = 2.0    

    # Burst configuration
    burst_size: int = 3
    burst_delay_ms: float = 50.0
    inter_burst_delay_ms: float = 5.0
    
    # Whether to vary TCP window sizes
    vary_window_size: bool = True
    window_size_range: Tuple[int, int] = (16384, 65535)
    
    # Whether to use different TTL values
    vary_ttl: bool = False
    ttl_range: Tuple[int, int] = (60, 64)
    
    # Whether to simulate network congestion
    simulate_congestion: bool = False
    congestion_probability: float = 0.3
    congestion_delay_multiplier: float = 3.0


@register_attack("tcp_timing")
class TCPTimingManipulationAttack(BaseAttack):
    """
    TCPTimingManipulationAttack using segments architecture.
    
    This attack manipulates TCP timing patterns to bypass DPI systems
    that use timing analysis for traffic classification.
    """
    
    def __init__(self, name: str = "tcp_timing_manipulation", config: Optional[TCPTimingConfig] = None):
        super().__init__(name)
        self.config = config or TCPTimingConfig()
        self.logger = logging.getLogger(f"TCPTimingManipulationAttack.{name}")
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate attack configuration."""
        if self.config.min_delay_ms < 0:
            raise ValueError(f"min_delay_ms must be non-negative, got {self.config.min_delay_ms}")
        
        if self.config.max_delay_ms < self.config.min_delay_ms:
            raise ValueError(f"max_delay_ms must be >= min_delay_ms")
        
        if self.config.base_delay_ms < 0:
            raise ValueError(f"base_delay_ms must be non-negative")
        
        if not (2 <= self.config.segment_count <= 20):
            raise ValueError(f"segment_count must be between 2 and 20")
        
        if self.config.jitter_ms < 0:
            raise ValueError(f"jitter_ms must be non-negative")
        
        if not (0.0 <= self.config.congestion_probability <= 1.0):
            raise ValueError(f"congestion_probability must be between 0.0 and 1.0")
    
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute TCPTimingManipulationAttack.
        
        Args:
            context: Attack context containing payload and connection info
            
        Returns:
            AttackResult with segments for timing manipulation
        """
        try:
            self.logger.info(f"Executing TCPTimingManipulationAttack on {context.connection_id}")
            
            # Validate context
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    modified_payload=None,
                    metadata={"error": "Empty payload provided"}
                )
            
            # Create segments with timing manipulation
            segments = self._create_timing_segments(context.payload)
            
            # Create attack result
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=None,  # Using segments instead
                metadata={
                    "attack_type": "tcp_timing_manipulation",
                    "segments": segments,
                    "total_segments": len(segments),
                    "timing_pattern": self.config.timing_pattern.value,
                    "original_payload_size": len(context.payload),
                    "config": {
                        "timing_pattern": self.config.timing_pattern.value,
                        "base_delay_ms": self.config.base_delay_ms,
                        "max_delay_ms": self.config.max_delay_ms,
                        "min_delay_ms": self.config.min_delay_ms,
                        "segment_count": self.config.segment_count,
                        "add_jitter": self.config.add_jitter,
                        "jitter_ms": self.config.jitter_ms,
                        "vary_window_size": self.config.vary_window_size,
                        "vary_ttl": self.config.vary_ttl,
                        "simulate_congestion": self.config.simulate_congestion
                    }
                }
            )
            
            # Set segments for engine processing
            result._segments = segments
            
            self.logger.info(f"TCPTimingManipulationAttack created {len(segments)} segments with {self.config.timing_pattern.value} pattern")
            
            return result
            
        except Exception as e:
            self.logger.error(f"TCPTimingManipulationAttack failed: {e}")
            return AttackResult(
                status=AttackStatus.FAILED,
                modified_payload=None,
                metadata={"error": str(e), "attack_type": "tcp_timing_manipulation"}
            )
    
    def _create_timing_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Create segments with timing manipulation.
        
        Args:
            payload: Original payload to segment
            
        Returns:
            List of segment tuples with timing options
        """
        segments = []
        
        # Split payload into segments
        segment_size = len(payload) // self.config.segment_count
        remainder = len(payload) % self.config.segment_count
        
        current_pos = 0
        for i in range(self.config.segment_count):
            # Calculate segment size
            size = segment_size + (1 if i < remainder else 0)
            segment_payload = payload[current_pos:current_pos + size]
            
            # Calculate delay based on timing pattern
            delay = self._calculate_delay(i, self.config.segment_count)
            
            # Add jitter if configured
            if self.config.add_jitter:
                jitter = random.uniform(-self.config.jitter_ms, self.config.jitter_ms)
                delay = max(0.0, delay + jitter)
            
            # Simulate congestion if configured
            if self.config.simulate_congestion and random.random() < self.config.congestion_probability:
                delay *= self.config.congestion_delay_multiplier
            
            # Create segment options
            options = self._create_segment_options(i, delay)
            
            segments.append((segment_payload, current_pos, options))
            current_pos += size
        
        return segments 
   
    def _calculate_delay(self, segment_index: int, total_segments: int) -> float:
        """
        Calculate delay based on timing pattern.
        
        Args:
            segment_index: Index of current segment
            total_segments: Total number of segments
            
        Returns:
            Delay in milliseconds
        """
        if self.config.timing_pattern == TimingPattern.LINEAR:
            # Linear increase from min to max
            progress = segment_index / (total_segments - 1) if total_segments > 1 else 0
            return self.config.min_delay_ms + progress * (self.config.max_delay_ms - self.config.min_delay_ms)
        
        elif self.config.timing_pattern == TimingPattern.EXPONENTIAL:
            # Exponential increase
            base = 2.0
            return min(self.config.base_delay_ms * (base ** segment_index), self.config.max_delay_ms)
        
        elif self.config.timing_pattern == TimingPattern.RANDOM:
            # Random delay within range
            return random.uniform(self.config.min_delay_ms, self.config.max_delay_ms)
        
        elif self.config.timing_pattern == TimingPattern.BURST:
            # Burst pattern: short delays within burst, long delays between bursts
            burst_position = segment_index % self.config.burst_size
            if burst_position == 0 and segment_index > 0:
                return self.config.burst_delay_ms  # Inter-burst delay
            else:
                return self.config.inter_burst_delay_ms  # Intra-burst delay
        
        elif self.config.timing_pattern == TimingPattern.SAWTOOTH:
            # Sawtooth pattern: increase then reset
            cycle_length = total_segments // 2 if total_segments > 2 else total_segments
            position_in_cycle = segment_index % cycle_length
            progress = position_in_cycle / (cycle_length - 1) if cycle_length > 1 else 0
            return self.config.min_delay_ms + progress * (self.config.max_delay_ms - self.config.min_delay_ms)
        
        elif self.config.timing_pattern == TimingPattern.FIBONACCI:
            # Fibonacci-based delays
            fib_sequence = self._generate_fibonacci(total_segments)
            max_fib = max(fib_sequence) if fib_sequence else 1
            normalized = fib_sequence[segment_index] / max_fib if max_fib > 0 else 0
            return self.config.min_delay_ms + normalized * (self.config.max_delay_ms - self.config.min_delay_ms)
        
        else:
            return self.config.base_delay_ms
    
    def _generate_fibonacci(self, count: int) -> List[int]:
        """Generate Fibonacci sequence of specified length."""
        if count <= 0:
            return []
        elif count == 1:
            return [1]
        elif count == 2:
            return [1, 1]
        
        fib = [1, 1]
        for i in range(2, count):
            fib.append(fib[i-1] + fib[i-2])
        
        return fib
    
    def _create_segment_options(self, segment_index: int, delay: float) -> Dict[str, Any]:
        """
        Create options for a segment.
        
        Args:
            segment_index: Index of current segment
            delay: Calculated delay for this segment
            
        Returns:
            Dictionary of segment options
        """
        options = {
            "delay_ms": delay,
            "flags": 0x18  # PSH+ACK
        }
        
        # Vary window size if configured
        if self.config.vary_window_size:
            window_size = random.randint(self.config.window_size_range[0], self.config.window_size_range[1])
            options["window_size"] = window_size
        
        # Vary TTL if configured
        if self.config.vary_ttl:
            ttl = random.randint(self.config.ttl_range[0], self.config.ttl_range[1])
            options["ttl"] = ttl
        else:
            options["ttl"] = 64
        
        return options
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get information about this attack."""
        return {
            "name": self.name,
            "type": "tcp_timing_manipulation",
            "description": "Manipulates TCP timing patterns to confuse timing-based DPI analysis",
            "technique": "timing_manipulation",
            "effectiveness": "high_against_timing_analysis_dpi",
            "config": {
                "timing_pattern": self.config.timing_pattern.value,
                "base_delay_ms": self.config.base_delay_ms,
                "max_delay_ms": self.config.max_delay_ms,
                "min_delay_ms": self.config.min_delay_ms,
                "segment_count": self.config.segment_count,
                "add_jitter": self.config.add_jitter,
                "jitter_ms": self.config.jitter_ms,
                "vary_window_size": self.config.vary_window_size,
                "vary_ttl": self.config.vary_ttl,
                "simulate_congestion": self.config.simulate_congestion
            },
            "timing_patterns": [pattern.value for pattern in TimingPattern],
            "advantages": [
                "Confuses timing-based DPI analysis",
                "Multiple timing patterns available",
                "Configurable jitter and congestion simulation",
                "TCP parameter variation",
                "Burst pattern support"
            ]
        }
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        effectiveness = 0.7  # Base effectiveness
        
        # Higher effectiveness with more complex patterns
        if self.config.timing_pattern in [TimingPattern.BURST, TimingPattern.FIBONACCI]:
            effectiveness += 0.1
        
        # Higher effectiveness with jitter
        if self.config.add_jitter:
            effectiveness += 0.05
        
        # Higher effectiveness with TCP variations
        if self.config.vary_window_size or self.config.vary_ttl:
            effectiveness += 0.05
        
        # Higher effectiveness with congestion simulation
        if self.config.simulate_congestion:
            effectiveness += 0.05
        
        # Higher effectiveness with more segments
        if self.config.segment_count >= 6:
            effectiveness += 0.05
        
        return min(1.0, max(0.0, effectiveness))
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        capabilities = [
            "packet_construction",
            "timing_control",
            "sequence_manipulation"
        ]
        
        if self.config.vary_window_size:
            capabilities.append("window_size_modification")
        
        if self.config.vary_ttl:
            capabilities.append("ttl_modification")
        
        return capabilities
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload provided"
        
        min_payload_size = self.config.segment_count * 5  # Minimum 5 bytes per segment
        if len(context.payload) < min_payload_size:
            return False, f"Payload too small for {self.config.segment_count} segments"
        
        return True, None


# Factory functions
def create_tcp_timing_attack(
    name: str = "tcp_timing_manipulation",
    timing_pattern: TimingPattern = TimingPattern.RANDOM,
    base_delay_ms: float = 10.0,
    max_delay_ms: float = 100.0,
    min_delay_ms: float = 1.0,
    segment_count: int = 4,
    add_jitter: bool = True,
    jitter_ms: float = 2.0,
    vary_window_size: bool = True,
    vary_ttl: bool = False,
    simulate_congestion: bool = False
) -> TCPTimingManipulationAttack:
    """Factory function to create TCPTimingManipulationAttack."""
    config = TCPTimingConfig(
        timing_pattern=timing_pattern,
        base_delay_ms=base_delay_ms,
        max_delay_ms=max_delay_ms,
        min_delay_ms=min_delay_ms,
        segment_count=segment_count,
        add_jitter=add_jitter,
        jitter_ms=jitter_ms,
        vary_window_size=vary_window_size,
        vary_ttl=vary_ttl,
        simulate_congestion=simulate_congestion
    )
    
    return TCPTimingManipulationAttack(name=name, config=config)


# Predefined variants
def create_burst_timing_attack() -> TCPTimingManipulationAttack:
    """Create burst timing variant."""
    return create_tcp_timing_attack(
        name="burst_timing_attack",
        timing_pattern=TimingPattern.BURST,
        segment_count=6,
        add_jitter=True,
        vary_window_size=True,
        simulate_congestion=True
    )


def create_fibonacci_timing_attack() -> TCPTimingManipulationAttack:
    """Create Fibonacci timing variant."""
    return create_tcp_timing_attack(
        name="fibonacci_timing_attack",
        timing_pattern=TimingPattern.FIBONACCI,
        segment_count=8,
        max_delay_ms=80.0,
        add_jitter=True,
        vary_ttl=True
    )


def create_congestion_simulation_attack() -> TCPTimingManipulationAttack:
    """Create congestion simulation variant."""
    return create_tcp_timing_attack(
        name="congestion_simulation_attack",
        timing_pattern=TimingPattern.RANDOM,
        segment_count=5,
        simulate_congestion=True,
        vary_window_size=True,
        jitter_ms=5.0
    )