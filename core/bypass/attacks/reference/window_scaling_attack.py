#!/usr/bin/env python3
"""
WindowScalingAttack implementation using segments architecture.

This attack manipulates TCP window sizes and scaling to confuse DPI systems
that make assumptions about normal TCP window behavior or use window size
patterns for traffic classification.
"""

import logging
import random
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext
from ..safe_result_utils import create_success_result, create_failed_result


class WindowPattern(Enum):
    """Different window scaling patterns."""
    RANDOM = "random"
    INCREASING = "increasing"
    DECREASING = "decreasing"
    OSCILLATING = "oscillating"
    ZERO_WINDOW = "zero_window"
    EXTREME_VALUES = "extreme_values"


@dataclass
class WindowScalingConfig:
    """Configuration for WindowScalingAttack."""
    
    # Window scaling pattern to use
    window_pattern: WindowPattern = WindowPattern.RANDOM
    
    # Number of segments to create
    segment_count: int = 4
    
    # Window size range
    min_window_size: int = 0
    max_window_size: int = 65535
    
    # Whether to use zero window advertisements
    use_zero_window: bool = True
    
    # Probability of zero window (0.0-1.0)
    zero_window_probability: float = 0.2
    
    # Whether to use extreme window values
    use_extreme_values: bool = True
    
    # Base delay between segments
    base_delay_ms: float = 8.0
    
    # Whether to add window scaling option
    add_window_scaling: bool = True
    
    # Window scaling factor (0-14)
    window_scale_factor: int = 7
    
    # Whether to vary other TCP parameters
    vary_tcp_flags: bool = True
    vary_ttl: bool = False
    ttl_range: Tuple[int, int] = (60, 64)


class WindowScalingAttack(BaseAttack):
    """
    WindowScalingAttack using segments architecture.
    
    This attack manipulates TCP window sizes and scaling to bypass
    DPI systems that rely on window size analysis.
    """
    
    def __init__(self, name: str = "window_scaling", config: Optional[WindowScalingConfig] = None):
        super().__init__(name)
        self.config = config or WindowScalingConfig()
        self.logger = logging.getLogger(f"WindowScalingAttack.{name}")
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate attack configuration."""
        if not (2 <= self.config.segment_count <= 15):
            raise ValueError(f"segment_count must be between 2 and 15, got {self.config.segment_count}")
        
        if self.config.min_window_size < 0 or self.config.min_window_size > 65535:
            raise ValueError(f"min_window_size must be between 0 and 65535")
        
        if self.config.max_window_size < 0 or self.config.max_window_size > 65535:
            raise ValueError(f"max_window_size must be between 0 and 65535")
        
        if self.config.min_window_size > self.config.max_window_size:
            raise ValueError(f"min_window_size must be <= max_window_size")
        
        if not (0.0 <= self.config.zero_window_probability <= 1.0):
            raise ValueError(f"zero_window_probability must be between 0.0 and 1.0")
        
        if not (0 <= self.config.window_scale_factor <= 14):
            raise ValueError(f"window_scale_factor must be between 0 and 14")
        
        if self.config.base_delay_ms < 0:
            raise ValueError(f"base_delay_ms must be non-negative")
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute WindowScalingAttack."""
        try:
            self.logger.info(f"Executing WindowScalingAttack on {context.connection_id}")
            
            # Validate context
            if not context.payload:
                return create_failed_result(
                    error_message="Empty payload provided",
                    modified_payload=None,
                    metadata={"error": "Empty payload provided"}
                )
            
            # Create segments with window scaling manipulation
            segments = self._create_window_segments(context.payload)
            
            # Create attack result
            result = create_success_result(
                modified_payload=None,
                metadata={
                    "attack_type": "window_scaling",
                    "segments": segments,
                    "total_segments": len(segments),
                    "window_pattern": self.config.window_pattern.value,
                    "original_payload_size": len(context.payload),
                    "config": {
                        "window_pattern": self.config.window_pattern.value,
                        "segment_count": self.config.segment_count,
                        "min_window_size": self.config.min_window_size,
                        "max_window_size": self.config.max_window_size,
                        "use_zero_window": self.config.use_zero_window,
                        "zero_window_probability": self.config.zero_window_probability,
                        "use_extreme_values": self.config.use_extreme_values,
                        "add_window_scaling": self.config.add_window_scaling,
                        "window_scale_factor": self.config.window_scale_factor,
                        "vary_tcp_flags": self.config.vary_tcp_flags,
                        "vary_ttl": self.config.vary_ttl
                    }
                }
            )
            
            result._segments = segments
            
            self.logger.info(f"WindowScalingAttack created {len(segments)} segments with {self.config.window_pattern.value} pattern")
            
            return result
            
        except Exception as e:
            self.logger.error(f"WindowScalingAttack failed: {e}")
            return create_failed_result(
                error_message=str(e),
                modified_payload=None,
                metadata={"error": str(e), "attack_type": "window_scaling"}
            )
    
    def _create_window_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create segments with window scaling manipulation."""
        segments = []
        
        # Split payload into segments
        segment_size = len(payload) // self.config.segment_count
        remainder = len(payload) % self.config.segment_count
        
        # Generate window sizes based on pattern
        window_sizes = self._generate_window_pattern()
        
        current_pos = 0
        for i in range(self.config.segment_count):
            # Calculate segment size
            size = segment_size + (1 if i < remainder else 0)
            segment_payload = payload[current_pos:current_pos + size]
            
            # Create segment options with window manipulation
            options = self._create_segment_options(i, window_sizes[i])
            
            segments.append((segment_payload, current_pos, options))
            current_pos += size
        
        return segments
    
    def _generate_window_pattern(self) -> List[int]:
        """Generate window sizes based on configured pattern."""
        window_sizes = []
        
        for i in range(self.config.segment_count):
            if self.config.use_zero_window and random.random() < self.config.zero_window_probability:
                window_size = 0
            elif self.config.window_pattern == WindowPattern.RANDOM:
                window_size = self._get_random_window_size()
            elif self.config.window_pattern == WindowPattern.INCREASING:
                progress = i / (self.config.segment_count - 1) if self.config.segment_count > 1 else 0
                window_size = int(self.config.min_window_size + progress * (self.config.max_window_size - self.config.min_window_size))
            elif self.config.window_pattern == WindowPattern.DECREASING:
                progress = 1.0 - (i / (self.config.segment_count - 1) if self.config.segment_count > 1 else 0)
                window_size = int(self.config.min_window_size + progress * (self.config.max_window_size - self.config.min_window_size))
            elif self.config.window_pattern == WindowPattern.OSCILLATING:
                # Sine wave pattern
                import math
                phase = (i / self.config.segment_count) * 2 * math.pi
                normalized = (math.sin(phase) + 1) / 2  # Normalize to 0-1
                window_size = int(self.config.min_window_size + normalized * (self.config.max_window_size - self.config.min_window_size))
            elif self.config.window_pattern == WindowPattern.ZERO_WINDOW:
                window_size = 0 if i % 2 == 0 else self.config.max_window_size
            elif self.config.window_pattern == WindowPattern.EXTREME_VALUES:
                window_size = random.choice([0, 1, 65535, self.config.max_window_size])
            else:
                window_size = self._get_random_window_size()
            
            window_sizes.append(window_size)
        
        return window_sizes
    
    def _get_random_window_size(self) -> int:
        """Get random window size within configured range."""
        if self.config.use_extreme_values and random.random() < 0.3:
            # 30% chance of extreme values
            return random.choice([0, 1, 65535])
        else:
            return random.randint(self.config.min_window_size, self.config.max_window_size)
    
    def _create_segment_options(self, segment_index: int, window_size: int) -> Dict[str, Any]:
        """Create options for a segment."""
        options = {
            "delay_ms": self.config.base_delay_ms,
            "window_size": window_size,
            "ttl": 64
        }
        
        # Set TCP flags
        if self.config.vary_tcp_flags:
            # Vary flags based on window size
            if window_size == 0:
                options["flags"] = 0x10  # ACK only (window closed)
            elif window_size < 1000:
                options["flags"] = 0x18  # PSH+ACK (small window)
            else:
                options["flags"] = 0x18  # PSH+ACK (normal)
        else:
            options["flags"] = 0x18  # PSH+ACK
        
        # Add window scaling option if configured
        if self.config.add_window_scaling and segment_index == 0:
            options["tcp_options"] = {
                "window_scale": self.config.window_scale_factor
            }
        
        # Vary TTL if configured
        if self.config.vary_ttl:
            ttl = random.randint(self.config.ttl_range[0], self.config.ttl_range[1])
            options["ttl"] = ttl
        
        return options
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get information about this attack."""
        return {
            "name": self.name,
            "type": "window_scaling",
            "description": "Manipulates TCP window sizes and scaling to confuse window-based DPI analysis",
            "technique": "tcp_window_manipulation",
            "effectiveness": "medium_against_window_analysis_dpi",
            "config": {
                "window_pattern": self.config.window_pattern.value,
                "segment_count": self.config.segment_count,
                "min_window_size": self.config.min_window_size,
                "max_window_size": self.config.max_window_size,
                "use_zero_window": self.config.use_zero_window,
                "zero_window_probability": self.config.zero_window_probability,
                "use_extreme_values": self.config.use_extreme_values,
                "add_window_scaling": self.config.add_window_scaling,
                "window_scale_factor": self.config.window_scale_factor
            },
            "window_patterns": [pattern.value for pattern in WindowPattern],
            "advantages": [
                "Confuses window-based DPI analysis",
                "Multiple window scaling patterns",
                "Zero window advertisement support",
                "Extreme value generation",
                "TCP window scaling option support"
            ]
        }
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        effectiveness = 0.6  # Base effectiveness
        
        # Higher effectiveness with zero window usage
        if self.config.use_zero_window:
            effectiveness += 0.1
        
        # Higher effectiveness with extreme values
        if self.config.use_extreme_values:
            effectiveness += 0.05
        
        # Higher effectiveness with window scaling
        if self.config.add_window_scaling:
            effectiveness += 0.05
        
        # Higher effectiveness with complex patterns
        if self.config.window_pattern in [WindowPattern.OSCILLATING, WindowPattern.EXTREME_VALUES]:
            effectiveness += 0.1
        
        # Higher effectiveness with TCP flag variation
        if self.config.vary_tcp_flags:
            effectiveness += 0.05
        
        return min(1.0, max(0.0, effectiveness))
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        capabilities = [
            "packet_construction",
            "window_size_modification",
            "timing_control",
            "sequence_manipulation"
        ]
        
        if self.config.vary_tcp_flags:
            capabilities.append("tcp_flags_modification")
        
        if self.config.vary_ttl:
            capabilities.append("ttl_modification")
        
        if self.config.add_window_scaling:
            capabilities.append("tcp_options_modification")
        
        return capabilities
    
    def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
        """Validate attack context."""
        if not context.payload:
            return False, "Empty payload provided"
        
        min_payload_size = self.config.segment_count * 5
        if len(context.payload) < min_payload_size:
            return False, f"Payload too small for {self.config.segment_count} segments"
        
        return True, None


# Factory functions
def create_window_scaling_attack(
    name: str = "window_scaling",
    window_pattern: WindowPattern = WindowPattern.RANDOM,
    segment_count: int = 4,
    min_window_size: int = 0,
    max_window_size: int = 65535,
    use_zero_window: bool = True,
    zero_window_probability: float = 0.2,
    use_extreme_values: bool = True,
    add_window_scaling: bool = True,
    window_scale_factor: int = 7,
    vary_tcp_flags: bool = True,
    vary_ttl: bool = False
) -> WindowScalingAttack:
    """Factory function to create WindowScalingAttack."""
    config = WindowScalingConfig(
        window_pattern=window_pattern,
        segment_count=segment_count,
        min_window_size=min_window_size,
        max_window_size=max_window_size,
        use_zero_window=use_zero_window,
        zero_window_probability=zero_window_probability,
        use_extreme_values=use_extreme_values,
        add_window_scaling=add_window_scaling,
        window_scale_factor=window_scale_factor,
        vary_tcp_flags=vary_tcp_flags,
        vary_ttl=vary_ttl
    )
    
    return WindowScalingAttack(name=name, config=config)


# Predefined variants
def create_zero_window_attack() -> WindowScalingAttack:
    """Create zero window variant."""
    return create_window_scaling_attack(
        name="zero_window_attack",
        window_pattern=WindowPattern.ZERO_WINDOW,
        segment_count=5,
        use_zero_window=True,
        zero_window_probability=0.6,
        vary_tcp_flags=True
    )


def create_oscillating_window_attack() -> WindowScalingAttack:
    """Create oscillating window variant."""
    return create_window_scaling_attack(
        name="oscillating_window_attack",
        window_pattern=WindowPattern.OSCILLATING,
        segment_count=8,
        min_window_size=1024,
        max_window_size=32768,
        add_window_scaling=True,
        vary_tcp_flags=True
    )


def create_extreme_window_attack() -> WindowScalingAttack:
    """Create extreme window values variant."""
    return create_window_scaling_attack(
        name="extreme_window_attack",
        window_pattern=WindowPattern.EXTREME_VALUES,
        segment_count=6,
        use_extreme_values=True,
        use_zero_window=True,
        zero_window_probability=0.4,
        vary_tcp_flags=True,
        vary_ttl=True
    )