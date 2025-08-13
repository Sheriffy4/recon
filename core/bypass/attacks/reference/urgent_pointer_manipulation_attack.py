#!/usr/bin/env python3
"""
UrgentPointerManipulationAttack implementation using segments architecture.

This attack manipulates TCP urgent pointer and URG flag to confuse DPI systems
that don't properly handle urgent data or make assumptions about normal TCP behavior.
"""

import logging
import random
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext


@dataclass
class UrgentPointerConfig:
    """Configuration for UrgentPointerManipulationAttack."""
    
    # Number of segments to create
    segment_count: int = 3
    
    # Which segments should have URG flag set
    urgent_segments: List[int] = None  # None means random selection
    
    # Urgent pointer values to use
    urgent_pointer_values: List[int] = None  # None means random values
    
    # Whether to use invalid urgent pointer values
    use_invalid_pointers: bool = True
    
    # Range for random urgent pointer values
    pointer_range: Tuple[int, int] = (0, 65535)
    
    # Base delay between segments
    base_delay_ms: float = 5.0
    
    # Whether to add fake urgent data
    add_fake_urgent_data: bool = True
    
    # Size of fake urgent data
    fake_urgent_size: int = 10
    
    # Whether to vary other TCP parameters
    vary_window_size: bool = True
    window_size_range: Tuple[int, int] = (32768, 65535)


class UrgentPointerManipulationAttack(BaseAttack):
    """
    UrgentPointerManipulationAttack using segments architecture.
    
    This attack manipulates TCP urgent pointer and URG flag to bypass
    DPI systems that don't handle urgent data properly.
    """
    
    def __init__(self, name: str = "urgent_pointer_manipulation", config: Optional[UrgentPointerConfig] = None):
        super().__init__(name)
        self.config = config or UrgentPointerConfig()
        self.logger = logging.getLogger(f"UrgentPointerManipulationAttack.{name}")
        
        # Set defaults for None values
        if self.config.urgent_segments is None:
            self.config.urgent_segments = [0, 2]  # First and last segments
        
        if self.config.urgent_pointer_values is None:
            self.config.urgent_pointer_values = []  # Will be generated randomly
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate attack configuration."""
        if not (2 <= self.config.segment_count <= 10):
            raise ValueError(f"segment_count must be between 2 and 10, got {self.config.segment_count}")
        
        if self.config.base_delay_ms < 0:
            raise ValueError(f"base_delay_ms must be non-negative, got {self.config.base_delay_ms}")
        
        if self.config.fake_urgent_size < 0:
            raise ValueError(f"fake_urgent_size must be non-negative, got {self.config.fake_urgent_size}")
        
        # Validate urgent segments indices
        for seg_idx in self.config.urgent_segments:
            if not (0 <= seg_idx < self.config.segment_count):
                raise ValueError(f"urgent_segments index {seg_idx} out of range for {self.config.segment_count} segments")
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute UrgentPointerManipulationAttack."""
        try:
            self.logger.info(f"Executing UrgentPointerManipulationAttack on {context.connection_id}")
            
            # Validate context
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    modified_payload=None,
                    metadata={"error": "Empty payload provided"}
                )
            
            # Create segments with urgent pointer manipulation
            segments = self._create_urgent_segments(context.payload)
            
            # Create attack result
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                modified_payload=None,
                metadata={
                    "attack_type": "urgent_pointer_manipulation",
                    "segments": segments,
                    "total_segments": len(segments),
                    "urgent_segments": self.config.urgent_segments,
                    "original_payload_size": len(context.payload),
                    "config": {
                        "segment_count": self.config.segment_count,
                        "urgent_segments": self.config.urgent_segments,
                        "use_invalid_pointers": self.config.use_invalid_pointers,
                        "add_fake_urgent_data": self.config.add_fake_urgent_data,
                        "fake_urgent_size": self.config.fake_urgent_size,
                        "vary_window_size": self.config.vary_window_size
                    }
                }
            )
            
            result._segments = segments
            
            self.logger.info(f"UrgentPointerManipulationAttack created {len(segments)} segments with urgent manipulation")
            
            return result
            
        except Exception as e:
            self.logger.error(f"UrgentPointerManipulationAttack failed: {e}")
            return AttackResult(
                status=AttackStatus.FAILED,
                modified_payload=None,
                metadata={"error": str(e), "attack_type": "urgent_pointer_manipulation"}
            )
    
    def _create_urgent_segments(self, payload: bytes) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create segments with urgent pointer manipulation."""
        segments = []
        
        # Split payload into segments
        segment_size = len(payload) // self.config.segment_count
        remainder = len(payload) % self.config.segment_count
        
        current_pos = 0
        for i in range(self.config.segment_count):
            # Calculate segment size
            size = segment_size + (1 if i < remainder else 0)
            segment_payload = payload[current_pos:current_pos + size]
            
            # Add fake urgent data if this is an urgent segment
            if i in self.config.urgent_segments and self.config.add_fake_urgent_data:
                fake_urgent = self._generate_fake_urgent_data()
                segment_payload = fake_urgent + segment_payload
            
            # Create segment options
            options = self._create_segment_options(i)
            
            segments.append((segment_payload, current_pos, options))
            current_pos += size
        
        return segments
    
    def _generate_fake_urgent_data(self) -> bytes:
        """Generate fake urgent data."""
        # Generate random urgent data that looks legitimate but is meaningless
        fake_data = b"URG:" + bytes([random.randint(65, 90) for _ in range(self.config.fake_urgent_size - 4)])
        return fake_data
    
    def _create_segment_options(self, segment_index: int) -> Dict[str, Any]:
        """Create options for a segment."""
        options = {
            "delay_ms": self.config.base_delay_ms,
            "ttl": 64
        }
        
        # Set URG flag and urgent pointer for urgent segments
        if segment_index in self.config.urgent_segments:
            options["flags"] = 0x20 | 0x18  # URG + PSH + ACK
            
            # Set urgent pointer
            if segment_index < len(self.config.urgent_pointer_values):
                urgent_pointer = self.config.urgent_pointer_values[segment_index]
            else:
                if self.config.use_invalid_pointers:
                    # Use potentially invalid urgent pointer values
                    urgent_pointer = random.choice([
                        0,      # Zero pointer (often invalid)
                        65535,  # Maximum value
                        random.randint(1000, 5000),  # Random high value
                        random.randint(self.config.pointer_range[0], self.config.pointer_range[1])
                    ])
                else:
                    # Use reasonable urgent pointer value
                    urgent_pointer = random.randint(1, 100)
            
            options["urgent_pointer"] = urgent_pointer
        else:
            options["flags"] = 0x18  # PSH + ACK (no URG)
            options["urgent_pointer"] = 0
        
        # Vary window size if configured
        if self.config.vary_window_size:
            window_size = random.randint(self.config.window_size_range[0], self.config.window_size_range[1])
            options["window_size"] = window_size
        
        return options
    
    def get_attack_info(self) -> Dict[str, Any]:
        """Get information about this attack."""
        return {
            "name": self.name,
            "type": "urgent_pointer_manipulation",
            "description": "Manipulates TCP urgent pointer and URG flag to confuse DPI systems",
            "technique": "tcp_urgent_manipulation",
            "effectiveness": "medium_against_urgent_unaware_dpi",
            "config": {
                "segment_count": self.config.segment_count,
                "urgent_segments": self.config.urgent_segments,
                "use_invalid_pointers": self.config.use_invalid_pointers,
                "add_fake_urgent_data": self.config.add_fake_urgent_data,
                "fake_urgent_size": self.config.fake_urgent_size,
                "vary_window_size": self.config.vary_window_size
            },
            "advantages": [
                "Exploits DPI systems that don't handle urgent data properly",
                "Uses invalid urgent pointer values to cause confusion",
                "Adds fake urgent data for additional obfuscation",
                "Varies TCP parameters for diversity"
            ]
        }
    
    def estimate_effectiveness(self, context: AttackContext) -> float:
        """Estimate attack effectiveness."""
        effectiveness = 0.6  # Base effectiveness
        
        # Higher effectiveness with more urgent segments
        urgent_ratio = len(self.config.urgent_segments) / self.config.segment_count
        effectiveness += urgent_ratio * 0.1
        
        # Higher effectiveness with invalid pointers
        if self.config.use_invalid_pointers:
            effectiveness += 0.1
        
        # Higher effectiveness with fake urgent data
        if self.config.add_fake_urgent_data:
            effectiveness += 0.05
        
        # Higher effectiveness with window size variation
        if self.config.vary_window_size:
            effectiveness += 0.05
        
        return min(1.0, max(0.0, effectiveness))
    
    def get_required_capabilities(self) -> List[str]:
        """Get required capabilities."""
        capabilities = [
            "packet_construction",
            "tcp_flags_modification",
            "urgent_pointer_modification",
            "timing_control",
            "sequence_manipulation"
        ]
        
        if self.config.vary_window_size:
            capabilities.append("window_size_modification")
        
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
def create_urgent_pointer_attack(
    name: str = "urgent_pointer_manipulation",
    segment_count: int = 3,
    urgent_segments: List[int] = None,
    use_invalid_pointers: bool = True,
    add_fake_urgent_data: bool = True,
    fake_urgent_size: int = 10,
    vary_window_size: bool = True
) -> UrgentPointerManipulationAttack:
    """Factory function to create UrgentPointerManipulationAttack."""
    config = UrgentPointerConfig(
        segment_count=segment_count,
        urgent_segments=urgent_segments or [0, segment_count-1],
        use_invalid_pointers=use_invalid_pointers,
        add_fake_urgent_data=add_fake_urgent_data,
        fake_urgent_size=fake_urgent_size,
        vary_window_size=vary_window_size
    )
    
    return UrgentPointerManipulationAttack(name=name, config=config)


def create_aggressive_urgent_attack() -> UrgentPointerManipulationAttack:
    """Create aggressive urgent pointer variant."""
    return create_urgent_pointer_attack(
        name="aggressive_urgent_attack",
        segment_count=5,
        urgent_segments=[0, 1, 3, 4],  # Most segments are urgent
        use_invalid_pointers=True,
        add_fake_urgent_data=True,
        fake_urgent_size=15,
        vary_window_size=True
    )


def create_subtle_urgent_attack() -> UrgentPointerManipulationAttack:
    """Create subtle urgent pointer variant."""
    return create_urgent_pointer_attack(
        name="subtle_urgent_attack",
        segment_count=3,
        urgent_segments=[1],  # Only middle segment is urgent
        use_invalid_pointers=False,
        add_fake_urgent_data=False,
        vary_window_size=False
    )