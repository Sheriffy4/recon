"""
STUN Bypass Attack for VoIP applications like Telegram, WhatsApp.

This attack targets STUN (Session Traversal Utilities for NAT) protocol
which is commonly used by VoIP and messaging applications for NAT traversal.
"""

import struct
import random
import time
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext
from ..registry import register_attack


@dataclass
class STUNBypassConfig:
    """Configuration for STUN bypass attack."""
    stun_method: str = "binding"
    fake_transaction_id: bool = True
    fragment_size: int = 64
    delay_ms: int = 10


@register_attack("stun_bypass")
class STUNBypassAttack(BaseAttack):
    """
    STUN protocol bypass attack.
    
    Targets STUN packets used by VoIP applications for NAT traversal.
    Effective against Telegram calls, WhatsApp calls, Discord voice, etc.
    """
    
    def __init__(self, name: str = "stun_bypass", config: Optional[STUNBypassConfig] = None):
        super().__init__()
        self._name = name
        self.config = config or STUNBypassConfig()
        
    @property
    def name(self) -> str:
        return self._name
        
    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute STUN bypass attack."""
        try:
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No payload provided for STUN bypass",
                    metadata={"attack_type": "stun_bypass"}
                )
            
            # Check if this looks like a STUN packet
            if not self._is_stun_packet(context.payload):
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Payload does not appear to be STUN packet",
                    metadata={"attack_type": "stun_bypass"}
                )
            
            # Generate bypass segments
            segments = await self._create_stun_bypass_segments(context.payload, context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                packets_sent=len(segments),
                metadata={
                    "attack_type": "stun_bypass",
                    "stun_method": self.config.stun_method,
                    "segments": len(segments),
                    "target_protocol": "STUN/UDP"
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"attack_type": "stun_bypass"}
            )
    
    def _is_stun_packet(self, payload: bytes) -> bool:
        """Check if payload is a STUN packet."""
        if len(payload) < 20:  # Minimum STUN header size
            return False
            
        # STUN magic cookie (0x2112A442)
        if len(payload) >= 8:
            magic_cookie = struct.unpack("!I", payload[4:8])[0]
            if magic_cookie == 0x2112A442:
                return True
        
        # Check STUN message type (first 2 bytes)
        if len(payload) >= 2:
            msg_type = struct.unpack("!H", payload[0:2])[0]
            # STUN message types: 0x0001 (Binding Request), 0x0101 (Binding Response), etc.
            if msg_type in [0x0001, 0x0101, 0x0111, 0x0003, 0x0103, 0x0113]:
                return True
        
        return False
    
    async def _create_stun_bypass_segments(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create STUN bypass segments."""
        segments = []
        
        if self.config.fake_transaction_id and len(payload) >= 20:
            # Create fake STUN packet with different transaction ID
            fake_payload = bytearray(payload)
            # Replace transaction ID (bytes 8-19) with random data
            for i in range(8, min(20, len(fake_payload))):
                fake_payload[i] = random.randint(0, 255)
            
            segments.append((
                bytes(fake_payload),
                0,
                {
                    "is_fake": True,
                    "ttl": 1,  # Low TTL for fake packet
                    "delay_ms": 0
                }
            ))
        
        # Fragment the real STUN packet
        if len(payload) > self.config.fragment_size:
            fragments = []
            for i in range(0, len(payload), self.config.fragment_size):
                fragment = payload[i:i + self.config.fragment_size]
                fragments.append(fragment)
            
            # Send fragments with delays
            for i, fragment in enumerate(fragments):
                segments.append((
                    fragment,
                    i * self.config.fragment_size,
                    {
                        "is_fake": False,
                        "delay_ms": i * self.config.delay_ms,
                        "fragment_index": i,
                        "total_fragments": len(fragments)
                    }
                ))
        else:
            # Send original packet if small enough
            segments.append((
                payload,
                0,
                {
                    "is_fake": False,
                    "delay_ms": self.config.delay_ms
                }
            ))
        
        return segments