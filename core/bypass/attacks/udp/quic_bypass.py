"""
QUIC Bypass Attack for HTTP/3 and modern web applications.

This attack targets QUIC (Quick UDP Internet Connections) protocol
which is used by HTTP/3 and modern web applications.

Techniques:
- Connection ID manipulation
- Packet number scrambling
- Version negotiation confusion
- Frame reordering
- Token manipulation
"""

import struct
import random
import secrets
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..base_classes.udp_attack_base import (
    UDPAttackBase,
    QUICPacket,
    QUIC_VERSION_1,
    QUIC_VERSION_DRAFT_29,
    QUIC_PACKET_INITIAL,
    QUIC_FRAME_PADDING,
    QUIC_FRAME_CRYPTO,
)
from ..base import AttackResult, AttackStatus, AttackContext
from ..registry import register_attack
from ..metadata import AttackCategories

logger = logging.getLogger(__name__)


@dataclass
class QUICBypassConfig:
    """Configuration for QUIC bypass attack."""
    
    # Connection ID manipulation
    scramble_dcid: bool = True
    scramble_scid: bool = False
    fake_dcid_length: int = 8
    
    # Packet number manipulation
    packet_number_offset: int = 1000
    randomize_packet_number: bool = True
    
    # Version manipulation
    fake_version: Optional[int] = None
    version_negotiation: bool = False
    
    # Frame manipulation
    inject_padding: bool = True
    padding_size: int = 100
    reorder_frames: bool = False
    
    # Token manipulation
    fake_token: bool = True
    token_size: int = 32
    
    # Timing
    send_fake_first: bool = True
    fake_packet_delay_ms: int = 0
    real_packet_delay_ms: int = 10


@register_attack("quic_bypass")
class QUICBypassAttack(UDPAttackBase):
    """
    QUIC protocol bypass attack.
    
    Targets QUIC packets used by HTTP/3 and modern web applications.
    Effective against Google services, Cloudflare, and other QUIC-enabled sites.
    
    This attack manipulates QUIC headers to evade DPI:
    - Scrambles connection IDs to confuse stateful inspection
    - Modifies packet numbers to break sequence tracking
    - Injects fake version negotiation packets
    - Adds padding and reorders frames
    - Manipulates tokens in Initial packets
    """
    
    def __init__(self, config: Optional[QUICBypassConfig] = None):
        """Initialize QUIC bypass attack."""
        super().__init__()
        self.config = config or QUICBypassConfig()
    
    @property
    def name(self) -> str:
        return "quic_bypass"
    
    @property
    def category(self) -> str:
        return AttackCategories.TUNNELING
    
    @property
    def required_params(self) -> list:
        return []
    
    @property
    def optional_params(self) -> dict:
        return {
            "scramble_dcid": True,
            "scramble_scid": False,
            "packet_number_offset": 1000,
            "inject_padding": True,
            "padding_size": 100,
            "fake_token": True,
            "token_size": 32,
        }
    
    def modify_udp_packet(self, packet, context: AttackContext) -> Optional[bytes]:
        """Modify UDP packet - not used for QUIC bypass."""
        return None
    
    def should_fragment_udp(self, packet, context: AttackContext) -> bool:
        """QUIC bypass doesn't use fragmentation."""
        return False
    
    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC bypass attack."""
        try:
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No payload provided for QUIC bypass",
                    metadata={"attack": self.name},
                )
            
            # Detect and parse QUIC packet
            if not self.detect_quic(context.payload):
                return AttackResult(
                    status=AttackStatus.SKIPPED,
                    error_message="Payload is not a QUIC packet",
                    metadata={"attack": self.name},
                )
            
            quic_packet = self.parse_quic_packet(context.payload)
            if not quic_packet:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Failed to parse QUIC packet",
                    metadata={"attack": self.name},
                )
            
            # Generate bypass packets
            bypass_packets = self._create_bypass_packets(quic_packet, context)
            
            if not bypass_packets:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Failed to create bypass packets",
                    metadata={"attack": self.name},
                )
            
            # Send packets (implementation would send via network)
            packets_sent = len(bypass_packets)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                packets_sent=packets_sent,
                metadata={
                    "attack": self.name,
                    "quic_version": hex(quic_packet.version) if quic_packet.version else "short_header",
                    "is_long_header": quic_packet.is_long_header,
                    "dcid_length": len(quic_packet.dcid),
                    "scid_length": len(quic_packet.scid),
                    "bypass_packets": packets_sent,
                    "techniques": self._get_active_techniques(),
                },
            )
        
        except Exception as e:
            logger.error(f"QUIC bypass attack failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"attack": self.name},
            )
    
    def _create_bypass_packets(
        self,
        quic_packet: QUICPacket,
        context: AttackContext
    ) -> List[Dict[str, Any]]:
        """
        Create bypass packets with various manipulation techniques.
        
        Returns list of packet dictionaries with:
        - data: packet bytes
        - delay_ms: delay before sending
        - ttl: TTL value (for fake packets)
        - is_fake: whether this is a decoy packet
        """
        packets = []
        
        # Only manipulate long header packets (Initial, Handshake, etc.)
        if not quic_packet.is_long_header:
            logger.info("Short header packet - limited manipulation available")
            packets.append({
                "data": quic_packet.raw_data,
                "delay_ms": 0,
                "ttl": None,
                "is_fake": False,
            })
            return packets
        
        # Create fake packets first if configured
        if self.config.send_fake_first:
            fake_packets = self._create_fake_packets(quic_packet, context)
            packets.extend(fake_packets)
        
        # Create modified real packet
        modified_packet = self._create_modified_packet(quic_packet, context)
        if modified_packet:
            packets.append({
                "data": modified_packet,
                "delay_ms": self.config.real_packet_delay_ms,
                "ttl": None,
                "is_fake": False,
            })
        else:
            # Fallback to original if modification fails
            packets.append({
                "data": quic_packet.raw_data,
                "delay_ms": self.config.real_packet_delay_ms,
                "ttl": None,
                "is_fake": False,
            })
        
        return packets
    
    def _create_fake_packets(
        self,
        quic_packet: QUICPacket,
        context: AttackContext
    ) -> List[Dict[str, Any]]:
        """Create fake decoy packets."""
        fake_packets = []
        
        # Fake packet with scrambled DCID
        if self.config.scramble_dcid and len(quic_packet.dcid) > 0:
            fake_dcid = self._scramble_connection_id(quic_packet.dcid)
            fake_packet = self._rebuild_quic_packet(
                quic_packet,
                dcid=fake_dcid,
                scid=quic_packet.scid,
            )
            
            if fake_packet:
                fake_packets.append({
                    "data": fake_packet,
                    "delay_ms": self.config.fake_packet_delay_ms,
                    "ttl": 2,  # Low TTL so it doesn't reach destination
                    "is_fake": True,
                })
        
        # Fake packet with wrong version
        if self.config.version_negotiation and quic_packet.version:
            fake_version = self._get_fake_version(quic_packet.version)
            fake_packet = self._rebuild_quic_packet(
                quic_packet,
                version=fake_version,
            )
            
            if fake_packet:
                fake_packets.append({
                    "data": fake_packet,
                    "delay_ms": self.config.fake_packet_delay_ms + 2,
                    "ttl": 3,
                    "is_fake": True,
                })
        
        # Fake packet with offset packet number
        if self.config.packet_number_offset > 0:
            fake_packet = self._create_offset_packet_number(quic_packet)
            
            if fake_packet:
                fake_packets.append({
                    "data": fake_packet,
                    "delay_ms": self.config.fake_packet_delay_ms + 5,
                    "ttl": 3,
                    "is_fake": True,
                })
        
        return fake_packets
    
    def _create_modified_packet(
        self,
        quic_packet: QUICPacket,
        context: AttackContext
    ) -> Optional[bytes]:
        """Create modified real packet with subtle changes."""
        try:
            # Start with original packet
            modified = bytearray(quic_packet.raw_data)
            
            # Inject padding frames if configured
            if self.config.inject_padding:
                modified = self._inject_padding_frames(modified, quic_packet)
            
            # Manipulate token in Initial packets
            if self.config.fake_token and quic_packet.packet_type == QUIC_PACKET_INITIAL:
                modified = self._manipulate_token(modified, quic_packet)
            
            return bytes(modified)
        
        except Exception as e:
            logger.error(f"Failed to create modified packet: {e}")
            return None
    
    def _scramble_connection_id(self, cid: bytes) -> bytes:
        """Scramble connection ID."""
        if len(cid) == 0:
            # Generate random CID
            length = self.config.fake_dcid_length
            return secrets.token_bytes(length)
        
        # Scramble existing CID
        scrambled = bytearray(cid)
        for i in range(len(scrambled)):
            scrambled[i] = random.randint(0, 255)
        
        return bytes(scrambled)
    
    def _get_fake_version(self, real_version: int) -> int:
        """Get a fake QUIC version different from real one."""
        if self.config.fake_version:
            return self.config.fake_version
        
        # Use a different known version
        versions = [QUIC_VERSION_1, QUIC_VERSION_DRAFT_29, 0xFF00001C, 0xFF00001B]
        fake_versions = [v for v in versions if v != real_version]
        
        if fake_versions:
            return random.choice(fake_versions)
        
        # Generate random draft version
        return 0xFF000000 | random.randint(1, 255)
    
    def _rebuild_quic_packet(
        self,
        original: QUICPacket,
        version: Optional[int] = None,
        dcid: Optional[bytes] = None,
        scid: Optional[bytes] = None,
    ) -> Optional[bytes]:
        """Rebuild QUIC packet with modified fields."""
        try:
            if not original.is_long_header:
                return None
            
            # Use original values if not specified
            version = version if version is not None else original.version
            dcid = dcid if dcid is not None else original.dcid
            scid = scid if scid is not None else original.scid
            
            # Build packet
            packet = bytearray()
            
            # First byte (preserve packet type and flags)
            packet.append(original.first_byte)
            
            # Version
            packet.extend(struct.pack('!I', version))
            
            # DCID
            packet.append(len(dcid))
            packet.extend(dcid)
            
            # SCID
            packet.append(len(scid))
            packet.extend(scid)
            
            # Payload (simplified - real implementation would parse and rebuild properly)
            packet.extend(original.payload)
            
            return bytes(packet)
        
        except Exception as e:
            logger.error(f"Failed to rebuild QUIC packet: {e}")
            return None
    
    def _create_offset_packet_number(self, quic_packet: QUICPacket) -> Optional[bytes]:
        """Create packet with offset packet number."""
        try:
            # This is a simplified implementation
            # Real implementation would properly parse and modify packet number
            modified = bytearray(quic_packet.raw_data)
            
            # Packet number location varies by packet type
            # This is a heuristic approach
            if len(modified) > 20:
                # Try to modify what might be packet number bytes
                offset = 15  # Approximate location
                if offset + 4 <= len(modified):
                    # Add offset to potential packet number
                    try:
                        pn = struct.unpack('!I', modified[offset:offset+4])[0]
                        new_pn = (pn + self.config.packet_number_offset) & 0xFFFFFFFF
                        modified[offset:offset+4] = struct.pack('!I', new_pn)
                    except:
                        pass
            
            return bytes(modified)
        
        except Exception as e:
            logger.error(f"Failed to create offset packet number: {e}")
            return None
    
    def _inject_padding_frames(
        self,
        packet: bytearray,
        quic_packet: QUICPacket
    ) -> bytearray:
        """Inject QUIC padding frames into packet."""
        try:
            # Add padding frames at the end of payload
            # QUIC padding frame is just 0x00 bytes
            padding = bytes([QUIC_FRAME_PADDING] * self.config.padding_size)
            packet.extend(padding)
            
            return packet
        
        except Exception as e:
            logger.error(f"Failed to inject padding: {e}")
            return packet
    
    def _manipulate_token(
        self,
        packet: bytearray,
        quic_packet: QUICPacket
    ) -> bytearray:
        """Manipulate token in Initial packet."""
        try:
            # Initial packets have a token field after connection IDs
            # This is a simplified implementation
            
            # Calculate offset to token field
            offset = 5  # First byte + version
            offset += 1 + len(quic_packet.dcid)  # DCID length + DCID
            offset += 1 + len(quic_packet.scid)  # SCID length + SCID
            
            if offset < len(packet):
                # Token is variable length integer followed by token data
                # For simplicity, we'll just inject a fake token
                fake_token = secrets.token_bytes(self.config.token_size)
                
                # Insert token (this is simplified - real implementation would
                # properly encode variable length integer)
                token_length_varint = bytes([self.config.token_size])
                packet[offset:offset] = token_length_varint + fake_token
            
            return packet
        
        except Exception as e:
            logger.error(f"Failed to manipulate token: {e}")
            return packet
    
    def _get_active_techniques(self) -> List[str]:
        """Get list of active bypass techniques."""
        techniques = []
        
        if self.config.scramble_dcid:
            techniques.append("dcid_scrambling")
        if self.config.scramble_scid:
            techniques.append("scid_scrambling")
        if self.config.packet_number_offset > 0:
            techniques.append("packet_number_offset")
        if self.config.version_negotiation:
            techniques.append("version_negotiation")
        if self.config.inject_padding:
            techniques.append("padding_injection")
        if self.config.fake_token:
            techniques.append("token_manipulation")
        
        return techniques
