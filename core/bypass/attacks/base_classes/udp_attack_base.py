"""
Base class for UDP-layer attacks.

Provides common functionality for attacks that manipulate UDP protocol:
- UDP packet parsing and construction
- QUIC protocol detection and parsing
- STUN message handling
- UDP fragmentation support
- Datagram manipulation utilities
"""

import logging
import struct
import socket
import secrets
from abc import abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Union
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..metadata import AttackCategories

logger = logging.getLogger(__name__)


# UDP Constants
UDP_HEADER_SIZE = 8
UDP_MAX_PACKET_SIZE = 65535

# QUIC Constants
QUIC_VERSION_1 = 0x00000001  # RFC 9000
QUIC_VERSION_DRAFT_29 = 0xff00001d
QUIC_VERSION_NEGOTIATION = 0x00000000

# QUIC Packet Types (Long Header)
QUIC_PACKET_INITIAL = 0x00
QUIC_PACKET_0RTT = 0x01
QUIC_PACKET_HANDSHAKE = 0x02
QUIC_PACKET_RETRY = 0x03

# QUIC Frame Types
QUIC_FRAME_PADDING = 0x00
QUIC_FRAME_PING = 0x01
QUIC_FRAME_ACK = 0x02
QUIC_FRAME_RESET_STREAM = 0x04
QUIC_FRAME_STOP_SENDING = 0x05
QUIC_FRAME_CRYPTO = 0x06
QUIC_FRAME_NEW_TOKEN = 0x07
QUIC_FRAME_STREAM = 0x08

# STUN Constants
STUN_HEADER_SIZE = 20
STUN_MAGIC_COOKIE = 0x2112A442

# STUN Message Types
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_BINDING_ERROR = 0x0111

# STUN Attribute Types
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_USERNAME = 0x0006
STUN_ATTR_MESSAGE_INTEGRITY = 0x0008
STUN_ATTR_ERROR_CODE = 0x0009
STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A
STUN_ATTR_REALM = 0x0014
STUN_ATTR_NONCE = 0x0015
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020


class UDPPacket:
    """Represents a parsed UDP packet."""
    
    def __init__(self, data: bytes):
        """Parse UDP packet from raw bytes."""
        if len(data) < UDP_HEADER_SIZE:
            raise ValueError(f"UDP packet too short: {len(data)} bytes")
        
        self.raw_data = data
        self.src_port = struct.unpack('!H', data[0:2])[0]
        self.dst_port = struct.unpack('!H', data[2:4])[0]
        self.length = struct.unpack('!H', data[4:6])[0]
        self.checksum = struct.unpack('!H', data[6:8])[0]
        self.payload = data[8:self.length] if self.length <= len(data) else data[8:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        return {
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'length': self.length,
            'checksum': self.checksum,
            'payload_length': len(self.payload)
        }


class QUICPacket:
    """Represents a parsed QUIC packet."""
    
    def __init__(self, data: bytes):
        """Parse QUIC packet from raw bytes."""
        if len(data) < 1:
            raise ValueError("QUIC packet too short")
        
        self.raw_data = data
        self.first_byte = data[0]
        self.is_long_header = (self.first_byte & 0x80) != 0
        
        if self.is_long_header:
            self._parse_long_header(data)
        else:
            self._parse_short_header(data)
    
    def _parse_long_header(self, data: bytes):
        """Parse QUIC long header packet."""
        if len(data) < 5:
            raise ValueError("QUIC long header too short")
        
        self.header_form = 1
        self.fixed_bit = (self.first_byte & 0x40) != 0
        self.packet_type = (self.first_byte >> 4) & 0x03
        self.type_specific = self.first_byte & 0x0F
        
        # Parse version
        self.version = struct.unpack('!I', data[1:5])[0]
        
        offset = 5
        
        # Parse DCID length and value
        if offset < len(data):
            dcid_len = data[offset]
            offset += 1
            if offset + dcid_len <= len(data):
                self.dcid = data[offset:offset + dcid_len]
                offset += dcid_len
            else:
                self.dcid = b''
        else:
            self.dcid = b''
        
        # Parse SCID length and value
        if offset < len(data):
            scid_len = data[offset]
            offset += 1
            if offset + scid_len <= len(data):
                self.scid = data[offset:offset + scid_len]
                offset += scid_len
            else:
                self.scid = b''
        else:
            self.scid = b''
        
        self.payload = data[offset:]
    
    def _parse_short_header(self, data: bytes):
        """Parse QUIC short header packet."""
        self.header_form = 0
        self.fixed_bit = (self.first_byte & 0x40) != 0
        self.spin_bit = (self.first_byte & 0x20) != 0
        self.key_phase = (self.first_byte & 0x04) != 0
        
        self.version = None
        self.dcid = b''  # DCID length is implicit in short header
        self.scid = b''
        self.payload = data[1:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        result = {
            'is_long_header': self.is_long_header,
            'fixed_bit': self.fixed_bit,
            'payload_length': len(self.payload)
        }
        
        if self.is_long_header:
            result.update({
                'packet_type': self.packet_type,
                'version': hex(self.version) if self.version else None,
                'dcid_length': len(self.dcid),
                'scid_length': len(self.scid)
            })
        else:
            result.update({
                'spin_bit': self.spin_bit,
                'key_phase': self.key_phase
            })
        
        return result


class STUNMessage:
    """Represents a parsed STUN message."""
    
    def __init__(self, data: bytes):
        """Parse STUN message from raw bytes."""
        if len(data) < STUN_HEADER_SIZE:
            raise ValueError(f"STUN message too short: {len(data)} bytes")
        
        self.raw_data = data
        
        # Parse header
        msg_type_and_length = struct.unpack('!HH', data[0:4])
        self.message_type = msg_type_and_length[0]
        self.message_length = msg_type_and_length[1]
        
        self.magic_cookie = struct.unpack('!I', data[4:8])[0]
        self.transaction_id = data[8:20]
        
        # Parse attributes
        self.attributes = []
        offset = 20
        
        while offset + 4 <= len(data):
            attr_type = struct.unpack('!H', data[offset:offset+2])[0]
            attr_length = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4
            
            if offset + attr_length > len(data):
                break
            
            attr_value = data[offset:offset+attr_length]
            self.attributes.append({
                'type': attr_type,
                'length': attr_length,
                'value': attr_value
            })
            
            # Attributes are padded to 4-byte boundary
            padding = (4 - (attr_length % 4)) % 4
            offset += attr_length + padding
    
    def is_valid(self) -> bool:
        """Check if STUN message is valid."""
        return self.magic_cookie == STUN_MAGIC_COOKIE
    
    def get_message_class(self) -> int:
        """Get STUN message class."""
        return (self.message_type >> 4) & 0x03
    
    def get_message_method(self) -> int:
        """Get STUN message method."""
        return (self.message_type & 0x000F) | ((self.message_type >> 1) & 0x0070) | ((self.message_type >> 2) & 0x0F80)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary representation."""
        return {
            'message_type': hex(self.message_type),
            'message_length': self.message_length,
            'magic_cookie': hex(self.magic_cookie),
            'transaction_id': self.transaction_id.hex(),
            'is_valid': self.is_valid(),
            'message_class': self.get_message_class(),
            'message_method': self.get_message_method(),
            'attributes_count': len(self.attributes)
        }


class UDPAttackBase(BaseAttack):
    """Base class for UDP-layer attacks."""
    
    # Default fragment size for UDP
    DEFAULT_FRAGMENT_SIZE = 1400
    
    def __init__(self):
        """Initialize UDP attack base."""
        super().__init__()
        self._quic_detected = False
        self._stun_detected = False
    
    @abstractmethod
    def modify_udp_packet(self, packet: UDPPacket, context: AttackContext) -> Optional[bytes]:
        """
        Modify UDP packet according to attack strategy.
        
        Args:
            packet: Parsed UDP packet
            context: Attack context
            
        Returns:
            Modified packet bytes or None if no modification
        """
        pass
    
    @abstractmethod
    def should_fragment_udp(self, packet: UDPPacket, context: AttackContext) -> bool:
        """
        Determine if UDP packet should be fragmented.
        
        Args:
            packet: Parsed UDP packet
            context: Attack context
            
        Returns:
            True if packet should be fragmented
        """
        pass
    
    # UDP Packet Parsing
    
    def parse_udp_packet(self, data: bytes) -> Optional[UDPPacket]:
        """
        Parse UDP packet from raw bytes.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Parsed UDPPacket or None if parsing fails
        """
        try:
            if len(data) < UDP_HEADER_SIZE:
                logger.warning(f"UDP packet too short: {len(data)} bytes")
                return None
            
            packet = UDPPacket(data)
            
            # Validate packet
            if packet.length < UDP_HEADER_SIZE:
                logger.warning(f"Invalid UDP length: {packet.length}")
                return None
            
            return packet
            
        except Exception as e:
            logger.error(f"Failed to parse UDP packet: {e}")
            return None
    
    # UDP Packet Construction
    
    def build_udp_packet(
        self,
        src_port: int,
        dst_port: int,
        payload: bytes,
        checksum: Optional[int] = None
    ) -> bytes:
        """
        Build UDP packet from components.
        
        Args:
            src_port: Source port
            dst_port: Destination port
            payload: Packet payload
            checksum: UDP checksum (calculated if None)
            
        Returns:
            Complete UDP packet bytes
        """
        length = UDP_HEADER_SIZE + len(payload)
        
        if checksum is None:
            checksum = 0  # Optional in IPv4
        
        header = struct.pack(
            '!HHHH',
            src_port,
            dst_port,
            length,
            checksum
        )
        
        return header + payload
    
    def calculate_udp_checksum(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload: bytes
    ) -> int:
        """
        Calculate UDP checksum with pseudo-header.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            payload: UDP payload
            
        Returns:
            Calculated checksum
        """
        # Build pseudo-header
        pseudo_header = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,  # Reserved
            17,  # Protocol (UDP)
            UDP_HEADER_SIZE + len(payload)
        )
        
        # Build UDP header with checksum = 0
        udp_header = struct.pack(
            '!HHHH',
            src_port,
            dst_port,
            UDP_HEADER_SIZE + len(payload),
            0
        )
        
        # Combine for checksum calculation
        data = pseudo_header + udp_header + payload
        
        # Ensure even length
        if len(data) % 2 == 1:
            data += b'\x00'
        
        # Calculate checksum
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        checksum = ~checksum & 0xFFFF
        
        # UDP checksum of 0 means no checksum
        if checksum == 0:
            checksum = 0xFFFF
        
        return checksum
    
    # QUIC Protocol Detection and Parsing
    
    def detect_quic(self, data: bytes) -> bool:
        """
        Detect if data is a QUIC packet.
        
        Args:
            data: Packet data
            
        Returns:
            True if QUIC packet detected
        """
        if len(data) < 5:
            return False
        
        first_byte = data[0]
        
        # Check for QUIC long header (version negotiation or versioned packet)
        if (first_byte & 0x80) != 0:
            # Long header - must also have fixed bit set
            if (first_byte & 0x40) == 0:
                return False
            
            # Check version field
            version = struct.unpack('!I', data[1:5])[0]
            # Known QUIC versions or version negotiation
            if version == QUIC_VERSION_NEGOTIATION or version == QUIC_VERSION_1 or (version & 0xFF000000) == 0xFF000000:
                self._quic_detected = True
                return True
        
        # For short header, we need more validation to avoid false positives
        # Short header packets are harder to detect reliably without context
        # We'll be conservative and only detect long headers
        
        return False
    
    def parse_quic_packet(self, data: bytes) -> Optional[QUICPacket]:
        """
        Parse QUIC packet.
        
        Args:
            data: Raw packet data
            
        Returns:
            Parsed QUICPacket or None if parsing fails
        """
        try:
            if not self.detect_quic(data):
                return None
            
            packet = QUICPacket(data)
            return packet
            
        except Exception as e:
            logger.error(f"Failed to parse QUIC packet: {e}")
            return None
    
    def build_quic_initial_packet(
        self,
        version: int,
        dcid: bytes,
        scid: bytes,
        payload: bytes
    ) -> bytes:
        """
        Build QUIC Initial packet.
        
        Args:
            version: QUIC version
            dcid: Destination Connection ID
            scid: Source Connection ID
            payload: Packet payload
            
        Returns:
            QUIC packet bytes
        """
        # First byte: Long header, Initial packet type
        first_byte = 0x80 | 0x40 | (QUIC_PACKET_INITIAL << 4)
        
        packet = bytes([first_byte])
        packet += struct.pack('!I', version)
        packet += bytes([len(dcid)]) + dcid
        packet += bytes([len(scid)]) + scid
        packet += payload
        
        return packet
    
    def extract_quic_connection_ids(self, packet: QUICPacket) -> Tuple[bytes, bytes]:
        """
        Extract connection IDs from QUIC packet.
        
        Args:
            packet: Parsed QUIC packet
            
        Returns:
            Tuple of (dcid, scid)
        """
        return (packet.dcid, packet.scid)
    
    def get_quic_version(self, packet: QUICPacket) -> Optional[int]:
        """
        Get QUIC version from packet.
        
        Args:
            packet: Parsed QUIC packet
            
        Returns:
            QUIC version or None
        """
        return packet.version if packet.is_long_header else None
    
    # STUN Message Handling
    
    def detect_stun(self, data: bytes) -> bool:
        """
        Detect if data is a STUN message.
        
        Args:
            data: Packet data
            
        Returns:
            True if STUN message detected
        """
        if len(data) < STUN_HEADER_SIZE:
            return False
        
        # Check magic cookie
        magic_cookie = struct.unpack('!I', data[4:8])[0]
        if magic_cookie != STUN_MAGIC_COOKIE:
            return False
        
        # Check message type (first 2 bits should be 0)
        msg_type = struct.unpack('!H', data[0:2])[0]
        if (msg_type & 0xC000) != 0:
            return False
        
        self._stun_detected = True
        return True
    
    def parse_stun_message(self, data: bytes) -> Optional[STUNMessage]:
        """
        Parse STUN message.
        
        Args:
            data: Raw message data
            
        Returns:
            Parsed STUNMessage or None if parsing fails
        """
        try:
            if not self.detect_stun(data):
                return None
            
            message = STUNMessage(data)
            
            if not message.is_valid():
                logger.warning("Invalid STUN message (bad magic cookie)")
                return None
            
            return message
            
        except Exception as e:
            logger.error(f"Failed to parse STUN message: {e}")
            return None
    
    def build_stun_message(
        self,
        message_type: int,
        transaction_id: Optional[bytes] = None,
        attributes: Optional[List[Dict[str, Any]]] = None
    ) -> bytes:
        """
        Build STUN message.
        
        Args:
            message_type: STUN message type
            transaction_id: Transaction ID (generated if None)
            attributes: List of attribute dicts with 'type' and 'value'
            
        Returns:
            STUN message bytes
        """
        if transaction_id is None:
            transaction_id = secrets.token_bytes(12)
        
        if len(transaction_id) != 12:
            raise ValueError("Transaction ID must be 12 bytes")
        
        # Build attributes
        attrs_data = b''
        if attributes:
            for attr in attributes:
                attr_type = attr['type']
                attr_value = attr['value']
                attr_length = len(attr_value)
                
                attrs_data += struct.pack('!HH', attr_type, attr_length)
                attrs_data += attr_value
                
                # Pad to 4-byte boundary
                padding = (4 - (attr_length % 4)) % 4
                attrs_data += b'\x00' * padding
        
        # Build header
        message_length = len(attrs_data)
        header = struct.pack(
            '!HHI12s',
            message_type,
            message_length,
            STUN_MAGIC_COOKIE,
            transaction_id
        )
        
        return header + attrs_data
    
    def get_stun_attribute(self, message: STUNMessage, attr_type: int) -> Optional[bytes]:
        """
        Get STUN attribute value by type.
        
        Args:
            message: Parsed STUN message
            attr_type: Attribute type to find
            
        Returns:
            Attribute value or None if not found
        """
        for attr in message.attributes:
            if attr['type'] == attr_type:
                return attr['value']
        return None
    
    # UDP Fragmentation
    
    def fragment_udp_payload(
        self,
        payload: bytes,
        fragment_size: int = DEFAULT_FRAGMENT_SIZE
    ) -> List[bytes]:
        """
        Fragment UDP payload into smaller chunks.
        
        Args:
            payload: Payload to fragment
            fragment_size: Maximum fragment size
            
        Returns:
            List of payload fragments
        """
        if len(payload) <= fragment_size:
            return [payload]
        
        fragments = []
        offset = 0
        
        while offset < len(payload):
            end = min(offset + fragment_size, len(payload))
            fragments.append(payload[offset:end])
            offset = end
        
        logger.info(f"Fragmented payload into {len(fragments)} fragments")
        return fragments
    
    def create_fragmented_packets(
        self,
        src_port: int,
        dst_port: int,
        payload: bytes,
        fragment_size: int = DEFAULT_FRAGMENT_SIZE
    ) -> List[bytes]:
        """
        Create multiple UDP packets from fragmented payload.
        
        Args:
            src_port: Source port
            dst_port: Destination port
            payload: Complete payload
            fragment_size: Maximum fragment size
            
        Returns:
            List of complete UDP packets
        """
        fragments = self.fragment_udp_payload(payload, fragment_size)
        packets = []
        
        for fragment in fragments:
            packet = self.build_udp_packet(src_port, dst_port, fragment)
            packets.append(packet)
        
        return packets
    
    # Protocol Detection Helpers
    
    def detect_protocol(self, data: bytes) -> str:
        """
        Detect protocol type from UDP payload.
        
        Args:
            data: UDP payload data
            
        Returns:
            Protocol name ('quic', 'stun', 'dns', 'unknown')
        """
        if self.detect_quic(data):
            return 'quic'
        elif self.detect_stun(data):
            return 'stun'
        elif len(data) >= 12:
            # Check for DNS (has header structure)
            try:
                # DNS has specific structure we can check
                qdcount = struct.unpack('!H', data[4:6])[0]
                ancount = struct.unpack('!H', data[6:8])[0]
                if qdcount > 0 and qdcount < 100 and ancount < 100:
                    return 'dns'
            except:
                pass
        
        return 'unknown'
    
    def is_quic_detected(self) -> bool:
        """Check if QUIC protocol was detected."""
        return self._quic_detected
    
    def is_stun_detected(self) -> bool:
        """Check if STUN protocol was detected."""
        return self._stun_detected
    
    # Helper Methods
    
    def get_optimal_fragment_size(self, mtu: int = 1500) -> int:
        """
        Calculate optimal fragment size based on MTU.
        
        Args:
            mtu: Maximum Transmission Unit
            
        Returns:
            Optimal fragment size
        """
        # Account for IP header (20 bytes) and UDP header (8 bytes)
        return mtu - 20 - UDP_HEADER_SIZE
    
    def validate_port(self, port: int) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            True if valid
        """
        return 0 <= port <= 65535
