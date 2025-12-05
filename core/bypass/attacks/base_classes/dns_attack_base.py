"""
Base class for DNS-layer attacks.

Provides common functionality for attacks that manipulate DNS protocol:
- DNS query/response parsing and construction
- DNS record type handling
- Encoding/decoding utilities for DNS tunneling
- Support for multiple DNS encoding schemes
- DNS packet manipulation
"""

import logging
import struct
import socket
import base64
import binascii
from abc import abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Union
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..metadata import AttackCategories

logger = logging.getLogger(__name__)


# DNS Constants
DNS_HEADER_SIZE = 12
DNS_MAX_LABEL_LENGTH = 63
DNS_MAX_NAME_LENGTH = 255
DNS_MAX_UDP_SIZE = 512
DNS_EDNS_MAX_SIZE = 4096

# DNS Record Types
DNS_TYPE_A = 1
DNS_TYPE_NS = 2
DNS_TYPE_CNAME = 5
DNS_TYPE_SOA = 6
DNS_TYPE_PTR = 12
DNS_TYPE_MX = 15
DNS_TYPE_TXT = 16
DNS_TYPE_AAAA = 28
DNS_TYPE_SRV = 33
DNS_TYPE_OPT = 41  # EDNS
DNS_TYPE_ANY = 255

# DNS Classes
DNS_CLASS_IN = 1  # Internet
DNS_CLASS_CS = 2  # CSNET
DNS_CLASS_CH = 3  # CHAOS
DNS_CLASS_HS = 4  # Hesiod
DNS_CLASS_ANY = 255

# DNS Response Codes
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4
DNS_RCODE_REFUSED = 5

# DNS Flags
DNS_FLAG_QR = 0x8000  # Query/Response
DNS_FLAG_AA = 0x0400  # Authoritative Answer
DNS_FLAG_TC = 0x0200  # Truncated
DNS_FLAG_RD = 0x0100  # Recursion Desired
DNS_FLAG_RA = 0x0080  # Recursion Available
DNS_FLAG_AD = 0x0020  # Authenticated Data
DNS_FLAG_CD = 0x0010  # Checking Disabled


class DNSHeader:
    """Represents a DNS packet header."""
    
    def __init__(
        self,
        transaction_id: int = 0,
        flags: int = 0,
        questions: int = 0,
        answers: int = 0,
        authority: int = 0,
        additional: int = 0
    ):
        """Initialize DNS header."""
        self.transaction_id = transaction_id
        self.flags = flags
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSHeader':
        """Parse DNS header from bytes."""
        if len(data) < DNS_HEADER_SIZE:
            raise ValueError(f"DNS header too short: {len(data)} bytes")
        
        values = struct.unpack('!HHHHHH', data[:DNS_HEADER_SIZE])
        return cls(*values)
    
    def to_bytes(self) -> bytes:
        """Convert DNS header to bytes."""
        return struct.pack(
            '!HHHHHH',
            self.transaction_id,
            self.flags,
            self.questions,
            self.answers,
            self.authority,
            self.additional
        )
    
    def is_query(self) -> bool:
        """Check if this is a query packet."""
        return (self.flags & DNS_FLAG_QR) == 0
    
    def is_response(self) -> bool:
        """Check if this is a response packet."""
        return (self.flags & DNS_FLAG_QR) != 0
    
    def get_opcode(self) -> int:
        """Get DNS opcode."""
        return (self.flags >> 11) & 0xF
    
    def get_rcode(self) -> int:
        """Get DNS response code."""
        return self.flags & 0xF
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert header to dictionary."""
        return {
            'transaction_id': self.transaction_id,
            'flags': hex(self.flags),
            'is_query': self.is_query(),
            'is_response': self.is_response(),
            'opcode': self.get_opcode(),
            'rcode': self.get_rcode(),
            'questions': self.questions,
            'answers': self.answers,
            'authority': self.authority,
            'additional': self.additional
        }


class DNSQuestion:
    """Represents a DNS question."""
    
    def __init__(self, name: str, qtype: int, qclass: int = DNS_CLASS_IN):
        """Initialize DNS question."""
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert question to dictionary."""
        return {
            'name': self.name,
            'type': self.qtype,
            'class': self.qclass
        }


class DNSRecord:
    """Represents a DNS resource record."""
    
    def __init__(
        self,
        name: str,
        rtype: int,
        rclass: int,
        ttl: int,
        rdata: bytes
    ):
        """Initialize DNS record."""
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary."""
        return {
            'name': self.name,
            'type': self.rtype,
            'class': self.rclass,
            'ttl': self.ttl,
            'rdata_length': len(self.rdata)
        }


class DNSPacket:
    """Represents a complete DNS packet."""
    
    def __init__(
        self,
        header: DNSHeader,
        questions: List[DNSQuestion] = None,
        answers: List[DNSRecord] = None,
        authority: List[DNSRecord] = None,
        additional: List[DNSRecord] = None
    ):
        """Initialize DNS packet."""
        self.header = header
        self.questions = questions or []
        self.answers = answers or []
        self.authority = authority or []
        self.additional = additional or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary."""
        return {
            'header': self.header.to_dict(),
            'questions': [q.to_dict() for q in self.questions],
            'answers': [a.to_dict() for a in self.answers],
            'authority': [a.to_dict() for a in self.authority],
            'additional': [a.to_dict() for a in self.additional]
        }


class DNSAttackBase(BaseAttack):
    """Base class for DNS-layer attacks."""
    
    # DNS encoding schemes
    ENCODING_BASE32 = 'base32'
    ENCODING_BASE64 = 'base64'
    ENCODING_HEX = 'hex'
    ENCODING_BINARY = 'binary'
    ENCODING_CUSTOM = 'custom'
    
    def __init__(self):
        """Initialize DNS attack base."""
        super().__init__()
        self._transaction_id_counter = 0
    
    @abstractmethod
    def modify_dns_packet(self, packet: DNSPacket, context: AttackContext) -> Optional[bytes]:
        """
        Modify DNS packet according to attack strategy.
        
        Args:
            packet: Parsed DNS packet
            context: Attack context
            
        Returns:
            Modified packet bytes or None if no modification
        """
        pass
    
    @abstractmethod
    def encode_data_for_tunnel(self, data: bytes, scheme: str) -> str:
        """
        Encode data for DNS tunneling.
        
        Args:
            data: Data to encode
            scheme: Encoding scheme to use
            
        Returns:
            Encoded string suitable for DNS labels
        """
        pass
    
    @abstractmethod
    def decode_data_from_tunnel(self, encoded: str, scheme: str) -> bytes:
        """
        Decode data from DNS tunnel.
        
        Args:
            encoded: Encoded string from DNS labels
            scheme: Encoding scheme used
            
        Returns:
            Decoded data bytes
        """
        pass
    
    # DNS Packet Parsing
    
    def parse_dns_packet(self, data: bytes) -> Optional[DNSPacket]:
        """
        Parse DNS packet from raw bytes.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            Parsed DNSPacket or None if parsing fails
        """
        try:
            if len(data) < DNS_HEADER_SIZE:
                logger.warning(f"DNS packet too short: {len(data)} bytes")
                return None
            
            # Parse header
            header = DNSHeader.from_bytes(data)
            
            # Parse questions, answers, authority, additional
            offset = DNS_HEADER_SIZE
            questions = []
            answers = []
            authority = []
            additional = []
            
            # Parse questions
            for _ in range(header.questions):
                name, offset = self._parse_dns_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                questions.append(DNSQuestion(name, qtype, qclass))
            
            # Parse answer records
            for _ in range(header.answers):
                record, offset = self._parse_dns_record(data, offset)
                if record:
                    answers.append(record)
                else:
                    break
            
            # Parse authority records
            for _ in range(header.authority):
                record, offset = self._parse_dns_record(data, offset)
                if record:
                    authority.append(record)
                else:
                    break
            
            # Parse additional records
            for _ in range(header.additional):
                record, offset = self._parse_dns_record(data, offset)
                if record:
                    additional.append(record)
                else:
                    break
            
            return DNSPacket(header, questions, answers, authority, additional)
            
        except Exception as e:
            logger.error(f"Failed to parse DNS packet: {e}")
            return None
    
    def _parse_dns_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse DNS name with compression support."""
        labels = []
        jumped = False
        jump_offset = 0
        max_jumps = 10
        jumps = 0
        
        while offset < len(data):
            length = data[offset]
            
            # Check for compression pointer
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                if not jumped:
                    jump_offset = offset + 2
                    jumped = True
                offset = pointer
                jumps += 1
                if jumps > max_jumps:
                    break
                continue
            
            # End of name
            if length == 0:
                offset += 1
                break
            
            # Regular label
            offset += 1
            if offset + length > len(data):
                break
            label = data[offset:offset+length].decode('ascii', errors='ignore')
            labels.append(label)
            offset += length
        
        name = '.'.join(labels) if labels else ''
        final_offset = jump_offset if jumped else offset
        return name, final_offset
    
    def _parse_dns_record(self, data: bytes, offset: int) -> Tuple[Optional[DNSRecord], int]:
        """Parse DNS resource record."""
        try:
            name, offset = self._parse_dns_name(data, offset)
            if offset + 10 > len(data):
                return None, offset
            
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(data):
                return None, offset
            
            rdata = data[offset:offset+rdlength]
            offset += rdlength
            
            return DNSRecord(name, rtype, rclass, ttl, rdata), offset
            
        except Exception as e:
            logger.error(f"Failed to parse DNS record: {e}")
            return None, offset
    
    # DNS Packet Construction
    
    def build_dns_query(
        self,
        domain: str,
        qtype: int = DNS_TYPE_A,
        qclass: int = DNS_CLASS_IN,
        transaction_id: Optional[int] = None,
        recursion_desired: bool = True
    ) -> bytes:
        """
        Build DNS query packet.
        
        Args:
            domain: Domain name to query
            qtype: Query type
            qclass: Query class
            transaction_id: Transaction ID (auto-generated if None)
            recursion_desired: Set RD flag
            
        Returns:
            DNS query packet bytes
        """
        if transaction_id is None:
            transaction_id = self._get_next_transaction_id()
        
        # Build header
        flags = 0
        if recursion_desired:
            flags |= DNS_FLAG_RD
        
        header = DNSHeader(
            transaction_id=transaction_id,
            flags=flags,
            questions=1,
            answers=0,
            authority=0,
            additional=0
        )
        
        # Build question
        packet = header.to_bytes()
        packet += self._encode_dns_name(domain)
        packet += struct.pack('!HH', qtype, qclass)
        
        return packet
    
    def build_dns_response(
        self,
        query_packet: DNSPacket,
        answers: List[Tuple[str, int, int, bytes]],
        rcode: int = DNS_RCODE_NOERROR
    ) -> bytes:
        """
        Build DNS response packet.
        
        Args:
            query_packet: Original query packet
            answers: List of (name, type, ttl, rdata) tuples
            rcode: Response code
            
        Returns:
            DNS response packet bytes
        """
        # Build response header
        flags = DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | rcode
        header = DNSHeader(
            transaction_id=query_packet.header.transaction_id,
            flags=flags,
            questions=len(query_packet.questions),
            answers=len(answers),
            authority=0,
            additional=0
        )
        
        packet = header.to_bytes()
        
        # Add questions
        for question in query_packet.questions:
            packet += self._encode_dns_name(question.name)
            packet += struct.pack('!HH', question.qtype, question.qclass)
        
        # Add answers
        for name, rtype, ttl, rdata in answers:
            packet += self._encode_dns_name(name)
            packet += struct.pack('!HHIH', rtype, DNS_CLASS_IN, ttl, len(rdata))
            packet += rdata
        
        return packet
    
    def _encode_dns_name(self, name: str) -> bytes:
        """Encode DNS name to wire format."""
        if not name or name == '.':
            return b'\x00'
        
        encoded = b''
        labels = name.rstrip('.').split('.')
        
        for label in labels:
            if len(label) > DNS_MAX_LABEL_LENGTH:
                raise ValueError(f"DNS label too long: {len(label)} > {DNS_MAX_LABEL_LENGTH}")
            encoded += bytes([len(label)]) + label.encode('ascii')
        
        encoded += b'\x00'
        return encoded
    
    def _get_next_transaction_id(self) -> int:
        """Get next transaction ID."""
        self._transaction_id_counter = (self._transaction_id_counter + 1) & 0xFFFF
        return self._transaction_id_counter
    
    # DNS Record Type Handling
    
    def parse_a_record(self, rdata: bytes) -> Optional[str]:
        """Parse A record (IPv4 address)."""
        if len(rdata) != 4:
            return None
        return socket.inet_ntoa(rdata)
    
    def parse_aaaa_record(self, rdata: bytes) -> Optional[str]:
        """Parse AAAA record (IPv6 address)."""
        if len(rdata) != 16:
            return None
        return socket.inet_ntop(socket.AF_INET6, rdata)
    
    def parse_txt_record(self, rdata: bytes) -> List[str]:
        """Parse TXT record."""
        texts = []
        offset = 0
        while offset < len(rdata):
            length = rdata[offset]
            offset += 1
            if offset + length > len(rdata):
                break
            text = rdata[offset:offset+length].decode('utf-8', errors='ignore')
            texts.append(text)
            offset += length
        return texts
    
    def build_a_record(self, ip: str) -> bytes:
        """Build A record rdata."""
        return socket.inet_aton(ip)
    
    def build_aaaa_record(self, ip: str) -> bytes:
        """Build AAAA record rdata."""
        return socket.inet_pton(socket.AF_INET6, ip)
    
    def build_txt_record(self, texts: List[str]) -> bytes:
        """Build TXT record rdata."""
        rdata = b''
        for text in texts:
            text_bytes = text.encode('utf-8')
            if len(text_bytes) > 255:
                # Split into multiple strings
                for i in range(0, len(text_bytes), 255):
                    chunk = text_bytes[i:i+255]
                    rdata += bytes([len(chunk)]) + chunk
            else:
                rdata += bytes([len(text_bytes)]) + text_bytes
        return rdata
    
    # DNS Tunneling Encoding/Decoding
    
    def encode_base32(self, data: bytes) -> str:
        """Encode data using base32 (DNS-safe)."""
        encoded = base64.b32encode(data).decode('ascii')
        # Remove padding and convert to lowercase for DNS
        return encoded.rstrip('=').lower()
    
    def decode_base32(self, encoded: str) -> bytes:
        """Decode base32 encoded data."""
        # Add padding back
        padding = (8 - len(encoded) % 8) % 8
        encoded = encoded.upper() + '=' * padding
        return base64.b32decode(encoded)
    
    def encode_base64_dns_safe(self, data: bytes) -> str:
        """Encode data using DNS-safe base64."""
        encoded = base64.b64encode(data).decode('ascii')
        # Replace non-DNS-safe characters
        encoded = encoded.replace('+', '-').replace('/', '_').rstrip('=')
        return encoded
    
    def decode_base64_dns_safe(self, encoded: str) -> bytes:
        """Decode DNS-safe base64 data."""
        # Restore standard base64 characters
        encoded = encoded.replace('-', '+').replace('_', '/')
        # Add padding
        padding = (4 - len(encoded) % 4) % 4
        encoded = encoded + '=' * padding
        return base64.b64decode(encoded)
    
    def encode_hex(self, data: bytes) -> str:
        """Encode data as hexadecimal."""
        return binascii.hexlify(data).decode('ascii')
    
    def decode_hex(self, encoded: str) -> bytes:
        """Decode hexadecimal data."""
        return binascii.unhexlify(encoded)
    
    def encode_binary_to_labels(self, data: bytes, max_label_len: int = 63) -> List[str]:
        """
        Encode binary data into DNS labels.
        
        Args:
            data: Data to encode
            max_label_len: Maximum label length
            
        Returns:
            List of DNS labels
        """
        # Use base32 encoding for DNS-safe representation
        encoded = self.encode_base32(data)
        
        # Split into labels
        labels = []
        for i in range(0, len(encoded), max_label_len):
            labels.append(encoded[i:i+max_label_len])
        
        return labels
    
    def decode_labels_to_binary(self, labels: List[str]) -> bytes:
        """
        Decode DNS labels back to binary data.
        
        Args:
            labels: List of DNS labels
            
        Returns:
            Decoded binary data
        """
        # Join labels and decode
        encoded = ''.join(labels)
        return self.decode_base32(encoded)
    
    def create_tunnel_domain(self, data: bytes, base_domain: str, scheme: str = ENCODING_BASE32) -> str:
        """
        Create a DNS tunnel domain name.
        
        Args:
            data: Data to tunnel
            base_domain: Base domain for tunneling
            scheme: Encoding scheme
            
        Returns:
            Complete domain name with encoded data
        """
        # Encode data
        if scheme == self.ENCODING_BASE32:
            encoded = self.encode_base32(data)
        elif scheme == self.ENCODING_BASE64:
            encoded = self.encode_base64_dns_safe(data)
        elif scheme == self.ENCODING_HEX:
            encoded = self.encode_hex(data)
        else:
            raise ValueError(f"Unsupported encoding scheme: {scheme}")
        
        # Split into labels (max 63 chars per label)
        labels = []
        for i in range(0, len(encoded), DNS_MAX_LABEL_LENGTH):
            labels.append(encoded[i:i+DNS_MAX_LABEL_LENGTH])
        
        # Construct domain
        tunnel_domain = '.'.join(labels) + '.' + base_domain
        
        if len(tunnel_domain) > DNS_MAX_NAME_LENGTH:
            raise ValueError(f"Tunnel domain too long: {len(tunnel_domain)} > {DNS_MAX_NAME_LENGTH}")
        
        return tunnel_domain
    
    def extract_tunnel_data(self, domain: str, base_domain: str, scheme: str = ENCODING_BASE32) -> Optional[bytes]:
        """
        Extract data from DNS tunnel domain.
        
        Args:
            domain: Complete tunnel domain
            base_domain: Base domain to remove
            scheme: Encoding scheme used
            
        Returns:
            Extracted data or None if extraction fails
        """
        try:
            # Remove base domain
            if not domain.endswith('.' + base_domain):
                return None
            
            encoded_part = domain[:-len(base_domain)-1]
            # Remove label separators
            encoded = encoded_part.replace('.', '')
            
            # Decode based on scheme
            if scheme == self.ENCODING_BASE32:
                return self.decode_base32(encoded)
            elif scheme == self.ENCODING_BASE64:
                return self.decode_base64_dns_safe(encoded)
            elif scheme == self.ENCODING_HEX:
                return self.decode_hex(encoded)
            else:
                raise ValueError(f"Unsupported encoding scheme: {scheme}")
                
        except Exception as e:
            logger.error(f"Failed to extract tunnel data: {e}")
            return None
    
    # Helper Methods
    
    def validate_dns_name(self, name: str) -> bool:
        """
        Validate DNS name format.
        
        Args:
            name: DNS name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not name or len(name) > DNS_MAX_NAME_LENGTH:
            return False
        
        labels = name.rstrip('.').split('.')
        for label in labels:
            if not label or len(label) > DNS_MAX_LABEL_LENGTH:
                return False
            # Check valid characters (alphanumeric and hyphen)
            if not all(c.isalnum() or c == '-' for c in label):
                return False
            # Cannot start or end with hyphen
            if label[0] == '-' or label[-1] == '-':
                return False
        
        return True
    
    def calculate_dns_packet_size(self, packet: DNSPacket) -> int:
        """
        Calculate size of DNS packet.
        
        Args:
            packet: DNS packet
            
        Returns:
            Estimated packet size in bytes
        """
        size = DNS_HEADER_SIZE
        
        # Questions
        for question in packet.questions:
            size += len(self._encode_dns_name(question.name))
            size += 4  # type + class
        
        # Answers
        for answer in packet.answers:
            size += len(self._encode_dns_name(answer.name))
            size += 10  # type + class + ttl + rdlength
            size += len(answer.rdata)
        
        # Authority
        for auth in packet.authority:
            size += len(self._encode_dns_name(auth.name))
            size += 10
            size += len(auth.rdata)
        
        # Additional
        for add in packet.additional:
            size += len(self._encode_dns_name(add.name))
            size += 10
            size += len(add.rdata)
        
        return size
    
    def should_use_tcp(self, packet_size: int, use_edns: bool = False) -> bool:
        """
        Determine if TCP should be used instead of UDP.
        
        Args:
            packet_size: Estimated packet size
            use_edns: Whether EDNS is enabled
            
        Returns:
            True if TCP should be used
        """
        max_size = DNS_EDNS_MAX_SIZE if use_edns else DNS_MAX_UDP_SIZE
        return packet_size > max_size
    
    def get_record_type_name(self, rtype: int) -> str:
        """Get human-readable name for record type."""
        type_names = {
            DNS_TYPE_A: 'A',
            DNS_TYPE_NS: 'NS',
            DNS_TYPE_CNAME: 'CNAME',
            DNS_TYPE_SOA: 'SOA',
            DNS_TYPE_PTR: 'PTR',
            DNS_TYPE_MX: 'MX',
            DNS_TYPE_TXT: 'TXT',
            DNS_TYPE_AAAA: 'AAAA',
            DNS_TYPE_SRV: 'SRV',
            DNS_TYPE_OPT: 'OPT',
            DNS_TYPE_ANY: 'ANY'
        }
        return type_names.get(rtype, f'TYPE{rtype}')
