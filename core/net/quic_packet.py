from dataclasses import dataclass
from enum import IntEnum
import struct
from core.net.byte_packet import Packet

class QUICPacketType(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    VERSION_NEGOTIATION = 240
    SHORT = 64

class QUICVersion(IntEnum):
    VERSION_1 = 1
    VERSION_2 = 2
    NEGOTIATION = 0

@dataclass
class QUICHeader:
    """QUIC packet header"""
    header_form: bool
    packet_type: QUICPacketType
    version: QUICVersion
    dcid_len: int
    dcid: bytes
    scid_len: int
    scid: bytes
    token_length: int = 0
    token: bytes = b''
    length: int = 0
    packet_number: int = 0

    @classmethod
    def parse(cls, data: bytes) -> tuple['QUICHeader', int]:
        """Parse QUIC header from bytes, returns (header, bytes_consumed)"""
        if not data:
            raise ValueError('Empty QUIC packet')
        header_form = bool(data[0] & 128)
        if header_form:
            version = struct.unpack('!I', data[1:5])[0]
            dcid_len = data[5]
            pos = 6
            if pos + dcid_len > len(data):
                raise ValueError('Packet too short for DCID')
            dcid = data[pos:pos + dcid_len]
            pos += dcid_len
            if pos >= len(data):
                raise ValueError('Packet too short for SCID length')
            scid_len = data[pos]
            pos += 1
            if pos + scid_len > len(data):
                raise ValueError('Packet too short for SCID')
            scid = data[pos:pos + scid_len]
            pos += scid_len
            packet_type = QUICPacketType(data[0] & 48)
            token_length = 0
            token = b''
            if packet_type == QUICPacketType.INITIAL:
                token_length = data[pos]
                pos += 1
                token = data[pos:pos + token_length]
                pos += token_length
            length = struct.unpack('!H', data[pos:pos + 2])[0]
            pos += 2
            pn_length = (data[0] & 3) + 1
            packet_number = int.from_bytes(data[pos:pos + pn_length], 'big')
            pos += pn_length
            return (cls(header_form=header_form, packet_type=packet_type, version=version, dcid_len=dcid_len, dcid=dcid, scid_len=scid_len, scid=scid, token_length=token_length, token=token, length=length, packet_number=packet_number), pos)
        else:
            dcid_len = 0
            packet_type = QUICPacketType.SHORT
            return (cls(header_form=header_form, packet_type=packet_type, version=QUICVersion.VERSION_1, dcid_len=dcid_len, dcid=b'', scid_len=0, scid=b''), 1)

    def serialize(self) -> bytes:
        """Serialize QUIC header to bytes"""
        first_byte = 128 if self.header_form else 64
        if self.header_form:
            first_byte |= self.packet_type
            first_byte |= 3
            result = bytes([first_byte])
            result += struct.pack('!I', self.version)
            result += bytes([self.dcid_len]) + self.dcid
            result += bytes([self.scid_len]) + self.scid
            if self.packet_type == QUICPacketType.INITIAL:
                result += bytes([self.token_length]) + self.token
            result += struct.pack('!H', self.length)
            result += self.packet_number.to_bytes(4, 'big')
            return result
        else:
            return bytes([first_byte]) + self.dcid

@dataclass
class QUICPacket(Packet):
    """QUIC packet implementation"""
    header: QUICHeader
    payload: bytes = b''

    @classmethod
    def parse(cls, raw: bytes) -> 'QUICPacket':
        """Parse QUIC packet from bytes"""
        header, pos = QUICHeader.parse(raw)
        payload = raw[pos:]
        return cls(header=header, payload=payload)

    def serialize(self) -> bytes:
        """Serialize QUIC packet to bytes"""
        return self.header.serialize() + self.payload

    def clone(self) -> 'QUICPacket':
        """Create a copy of the QUIC packet"""
        return QUICPacket(header=self.header, payload=self.payload)