from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Tuple
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
    token: bytes = b""
    length: int = 0
    packet_number: int = 0

    @classmethod
    def parse(cls, data: bytes) -> tuple["QUICHeader", int]:
        """Parse QUIC header from bytes, returns (header, bytes_consumed)"""
        if not data:
            raise ValueError("Empty QUIC packet")
        header_form = bool(data[0] & 0x80)
        if header_form:
            if len(data) < 6:
                raise ValueError("Packet too short")
            version = struct.unpack("!I", data[1:5])[0]
            dcid_len = data[5]
            pos = 6
            if pos + dcid_len > len(data):
                raise ValueError("Packet too short for DCID")
            dcid = data[pos : pos + dcid_len]
            pos += dcid_len
            if pos >= len(data):
                raise ValueError("Packet too short for SCID length")
            scid_len = data[pos]
            pos += 1
            if pos + scid_len > len(data):
                raise ValueError("Packet too short for SCID")
            scid = data[pos : pos + scid_len]
            pos += scid_len
            packet_type = QUICPacketType((data[0] & 0x30) >> 4)
            token_length = 0
            token = b""
            if packet_type == QUICPacketType.INITIAL:
                token_length, tl_len = _decode_varint(data, pos)
                pos += tl_len
                if pos + token_length > len(data):
                    raise ValueError("Packet too short for token")
                token = data[pos : pos + token_length]
                pos += token_length
            # Length (varint)
            length, l_len = _decode_varint(data, pos)
            pos += l_len
            # PN length (lowest 2 bits + 1)
            pn_length = (data[0] & 0x03) + 1
            if pos + pn_length > len(data):
                raise ValueError("Packet too short for PN")
            packet_number = int.from_bytes(data[pos : pos + pn_length], "big")
            pos += pn_length
            return (
                cls(
                    header_form=header_form,
                    packet_type=packet_type,
                    version=version,
                    dcid_len=dcid_len,
                    dcid=dcid,
                    scid_len=scid_len,
                    scid=scid,
                    token_length=token_length,
                    token=token,
                    length=length,
                    packet_number=packet_number,
                ),
                pos,
            )
        else:
            dcid_len = 0
            packet_type = QUICPacketType.SHORT
            return (
                cls(
                    header_form=header_form,
                    packet_type=packet_type,
                    version=QUICVersion.VERSION_1,
                    dcid_len=dcid_len,
                    dcid=b"",
                    scid_len=0,
                    scid=b"",
                ),
                1,
            )

    def serialize(self) -> bytes:
        """Serialize QUIC header to bytes"""
        first_byte = 0x80 if self.header_form else 0x40
        if self.header_form:
            # long header: fixed bit=1, type in bits [5:4], PN len bits [1:0] (we'll default to 2 bytes: 1 => PN len=2)
            first_byte |= (int(self.packet_type) & 0x03) << 4
            first_byte |= 0x01  # PN length bits -> 1 => 2 bytes
            result = bytes([first_byte])
            result += struct.pack("!I", int(self.version))
            result += bytes([self.dcid_len]) + self.dcid
            result += bytes([self.scid_len]) + self.scid
            if self.packet_type == QUICPacketType.INITIAL:
                result += _encode_varint(self.token_length) + self.token
            result += _encode_varint(self.length)
            # PN length = 2 bytes by default here
            result += self.packet_number.to_bytes(2, "big")
            return result
        else:
            return bytes([first_byte]) + self.dcid


@dataclass
class QUICPacket(Packet):
    """QUIC packet implementation"""

    header: QUICHeader
    payload: bytes = b""

    @classmethod
    def parse(cls, raw: bytes) -> "QUICPacket":
        """Parse QUIC packet from bytes"""
        header, pos = QUICHeader.parse(raw)
        payload = raw[pos:]
        return cls(header=header, payload=payload)

    def serialize(self) -> bytes:
        """Serialize QUIC packet to bytes"""
        return self.header.serialize() + self.payload

    def clone(self) -> "QUICPacket":
        """Create a copy of the QUIC packet"""
        return QUICPacket(header=self.header, payload=self.payload)


# --- helpers ---
def _decode_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(buf):
        raise ValueError("varint: OOB")
    first = buf[pos]
    prefix = first >> 6
    length = 1 << prefix
    if pos + length > len(buf):
        raise ValueError("varint: incomplete")
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, length


def _encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value & 0x3F])
    elif value < 0x4000:
        val = 0x4000 | value
        return struct.pack("!H", val)
    elif value < 0x40000000:
        val = 0x80000000 | value
        return struct.pack("!I", val)
    else:
        val = 0xC000000000000000 | value
        return struct.pack("!Q", val)
