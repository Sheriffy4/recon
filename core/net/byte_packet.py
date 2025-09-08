import struct
from dataclasses import dataclass
from typing import List
from core.net.base_packet import Packet
from core.net.tcp_options import TCPOption


@dataclass
class IPv4Packet(Packet):
    version: int = 4
    ihl: int = 5
    tos: int = 0
    total_length: int = 20
    id: int = 0
    flags: int = 0
    frag_offset: int = 0
    ttl: int = 64
    protocol: int = 6
    checksum: int = 0
    src_addr: str = "0.0.0.0"
    dst_addr: str = "0.0.0.0"
    options: bytes = b""
    payload: bytes = b""

    @classmethod
    def parse(cls, raw: bytes) -> "IPv4Packet":
        if len(raw) < 20:
            raise ValueError("Packet too short for IPv4")
        ver_ihl = raw[0]
        version = ver_ihl >> 4
        ihl = ver_ihl & 15
        if version != 4:
            raise ValueError(f"Not an IPv4 packet (version={version})")
        header_length = ihl * 4
        if len(raw) < header_length:
            raise ValueError("Packet shorter than header length")
        fields = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        options = raw[20:header_length] if header_length > 20 else b""
        payload = raw[header_length:]
        return cls(
            version=version,
            ihl=ihl,
            tos=fields[1],
            total_length=fields[2],
            id=fields[3],
            flags=fields[4] >> 13,
            frag_offset=fields[4] & 8191,
            ttl=fields[5],
            protocol=fields[6],
            checksum=fields[7],
            src_addr=".".join((str(b) for b in fields[8])),
            dst_addr=".".join((str(b) for b in fields[9])),
            options=options,
            payload=payload,
        )

    def serialize(self) -> bytes:
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (self.version << 4) + self.ihl,
            self.tos,
            self.total_length,
            self.id,
            (self.flags << 13) + self.frag_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            bytes(map(int, self.src_addr.split("."))),
            bytes(map(int, self.dst_addr.split("."))),
        )
        options_bytes = b"".join((opt.serialize() for opt in self.options))
        return header + options_bytes + self.payload

    def clone(self) -> "IPv4Packet":
        return IPv4Packet(
            version=self.version,
            ihl=self.ihl,
            tos=self.tos,
            total_length=self.total_length,
            id=self.id,
            flags=self.flags,
            frag_offset=self.frag_offset,
            ttl=self.ttl,
            protocol=self.protocol,
            checksum=self.checksum,
            src_addr=self.src_addr,
            dst_addr=self.dst_addr,
            options=self.options,
            payload=self.payload,
        )

    def update_checksum(self):
        self.checksum = 0
        header = self.serialize()[: self.ihl * 4]
        if len(header) % 2 == 1:
            header += b"\x00"
        words = struct.unpack(f"!{len(header) // 2}H", header)
        checksum = sum(words)
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        self.checksum = ~checksum & 65535


@dataclass
class TCPPacket(Packet):
    src_port: int = 0
    dst_port: int = 0
    seq_num: int = 0
    ack_num: int = 0
    data_offset: int = 5
    reserved: int = 0
    flags: int = 0
    window: int = 8192
    checksum: int = 0
    urgent_ptr: int = 0
    options: List["TCPOption"] = None
    payload: bytes = b""

    def __post_init__(self):
        if self.options is None:
            self.options = []

    @classmethod
    def parse(cls, raw: bytes) -> "TCPPacket":
        if len(raw) < 20:
            raise ValueError("Packet too short for TCP")
        fields = struct.unpack("!HHIIBBHHH", raw[:20])
        data_offset = fields[4] >> 4
        header_length = data_offset * 4
        if len(raw) < header_length:
            raise ValueError("Packet shorter than header length")
        options = raw[20:header_length] if header_length > 20 else b""
        payload = raw[header_length:]
        return cls(
            src_port=fields[0],
            dst_port=fields[1],
            seq_num=fields[2],
            ack_num=fields[3],
            data_offset=data_offset,
            reserved=fields[4] >> 1 & 7,
            flags=fields[5],
            window=fields[6],
            checksum=fields[7],
            urgent_ptr=fields[8],
            options=options,
            payload=payload,
        )

    def serialize(self) -> bytes:
        header = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            (self.data_offset << 4) + (self.reserved << 1),
            self.flags,
            self.window,
            self.checksum,
            self.urgent_ptr,
        )

        options_bytes = b""
        if self.options:
            options_bytes = b"".join(opt.serialize() for opt in self.options)

        # Ensure options length is a multiple of 4
        while len(options_bytes) % 4 != 0:
            options_bytes += b"\x01"  # NOP option

        return header + options_bytes + self.payload

    def clone(self) -> "TCPPacket":
        return TCPPacket(
            src_port=self.src_port,
            dst_port=self.dst_port,
            seq_num=self.seq_num,
            ack_num=self.ack_num,
            data_offset=self.data_offset,
            reserved=self.reserved,
            flags=self.flags,
            window=self.window,
            checksum=self.checksum,
            urgent_ptr=self.urgent_ptr,
            options=self.options,
            payload=self.payload,
        )

    def update_checksum(self, ip_packet: IPv4Packet):
        self.checksum = 0
        pseudo_header = struct.pack(
            "!4s4sHH",
            bytes(map(int, ip_packet.src_addr.split("."))),
            bytes(map(int, ip_packet.dst_addr.split("."))),
            ip_packet.protocol,
            len(self.serialize()),
        )
        packet = pseudo_header + self.serialize()
        if len(packet) % 2 == 1:
            packet += b"\x00"
        words = struct.unpack(f"!{len(packet) // 2}H", packet)
        checksum = sum(words)
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        self.checksum = ~checksum & 65535


@dataclass
class UDPPacket(Packet):
    src_port: int = 0
    dst_port: int = 0
    length: int = 8
    checksum: int = 0
    payload: bytes = b""

    @classmethod
    def parse(cls, raw: bytes) -> "UDPPacket":
        if len(raw) < 8:
            raise ValueError("Packet too short for UDP")
        fields = struct.unpack("!HHHH", raw[:8])
        return cls(
            src_port=fields[0],
            dst_port=fields[1],
            length=fields[2],
            checksum=fields[3],
            payload=raw[8:],
        )

    def serialize(self) -> bytes:
        header = struct.pack(
            "!HHHH", self.src_port, self.dst_port, self.length, self.checksum
        )
        return header + self.payload

    def clone(self) -> "UDPPacket":
        return UDPPacket(
            src_port=self.src_port,
            dst_port=self.dst_port,
            length=self.length,
            checksum=self.checksum,
            payload=self.payload,
        )

    def update_checksum(self, ip_packet: IPv4Packet):
        self.checksum = 0
        self.length = 8 + len(self.payload)
        pseudo_header = struct.pack(
            "!4s4sHH",
            bytes(map(int, ip_packet.src_addr.split("."))),
            bytes(map(int, ip_packet.dst_addr.split("."))),
            17,
            self.length,
        )
        packet = pseudo_header + self.serialize()
        if len(packet) % 2 == 1:
            packet += b"\x00"
        words = struct.unpack(f"!{len(packet) // 2}H", packet)
        checksum = sum(words)
        while checksum >> 16:
            checksum = (checksum & 65535) + (checksum >> 16)
        self.checksum = ~checksum & 65535
