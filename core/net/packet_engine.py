import struct
from abc import ABC, abstractmethod
from typing import Optional, List, Union
from .tcp_options import TCPOption, TCPOptions
from .quic_packet import QUICPacket, QUICHeader, QUICPacketType, QUICVersion
from .ech import ECHConfig, ECHClientHello, ECHCipherSuite, ECHVersion


class Packet(ABC):
    @classmethod
    @abstractmethod
    def parse(cls, raw: bytes) -> "Packet":
        pass

    @abstractmethod
    def serialize(self) -> bytes:
        pass

    @abstractmethod
    def clone(self) -> "Packet":
        pass


# Adapter: Scapy fallback, else BytePacket
try:
    import scapy.all as scapy

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.net.base_packet import Packet
from core.net.byte_packet import IPv4Packet, TCPPacket, UDPPacket
from core.net.tcp_tracker import TCPTracker, TCPState
from core.net.tcp_manipulator import TCPSegmentManipulator, SegmentConfig


class PacketEngine:
    def __init__(self, use_scapy: bool = False):
        self.use_scapy = use_scapy and SCAPY_AVAILABLE
        self.tcp_tracker = TCPTracker()
        self.tcp_manipulator = TCPSegmentManipulator()

    def parse_packet(self, raw: bytes) -> Packet:
        if self.use_scapy and SCAPY_AVAILABLE:
            pkt = scapy.IP(raw)
            return pkt  # Scapy packet
        else:
            return IPv4Packet.parse(raw)

    def serialize_packet(self, pkt: Packet) -> bytes:
        if self.use_scapy:
            return bytes(pkt)
        else:
            return pkt.serialize()

    def clone_packet(self, pkt: Packet) -> Packet:
        if self.use_scapy:
            return pkt.copy()
        else:
            return pkt.clone()

    def modify_ttl(self, pkt: Packet, new_ttl: int) -> Packet:
        """Изменяет TTL пакета."""
        if self.use_scapy:
            pkt.ttl = new_ttl
            return pkt
        else:
            if isinstance(pkt, IPv4Packet):
                pkt.ttl = new_ttl
                pkt.update_checksum()
            return pkt

    def add_padding(self, pkt: Packet, pad_length: int, random: bool = True) -> Packet:
        """Добавляет padding к payload пакета."""
        if random:
            import os

            padding = os.urandom(pad_length)
        else:
            padding = b"\x00" * pad_length

        if self.use_scapy:
            if pkt.haslayer("TCP"):
                pkt["TCP"].payload = padding + bytes(pkt["TCP"].payload)
            elif pkt.haslayer("UDP"):
                pkt["UDP"].payload = padding + bytes(pkt["UDP"].payload)
        else:
            if isinstance(pkt, IPv4Packet):
                if hasattr(pkt, "payload"):
                    pkt.payload = padding + pkt.payload
                    pkt.update_checksum()
        return pkt

    def obfuscate_payload(self, pkt: Packet, method: str = "xor") -> Packet:
        """Простая обфускация payload."""
        if self.use_scapy:
            if pkt.haslayer("TCP"):
                payload = bytes(pkt["TCP"].payload)
            elif pkt.haslayer("UDP"):
                payload = bytes(pkt["UDP"].payload)
            else:
                return pkt
        else:
            if isinstance(pkt, (TCPPacket, UDPPacket)):
                payload = pkt.payload
            else:
                return pkt

        if method == "xor":
            # Простой XOR с ключом
            key = 0x42
            obfuscated = bytes([b ^ key for b in payload])
        elif method == "reverse":
            # Реверс байтов
            obfuscated = payload[::-1]
        else:
            return pkt

        # Применяем обфусцированный payload
        if self.use_scapy:
            if pkt.haslayer("TCP"):
                pkt["TCP"].payload = obfuscated
            elif pkt.haslayer("UDP"):
                pkt["UDP"].payload = obfuscated
        else:
            if isinstance(pkt, (TCPPacket, UDPPacket)):
                pkt.payload = obfuscated
                # Обновляем чексуммы
                if isinstance(pkt, IPv4Packet):
                    pkt.update_checksum()
                elif isinstance(pkt, (TCPPacket, UDPPacket)):
                    # Для TCP/UDP нужен IP-пакет для правильного подсчета чексуммы
                    # В реальном использовании он должен передаваться из контекста
                    pass
        return pkt

    def process_tcp_packet(self, ip_packet: IPv4Packet, tcp_packet: TCPPacket) -> bool:
        """Обработка TCP пакета с учетом состояния соединения"""
        # Проверяем валидность пакета
        if not self.tcp_tracker.verify_packet(ip_packet, tcp_packet):
            return False

        # Получаем информацию о соединении
        conn = self.tcp_tracker.get_connection(ip_packet, tcp_packet)
        if conn:
            # Обновляем состояние соединения
            self.tcp_tracker.update_connection(ip_packet, tcp_packet, conn)

        return True

    def fragment_tcp_packet(
        self, ip_packet: IPv4Packet, tcp_packet: TCPPacket, fragment_size: int = 8
    ) -> list[IPv4Packet]:
        """Фрагментация TCP пакета"""
        if not isinstance(tcp_packet, TCPPacket):
            return [ip_packet]

        # Получаем payload TCP пакета
        payload = tcp_packet.payload
        if len(payload) <= fragment_size:
            return [ip_packet]

        fragments = []
        offset = 0

        while offset < len(payload):
            # Создаем новый TCP пакет для каждого фрагмента
            frag_payload = payload[offset : offset + fragment_size]
            frag_tcp = TCPPacket(
                src_port=tcp_packet.src_port,
                dst_port=tcp_packet.dst_port,
                seq_num=tcp_packet.seq_num + offset,
                ack_num=tcp_packet.ack_num,
                flags=tcp_packet.flags,
                window=tcp_packet.window,
                payload=frag_payload,
            )

            # Создаем новый IP пакет для фрагмента
            frag_ip = IPv4Packet(
                src_addr=ip_packet.src_addr,
                dst_addr=ip_packet.dst_addr,
                ttl=ip_packet.ttl,
                protocol=ip_packet.protocol,
                id=ip_packet.id,
                flags=ip_packet.flags,
                frag_offset=offset // 8,  # Смещение в 8-байтовых блоках
            )

            # Добавляем TCP пакет как payload
            frag_ip.payload = frag_tcp.serialize()

            # Обновляем чексуммы
            frag_tcp.update_checksum(frag_ip)
            frag_ip.update_checksum()

            fragments.append(frag_ip)
            offset += fragment_size

        return fragments

    def get_connection_state(
        self, ip_packet: IPv4Packet, tcp_packet: TCPPacket
    ) -> Optional[TCPState]:
        """Получить текущее состояние TCP-соединения"""
        conn = self.tcp_tracker.get_connection(ip_packet, tcp_packet)
        return conn.state if conn else None

    def create_multisplit_attack(
        self,
        ip_packet: IPv4Packet,
        tcp_packet: TCPPacket,
        config: Optional[SegmentConfig] = None,
    ) -> List[IPv4Packet]:
        """Создать multisplit атаку"""
        if not isinstance(tcp_packet, TCPPacket):
            return [ip_packet]

        if config is None:
            config = SegmentConfig()

        return self.tcp_manipulator.multisplit_packet(ip_packet, tcp_packet, config)

    def create_overlap_attack(
        self,
        ip_packet: IPv4Packet,
        tcp_packet: TCPPacket,
        overlap_data: bytes,
        offset: int,
    ) -> List[IPv4Packet]:
        """Создать атаку с перекрывающимися сегментами"""
        if not isinstance(tcp_packet, TCPPacket):
            return [ip_packet]

        return self.tcp_manipulator.create_overlap_attack(
            ip_packet, tcp_packet, overlap_data, offset
        )

    def create_tcp_option(self, option_type: int, **kwargs) -> TCPOption:
        """Создать TCP option заданного типа"""
        if option_type == TCPOptions.MSS:
            return TCPOptions.create_mss(kwargs.get("mss", 1460))
        elif option_type == TCPOptions.WINDOW_SCALE:
            return TCPOptions.create_window_scale(kwargs.get("shift_count", 7))
        elif option_type == TCPOptions.TIMESTAMP:
            return TCPOptions.create_timestamp(
                kwargs.get("ts_val", 0), kwargs.get("ts_echo", 0)
            )
        elif option_type == TCPOptions.SACK_PERMITTED:
            return TCPOptions.create_sack_permitted()
        elif option_type == TCPOptions.SACK:
            return TCPOptions.create_sack(kwargs.get("blocks", []))
        else:
            return TCPOption(kind=option_type, length=2)

    def parse_quic_packet(self, data: bytes) -> Optional[QUICPacket]:
        """Parse QUIC packet from raw bytes"""
        try:
            return QUICPacket.parse(data)
        except ValueError:
            return None

    def create_quic_packet(
        self,
        packet_type: QUICPacketType,
        version: QUICVersion,
        dcid: bytes,
        scid: bytes,
        payload: bytes = b"",
    ) -> QUICPacket:
        """Create a new QUIC packet"""
        header = QUICHeader(
            header_form=True,  # Long header format
            packet_type=packet_type,
            version=version,
            dcid_len=len(dcid),
            dcid=dcid,
            scid_len=len(scid),
            scid=scid,
            length=len(payload),
            packet_number=0,  # Will be set by connection
        )

        return QUICPacket(header=header, payload=payload)

    def create_ech_config(self, public_name: str, **kwargs) -> ECHConfig:
        """Create ECH configuration"""
        return ECHConfig(
            version=kwargs.get("version", ECHVersion.DRAFT_13),
            config_id=kwargs.get("config_id", 0),
            cipher_suites=kwargs.get(
                "cipher_suites", [ECHCipherSuite.AES_128_GCM_SHA256]
            ),
            public_name=public_name,
            public_key=kwargs.get("public_key", b""),
            maximum_name_length=kwargs.get("maximum_name_length", 64),
        )

    def create_ech_client_hello(
        self,
        config: ECHConfig,
        inner_ch: bytes,
        cipher_suite: Optional[ECHCipherSuite] = None,
    ) -> ECHClientHello:
        """Create ECH ClientHello extension"""
        if cipher_suite is None:
            cipher_suite = config.cipher_suites[0]

        # В реальном использовании здесь должно быть шифрование inner_ch
        # с использованием выбранного cipher_suite и public_key из config
        encrypted_ch = inner_ch  # Placeholder

        return ECHClientHello(
            config_id=config.config_id,
            cipher_suite=cipher_suite,
            encrypted_ch=encrypted_ch,
        )

    def process_quic_initial(
        self, packet: QUICPacket
    ) -> Union[QUICPacket, List[QUICPacket]]:
        """Process QUIC Initial packet - special handling for the first packet"""
        if packet.header.packet_type != QUICPacketType.INITIAL:
            return packet

        # В Initial пакетах мы можем только:
        # 1. Проверять версию
        # 2. Отправлять Version Negotiation если версия не поддерживается
        # 3. Не модифицировать зашифрованные данные

        if packet.header.version not in [QUICVersion.VERSION_1, QUICVersion.VERSION_2]:
            # Создаем Version Negotiation пакет
            return self.create_quic_packet(
                packet_type=QUICPacketType.VERSION_NEGOTIATION,
                version=QUICVersion.NEGOTIATION,
                dcid=packet.header.scid,  # Swap DCID and SCID
                scid=packet.header.dcid,
                payload=struct.pack(
                    "!II", QUICVersion.VERSION_1, QUICVersion.VERSION_2
                ),
            )

        return packet
