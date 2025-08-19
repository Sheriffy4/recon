from dataclasses import dataclass
from typing import List, Optional
import random
from .byte_packet import IPv4Packet, TCPPacket
from .tcp_options import TCPOption, TCPOptions

@dataclass
class SegmentConfig:
    """Конфигурация для TCP segment manipulation"""
    min_size: int = 1
    max_size: int = 100
    overlap_size: int = 10
    duplicate_chance: float = 0.3
    randomize_sizes: bool = True
    allow_empty: bool = False
    preserve_options: bool = True

class TCPSegmentManipulator:
    """Класс для манипуляций с TCP сегментами"""
    
    @staticmethod
    def create_segment(base_packet: TCPPacket, 
                      seq_num: int,
                      payload: bytes,
                      preserve_options: bool = True) -> TCPPacket:
        """Создать новый TCP сегмент на основе базового пакета"""
        options = base_packet.options if preserve_options else []
        
        return TCPPacket(
            src_port=base_packet.src_port,
            dst_port=base_packet.dst_port,
            seq_num=seq_num,
            ack_num=base_packet.ack_num,
            flags=base_packet.flags,
            window=base_packet.window,
            options=options,
            payload=payload
        )

    @staticmethod
    def split_payload(payload: bytes, config: SegmentConfig) -> List[bytes]:
        """Разделить payload на части согласно конфигурации"""
        if not payload and not config.allow_empty:
            return [payload]
            
        segments = []
        pos = 0
        
        while pos < len(payload):
            # Определяем размер следующего сегмента
            if config.randomize_sizes:
                size = random.randint(config.min_size, min(config.max_size, len(payload) - pos))
            else:
                size = min(config.max_size, len(payload) - pos)
                
            segment = payload[pos:pos + size]
            segments.append(segment)
            
            # Возможное дублирование с overlap
            if random.random() < config.duplicate_chance and len(segment) > config.overlap_size:
                overlap = segment[-config.overlap_size:]
                segments.append(overlap)
                
            pos += size
            
        return segments

    def multisplit_packet(self, ip_packet: IPv4Packet, tcp_packet: TCPPacket, 
                         config: SegmentConfig) -> List[IPv4Packet]:
        """Разделить TCP пакет на множество сегментов с возможным перекрытием"""
        segments = self.split_payload(tcp_packet.payload, config)
        packets = []
        
        seq_num = tcp_packet.seq_num
        for i, segment in enumerate(segments):
            # Создаем TCP сегмент
            tcp_segment = self.create_segment(
                tcp_packet,
                seq_num,
                segment,
                config.preserve_options
            )
            
            # Создаем IP пакет для сегмента
            ip_segment = IPv4Packet(
                src_addr=ip_packet.src_addr,
                dst_addr=ip_packet.dst_addr,
                ttl=ip_packet.ttl,
                protocol=ip_packet.protocol,
                id=ip_packet.id + i,  # Увеличиваем ID для каждого сегмента
                flags=ip_packet.flags
            )
            
            # Добавляем TCP сегмент как payload
            ip_segment.payload = tcp_segment.serialize()
            
            # Обновляем чексуммы
            tcp_segment.update_checksum(ip_segment)
            ip_segment.update_checksum()
            
            packets.append(ip_segment)
            
            # Обновляем sequence number, учитывая overlap
            if i < len(segments) - 1:  # Не последний сегмент
                seq_num += len(segment)
                if random.random() < config.duplicate_chance:
                    seq_num -= config.overlap_size
                    
        return packets

    def create_overlap_attack(self, ip_packet: IPv4Packet, tcp_packet: TCPPacket,
                            overlap_data: bytes, overlap_offset: int) -> List[IPv4Packet]:
        """Создать атаку с перекрывающимися sequence numbers"""
        original_payload = tcp_packet.payload
        
        # Первый пакет с оригинальным payload
        packets = [ip_packet]
        
        # Создаем пакет с перекрывающимися данными
        overlap_tcp = self.create_segment(
            tcp_packet,
            tcp_packet.seq_num + overlap_offset,
            overlap_data,
            True
        )
        
        overlap_ip = IPv4Packet(
            src_addr=ip_packet.src_addr,
            dst_addr=ip_packet.dst_addr,
            ttl=ip_packet.ttl,
            protocol=ip_packet.protocol,
            id=ip_packet.id + 1,
            flags=ip_packet.flags
        )
        
        overlap_ip.payload = overlap_tcp.serialize()
        overlap_tcp.update_checksum(overlap_ip)
        overlap_ip.update_checksum()
        
        packets.append(overlap_ip)
        return packets
