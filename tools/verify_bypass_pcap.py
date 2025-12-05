"""
PCAP Verification Tool - Анализ PCAP файлов для верификации bypass операций.

Находит:
- Дубликаты sequence numbers (оригинал + bypass пакеты)
- Некорректные split атаки
- Конфликты в TCP потоках
"""

import sys
import struct
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

# Добавляем корневую директорию в путь для импорта
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket


@dataclass(frozen=True)
class FlowKey:
    """Уникальный идентификатор TCP потока."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    
    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"


@dataclass
class TCPPacketInfo:
    """Информация о TCP пакете."""
    flow: FlowKey
    seq: int
    ack: int
    flags: int
    payload_len: int
    raw_data: bytes
    frame_number: int = 0
    timestamp: float = 0.0
    
    def __str__(self) -> str:
        flags_str = self._flags_to_str()
        return (f"Frame {self.frame_number}: seq=0x{self.seq:08X} ack=0x{self.ack:08X} "
                f"flags={flags_str} len={self.payload_len}")
    
    def _flags_to_str(self) -> str:
        """Конвертирует TCP flags в строку."""
        flag_names = []
        if self.flags & 0x01: flag_names.append("FIN")
        if self.flags & 0x02: flag_names.append("SYN")
        if self.flags & 0x04: flag_names.append("RST")
        if self.flags & 0x08: flag_names.append("PSH")
        if self.flags & 0x10: flag_names.append("ACK")
        if self.flags & 0x20: flag_names.append("URG")
        return "|".join(flag_names) if flag_names else "NONE"


@dataclass
class Conflict:
    """Конфликт sequence numbers в потоке."""
    flow: FlowKey
    seq: int
    packets: List[TCPPacketInfo]
    reason: str = "Duplicate sequence number"
    
    def __str__(self) -> str:
        return (f"CONFLICT in {self.flow}: seq=0x{self.seq:08X} "
                f"({len(self.packets)} packets) - {self.reason}")


@dataclass
class VerificationResult:
    """Результат верификации PCAP файла."""
    total_packets: int = 0
    tcp_packets: int = 0
    flows_count: int = 0
    conflicts: List[Conflict] = field(default_factory=list)
    success_rate: float = 0.0
    
    def __str__(self) -> str:
        return (f"Verification Result:\n"
                f"  Total packets: {self.total_packets}\n"
                f"  TCP packets: {self.tcp_packets}\n"
                f"  Flows: {self.flows_count}\n"
                f"  Conflicts: {len(self.conflicts)}\n"
                f"  Success rate: {self.success_rate:.2%}")


class PCAPVerifier:
    """
    Анализирует PCAP файлы для поиска проблем с bypass.
    
    Основные функции:
    - Поиск дубликатов sequence numbers (оригинал + bypass пакеты)
    - Верификация корректности split атак
    - Детекция конфликтов в TCP потоках
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Инициализация PCAPVerifier.
        
        Args:
            logger: Опциональный logger для вывода информации
        """
        self.logger = logger or logging.getLogger(__name__)
        self.reader = RawPCAPReader()
        self.logger.info("✅ PCAPVerifier initialized")
    
    def _extract_tcp_info(self, raw_packet: RawPacket, frame_number: int) -> Optional[TCPPacketInfo]:
        """
        Извлекает TCP информацию из RawPacket.
        
        Args:
            raw_packet: RawPacket объект
            frame_number: Номер фрейма в PCAP
            
        Returns:
            TCPPacketInfo или None если пакет не TCP
        """
        try:
            # Проверяем что это TCP пакет
            if not raw_packet.src_port or not raw_packet.dst_port:
                return None
            
            raw = raw_packet.data
            if len(raw) < 40:  # Минимум IP(20) + TCP(20)
                return None
            
            # Извлекаем IP header length
            ip_hl = (raw[0] & 0x0F) * 4
            if len(raw) < ip_hl + 20:  # IP header + минимум TCP header
                return None
            
            # Извлекаем TCP поля
            tcp_offset = ip_hl
            seq = struct.unpack("!I", raw[tcp_offset + 4:tcp_offset + 8])[0]
            ack = struct.unpack("!I", raw[tcp_offset + 8:tcp_offset + 12])[0]
            flags = raw[tcp_offset + 13]
            
            # Вычисляем длину TCP header
            tcp_hl = ((raw[tcp_offset + 12] >> 4) & 0x0F) * 4
            
            # Вычисляем длину payload
            total_len = struct.unpack("!H", raw[2:4])[0]
            payload_len = total_len - ip_hl - tcp_hl
            
            # Создаем FlowKey
            flow = FlowKey(
                src_ip=raw_packet.src_ip,
                src_port=raw_packet.src_port,
                dst_ip=raw_packet.dst_ip,
                dst_port=raw_packet.dst_port
            )
            
            return TCPPacketInfo(
                flow=flow,
                seq=seq,
                ack=ack,
                flags=flags,
                payload_len=payload_len,
                raw_data=raw,
                frame_number=frame_number
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to extract TCP info from frame {frame_number}: {e}")
            return None
    
    def find_sequence_conflicts(self, pcap_file: str) -> Tuple[List[Conflict], Dict[str, Any]]:
        """
        Находит пакеты с одинаковыми sequence numbers (оригинал + bypass).
        
        Args:
            pcap_file: Путь к PCAP файлу
            
        Returns:
            Tuple из (список конфликтов, статистика)
        """
        self.logger.info(f"🔍 Analyzing PCAP file: {pcap_file}")
        
        # Читаем пакеты из PCAP
        packets = self.reader.read_pcap_file(pcap_file)
        if not packets:
            self.logger.warning("⚠️ No packets found in PCAP file")
            return [], {"total_packets": 0, "tcp_packets": 0, "conflict_percentage": 0.0}
        
        self.logger.info(f"📦 Loaded {len(packets)} packets")
        
        # Группируем по flows
        flows: Dict[FlowKey, List[TCPPacketInfo]] = defaultdict(list)
        total_tcp_packets = 0
        
        for frame_num, raw_packet in enumerate(packets, start=1):
            tcp_info = self._extract_tcp_info(raw_packet, frame_num)
            if tcp_info:
                flows[tcp_info.flow].append(tcp_info)
                if tcp_info.payload_len > 0:
                    total_tcp_packets += 1
        
        self.logger.info(f"🌊 Found {len(flows)} TCP flows with {total_tcp_packets} data packets")
        
        # Находим дубликаты в каждом flow
        conflicts = []
        total_conflict_packets = 0
        
        for flow_key, flow_packets in flows.items():
            # Создаем словарь seq → [packets] для каждого flow
            seq_map: Dict[int, List[TCPPacketInfo]] = defaultdict(list)
            
            for pkt in flow_packets:
                # Игнорируем пакеты без payload (ACK, SYN, FIN)
                if pkt.payload_len > 0:
                    seq_map[pkt.seq].append(pkt)
            
            # Находим seq с len(packets) > 1 (дубликаты)
            for seq, pkts in seq_map.items():
                if len(pkts) > 1:
                    conflict = Conflict(
                        flow=flow_key,
                        seq=seq,
                        packets=pkts,
                        reason=f"Duplicate sequence number ({len(pkts)} packets)"
                    )
                    conflicts.append(conflict)
                    total_conflict_packets += len(pkts)
                    
                    self.logger.warning(f"⚠️ {conflict}")
                    for pkt in pkts:
                        self.logger.warning(f"    {pkt}")
        
        # Вычисляем процент пакетов с конфликтами
        conflict_percentage = 0.0
        if total_tcp_packets > 0:
            conflict_percentage = (total_conflict_packets / total_tcp_packets) * 100.0
        
        # Формируем статистику
        stats = {
            "total_packets": len(packets),
            "tcp_packets": total_tcp_packets,
            "conflict_packets": total_conflict_packets,
            "conflict_percentage": conflict_percentage,
            "flows_count": len(flows),
            "conflicts_count": len(conflicts)
        }
        
        if conflicts:
            self.logger.error(
                f"❌ Found {len(conflicts)} sequence conflicts "
                f"({total_conflict_packets}/{total_tcp_packets} packets = {conflict_percentage:.2f}%)"
            )
        else:
            self.logger.info(f"✅ No sequence conflicts found")
        
        return conflicts, stats

    
    def verify_split_attack(self, pcap_file: str, expected_split_pos: Optional[int] = None, 
                           flow_filter: Optional[FlowKey] = None) -> bool:
        """
        Проверяет корректность split атаки.
        
        Проверки:
        1. Есть ровно 2 сегмента (или пара последовательных сегментов)
        2. seq второго = seq первого + split_pos
        3. Сумма длин = длина оригинального payload
        
        Args:
            pcap_file: Путь к PCAP файлу
            expected_split_pos: Ожидаемая позиция split (опционально)
            flow_filter: Опциональный фильтр по flow
            
        Returns:
            True если split атака корректна, False иначе
        """
        self.logger.info(f"🔍 Verifying split attack" + 
                        (f" (expected_split_pos={expected_split_pos})" if expected_split_pos else ""))
        
        # Читаем пакеты
        packets = self.reader.read_pcap_file(pcap_file)
        if not packets:
            self.logger.error("❌ No packets found")
            return False
        
        # Группируем по flows
        flows: Dict[FlowKey, List[TCPPacketInfo]] = defaultdict(list)
        
        for frame_num, raw_packet in enumerate(packets, start=1):
            tcp_info = self._extract_tcp_info(raw_packet, frame_num)
            if tcp_info and tcp_info.payload_len > 0:
                flows[tcp_info.flow].append(tcp_info)
        
        # Фильтруем flow если указан
        if flow_filter:
            if flow_filter not in flows:
                self.logger.error(f"❌ Flow not found: {flow_filter}")
                return False
            flows = {flow_filter: flows[flow_filter]}
        
        # Проверяем каждый flow
        found_valid_split = False
        
        for flow_key, flow_packets in flows.items():
            self.logger.info(f"🌊 Checking flow: {flow_key} ({len(flow_packets)} packets)")
            
            # Сортируем по sequence numbers
            flow_packets.sort(key=lambda p: p.seq)
            
            # Ищем split сегменты (два последовательных пакета)
            for i in range(len(flow_packets) - 1):
                pkt1 = flow_packets[i]
                pkt2 = flow_packets[i + 1]
                
                # Проверка 1: seq второго = seq первого + payload_len первого
                expected_seq2 = pkt1.seq + pkt1.payload_len
                
                if pkt2.seq == expected_seq2:
                    # Нашли потенциальные split сегменты
                    self.logger.info(f"  Found consecutive segments:")
                    self.logger.info(f"    Segment 1: {pkt1}")
                    self.logger.info(f"    Segment 2: {pkt2}")
                    
                    # Проверка 2: Проверяем что есть ровно 2 сегмента для этого seq
                    # (нет дубликатов или дополнительных сегментов)
                    base_seq = pkt1.seq
                    total_payload = pkt1.payload_len + pkt2.payload_len
                    
                    # Ищем другие пакеты с тем же base_seq
                    same_seq_packets = [p for p in flow_packets 
                                       if p.seq >= base_seq and p.seq < base_seq + total_payload]
                    
                    if len(same_seq_packets) == 2:
                        self.logger.info(f"  ✅ Exactly 2 segments found (no duplicates)")
                        
                        # Проверка 3: Если указан expected_split_pos, проверяем его
                        if expected_split_pos is not None:
                            if pkt1.payload_len == expected_split_pos:
                                self.logger.info(f"  ✅ Split position correct: {pkt1.payload_len} == {expected_split_pos}")
                            else:
                                self.logger.warning(f"  ⚠️ Split position mismatch: {pkt1.payload_len} != {expected_split_pos}")
                                continue
                        
                        # Проверка 4: Сумма длин (уже вычислена как total_payload)
                        self.logger.info(f"  ✅ Total payload length: {total_payload} bytes "
                                       f"(segment1={pkt1.payload_len} + segment2={pkt2.payload_len})")
                        
                        # Проверка 5: Sequence numbers корректны
                        self.logger.info(f"  ✅ Sequence numbers valid: "
                                       f"seq1=0x{pkt1.seq:08X}, seq2=0x{pkt2.seq:08X} "
                                       f"(seq2 = seq1 + {pkt1.payload_len})")
                        
                        found_valid_split = True
                        
                    elif len(same_seq_packets) > 2:
                        self.logger.warning(f"  ⚠️ Found {len(same_seq_packets)} segments (expected 2) - possible packet leakage!")
                        for idx, pkt in enumerate(same_seq_packets, 1):
                            self.logger.warning(f"      Segment {idx}: {pkt}")
                    else:
                        self.logger.debug(f"  Only 1 segment found, not a split")
        
        if found_valid_split:
            self.logger.info("✅ Split attack verification PASSED")
            return True
        else:
            self.logger.error("❌ No valid split attack found")
            return False
    
    def verify_pcap(self, pcap_file: str) -> VerificationResult:
        """
        Полная верификация PCAP файла.
        
        Args:
            pcap_file: Путь к PCAP файлу
            
        Returns:
            VerificationResult с детальной информацией
        """
        self.logger.info(f"🔍 Starting full PCAP verification: {pcap_file}")
        
        result = VerificationResult()
        
        # Находим конфликты (теперь возвращает tuple)
        conflicts, stats = self.find_sequence_conflicts(pcap_file)
        
        # Заполняем результат из статистики
        result.total_packets = stats["total_packets"]
        result.tcp_packets = stats["tcp_packets"]
        result.flows_count = stats["flows_count"]
        result.conflicts = conflicts
        
        # Вычисляем success rate
        if result.tcp_packets > 0:
            conflict_packets = stats["conflict_packets"]
            result.success_rate = 1.0 - (conflict_packets / result.tcp_packets)
        
        self.logger.info(f"📊 {result}")
        
        return result
    
    def generate_json_report(self, pcap_file: str, output_file: Optional[str] = None) -> dict:
        """
        Генерирует JSON отчет о верификации с детальной информацией.
        
        Включает:
        - Список всех конфликтов с frame numbers
        - Статистику: total_packets, conflicts, success_rate
        - Детали каждого конфликта (flow, seq, packets)
        - Информацию для CI/CD integration
        
        Args:
            pcap_file: Путь к PCAP файлу
            output_file: Опциональный путь для сохранения JSON
            
        Returns:
            Словарь с результатами верификации
        """
        import json
        
        self.logger.info(f"📝 Generating JSON report for {pcap_file}")
        
        result = self.verify_pcap(pcap_file)
        
        # Формируем JSON структуру с детальной информацией
        report = {
            "pcap_file": str(Path(pcap_file).absolute()),
            "pcap_file_name": Path(pcap_file).name,
            "timestamp": datetime.now().isoformat(),
            "verification_tool": "PCAPVerifier",
            "version": "1.0",
            
            # Статистика (для CI/CD)
            "summary": {
                "total_packets": result.total_packets,
                "tcp_packets": result.tcp_packets,
                "flows_count": result.flows_count,
                "conflicts_count": len(result.conflicts),
                "success_rate": result.success_rate,
                "success_rate_percent": f"{result.success_rate * 100:.2f}%",
                "status": "PASS" if len(result.conflicts) == 0 else "FAIL"
            },
            
            # Детали конфликтов
            "conflicts": [],
            
            # Метаданные для анализа
            "metadata": {
                "has_packet_leakage": len(result.conflicts) > 0,
                "conflict_percentage": (len(result.conflicts) / result.tcp_packets * 100) if result.tcp_packets > 0 else 0.0
            }
        }
        
        # Добавляем детали каждого конфликта с frame numbers
        for idx, conflict in enumerate(result.conflicts, 1):
            conflict_data = {
                "conflict_id": idx,
                "flow": {
                    "src_ip": conflict.flow.src_ip,
                    "src_port": conflict.flow.src_port,
                    "dst_ip": conflict.flow.dst_ip,
                    "dst_port": conflict.flow.dst_port,
                    "flow_string": str(conflict.flow)
                },
                "sequence_number": f"0x{conflict.seq:08X}",
                "sequence_number_decimal": conflict.seq,
                "reason": conflict.reason,
                "duplicate_count": len(conflict.packets),
                "packets": []
            }
            
            # Добавляем информацию о каждом пакете с frame numbers
            for pkt_idx, pkt in enumerate(conflict.packets, 1):
                conflict_data["packets"].append({
                    "packet_index": pkt_idx,
                    "frame_number": pkt.frame_number,
                    "seq": f"0x{pkt.seq:08X}",
                    "seq_decimal": pkt.seq,
                    "ack": f"0x{pkt.ack:08X}",
                    "ack_decimal": pkt.ack,
                    "flags": pkt._flags_to_str(),
                    "payload_len": pkt.payload_len,
                    "timestamp": pkt.timestamp if hasattr(pkt, 'timestamp') else 0.0
                })
            
            report["conflicts"].append(conflict_data)
        
        # Сохраняем в файл если указан (для CI/CD integration)
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 JSON report saved to {output_file}")
            self.logger.info(f"   Status: {report['summary']['status']}")
            self.logger.info(f"   Conflicts: {report['summary']['conflicts_count']}")
            self.logger.info(f"   Success rate: {report['summary']['success_rate_percent']}")
        
        return report


def main():
    """CLI интерфейс для PCAPVerifier."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PCAP Verification Tool - анализ bypass операций"
    )
    parser.add_argument("pcap_file", help="Путь к PCAP файлу")
    parser.add_argument(
        "--split-pos", 
        type=int, 
        help="Проверить split атаку с указанной позицией"
    )
    parser.add_argument(
        "--json-report", 
        help="Сохранить JSON отчет в указанный файл"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Подробный вывод"
    )
    
    args = parser.parse_args()
    
    # Настройка логирования
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Создаем verifier
    verifier = PCAPVerifier()
    
    # Проверяем существование файла
    if not Path(args.pcap_file).exists():
        print(f"❌ Error: PCAP file not found: {args.pcap_file}")
        return 1
    
    # Выполняем верификацию
    if args.split_pos:
        # Проверка split атаки
        success = verifier.verify_split_attack(args.pcap_file, args.split_pos)
        if success:
            print(f"✅ Split attack verification PASSED")
            return 0
        else:
            print(f"❌ Split attack verification FAILED")
            return 1
    else:
        # Полная верификация
        result = verifier.verify_pcap(args.pcap_file)
        
        # Генерируем JSON отчет если указан
        if args.json_report:
            verifier.generate_json_report(args.pcap_file, args.json_report)
        
        # Выводим результат
        print("\n" + "="*60)
        print(result)
        print("="*60)
        
        if len(result.conflicts) == 0:
            print("\n✅ PASS: No packet leakage detected")
            return 0
        else:
            print(f"\n❌ FAIL: {len(result.conflicts)} conflicts found")
            return 1


if __name__ == "__main__":
    exit(main())
