"""
Attack Application Verifier for Testing and Service Mode Parity

This module provides verification capabilities for attack application
in both testing and service modes. It analyzes PCAP files to ensure
attacks are applied correctly and identically in both modes.

Requirements: 13.1, 13.2, 13.3, 13.4
Task: 9.1.1 Создать AttackApplicationVerifier класс
"""

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

# Import RawPCAPReader for PCAP analysis
from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket, RawPacketEngine, ProtocolType, IPHeader, TCPHeader

LOG = logging.getLogger(__name__)


@dataclass
class FakeAttackVerification:
    """Результат верификации fake атаки."""
    
    fake_packet_found: bool  # Найден ли fake пакет
    fake_seq: Optional[int] = None  # Sequence number fake пакета
    real_seq: Optional[int] = None  # Sequence number real пакета
    seq_difference: Optional[int] = None  # Разница между sequence numbers
    fake_ttl: Optional[int] = None  # TTL fake пакета
    real_ttl: Optional[int] = None  # TTL real пакета
    fake_payload_len: Optional[int] = None  # Длина payload fake пакета
    real_payload_len: Optional[int] = None  # Длина payload real пакета
    is_correct: bool = False  # Корректно ли применена атака
    issues: List[str] = field(default_factory=list)  # Список проблем
    
    def is_seq_overlap(self) -> bool:
        """
        Проверяет перекрытие sequence numbers.
        
        Returns:
            True если есть перекрытие (проблема)
        """
        if self.seq_difference is None:
            return False
        # Если разница меньше размера пакета - есть перекрытие
        return abs(self.seq_difference) < 1500


@dataclass
class MultisplitVerification:
    """Результат верификации multisplit атаки."""
    
    expected_positions: List[int]  # Ожидаемые позиции split
    found_positions: List[int]  # Найденные позиции split
    is_correct: bool  # Корректно ли применена атака
    missing_splits: List[int] = field(default_factory=list)  # Отсутствующие split
    extra_splits: List[int] = field(default_factory=list)  # Лишние split
    issues: List[str] = field(default_factory=list)  # Список проблем


@dataclass
class DisorderVerification:
    """Результат верификации disorder атаки."""
    
    packet_order: List[Tuple[int, float]] = field(default_factory=list)  # Порядок пакетов (seq, timestamp)
    is_disordered: bool = False  # Есть ли нарушение порядка
    disorder_count: int = 0  # Количество нарушений порядка
    is_correct: bool = False  # Корректно ли применена атака
    issues: List[str] = field(default_factory=list)  # Список проблем


@dataclass
class ComparisonReport:
    """Детальный отчет о сравнении применения атак между режимами."""
    
    testing_pcap: str  # Путь к PCAP из testing mode
    service_pcap: str  # Путь к PCAP из service mode
    attack_type: str  # Тип атаки
    differences: List[Dict[str, Any]] = field(default_factory=list)  # Найденные различия
    testing_verification: Optional[Any] = None  # Результат верификации testing mode
    service_verification: Optional[Any] = None  # Результат верификации service mode
    is_identical: bool = False  # Идентичны ли применения атак
    recommendations: List[str] = field(default_factory=list)  # Рекомендации по исправлению
    
    def generate_report(self) -> str:
        """
        Генерирует текстовый отчет о сравнении.
        
        Returns:
            Текстовый отчет
        """
        lines = []
        lines.append("=" * 80)
        lines.append(f"Attack Application Comparison Report: {self.attack_type}")
        lines.append("=" * 80)
        lines.append(f"Testing PCAP: {self.testing_pcap}")
        lines.append(f"Service PCAP: {self.service_pcap}")
        lines.append(f"Identical: {'✓ YES' if self.is_identical else '✗ NO'}")
        lines.append("")
        
        if self.differences:
            lines.append(f"Found {len(self.differences)} differences:")
            for i, diff in enumerate(self.differences, 1):
                lines.append(f"  {i}. {diff.get('type', 'Unknown')}: {diff.get('description', 'No description')}")
                if 'file' in diff:
                    lines.append(f"     File: {diff['file']}")
                if 'method' in diff:
                    lines.append(f"     Method: {diff['method']}")
        else:
            lines.append("✓ No differences found - attacks applied identically")
        
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"  {i}. {rec}")
        
        lines.append("")
        lines.append("=" * 80)
        
        return "\n".join(lines)


class AttackApplicationVerifier:
    """
    Верификатор применения атак для обоих режимов.
    
    Анализирует PCAP файлы для проверки корректности применения различных
    типов атак (fake, multisplit, disorder, seqovl) и сравнивает применение
    между testing и service режимами.
    
    Requirements: 13.1, 13.2, 13.3, 13.4
    Task: 9.1.1 Создать AttackApplicationVerifier класс
    """
    
    def __init__(self):
        """Инициализация верификатора."""
        self.logger = LOG
        self.pcap_reader = RawPCAPReader()
        self.packet_engine = RawPacketEngine()
        self.logger.info("✅ AttackApplicationVerifier инициализирован")
    
    def verify_fake_attack(self, pcap_file: str) -> FakeAttackVerification:
        """
        Проверяет корректность применения fake атаки.
        
        Fake атака должна:
        1. Отправить fake пакет с низким TTL (1-3)
        2. Отправить real пакет с нормальным TTL
        3. Fake и real пакеты должны иметь РАЗНЫЕ sequence numbers
        4. Fake пакет НЕ должен перекрывать real пакет
        
        Args:
            pcap_file: Путь к PCAP файлу
            
        Returns:
            FakeAttackVerification с деталями sequence numbers
            
        Requirements: 13.2
        """
        self.logger.info(f"🔍 Верификация fake атаки в {pcap_file}")
        
        try:
            # Read PCAP file
            packets = self._read_pcap(pcap_file)
            if not packets:
                self.logger.warning(f"⚠️ Нет пакетов в {pcap_file}")
                return FakeAttackVerification(
                    fake_packet_found=False,
                    is_correct=False,
                    issues=["No packets found in PCAP"]
                )
            
            # Find TCP packets with payload
            tcp_packets = self._extract_tcp_packets(packets)
            if len(tcp_packets) < 2:
                self.logger.warning(f"⚠️ Недостаточно TCP пакетов для fake атаки")
                return FakeAttackVerification(
                    fake_packet_found=False,
                    is_correct=False,
                    issues=["Not enough TCP packets for fake attack"]
                )
            
            # Identify fake and real packets
            # Fake packet should have low TTL (1-3)
            fake_packet = None
            real_packet = None
            
            for pkt in tcp_packets:
                if pkt['ttl'] <= 3 and pkt['payload_len'] > 0:
                    fake_packet = pkt
                elif pkt['ttl'] > 3 and pkt['payload_len'] > 0:
                    real_packet = pkt
                
                if fake_packet and real_packet:
                    break
            
            if not fake_packet:
                self.logger.warning("⚠️ Fake пакет не найден (TTL <= 3)")
                return FakeAttackVerification(
                    fake_packet_found=False,
                    is_correct=False,
                    issues=["Fake packet not found (no packet with TTL <= 3)"]
                )
            
            if not real_packet:
                self.logger.warning("⚠️ Real пакет не найден")
                return FakeAttackVerification(
                    fake_packet_found=True,
                    fake_seq=fake_packet['seq'],
                    fake_ttl=fake_packet['ttl'],
                    is_correct=False,
                    issues=["Real packet not found"]
                )
            
            # Calculate sequence difference
            seq_diff = abs(real_packet['seq'] - fake_packet['seq'])
            
            # Check for issues
            issues = []
            is_correct = True
            
            # Issue 1: Sequence overlap
            if seq_diff < 1500:
                issues.append(
                    f"⚠️ CRITICAL: Sequence numbers too close (diff={seq_diff}). "
                    f"Fake packet may overlap with real packet!"
                )
                is_correct = False
            
            # Issue 2: Fake TTL too high
            if fake_packet['ttl'] > 3:
                issues.append(
                    f"⚠️ Fake packet TTL too high ({fake_packet['ttl']}). "
                    f"Should be 1-3 to expire before reaching server."
                )
                is_correct = False
            
            # Issue 3: Identical sequence numbers
            if fake_packet['seq'] == real_packet['seq']:
                issues.append(
                    "⚠️ CRITICAL: Fake and real packets have IDENTICAL sequence numbers! "
                    "This will cause packet collision."
                )
                is_correct = False
            
            result = FakeAttackVerification(
                fake_packet_found=True,
                fake_seq=fake_packet['seq'],
                real_seq=real_packet['seq'],
                seq_difference=seq_diff,
                fake_ttl=fake_packet['ttl'],
                real_ttl=real_packet['ttl'],
                fake_payload_len=fake_packet['payload_len'],
                real_payload_len=real_packet['payload_len'],
                is_correct=is_correct,
                issues=issues
            )
            
            if is_correct:
                self.logger.info("✅ Fake атака применена корректно")
            else:
                self.logger.warning(f"⚠️ Fake атака применена некорректно: {len(issues)} проблем")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка верификации fake атаки: {e}", exc_info=True)
            return FakeAttackVerification(
                fake_packet_found=False,
                is_correct=False,
                issues=[f"Verification error: {str(e)}"]
            )
    
    def verify_multisplit_attack(self, pcap_file: str, 
                                expected_positions: List[int]) -> MultisplitVerification:
        """
        Проверяет корректность применения multisplit атаки.
        
        Multisplit атака должна разделить payload на несколько фрагментов
        в указанных позициях.
        
        Args:
            pcap_file: Путь к PCAP файлу
            expected_positions: Ожидаемые позиции split
            
        Returns:
            MultisplitVerification с найденными позициями
            
        Requirements: 13.3
        """
        self.logger.info(f"🔍 Верификация multisplit атаки в {pcap_file}")
        
        try:
            # Read PCAP file
            packets = self._read_pcap(pcap_file)
            if not packets:
                return MultisplitVerification(
                    expected_positions=expected_positions,
                    found_positions=[],
                    is_correct=False,
                    issues=["No packets found in PCAP"]
                )
            
            # Find TCP packets with payload
            tcp_packets = self._extract_tcp_packets(packets)
            if len(tcp_packets) < 2:
                return MultisplitVerification(
                    expected_positions=expected_positions,
                    found_positions=[],
                    is_correct=False,
                    issues=["Not enough TCP packets for multisplit attack"]
                )
            
            # Analyze packet sequence numbers to find split positions
            found_positions = []
            
            # Sort packets by sequence number
            sorted_packets = sorted(tcp_packets, key=lambda p: p['seq'])
            
            # Calculate split positions from sequence numbers
            base_seq = sorted_packets[0]['seq']
            for pkt in sorted_packets[1:]:
                offset = pkt['seq'] - base_seq
                if offset > 0 and offset not in found_positions:
                    found_positions.append(offset)
            
            # Compare with expected positions
            missing_splits = [pos for pos in expected_positions if pos not in found_positions]
            extra_splits = [pos for pos in found_positions if pos not in expected_positions]
            
            issues = []
            is_correct = True
            
            if missing_splits:
                issues.append(f"Missing split positions: {missing_splits}")
                is_correct = False
            
            if extra_splits:
                issues.append(f"Extra split positions: {extra_splits}")
                is_correct = False
            
            result = MultisplitVerification(
                expected_positions=expected_positions,
                found_positions=found_positions,
                is_correct=is_correct,
                missing_splits=missing_splits,
                extra_splits=extra_splits,
                issues=issues
            )
            
            if is_correct:
                self.logger.info("✅ Multisplit атака применена корректно")
            else:
                self.logger.warning(f"⚠️ Multisplit атака применена некорректно: {len(issues)} проблем")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка верификации multisplit атаки: {e}", exc_info=True)
            return MultisplitVerification(
                expected_positions=expected_positions,
                found_positions=[],
                is_correct=False,
                issues=[f"Verification error: {str(e)}"]
            )
    
    def verify_disorder_attack(self, pcap_file: str) -> DisorderVerification:
        """
        Проверяет корректность применения disorder атаки.
        
        Disorder атака должна отправить пакеты в неправильном порядке
        (вторая часть перед первой). Правильный паттерн:
        1. Пакет с более высоким sequence number отправляется первым (part2)
        2. Пакет с более низким sequence number отправляется вторым (part1)
        3. Временные метки должны показывать этот порядок
        
        Args:
            pcap_file: Путь к PCAP файлу
            
        Returns:
            DisorderVerification с порядком пакетов
            
        Requirements: 13.4
        Task: 9.1.4 Реализовать верификацию disorder атак
        """
        self.logger.info(f"🔍 Верификация disorder атаки в {pcap_file}")
        
        try:
            # Read PCAP file
            packets = self._read_pcap(pcap_file)
            if not packets:
                return DisorderVerification(
                    is_correct=False,
                    issues=["No packets found in PCAP"]
                )
            
            # Find TCP packets with payload (data segments)
            tcp_packets = self._extract_tcp_packets(packets)
            
            # Filter only packets with payload (actual data)
            data_packets = [pkt for pkt in tcp_packets if pkt['payload_len'] > 0]
            
            if len(data_packets) < 2:
                return DisorderVerification(
                    is_correct=False,
                    issues=[f"Not enough data packets for disorder attack (found {len(data_packets)}, need at least 2)"]
                )
            
            # Extract packet order (seq, timestamp)
            packet_order = [(pkt['seq'], pkt['timestamp']) for pkt in data_packets]
            
            # Analyze disorder pattern
            is_disordered = False
            disorder_count = 0
            issues = []
            
            # Check each consecutive pair of packets
            for i in range(len(packet_order) - 1):
                curr_seq, curr_time = packet_order[i]
                next_seq, next_time = packet_order[i + 1]
                
                # Disorder pattern: packet with higher seq sent before packet with lower seq
                # This means: curr_seq > next_seq (sequence numbers are out of order)
                # AND: curr_time < next_time (but timestamps are in order)
                if curr_seq > next_seq:
                    is_disordered = True
                    disorder_count += 1
                    
                    self.logger.debug(
                        f"📊 Disorder detected at position {i}: "
                        f"seq1=0x{curr_seq:08X} (time={curr_time:.6f}), "
                        f"seq2=0x{next_seq:08X} (time={next_time:.6f})"
                    )
            
            # Determine if attack is correctly applied
            is_correct = is_disordered
            
            if not is_disordered:
                issues.append(
                    "No disorder detected - packets are in sequence order. "
                    "Expected: part2 (higher seq) sent before part1 (lower seq)"
                )
                is_correct = False
                self.logger.warning("⚠️ Disorder pattern not found in PCAP")
            else:
                self.logger.info(
                    f"✅ Disorder pattern detected: {disorder_count} out-of-order packet pair(s)"
                )
            
            # Additional validation: check if we have exactly 2 data packets (typical disorder)
            if len(data_packets) == 2 and is_disordered:
                seq1, time1 = packet_order[0]
                seq2, time2 = packet_order[1]
                
                # Verify the classic disorder pattern
                if seq1 > seq2:
                    self.logger.info(
                        f"✅ Classic disorder pattern confirmed: "
                        f"part2 (seq=0x{seq1:08X}) sent before part1 (seq=0x{seq2:08X})"
                    )
                else:
                    issues.append(
                        f"Unexpected pattern: first packet has lower seq (0x{seq1:08X}) "
                        f"than second packet (0x{seq2:08X})"
                    )
            
            result = DisorderVerification(
                packet_order=packet_order,
                is_disordered=is_disordered,
                disorder_count=disorder_count,
                is_correct=is_correct,
                issues=issues
            )
            
            if is_correct:
                self.logger.info(
                    f"✅ Disorder атака применена корректно "
                    f"({disorder_count} нарушений порядка обнаружено)"
                )
            else:
                self.logger.warning(
                    f"⚠️ Disorder атака применена некорректно: {', '.join(issues)}"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка верификации disorder атаки: {e}", exc_info=True)
            return DisorderVerification(
                is_correct=False,
                issues=[f"Verification error: {str(e)}"]
            )
    
    def compare_attack_application(self, testing_pcap: str, service_pcap: str,
                                  attack_type: str) -> ComparisonReport:
        """
        Сравнивает применение атак между режимами.
        
        Args:
            testing_pcap: PCAP из testing mode
            service_pcap: PCAP из service mode
            attack_type: Тип атаки (fake, multisplit, disorder, seqovl)
            
        Returns:
            ComparisonReport с детальным отчетом о различиях
            
        Requirements: 13.1, 13.5, 13.6, 13.7, 13.8
        """
        self.logger.info(f"🔍 Сравнение применения {attack_type} атаки между режимами")
        
        differences = []
        recommendations = []
        testing_verification = None
        service_verification = None
        
        try:
            # Verify attack in both modes
            if attack_type == "fake":
                testing_verification = self.verify_fake_attack(testing_pcap)
                service_verification = self.verify_fake_attack(service_pcap)
                
                # Compare fake attack parameters
                if testing_verification.fake_seq != service_verification.fake_seq:
                    differences.append({
                        'type': 'fake_sequence_number',
                        'description': f"Fake sequence numbers differ: "
                                     f"testing=0x{testing_verification.fake_seq:08X}, "
                                     f"service=0x{service_verification.fake_seq:08X}",
                        'testing': testing_verification.fake_seq,
                        'service': service_verification.fake_seq,
                        'file': 'core/bypass/packet/builder.py',
                        'method': 'build_tcp_segment'
                    })
                    recommendations.append(
                        "Check sequence number generation in PacketBuilder.build_tcp_segment(). "
                        "Ensure random sequence is used for fake packets in both modes."
                    )
                
                if testing_verification.fake_ttl != service_verification.fake_ttl:
                    differences.append({
                        'type': 'fake_ttl',
                        'description': f"Fake TTL differs: "
                                     f"testing={testing_verification.fake_ttl}, "
                                     f"service={service_verification.fake_ttl}",
                        'testing': testing_verification.fake_ttl,
                        'service': service_verification.fake_ttl,
                        'file': 'core/bypass/techniques/primitives.py',
                        'method': 'apply_fakeddisorder'
                    })
                    recommendations.append(
                        "Check TTL parameter passing in apply_fakeddisorder(). "
                        "Ensure fake_ttl is set correctly in both modes."
                    )
                
                # Check if both have sequence overlap issue
                if testing_verification.is_seq_overlap() or service_verification.is_seq_overlap():
                    differences.append({
                        'type': 'sequence_overlap',
                        'description': "Sequence overlap detected in one or both modes",
                        'testing': testing_verification.is_seq_overlap(),
                        'service': service_verification.is_seq_overlap(),
                        'file': 'core/bypass/packet/builder.py',
                        'method': 'build_tcp_segment'
                    })
                    recommendations.append(
                        "CRITICAL: Fix sequence number generation to avoid overlap. "
                        "Use random sequence for fake packets instead of base_seq + offset."
                    )
            
            elif attack_type == "multisplit":
                # For multisplit, we need expected positions
                # This should be passed as parameter, but for now we'll analyze what we find
                testing_verification = self.verify_multisplit_attack(testing_pcap, [])
                service_verification = self.verify_multisplit_attack(service_pcap, [])
                
                if set(testing_verification.found_positions) != set(service_verification.found_positions):
                    differences.append({
                        'type': 'split_positions',
                        'description': f"Split positions differ: "
                                     f"testing={testing_verification.found_positions}, "
                                     f"service={service_verification.found_positions}",
                        'testing': testing_verification.found_positions,
                        'service': service_verification.found_positions,
                        'file': 'core/bypass/techniques/primitives.py',
                        'method': 'apply_multisplit'
                    })
                    recommendations.append(
                        "Check split position calculation in apply_multisplit(). "
                        "Ensure positions are calculated identically in both modes."
                    )
            
            elif attack_type == "disorder":
                testing_verification = self.verify_disorder_attack(testing_pcap)
                service_verification = self.verify_disorder_attack(service_pcap)
                
                if testing_verification.is_disordered != service_verification.is_disordered:
                    differences.append({
                        'type': 'disorder_detection',
                        'description': f"Disorder detection differs: "
                                     f"testing={testing_verification.is_disordered}, "
                                     f"service={service_verification.is_disordered}",
                        'testing': testing_verification.is_disordered,
                        'service': service_verification.is_disordered,
                        'file': 'core/bypass/techniques/primitives.py',
                        'method': 'apply_disorder'
                    })
                    recommendations.append(
                        "Check packet send order in apply_disorder(). "
                        "Ensure part2 is sent before part1 in both modes."
                    )
            
            # Determine if applications are identical
            is_identical = len(differences) == 0
            
            if not is_identical:
                recommendations.append(
                    "Review UnifiedBypassEngine to ensure it applies attacks identically "
                    "in both testing and service modes."
                )
            
            report = ComparisonReport(
                testing_pcap=testing_pcap,
                service_pcap=service_pcap,
                attack_type=attack_type,
                differences=differences,
                testing_verification=testing_verification,
                service_verification=service_verification,
                is_identical=is_identical,
                recommendations=recommendations
            )
            
            if is_identical:
                self.logger.info(f"✅ {attack_type} атака применяется идентично в обоих режимах")
            else:
                self.logger.warning(f"⚠️ {attack_type} атака применяется по-разному: {len(differences)} различий")
            
            return report
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка сравнения: {e}", exc_info=True)
            return ComparisonReport(
                testing_pcap=testing_pcap,
                service_pcap=service_pcap,
                attack_type=attack_type,
                differences=[{
                    'type': 'comparison_error',
                    'description': f"Comparison failed: {str(e)}"
                }],
                is_identical=False,
                recommendations=["Fix comparison error before proceeding"]
            )
    
    def _read_pcap(self, pcap_file: str) -> List[RawPacket]:
        """Читает PCAP файл."""
        try:
            if not Path(pcap_file).exists():
                self.logger.warning(f"⚠️ PCAP файл не найден: {pcap_file}")
                return []
            
            packets = self.pcap_reader.read_pcap_file(pcap_file)
            return packets
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка чтения PCAP: {e}")
            return []
    
    def _extract_tcp_packets(self, packets: List[RawPacket]) -> List[Dict[str, Any]]:
        """
        Извлекает TCP пакеты с полезной информацией.
        
        Returns:
            Список словарей с информацией о TCP пакетах
        """
        tcp_packets = []
        
        for pkt in packets:
            if pkt.protocol != ProtocolType.TCP:
                continue
            
            try:
                # Parse IP header
                ip_header = IPHeader.unpack(pkt.data[:20])
                ip_header_size = ip_header.ihl * 4
                
                # Parse TCP header
                tcp_data = pkt.data[ip_header_size:]
                if len(tcp_data) < 20:
                    continue
                
                tcp_header = TCPHeader.unpack(tcp_data)
                
                # Extract payload
                tcp_header_size = tcp_header.data_offset * 4
                payload = tcp_data[tcp_header_size:] if len(tcp_data) > tcp_header_size else b""
                
                tcp_packets.append({
                    'seq': tcp_header.seq_num,
                    'ack': tcp_header.ack_num,
                    'flags': tcp_header.flags,
                    'ttl': ip_header.ttl,
                    'payload': payload,
                    'payload_len': len(payload),
                    'timestamp': pkt.timestamp,
                    'src_ip': pkt.src_ip,
                    'dst_ip': pkt.dst_ip,
                    'src_port': pkt.src_port,
                    'dst_port': pkt.dst_port
                })
                
            except Exception as e:
                self.logger.debug(f"⚠️ Ошибка парсинга TCP пакета: {e}")
                continue
        
        return tcp_packets
