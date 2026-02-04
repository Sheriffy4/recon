"""
PCAP Analyzer for Strategy Application Analysis

This module provides enhanced PCAP analysis capabilities for verifying
strategy application in both testing and service modes. It extends the
existing IntelligentPCAPAnalyzer with strategy-specific analysis.

Requirements: 8.1, 8.2, 8.4, 8.5, 8.6, 8.7
"""

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime

# Import RawPCAPReader instead of Scapy
from core.packet.raw_pcap_reader import RawPCAPReader
from core.packet.raw_packet_engine import RawPacket, RawPacketEngine, ProtocolType
from core.bypass.sni.manipulator import SNIManipulator

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DATA CLASSES
# ---------------------------------------------------------------------------


@dataclass
class StrategyAnalysisResult:
    """Результат анализа применения стратегии в PCAP."""

    strategy_detected: bool  # Стратегия обнаружена в PCAP
    split_positions: List[int] = field(default_factory=list)  # Найденные позиции split
    sni_values: List[str] = field(default_factory=list)  # Найденные SNI значения
    checksums_valid: Dict[str, bool] = field(default_factory=dict)  # Валидность checksums
    packet_count: int = 0  # Количество пакетов
    anomalies: List[str] = field(default_factory=list)  # Обнаруженные аномалии
    strategy_type: Optional[str] = None  # Тип примененной стратегии (включая combo)
    parameters: Dict[str, Any] = field(default_factory=dict)  # Извлеченные параметры
    detected_attacks: List[str] = field(
        default_factory=list
    )  # Обнаруженные базовые атаки (Task 3.1)
    fake_packets_detected: int = 0  # Количество фейковых пакетов (Task 3.2)
    combo_attacks: List[str] = field(
        default_factory=list
    )  # Выявленная комбинация атак (в порядке применения)

    def matches_expected(self, expected_strategy: Dict[str, Any]) -> bool:
        """
        Проверяет соответствие ожидаемой стратегии.

        Args:
            expected_strategy: Ожидаемая стратегия

        Returns:
            True если PCAP соответствует ожидаемой стратегии
        """
        if not self.strategy_detected:
            return False

        # Check strategy type
        expected_type = expected_strategy.get("attack", expected_strategy.get("type"))
        if expected_type and self.strategy_type != expected_type:
            return False

        # Check split positions if specified
        expected_split = expected_strategy.get("params", {}).get("split_pos")
        if expected_split and self.split_positions:
            # Приводим к int, если строка
            if isinstance(expected_split, str) and expected_split.isdigit():
                expected_split = int(expected_split)
            if expected_split not in self.split_positions:
                return False

        # Check SNI if specified
        expected_sni = expected_strategy.get("params", {}).get("sni")
        if expected_sni and self.sni_values:
            if expected_sni not in self.sni_values:
                return False

        # Check combo attacks list if задано в expected
        expected_attacks = expected_strategy.get("attacks")
        if expected_attacks and self.combo_attacks:
            # Сравниваем по множеству, чтобы не зависеть от порядка в expected
            if set(expected_attacks) != set(self.combo_attacks):
                return False

        return True


@dataclass
class ComparisonResult:
    """Результат сравнения PCAP между режимами."""

    testing_pcap: str  # Путь к PCAP из testing mode
    service_pcap: str  # Путь к PCAP из service mode
    differences: List[Dict[str, Any]] = field(default_factory=list)  # Найденные различия
    similarity_score: float = 0.0  # Оценка схожести (0.0-1.0)
    testing_analysis: Optional[StrategyAnalysisResult] = None
    service_analysis: Optional[StrategyAnalysisResult] = None

    def generate_report(self) -> str:
        """
        Генерирует текстовый отчет о сравнении.

        Returns:
            Текстовый отчет
        """
        lines: List[str] = []
        lines.append("=" * 80)
        lines.append("PCAP Comparison Report")
        lines.append("=" * 80)
        lines.append(f"Testing PCAP: {self.testing_pcap}")
        lines.append(f"Service PCAP: {self.service_pcap}")
        lines.append(f"Similarity Score: {self.similarity_score:.2%}")
        lines.append("")

        if self.differences:
            lines.append(f"Found {len(self.differences)} differences:")
            for i, diff in enumerate(self.differences, 1):
                lines.append(
                    f"  {i}. {diff.get('type', 'Unknown')}: "
                    f"{diff.get('description', 'No description')}"
                )
        else:
            lines.append("No significant differences found.")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# COMBO DETECTION CONSTANTS
# ---------------------------------------------------------------------------

# Базовые атаки, которые считаются "основными" компонентами стратегии
CORE_ATTACKS_ORDER: Dict[str, int] = {
    "disorder": 0,
    "fake": 1,
    "split": 2,
    "multisplit": 2,
    "seqovl": 4,
}

# Метки, относящиеся к fooling/low-level приёмам, а не к основным атакам
FOOLING_LABELS: Set[str] = {"badsum", "badseq", "ttl_manipulation"}


class PCAPAnalyzer:
    """
    Анализатор PCAP файлов для верификации стратегий.

    Расширяет существующий IntelligentPCAPAnalyzer функциональностью
    для анализа применения стратегий и сравнения между режимами.

    Requirements: 8.1, 8.2, 8.4, 8.5, 8.6, 8.7
    """

    def __init__(self):
        """Инициализация анализатора."""
        self.logger = LOG
        self.analysis_cache: Dict[str, StrategyAnalysisResult] = {}
        self.pcap_reader = RawPCAPReader()
        self.packet_engine = RawPacketEngine()
        self.logger.info("ℹ️ Используется RawPCAPReader для анализа PCAP")

    # ------------------------------------------------------------------ #
    # Высокоуровневый анализ (PCAPAnalysisResult)
    # ------------------------------------------------------------------ #

    def analyze_pcap(
        self,
        pcap_file: str,
        strategy_name: Optional[str] = None,
        test_start_time: Optional[float] = None,
    ) -> "PCAPAnalysisResult":
        """
        Analyzes PCAP file and returns structured PCAPAnalysisResult.

        This is the main entry point for PCAP analysis that returns
        the standardized PCAPAnalysisResult dataclass.

        Implements error handling for:
        - PCAP file not found → returns result with errors
        - PCAP file corrupted → returns result with errors
        - Empty PCAP → returns result with warnings

        Args:
            pcap_file: Path to PCAP file
            strategy_name: Strategy name for loading metadata (optional)
            test_start_time: Timestamp of test start for packet filtering (optional)

        Returns:
            PCAPAnalysisResult with all analysis data

        Requirements: 4.3 (Task 3.4), 6.1 (Task 8.2)
        """
        from core.test_result_models import PCAPAnalysisResult
        from core.pcap.metadata_saver import load_pcap_metadata
        import time

        start_time = time.time()
        errors: List[str] = []
        warnings: List[str] = []

        # Task: Testing-Production Parity - Load executed attacks from metadata (single source of truth)
        metadata = load_pcap_metadata(pcap_file, strategy_name)
        executed_attacks_from_log = metadata.get("executed_attacks") if metadata else None

        # Use provided test_start_time if available, otherwise try to load from metadata
        if test_start_time is None and metadata:
            test_start_time = metadata.get("test_start_time")

        if executed_attacks_from_log:
            self.logger.info(
                f"✅ Loaded executed attacks from metadata: {executed_attacks_from_log}"
            )
        else:
            self.logger.debug("⚠️ No metadata found, will use PCAP-based detection")

        if test_start_time:
            self.logger.info(f"✅ Using test_start_time for filtering: {test_start_time}")

        # Task 8.2: Handle PCAP file not found → INCONCLUSIVE verdict
        if not Path(pcap_file).exists():
            error_msg = f"PCAP file not found: {pcap_file}"
            self.logger.error(f"❌ {error_msg}")
            errors.append(error_msg)
            return PCAPAnalysisResult(
                pcap_file=pcap_file,
                packet_count=0,
                detected_attacks=[],
                executed_attacks_from_log=executed_attacks_from_log,
                parameters={},
                split_positions=[],
                fake_packets_detected=0,
                sni_values=[],
                analysis_time=time.time() - start_time,
                analyzer_version="1.0",
                errors=errors,
                warnings=warnings,
            )

        try:
            # Use existing analysis method with timestamp filtering
            # Pass test_start_time directly (not from metadata)
            strategy_result = self.analyze_strategy_application(
                pcap_file, test_start_time=test_start_time, strategy_name=strategy_name
            )

            # Task 8.2: Handle empty PCAP → INCONCLUSIVE verdict
            if strategy_result.packet_count == 0:
                warning_msg = "Empty PCAP file: no packets found"
                self.logger.warning(f"⚠️ {warning_msg}")
                warnings.append(warning_msg)

            # Convert to PCAPAnalysisResult
            result = PCAPAnalysisResult(
                pcap_file=pcap_file,
                packet_count=strategy_result.packet_count,
                detected_attacks=strategy_result.detected_attacks,
                executed_attacks_from_log=executed_attacks_from_log,
                strategy_type=strategy_result.strategy_type,
                combo_attacks=strategy_result.combo_attacks,
                parameters=strategy_result.parameters,
                split_positions=strategy_result.split_positions,
                fake_packets_detected=strategy_result.fake_packets_detected,
                sni_values=strategy_result.sni_values,
                analysis_time=time.time() - start_time,
                analyzer_version="1.0",
                errors=errors,
                warnings=warnings + strategy_result.anomalies,
            )

            return result

        except Exception as e:
            # Task 8.2: Handle PCAP file corrupted → INCONCLUSIVE verdict
            error_msg = f"PCAP file corrupted or unreadable: {e}"
            self.logger.error(f"❌ {error_msg}", exc_info=True)
            errors.append(error_msg)
            return PCAPAnalysisResult(
                pcap_file=pcap_file,
                packet_count=0,
                detected_attacks=[],
                executed_attacks_from_log=executed_attacks_from_log,
                parameters={},
                split_positions=[],
                fake_packets_detected=0,
                sni_values=[],
                analysis_time=time.time() - start_time,
                analyzer_version="1.0",
                errors=errors,
                warnings=warnings,
            )

    # ------------------------------------------------------------------ #
    # Анализ применения стратегии
    # ------------------------------------------------------------------ #

    def analyze_strategy_application(
        self,
        pcap_file: str,
        expected_strategy: Optional[Dict[str, Any]] = None,
        test_start_time: Optional[float] = None,
        strategy_name: Optional[str] = None,
    ) -> StrategyAnalysisResult:
        """
        Анализирует применение стратегии в PCAP.

        Args:
            pcap_file: Путь к PCAP файлу
            expected_strategy: Ожидаемая стратегия (опционально)
            test_start_time: Timestamp начала теста для фильтрации пакетов (опционально)
            strategy_name: Имя стратегии для загрузки метаданных (опционально)

        Returns:
            StrategyAnalysisResult с деталями применения

        Requirements: 8.4, 8.5
        """
        self.logger.info(f"🔍 Анализ применения стратегии в {pcap_file}")

        # Use provided test_start_time if available, otherwise try to load from metadata
        if test_start_time is None:
            from core.pcap.metadata_saver import load_pcap_metadata

            metadata = load_pcap_metadata(pcap_file, strategy_name)
            if metadata:
                test_start_time = metadata.get("test_start_time")

        if test_start_time:
            self.logger.info(f"✅ Using test_start_time for packet filtering: {test_start_time}")

        # Check cache (include test_start_time in cache key for unique caching per test)
        cache_key = self._get_cache_key(pcap_file, test_start_time, strategy_name)
        if cache_key in self.analysis_cache:
            self.logger.debug("📋 Используем кэшированный результат")
            return self.analysis_cache[cache_key]

        try:
            # Read PCAP file using RawPCAPReader
            packets = self._read_pcap(pcap_file)
            if not packets:
                self.logger.warning(f"⚠️ Нет пакетов в {pcap_file}")
                return StrategyAnalysisResult(strategy_detected=False, packet_count=0)

            # Use Flow-Based Isolation instead of unreliable timestamp filtering
            # This is more robust and avoids analyzing packets from other tests
            total_packets = len(packets)
            target_packets = self._extract_best_flow(packets, test_start_time)

            if not target_packets:
                self.logger.warning(
                    f"⚠️ Не найден подходящий TLS поток среди {total_packets} пакетов"
                )
                return StrategyAnalysisResult(strategy_detected=False, packet_count=0)

            self.logger.info(
                f"✅ Выделен целевой поток: {len(target_packets)} пакетов из {total_packets}"
            )
            packets = target_packets

            self.logger.info(f"📦 Загружено {len(packets)} пакетов")

            # Extract parameters from packets
            split_positions = self.find_split_positions(packets)
            sni_values = self.find_sni_values(packets)
            checksums = self.validate_checksums(packets)

            # Detect fake packets (Task 3.2)
            fake_packets_detected = self._detect_fake_packets(packets, checksums)

            # Detect all attacks present in PCAP (Task 3.1)
            detected_attacks = self._detect_attacks(
                packets, split_positions, fake_packets_detected, checksums
            )

            # Determine combo strategy type и список атак-компонент
            strategy_type, combo_attacks = self._determine_strategy_type_from_attacks(
                detected_attacks
            )

            # Extract parameters (Task 3.3)
            parameters = self._extract_all_parameters(
                packets, split_positions, sni_values, checksums
            )

            # Find anomalies
            anomalies = self._find_anomalies(packets, checksums)

            result = StrategyAnalysisResult(
                strategy_detected=bool(strategy_type or detected_attacks),
                split_positions=split_positions,
                sni_values=sni_values,
                checksums_valid=checksums,
                packet_count=len(packets),
                anomalies=anomalies,
                strategy_type=strategy_type,
                parameters=parameters,
                detected_attacks=detected_attacks,
                fake_packets_detected=fake_packets_detected,
                combo_attacks=combo_attacks,
            )

            # Cache result
            self.analysis_cache[cache_key] = result

            self.logger.info(
                "✅ Анализ завершен: strategy=%s, combo=%s, attacks=%s, splits=%d, fake=%d, sni=%d",
                strategy_type,
                combo_attacks,
                detected_attacks,
                len(split_positions),
                fake_packets_detected,
                len(sni_values),
            )

            return result

        except Exception as e:
            self.logger.error(f"❌ Ошибка анализа: {e}", exc_info=True)
            return StrategyAnalysisResult(strategy_detected=False)

    # ------------------------------------------------------------------ #
    # Низкоуровневые детекторы
    # ------------------------------------------------------------------ #

    def find_split_positions(self, packets: List[RawPacket]) -> List[int]:
        """
        Находит позиции split в захваченных пакетах.

        IMPROVED: Now analyzes TCP sequence numbers and payload fragmentation,
        focusing only on ClientHello sequence range to avoid counting retransmissions.
        This matches analyze_raw_pcap.py logic.

        Args:
            packets: Список RawPacket объектов

        Returns:
            Список позиций split (относительно начала потока)

        Requirements: 8.4, 8.7
        """
        split_positions: List[int] = []

        try:
            from core.packet.raw_packet_engine import IPHeader, TCPHeader

            # Step 1: Find ClientHello packet to get sequence range
            clienthello_seq = None
            clienthello_len = None

            for pkt in packets:
                if pkt.protocol != ProtocolType.TCP or not pkt.payload:
                    continue

                # Check if this is ClientHello
                if self.packet_engine.is_client_hello(pkt.payload):
                    try:
                        ip_header = IPHeader.unpack(pkt.data[:20])
                        ip_header_size = ip_header.ihl * 4
                        tcp_data = pkt.data[ip_header_size:]
                        tcp_header = TCPHeader.unpack(tcp_data)

                        clienthello_seq = tcp_header.seq_num
                        clienthello_len = len(pkt.payload)
                        break
                    except Exception:
                        continue

            if clienthello_seq is None:
                self.logger.debug("⚠️ ClientHello не найден, пропускаем анализ split")
                return []

            # Step 2: Filter for REAL TCP packets in ClientHello sequence range (TTL > 5)
            clienthello_end_seq = clienthello_seq + clienthello_len
            real_packets = []

            for pkt in packets:
                if pkt.protocol != ProtocolType.TCP or not pkt.payload:
                    continue

                try:
                    # Check TTL - skip fake packets
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    if ip_header.ttl <= 5:
                        continue

                    # Extract TCP info
                    ip_header_size = ip_header.ihl * 4
                    tcp_data = pkt.data[ip_header_size:]
                    if len(tcp_data) < 20:
                        continue

                    tcp_header = TCPHeader.unpack(tcp_data)
                    tcp_header_size = tcp_header.data_offset * 4
                    payload_len = len(tcp_data) - tcp_header_size

                    if payload_len == 0:
                        continue

                    # Only include packets in ClientHello sequence range
                    seq = tcp_header.seq_num
                    if seq >= clienthello_seq and seq < clienthello_end_seq:
                        real_packets.append({"seq": seq, "payload_len": payload_len, "pkt": pkt})
                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка парсинга пакета: {e}")
                    continue

            if not real_packets:
                return []

            # Sort by sequence number
            real_packets.sort(key=lambda x: x["seq"])

            # Calculate split positions based on sequence numbers
            base_seq = real_packets[0]["seq"]

            # Each fragment end is a split position (except the last one)
            for pkt_info in real_packets[:-1]:
                seq = pkt_info["seq"]
                length = pkt_info["payload_len"]
                relative_end = (seq - base_seq) + length
                if relative_end > 0:
                    split_positions.append(relative_end)

            split_positions = sorted(set(split_positions))
            self.logger.debug(
                f"🔍 Найдено {len(split_positions)} позиций split "
                f"(из {len(real_packets)} реальных фрагментов в ClientHello range)"
            )

        except Exception as e:
            self.logger.error(f"❌ Ошибка поиска split позиций: {e}")

        return split_positions

    def find_sni_values(self, packets: List[RawPacket]) -> List[str]:
        """
        Извлекает SNI значения из пакетов.

        Args:
            packets: Список RawPacket объектов

        Returns:
            Список SNI значений

        Requirements: 8.4, 8.7
        """
        sni_values: List[str] = []

        try:
            for pkt in packets:
                if pkt.protocol != ProtocolType.TCP or not pkt.payload:
                    continue

                payload = pkt.payload
                if not self.packet_engine.is_client_hello(payload):
                    continue

                sni = self.packet_engine.extract_tls_sni(payload)
                if sni:
                    sni_values.append(sni)

            # Remove duplicates while preserving order
            seen: Set[str] = set()
            unique_sni: List[str] = []
            for sni in sni_values:
                if sni not in seen:
                    seen.add(sni)
                    unique_sni.append(sni)

            self.logger.debug(f"🔍 Найдено {len(unique_sni)} уникальных SNI значений")
            return unique_sni

        except Exception as e:
            self.logger.error(f"❌ Ошибка извлечения SNI: {e}")
            return []

    def validate_checksums(self, packets: List[RawPacket]) -> Dict[str, bool]:
        """
        Проверяет checksums в пакетах.

        Args:
            packets: Список RawPacket объектов

        Returns:
            Словарь {packet_id: is_valid}

        Requirements: 8.4, 8.7
        """
        checksums: Dict[str, bool] = {}

        try:
            from core.packet.raw_packet_engine import IPHeader, TCPHeader

            for i, pkt in enumerate(packets):
                packet_id = f"packet_{i}"

                if pkt.protocol != ProtocolType.TCP:
                    continue

                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ip_header_size = ip_header.ihl * 4

                    tcp_data = pkt.data[ip_header_size:]
                    if len(tcp_data) < 20:
                        checksums[packet_id] = False
                        continue

                    tcp_header = TCPHeader.unpack(tcp_data)
                    original_checksum = tcp_header.checksum

                    tcp_header_size = tcp_header.data_offset * 4
                    tcp_payload = (
                        tcp_data[tcp_header_size:] if len(tcp_data) > tcp_header_size else b""
                    )

                    tcp_header.checksum = 0
                    calculated_checksum = tcp_header.calculate_checksum(
                        pkt.src_ip,
                        pkt.dst_ip,
                        tcp_payload,
                    )

                    is_valid = original_checksum == calculated_checksum
                    checksums[packet_id] = is_valid

                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка валидации checksum для пакета {i}: {e}")
                    checksums[packet_id] = False

            valid_count = sum(1 for v in checksums.values() if v)
            self.logger.debug(f"🔍 Проверено {len(checksums)} checksums, валидных: {valid_count}")

        except Exception as e:
            self.logger.error(f"❌ Ошибка валидации checksums: {e}")

        return checksums

    # ------------------------------------------------------------------ #
    # Сравнение с ожидаемой стратегией / другими PCAP
    # ------------------------------------------------------------------ #

    def compare_with_expected(
        self,
        pcap_file: str,
        expected_strategy: Dict[str, Any],
    ) -> ComparisonResult:
        """
        Сравнивает PCAP с ожидаемой стратегией.

        Args:
            pcap_file: Путь к PCAP файлу
            expected_strategy: Ожидаемая стратегия

        Returns:
            ComparisonResult с результатами сравнения

        Requirements: 8.5, 8.6
        """
        self.logger.info("🔍 Сравнение PCAP с ожидаемой стратегией")

        analysis = self.analyze_strategy_application(pcap_file, expected_strategy)

        differences: List[Dict[str, Any]] = []

        # Compare strategy type
        expected_type = expected_strategy.get("attack", expected_strategy.get("type"))
        if expected_type and analysis.strategy_type != expected_type:
            differences.append(
                {
                    "type": "strategy_type",
                    "description": f"Expected {expected_type}, found {analysis.strategy_type}",
                    "expected": expected_type,
                    "actual": analysis.strategy_type,
                }
            )

        # Compare split positions
        expected_split = expected_strategy.get("params", {}).get("split_pos")
        if expected_split:
            if isinstance(expected_split, str) and expected_split.isdigit():
                expected_split = int(expected_split)
            if expected_split not in analysis.split_positions:
                differences.append(
                    {
                        "type": "split_position",
                        "description": (
                            f"Expected split at {expected_split}, "
                            f"found {analysis.split_positions}"
                        ),
                        "expected": expected_split,
                        "actual": analysis.split_positions,
                    }
                )

        # Compare SNI
        expected_sni = expected_strategy.get("params", {}).get("sni")
        if expected_sni and expected_sni not in analysis.sni_values:
            differences.append(
                {
                    "type": "sni_value",
                    "description": (f"Expected SNI '{expected_sni}', found {analysis.sni_values}"),
                    "expected": expected_sni,
                    "actual": analysis.sni_values,
                }
            )

        # Compare attacks list (для combo-стратегий)
        expected_attacks = expected_strategy.get("attacks")
        if expected_attacks:
            if set(expected_attacks) != set(analysis.combo_attacks or analysis.detected_attacks):
                differences.append(
                    {
                        "type": "attack_combination",
                        "description": (
                            f"Expected attacks {expected_attacks}, "
                            f"found {analysis.combo_attacks or analysis.detected_attacks}"
                        ),
                        "expected": expected_attacks,
                        "actual": analysis.combo_attacks or analysis.detected_attacks,
                    }
                )

        similarity_score = self._calculate_similarity(analysis, expected_strategy)

        result = ComparisonResult(
            testing_pcap=pcap_file,
            service_pcap="",
            differences=differences,
            similarity_score=similarity_score,
            testing_analysis=analysis,
        )

        self.logger.info(
            "✅ Сравнение завершено: %d различий, similarity=%.2f%%",
            len(differences),
            similarity_score * 100.0,
        )

        return result

    def compare_pcaps(self, testing_pcap: str, service_pcap: str) -> ComparisonResult:
        """
        Сравнивает два PCAP файла (testing vs service mode).

        Args:
            testing_pcap: PCAP из testing mode
            service_pcap: PCAP из service mode

        Returns:
            ComparisonResult с результатами сравнения

        Requirements: 8.5, 8.6
        """
        self.logger.info("🔍 Сравнение PCAP файлов: testing vs service")

        testing_analysis = self.analyze_strategy_application(testing_pcap)
        service_analysis = self.analyze_strategy_application(service_pcap)

        differences: List[Dict[str, Any]] = []

        # Compare strategy types
        if testing_analysis.strategy_type != service_analysis.strategy_type:
            differences.append(
                {
                    "type": "strategy_type",
                    "description": (
                        f"Testing: {testing_analysis.strategy_type}, "
                        f"Service: {service_analysis.strategy_type}"
                    ),
                    "testing": testing_analysis.strategy_type,
                    "service": service_analysis.strategy_type,
                }
            )

        # Compare split positions
        if set(testing_analysis.split_positions) != set(service_analysis.split_positions):
            differences.append(
                {
                    "type": "split_positions",
                    "description": (
                        f"Testing: {testing_analysis.split_positions}, "
                        f"Service: {service_analysis.split_positions}"
                    ),
                    "testing": testing_analysis.split_positions,
                    "service": service_analysis.split_positions,
                }
            )

        # Compare SNI values
        if set(testing_analysis.sni_values) != set(service_analysis.sni_values):
            differences.append(
                {
                    "type": "sni_values",
                    "description": (
                        f"Testing: {testing_analysis.sni_values}, "
                        f"Service: {service_analysis.sni_values}"
                    ),
                    "testing": testing_analysis.sni_values,
                    "service": service_analysis.sni_values,
                }
            )

        # Compare packet counts (разница более чем на 5 пакетов)
        if abs(testing_analysis.packet_count - service_analysis.packet_count) > 5:
            differences.append(
                {
                    "type": "packet_count",
                    "description": (
                        f"Testing: {testing_analysis.packet_count}, "
                        f"Service: {service_analysis.packet_count}"
                    ),
                    "testing": testing_analysis.packet_count,
                    "service": service_analysis.packet_count,
                }
            )

        similarity_score = self._calculate_pcap_similarity(testing_analysis, service_analysis)

        result = ComparisonResult(
            testing_pcap=testing_pcap,
            service_pcap=service_pcap,
            differences=differences,
            similarity_score=similarity_score,
            testing_analysis=testing_analysis,
            service_analysis=service_analysis,
        )

        self.logger.info(
            "✅ Сравнение завершено: %d различий, similarity=%.2f%%",
            len(differences),
            similarity_score * 100.0,
        )

        return result

    # ------------------------------------------------------------------ #
    # Вспомогательные методы чтения и детекторы атак
    # ------------------------------------------------------------------ #

    def _read_pcap(self, pcap_file: str) -> List[RawPacket]:
        """Читает PCAP файл используя RawPCAPReader."""
        try:
            if not Path(pcap_file).exists():
                self.logger.warning(f"⚠️ PCAP файл не найден: {pcap_file}")
                return []

            packets = self.pcap_reader.read_pcap_file(pcap_file)
            return packets

        except Exception as e:
            self.logger.error(f"❌ Ошибка чтения PCAP: {e}")
            return []

    def _extract_best_flow(
        self, packets: List[RawPacket], test_start_time: Optional[float] = None
    ) -> List[RawPacket]:
        """
        Выделяет наиболее вероятный целевой поток (TCP Flow) для анализа.

        Логика:
        1. Группирует пакеты по 4-tuple (src_ip, src_port, dst_ip, dst_port)
        2. Ищет потоки, содержащие ClientHello
        3. Если есть test_start_time, выбирает поток, ближайший к этому времени
        4. Если нет, выбирает поток с наибольшим количеством признаков обхода (фрагментация)

        Args:
            packets: Список всех пакетов из PCAP
            test_start_time: Unix timestamp начала теста (опционально)

        Returns:
            Список пакетов целевого потока
        """
        from collections import defaultdict

        flows = defaultdict(list)

        # 1. Группировка по TCP flow
        for pkt in packets:
            if pkt.protocol != ProtocolType.TCP:
                continue

            # Ключ потока: (src_ip, src_port, dst_ip, dst_port)
            key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            flows[key].append(pkt)

        # 2. Оценка потоков
        candidates = []

        for key, flow_packets in flows.items():
            has_client_hello = False
            fragment_count = 0
            first_timestamp = (
                flow_packets[0].timestamp
                if hasattr(flow_packets[0], "timestamp") and flow_packets[0].timestamp
                else 0
            )

            for pkt in flow_packets:
                # Проверка на ClientHello
                if pkt.payload and self.packet_engine.is_client_hello(pkt.payload):
                    has_client_hello = True

                # Проверка на фрагментацию (маленькие пакеты с данными)
                if pkt.payload and len(pkt.payload) < 100:
                    fragment_count += 1

            # ClientHello - ОБЯЗАТЕЛЬНОЕ условие для кандидата
            if not has_client_hello:
                continue  # Пропускаем потоки без ClientHello

            # Оценка релевантности (только для потоков с ClientHello)
            score = 100  # Базовый score за наличие ClientHello
            score += fragment_count * 10  # Фрагментация - признак стратегии

            # Фильтрация по времени (если задано), но мягкая
            time_diff = float("inf")
            if test_start_time and first_timestamp:
                time_diff = abs(first_timestamp - test_start_time)
                # Если поток начался сильно раньше теста (>10 сек) или сильно позже, штрафуем
                if time_diff > 10.0:
                    score -= 500

            # Добавляем только потоки с положительным score
            if score > 0:
                candidates.append(
                    {"key": key, "packets": flow_packets, "score": score, "time_diff": time_diff}
                )

        if not candidates:
            return []

        # 3. Выбор лучшего кандидата
        # Сортируем: сначала по score (ClientHello + фрагментация), потом по близости к времени
        candidates.sort(key=lambda x: (-x["score"], x["time_diff"]))

        best_flow = candidates[0]
        self.logger.debug(
            f"🌊 Выбран лучший поток: {best_flow['key'][0]}:{best_flow['key'][1]} -> "
            f"{best_flow['key'][2]}:{best_flow['key'][3]} "
            f"(Score: {best_flow['score']}, TimeDiff: {best_flow['time_diff']:.3f}s)"
        )

        return best_flow["packets"]

    def _filter_packets_by_timestamp(
        self, packets: List[RawPacket], test_start_time: float, time_window: float = 5.0
    ) -> List[RawPacket]:
        """
        Фильтрует пакеты по timestamp для изоляции пакетов конкретного теста.

        Когда несколько тестов пишут в один PCAP файл, нужно отфильтровать
        пакеты только для текущего теста по времени.

        ВАЖНО: Окно расширено назад на 5 секунд, чтобы включить пакеты,
        захваченные во время инициализации PCAP до начала теста.

        Args:
            packets: Список всех пакетов из PCAP
            test_start_time: Unix timestamp начала теста (из metadata)
            time_window: Временное окно в секундах (по умолчанию 5 секунд)

        Returns:
            Отфильтрованный список пакетов для данного теста
        """
        filtered_packets = []

        try:
            # Define time range for this test
            # Expand window backwards to include packets captured during PCAP initialization
            time_window_before = 5.0  # 5 seconds before test start
            time_window_after = 10.0  # 10 seconds after test start

            test_window_start = test_start_time - time_window_before
            test_window_end = test_start_time + time_window_after

            self.logger.debug(
                f"🔍 Фильтрация пакетов: test_start={test_start_time}, window=[{test_window_start:.3f}, {test_window_end:.3f}]"
            )

            for pkt in packets:
                # Check if packet has timestamp
                if not hasattr(pkt, "timestamp") or pkt.timestamp is None:
                    # If no timestamp, include packet (fallback behavior)
                    filtered_packets.append(pkt)
                    continue

                # Filter by timestamp range (expanded window)
                if test_window_start <= pkt.timestamp <= test_window_end:
                    filtered_packets.append(pkt)

            self.logger.info(
                f"✅ Отфильтровано {len(filtered_packets)}/{len(packets)} пакетов в окне [{test_window_start:.3f}, {test_window_end:.3f}]"
            )

        except Exception as e:
            self.logger.error(f"❌ Ошибка фильтрации по timestamp: {e}")
            # Fallback: return all packets if filtering fails
            return packets

        return filtered_packets

    def _detect_fake_packets(
        self,
        packets: List[RawPacket],
        checksums: Dict[str, bool],
    ) -> int:
        """
        Detects fake packets in PCAP.

        Task 3.2: Detect packets with is_fake flag or bad checksums

        Returns:
            Count of fake packets detected

        Requirements: 2.4
        """
        fake_count = 0

        try:
            from core.packet.raw_packet_engine import IPHeader

            for i, pkt in enumerate(packets):
                packet_id = f"packet_{i}"

                # Explicit is_fake flag
                if hasattr(pkt, "is_fake") and getattr(pkt, "is_fake"):
                    fake_count += 1
                    continue

                # Bad checksum
                if packet_id in checksums and not checksums[packet_id]:
                    fake_count += 1
                    continue

                # Heuristic: very low TTL in TCP packets
                if pkt.protocol == ProtocolType.TCP:
                    try:
                        ip_header = IPHeader.unpack(pkt.data[:20])
                        if ip_header.ttl <= 3:
                            fake_count += 1
                    except Exception:
                        pass

            self.logger.debug(f"🔍 Обнаружено {fake_count} фейковых пакетов")

        except Exception as e:
            self.logger.error(f"❌ Ошибка обнаружения фейковых пакетов: {e}")

        return fake_count

    def _detect_attacks(
        self,
        packets: List[RawPacket],
        split_positions: List[int],
        fake_packets: int,
        checksums: Dict[str, bool],
    ) -> List[str]:
        """
        Detects all component attacks in PCAP.

        Task 3.1: Detect all component attacks in combo strategies

        Returns:
            List of detected base attack names (e.g., ['split', 'fake'])

        Requirements: 2.1, 7.4
        """
        detected: List[str] = []

        try:
            # Detect split vs multisplit
            if split_positions:
                if len(split_positions) > 1:
                    detected.append("multisplit")
                else:
                    detected.append("split")

            # Detect fake attack
            if fake_packets > 0:
                detected.append("fake")

            # Detect disorder (packets out of order)
            if self._detect_disorder(packets):
                detected.append("disorder")

            # Detect seqovl (sequence overlap)
            if self._detect_sequence_overlap(packets):
                detected.append("seqovl")

            # Detect TTL manipulation
            if self._detect_ttl_manipulation(packets):
                if "ttl_manipulation" not in detected:
                    detected.append("ttl_manipulation")

            # Detect fooling methods (badsum, badseq, etc.)
            fooling_methods = self._detect_fooling_methods(packets, checksums)
            for method in fooling_methods:
                if method not in detected:
                    detected.append(method)

            self.logger.debug(f"🔍 Обнаружены базовые атаки: {detected}")

        except Exception as e:
            self.logger.error(f"❌ Ошибка обнаружения атак: {e}")

        return detected

    def _detect_disorder(self, packets: List[RawPacket]) -> bool:
        """
        Detects if packets are sent out of order (disorder attack).

        Disorder attack patterns:
        1. Non-monotonic sequence numbers for REAL packets (not fake)
        2. Reverse order pattern: larger segment sent before smaller segment

        IMPORTANT: This method now filters out fake packets to avoid false positives.
        Fake packets (low TTL, bad checksum) are expected to have same seq as real packets,
        which would otherwise trigger false disorder detection.
        """
        try:
            from core.packet.raw_packet_engine import IPHeader, TCPHeader

            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP and p.payload]
            if len(tcp_packets) < 2:
                return False

            # Filter out fake packets (low TTL or bad checksum) to avoid false positives
            real_packets_data: List[Tuple[int, int, int, int]] = (
                []
            )  # (seq_num, packet_idx, payload_size, ttl)
            for idx, pkt in enumerate(tcp_packets):
                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_data = pkt.data[ip_header_size:]
                    if len(tcp_data) >= 20:
                        tcp_header = TCPHeader.unpack(tcp_data)
                        tcp_header_size = tcp_header.data_offset * 4
                        payload_size = len(tcp_data) - tcp_header_size

                        # Skip fake packets (TTL <= 5 is typically fake)
                        if ip_header.ttl <= 5:
                            continue

                        if payload_size > 0:
                            real_packets_data.append(
                                (tcp_header.seq_num, idx, payload_size, ip_header.ttl)
                            )
                except Exception:
                    continue

            if len(real_packets_data) < 2:
                return False

            # Group by unique (seq, size) to handle retransmissions
            # Retransmissions have same seq and size, disorder has different sizes
            unique_segments: Dict[int, List[Tuple[int, int, int]]] = {}  # seq -> [(idx, size, ttl)]
            for seq, idx, size, ttl in real_packets_data:
                unique_segments.setdefault(seq, []).append((idx, size, ttl))

            # Check for disorder pattern: same seq but different sizes sent in reverse order
            for seq, entries in unique_segments.items():
                if len(entries) > 1:
                    # Multiple packets with same seq - check if they have different sizes
                    sizes = set(e[1] for e in entries)
                    if len(sizes) > 1:
                        # Different sizes with same seq = disorder (split + reorder)
                        self.logger.debug(
                            f"🔍 Disorder detected: seq={seq} has packets with different sizes: {sizes}"
                        )
                        return True

            # Check for reverse order pattern in sequence numbers
            # Only consider packets with different seq numbers
            seq_order = [(seq, idx) for seq, idx, size, ttl in real_packets_data]
            unique_seqs = []
            seen_seqs = set()
            for seq, idx in seq_order:
                if seq not in seen_seqs:
                    unique_seqs.append((seq, idx))
                    seen_seqs.add(seq)

            if len(unique_seqs) >= 2:
                # Check if sequence numbers are in reverse order
                seqs_only = [s[0] for s in unique_seqs]
                if seqs_only == sorted(seqs_only, reverse=True):
                    # All seqs in reverse order = disorder
                    self.logger.debug(
                        f"🔍 Disorder detected: sequence numbers in reverse order: {seqs_only}"
                    )
                    return True

                # Check for partial reverse order (first seq > second seq)
                first_seq = unique_seqs[0][0]
                second_seq = unique_seqs[1][0]
                if first_seq > second_seq:
                    self.logger.debug(
                        f"🔍 Disorder detected: first seq ({first_seq}) > second seq ({second_seq})"
                    )
                    return True

        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка обнаружения disorder: {e}")

        return False

    def _detect_sequence_overlap(self, packets: List[RawPacket]) -> bool:
        """
        Detects sequence overlap attack.

        IMPORTANT: This method now filters out fake packets to avoid false positives.
        Fake packets have the same seq as real packets, which would otherwise
        trigger false seqovl detection.

        True seqovl is when REAL packets have overlapping byte ranges with
        different content (intentional overlap for DPI confusion).
        """
        try:
            from core.packet.raw_packet_engine import IPHeader, TCPHeader

            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
            if len(tcp_packets) < 2:
                return False

            # Collect seq ranges only for REAL packets (TTL > 5)
            real_seq_ranges: List[Tuple[int, int, int]] = []  # (start, end, ttl)
            for pkt in tcp_packets:
                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ip_header_size = ip_header.ihl * 4
                    tcp_data = pkt.data[ip_header_size:]
                    if len(tcp_data) >= 20:
                        tcp_header = TCPHeader.unpack(tcp_data)
                        tcp_header_size = tcp_header.data_offset * 4
                        payload_size = len(tcp_data) - tcp_header_size

                        # Skip fake packets (TTL <= 5)
                        if ip_header.ttl <= 5:
                            continue

                        if payload_size > 0:
                            seq_start = tcp_header.seq_num
                            seq_end = seq_start + payload_size
                            real_seq_ranges.append((seq_start, seq_end, ip_header.ttl))
                except Exception:
                    continue

            if len(real_seq_ranges) < 2:
                return False

            # Check for overlapping ranges between REAL packets only
            # Exclude exact duplicates (retransmissions)
            for i in range(len(real_seq_ranges) - 1):
                for j in range(i + 1, len(real_seq_ranges)):
                    start1, end1, ttl1 = real_seq_ranges[i]
                    start2, end2, ttl2 = real_seq_ranges[j]

                    # Skip exact duplicates (retransmissions)
                    if start1 == start2 and end1 == end2:
                        continue

                    # Check for partial overlap (true seqovl)
                    if start1 < end2 and start2 < end1:
                        # Ensure it's not just adjacent segments
                        overlap_size = min(end1, end2) - max(start1, start2)
                        if overlap_size > 0:
                            self.logger.debug(
                                f"🔍 Seqovl detected: ranges [{start1}-{end1}] and [{start2}-{end2}] "
                                f"overlap by {overlap_size} bytes"
                            )
                            return True

        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка обнаружения seqovl: {e}")

        return False

    def _detect_ttl_manipulation(self, packets: List[RawPacket]) -> bool:
        """Detects TTL manipulation (low TTL values)."""
        try:
            from core.packet.raw_packet_engine import IPHeader

            low_ttl_count = 0
            ttl_observed = 0
            for pkt in packets:
                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ttl_observed += 1
                    if ip_header.ttl <= 5:
                        low_ttl_count += 1
                except Exception:
                    continue

            if ttl_observed == 0:
                return False

            # If >20% of packets have low TTL → likely TTL manipulation
            return low_ttl_count > ttl_observed * 0.2

        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка обнаружения TTL manipulation: {e}")

        return False

    def _detect_fooling_methods(
        self,
        packets: List[RawPacket],
        checksums: Dict[str, bool],
    ) -> List[str]:
        """
        Detects fooling methods (badsum, badseq, etc.).

        IMPORTANT: badseq detection now only considers REAL packets (TTL > 5).
        Fake packets intentionally have duplicate seq numbers, which is not badseq.
        True badseq is when real packets have intentionally bad sequence numbers.
        """
        methods: List[str] = []

        try:
            # badsum - detected from checksums validation
            invalid_checksums = sum(1 for v in checksums.values() if not v)
            if invalid_checksums > 0:
                methods.append("badsum")

            # badseq detection - only for REAL packets
            # Fake packets have same seq as real packets by design, that's not badseq
            from core.packet.raw_packet_engine import IPHeader, TCPHeader

            real_seq_numbers: List[int] = []
            for pkt in [p for p in packets if p.protocol == ProtocolType.TCP]:
                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])

                    # Skip fake packets (TTL <= 5)
                    if ip_header.ttl <= 5:
                        continue

                    ip_header_size = ip_header.ihl * 4
                    tcp_data = pkt.data[ip_header_size:]
                    if len(tcp_data) >= 20:
                        tcp_header = TCPHeader.unpack(tcp_data)
                        real_seq_numbers.append(tcp_header.seq_num)
                except Exception:
                    continue

            # badseq is when REAL packets have duplicate seq numbers
            # (not counting retransmissions which are normal)
            # For now, we don't detect badseq as it's hard to distinguish from retransmissions
            # and fake packets already handle the DPI confusion

        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка обнаружения fooling methods: {e}")

        return methods

    # ------------------------------------------------------------------ #
    # Извлечение параметров / TTL / комбо-логика
    # ------------------------------------------------------------------ #

    def _extract_all_parameters(
        self,
        packets: List[RawPacket],
        split_positions: List[int],
        sni_values: List[str],
        checksums: Dict[str, bool],
    ) -> Dict[str, Any]:
        """
        Extracts all non-null parameters from PCAP.

        COMBINED APPROACH:
        1. Groups packets by TCP flow (src_ip, src_port, dst_ip, dst_port)
        2. Analyzes each flow separately to find the "best" flow
        3. Extracts parameters from the best flow (most splits = successful strategy)

        This solves the problem of mixing packets from different flows/retries.

        Task 3.3: Extract split_pos, ttl, fooling_modes, etc.
        """
        parameters: Dict[str, Any] = {}

        try:
            # STEP 1: Group packets by TCP flow
            from collections import defaultdict

            flows = defaultdict(list)

            for pkt in packets:
                if pkt.protocol == ProtocolType.TCP:
                    # Create flow key (src -> dst direction)
                    flow_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
                    flows[flow_key].append(pkt)

            # STEP 2: Analyze each flow to find the "best" one
            best_flow_key = None
            max_splits = -1
            best_flow_splits = []

            self.logger.debug(f"🌊 Found {len(flows)} TCP flows in PCAP")

            for flow_key, flow_packets in flows.items():
                # Calculate split positions for this specific flow
                flow_splits = self.find_split_positions(flow_packets)

                # Heuristic: flow with most splits is likely the successful strategy
                if len(flow_splits) > max_splits:
                    max_splits = len(flow_splits)
                    best_flow_key = flow_key
                    best_flow_splits = flow_splits

                    self.logger.debug(
                        f"🌊 Flow {flow_key[0]}:{flow_key[1]} -> {flow_key[2]}:{flow_key[3]} "
                        f"has {len(flow_splits)} splits"
                    )

            # STEP 3: Use parameters from the best flow
            if best_flow_key:
                self.logger.info(
                    f"✅ Selected best flow: {best_flow_key[0]}:{best_flow_key[1]} -> "
                    f"{best_flow_key[2]}:{best_flow_key[3]} with {max_splits} splits"
                )
                split_positions = best_flow_splits

            # split_pos / positions (from best flow)
            if split_positions:
                parameters["split_positions"] = split_positions
                parameters["split_count"] = len(split_positions)

                if len(split_positions) == 1:
                    parameters["split_pos"] = split_positions[0]
                elif len(split_positions) > 1:
                    parameters["split_pos"] = split_positions[0]
                    parameters["positions"] = split_positions

            # TTL values
            ttl_values = self._extract_ttl_values(packets)
            if ttl_values:
                from collections import Counter

                ttl_counter = Counter(ttl_values)
                most_common_ttl = ttl_counter.most_common(1)[0][0]
                parameters["ttl"] = most_common_ttl

                low_ttls = [ttl for ttl in ttl_values if ttl <= 5]
                if low_ttls:
                    parameters["fake_ttl"] = min(low_ttls)

            # fooling modes (badsum, badseq - NOT disorder, which is a separate attack)
            fooling_modes: List[str] = []
            invalid_checksums = sum(1 for v in checksums.values() if not v)
            if invalid_checksums > 0:
                fooling_modes.append("badsum")
            # Note: disorder is NOT a fooling mode, it's a separate attack type
            # Don't add it to fooling_modes
            if fooling_modes:
                parameters["fooling"] = fooling_modes
                parameters["fooling_modes"] = fooling_modes

            # SNI values
            if sni_values:
                parameters["sni_values"] = sni_values
                if len(sni_values) == 1:
                    parameters["sni"] = sni_values[0]

            # Packet count / bytes
            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
            if tcp_packets:
                parameters["packet_count"] = len(tcp_packets)
                parameters["total_bytes"] = sum(len(p.data) for p in tcp_packets)

            non_null_params = {k: v for k, v in parameters.items() if v is not None}
            self.logger.debug(f"🔍 Извлечено параметров: {len(non_null_params)}")
            for key, value in non_null_params.items():
                self.logger.debug(f"  - {key}: {value}")

        except Exception as e:
            self.logger.error(f"❌ Ошибка извлечения параметров: {e}")

        return parameters

    def _extract_ttl_values(self, packets: List[RawPacket]) -> List[int]:
        """Extracts TTL values from IP headers."""
        ttl_values: List[int] = []

        try:
            from core.packet.raw_packet_engine import IPHeader

            for pkt in packets:
                try:
                    ip_header = IPHeader.unpack(pkt.data[:20])
                    ttl_values.append(ip_header.ttl)
                except Exception:
                    continue

        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка извлечения TTL: {e}")

        return ttl_values

    def _determine_strategy_type_from_attacks(
        self,
        detected_attacks: List[str],
    ) -> Tuple[Optional[str], List[str]]:
        """
        Determines strategy type and combo attack list from detected attacks.

        Возвращает:
            (strategy_type, combo_attacks)

        strategy_type может быть:
        - одиночной атакой: "fake", "multisplit", ...
        - комбинированной: "fakeddisorder" (fake+disorder без split),
        - combo-стратегией: "smart_combo_fake_multisplit_disorder", и т.п.

        Edge case handling (Task 4.1, Requirements 7.1, 7.2):
        - Empty detected_attacks list → return (None, [])
        - None detected_attacks → return (None, [])
        - Only fooling attacks → return (first_attack, [])
        """
        # Task 4.1: Handle None detected_attacks → return (None, [])
        if detected_attacks is None:
            self.logger.warning("⚠️ Edge case: detected_attacks is None, returning (None, [])")
            return None, []

        # Task 4.1: Handle empty detected_attacks list → return (None, [])
        if not detected_attacks:
            self.logger.debug("⚠️ Edge case: empty detected_attacks list, returning (None, [])")
            return None, []

        # Отфильтровываем fooling/low-level теги
        main_attacks = [a for a in detected_attacks if a not in FOOLING_LABELS]

        # Task 4.1: Handle only fooling attacks → return (first_attack, [])
        if not main_attacks:
            # только fooling-методы → возвращаем первый из полного списка
            self.logger.warning(
                f"⚠️ Edge case: only fooling attacks detected {detected_attacks}, "
                f"returning ({detected_attacks[0]}, [])"
            )
            return detected_attacks[0], []

        # Убираем дубликаты, сохраняя относительный порядок
        unique_main: List[str] = []
        for a in main_attacks:
            if a not in unique_main:
                unique_main.append(a)

        # Сортируем по приоритету (для детерминированного имени)
        ordered = sorted(
            unique_main,
            key=lambda x: CORE_ATTACKS_ORDER.get(x, 99),
        )

        # Специальный случай: fake + disorder → fakeddisorder
        if set(ordered) == {"fake", "disorder"}:
            return "fakeddisorder", ordered

        # Общий случай combo: несколько основных атак
        if len(ordered) > 1:
            combo_name = "smart_combo_" + "_".join(ordered)
            return combo_name, ordered

        # Единственная основная атака
        return ordered[0], ordered

    # legacy helper (можно оставить для совместимости, но не используется)
    def _determine_strategy_type(
        self,
        packets: List[RawPacket],
        split_positions: List[int],
        sni_values: List[str],
    ) -> Optional[str]:
        """Определяет тип стратегии по пакетам (legacy, не используется)."""
        try:
            if split_positions:
                return "multisplit" if len(split_positions) > 1 else "split"
            if sni_values and len(set(sni_values)) > 1:
                return "sni_change"
            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
            tcp_with_payload = [p for p in packets if p.protocol == ProtocolType.TCP and p.payload]
            if len(tcp_packets) > len(tcp_with_payload):
                return "fake"
            return None
        except Exception as e:
            self.logger.error(f"❌ Ошибка определения типа стратегии: {e}")
            return None

    # ------------------------------------------------------------------ #
    # Аномалии и similarity
    # ------------------------------------------------------------------ #

    def _find_anomalies(
        self,
        packets: List[RawPacket],
        checksums: Dict[str, bool],
    ) -> List[str]:
        """Находит аномалии в пакетах."""
        anomalies: List[str] = []

        try:
            from core.packet.raw_packet_engine import TCPHeader, IPHeader

            invalid_checksums = [k for k, v in checksums.items() if not v]
            if invalid_checksums:
                anomalies.append(f"Invalid checksums in {len(invalid_checksums)} packets")

            # Дубликаты пакетов
            packet_hashes: Set[int] = set()
            duplicates = 0
            for pkt in packets:
                h = hash(pkt.data)
                if h in packet_hashes:
                    duplicates += 1
                packet_hashes.add(h)
            if duplicates > 0:
                anomalies.append(f"Found {duplicates} duplicate packets")

            # Out-of-order
            tcp_packets = [p for p in packets if p.protocol == ProtocolType.TCP]
            if len(tcp_packets) > 1:
                seq_numbers: List[int] = []
                for pkt in tcp_packets:
                    try:
                        ip_header = IPHeader.unpack(pkt.data[:20])
                        ip_header_size = ip_header.ihl * 4
                        tcp_data = pkt.data[ip_header_size:]
                        if len(tcp_data) >= 20:
                            tcp_header = TCPHeader.unpack(tcp_data)
                            seq_numbers.append(tcp_header.seq_num)
                    except Exception:
                        continue
                if seq_numbers and seq_numbers != sorted(seq_numbers):
                    anomalies.append("Out-of-order TCP packets detected")

        except Exception as e:
            self.logger.error(f"❌ Ошибка поиска аномалий: {e}")

        return anomalies

    def _calculate_similarity(
        self,
        analysis: StrategyAnalysisResult,
        expected: Dict[str, Any],
    ) -> float:
        """Вычисляет similarity score между анализом и ожидаемой стратегией."""
        score = 0.0
        checks = 0

        # Strategy type
        expected_type = expected.get("attack", expected.get("type"))
        if expected_type:
            checks += 1
            if analysis.strategy_type == expected_type:
                score += 1.0

        # split_pos
        expected_split = expected.get("params", {}).get("split_pos")
        if expected_split:
            checks += 1
            if isinstance(expected_split, str) and expected_split.isdigit():
                expected_split = int(expected_split)
            if expected_split in analysis.split_positions:
                score += 1.0

        # SNI
        expected_sni = expected.get("params", {}).get("sni")
        if expected_sni:
            checks += 1
            if expected_sni in analysis.sni_values:
                score += 1.0

        # attacks combo
        expected_attacks = expected.get("attacks")
        if expected_attacks:
            checks += 1
            if set(expected_attacks) == set(analysis.combo_attacks or analysis.detected_attacks):
                score += 1.0

        return score / checks if checks > 0 else 0.0

    def _calculate_pcap_similarity(
        self,
        testing: StrategyAnalysisResult,
        service: StrategyAnalysisResult,
    ) -> float:
        """Вычисляет similarity score между двумя PCAP анализами."""
        score = 0.0
        checks = 0

        # strategy_type
        checks += 1
        if testing.strategy_type == service.strategy_type:
            score += 1.0

        # split_positions
        if testing.split_positions or service.split_positions:
            checks += 1
            if set(testing.split_positions) == set(service.split_positions):
                score += 1.0

        # sni_values
        if testing.sni_values or service.sni_values:
            checks += 1
            if set(testing.sni_values) == set(service.sni_values):
                score += 1.0

        # packet_count (10% tolerance)
        if testing.packet_count > 0 and service.packet_count > 0:
            checks += 1
            ratio = min(testing.packet_count, service.packet_count) / max(
                testing.packet_count, service.packet_count
            )
            if ratio >= 0.9:
                score += 1.0

        return score / checks if checks > 0 else 0.0

    def _get_cache_key(
        self,
        pcap_file: str,
        test_start_time: Optional[float] = None,
        strategy_name: Optional[str] = None,
    ) -> str:
        """
        Генерирует ключ кэша для PCAP файла.

        Args:
            pcap_file: Путь к PCAP файлу
            test_start_time: Timestamp начала теста (для уникального кэша на тест)
            strategy_name: Имя стратегии (для уникального кэша на стратегию)

        Returns:
            MD5 хэш ключа кэша
        """
        import hashlib

        file_path = Path(pcap_file)
        file_stat = file_path.stat() if file_path.exists() else None
        key_data = f"{pcap_file}:{file_stat.st_mtime if file_stat else 0}:{test_start_time}:{strategy_name}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def clear_cache(self) -> None:
        """Очищает кэш анализа."""
        self.analysis_cache.clear()
        self.logger.info("🧹 Кэш анализа очищен")

    def load_operation_log(self, strategy_id: str) -> Optional[List[Dict[str, Any]]]:
        """
        Загружает operation log для заданного strategy_id.

        Args:
            strategy_id: Уникальный идентификатор стратегии

        Returns:
            Список операций (сегментов) или None если лог не найден
        """
        try:
            from core.operation_logger import get_operation_logger

            operation_logger = get_operation_logger()

            # Получаем путь к файлу лога для данной стратегии
            log_dir = Path("data/operation_logs")
            log_file = log_dir / f"{strategy_id}.json"

            if not log_file.exists():
                self.logger.warning(f"⚠️ Operation log not found: {log_file}")
                return None

            # Читаем JSON файл
            import json

            with open(log_file, "r", encoding="utf-8") as f:
                log_data = json.load(f)

            # Извлекаем операции типа "segment"
            operations = log_data.get("operations", [])
            segments = [op for op in operations if op.get("operation_type") == "segment"]

            self.logger.info(f"✅ Loaded {len(segments)} segment operations from {log_file}")
            return segments

        except ImportError:
            self.logger.warning("⚠️ operation_logger not available")
            return None
        except Exception as e:
            self.logger.error(f"❌ Failed to load operation log: {e}", exc_info=True)
            return None

    def compare_pcap_with_operation_log(
        self,
        pcap_file: str,
        strategy_id: str,
    ) -> Dict[str, Any]:
        """
        Сравнивает PCAP с operation log для валидации отправленных сегментов.

        Проверяет:
        - Количество сегментов (PCAP vs log)
        - Последовательность FAKE/REAL
        - TTL значения
        - Flags значения
        - Seq/Ack номера (если доступны)

        Args:
            pcap_file: Путь к PCAP файлу
            strategy_id: ID стратегии для загрузки operation log

        Returns:
            Словарь с результатами сравнения:
            {
                "match": bool,  # Полное совпадение
                "pcap_segments": int,  # Количество сегментов в PCAP
                "log_segments": int,  # Количество сегментов в логе
                "differences": List[str],  # Список расхождений
                "details": Dict[str, Any]  # Детальная информация
            }
        """
        result = {
            "match": False,
            "pcap_segments": 0,
            "log_segments": 0,
            "differences": [],
            "details": {},
        }

        try:
            # Загружаем operation log
            log_segments = self.load_operation_log(strategy_id)
            if log_segments is None:
                result["differences"].append("Operation log not found or empty")
                return result

            result["log_segments"] = len(log_segments)

            # Читаем PCAP
            if not Path(pcap_file).exists():
                result["differences"].append(f"PCAP file not found: {pcap_file}")
                return result

            packets = self.pcap_reader.read_pcap(pcap_file)
            if not packets:
                result["differences"].append("PCAP file is empty")
                return result

            # Фильтруем только TCP пакеты с payload (отправленные сегменты)
            tcp_segments = []
            for pkt_data, timestamp in packets:
                parsed = self.packet_engine.parse_packet(pkt_data)
                if parsed and parsed.protocol == ProtocolType.TCP and parsed.payload:
                    tcp_segments.append(parsed)

            result["pcap_segments"] = len(tcp_segments)

            # Сравниваем количество
            if len(tcp_segments) != len(log_segments):
                result["differences"].append(
                    f"Segment count mismatch: PCAP={len(tcp_segments)}, Log={len(log_segments)}"
                )

            # Детальное сравнение сегментов
            mismatches = []
            for i in range(min(len(tcp_segments), len(log_segments))):
                pcap_seg = tcp_segments[i]
                log_seg = log_segments[i]

                seg_diff = []

                # Проверяем TTL
                log_ttl = log_seg.get("parameters", {}).get("ttl")
                if log_ttl is not None and pcap_seg.ttl != log_ttl:
                    seg_diff.append(f"TTL: PCAP={pcap_seg.ttl}, Log={log_ttl}")

                # Проверяем flags
                log_flags = log_seg.get("parameters", {}).get("flags")
                if log_flags is not None and pcap_seg.tcp_flags != log_flags:
                    seg_diff.append(
                        f"Flags: PCAP=0x{pcap_seg.tcp_flags:02X}, Log=0x{log_flags:02X}"
                    )

                # Проверяем is_fake (по TTL < 64 или bad checksum)
                log_is_fake = log_seg.get("parameters", {}).get("is_fake", False)
                pcap_is_fake = pcap_seg.ttl < 64  # Простая эвристика
                if log_is_fake != pcap_is_fake:
                    seg_diff.append(f"is_fake: PCAP={pcap_is_fake}, Log={log_is_fake}")

                # Проверяем payload length
                log_payload_len = log_seg.get("parameters", {}).get("payload_len", 0)
                pcap_payload_len = len(pcap_seg.payload) if pcap_seg.payload else 0
                if log_payload_len != pcap_payload_len:
                    seg_diff.append(
                        f"Payload length: PCAP={pcap_payload_len}, Log={log_payload_len}"
                    )

                if seg_diff:
                    mismatches.append({"segment_index": i + 1, "differences": seg_diff})

            # Добавляем расхождения в результат
            if mismatches:
                result["differences"].append(f"Found {len(mismatches)} segment mismatches")
                result["details"]["segment_mismatches"] = mismatches

            # Определяем итоговый результат
            result["match"] = len(result["differences"]) == 0

            if result["match"]:
                self.logger.info(
                    f"✅ PCAP matches operation log perfectly: {len(tcp_segments)} segments"
                )
            else:
                self.logger.warning(
                    f"⚠️ PCAP vs operation log differences: {len(result['differences'])} issues"
                )
                for diff in result["differences"]:
                    self.logger.warning(f"   - {diff}")

            return result

        except Exception as e:
            self.logger.error(f"❌ Failed to compare PCAP with operation log: {e}", exc_info=True)
            result["differences"].append(f"Comparison error: {str(e)}")
            return result
