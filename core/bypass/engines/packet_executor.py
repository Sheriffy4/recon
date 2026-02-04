"""
Интеллектуальный исполнитель пакетов, который транслирует
результаты атак в реальные сетевые пакеты с помощью PacketBuilder.
"""

import pydivert
import logging
import random
import time
from typing import Tuple, Dict, Any, Union
from core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from core.packet_builder import EnhancedPacketBuilder
from core.windivert_filter import WinDivertFilterGenerator

LOG = logging.getLogger("PacketExecutor")


class IntelligentPacketExecutor:
    """
    Исполняет отправку пакетов, описанных в AttackResult,
    интерпретируя метаданные для точной сборки пакетов.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.packet_builder = EnhancedPacketBuilder()
        self._filter_gen = WinDivertFilterGenerator()

    def execute_attack_session(self, context: AttackContext, result: AttackResult) -> bool:
        """
        Открывает сессию pydivert и отправляет все пакеты, описанные в AttackResult.

        Args:
            context: Контекст атаки с информацией о соединении.
            result: Результат атаки с сегментами и метаданными.

        Returns:
            True в случае успешной отправки, False в случае ошибки.
        """
        # Use the public API (property) to avoid bypassing AttackResult validation logic.
        segments = result.segments
        if result.status != AttackStatus.SUCCESS or not segments:
            LOG.debug("Нет сегментов для отправки или атака не была успешной.")
            return False
        filter_str = self._filter_gen.generate(
            target_ports=[context.dst_port],
            direction="outbound",
            protocols=("tcp",),
        )
        try:
            try:
                w = pydivert.WinDivert(filter_str)
                w.open()
            except Exception as e:
                LOG.warning(f"Failed to create WinDivert handle with filter '{filter_str}': {e}")
                simple_filter = "outbound and tcp"
                LOG.info(f"Trying simplified filter: {simple_filter}")
                w = pydivert.WinDivert(simple_filter)
                w.open()
            try:
                base_seq = context.seq or 0
                base_ack = context.ack or 0
                for i, segment_info in enumerate(segments):
                    segment_data, seq_offset, delay_ms, options = self._parse_segment_info(
                        segment_info
                    )
                    if delay_ms and delay_ms > 0:
                        time.sleep(float(delay_ms) / 1000.0)
                    packet_params = {
                        "src_ip": context.src_ip or "127.0.0.1",
                        "dst_ip": context.dst_ip,
                        "src_port": context.src_port or random.randint(49152, 65535),
                        "dst_port": context.dst_port,
                        "seq": (base_seq + seq_offset) & 0xFFFFFFFF,
                        "ack": base_ack,
                        "flags": "PA" if i == len(segments) - 1 else "A",
                        "payload": segment_data,
                    }
                    packet_mods = options.get("packet_mods", {})
                    if "bad_checksum" in packet_mods:
                        packet_params["override_tcp_checksum"] = 57005
                    if options:
                        packet_params["ttl"] = options.get("ttl", 64)
                        packet_params["ip_id"] = options.get("ip_id", 0)
                        packet_params["tcp_options"] = options.get("tcp_options", b"")
                        if "bad_checksum" in options:
                            packet_params["override_tcp_checksum"] = options["bad_checksum"]
                        if "seq_increment" in options:
                            packet_params["seq"] = (
                                (packet_params["seq"] + int(options["seq_increment"])) & 0xFFFFFFFF
                            )
                        if "md5_signature" in options:
                            packet_params["tcp_options"] += options["md5_signature"]
                    packet_result = self.packet_builder.create_tcp_packet(**packet_params)
                    if packet_result is None:
                        LOG.warning(f"PacketBuilder returned None for segment {i + 1}")
                        continue
                    if hasattr(packet_result, "build"):
                        packet_bytes = bytes(packet_result.build())
                    elif isinstance(packet_result, bytes):
                        packet_bytes = packet_result
                    else:
                        LOG.warning(f"Unknown packet type: {type(packet_result)}")
                        continue
                    pydivert_packet = pydivert.Packet(
                        packet_bytes, (0, 0), pydivert.Direction.OUTBOUND
                    )
                    w.send(pydivert_packet)
                    LOG.debug(
                        f"Отправлен сегмент {i + 1}/{len(segments)} размером {len(segment_data)} байт."
                    )
                return True
            finally:
                w.close()
        except Exception as e:
            LOG.error(f"Критическая ошибка при отправке пакетов: {type(e).__name__}: {str(e)}")
            LOG.error(f"Полная информация об ошибке: {repr(e)}")
            LOG.error(
                "Возможные причины: отсутствуют права администратора или проблема с драйвером WinDivert."
            )
            import traceback

            LOG.debug(f"Traceback: {traceback.format_exc()}")
            return False

    def _parse_segment_info(
        self, segment_info: Union[tuple, bytes]
    ) -> Tuple[bytes, int, int, Dict[str, Any]]:
        """
        Парсит информацию о сегменте в унифицированный формат.
        Возвращает: (data, seq_offset, delay_ms, options_dict)
        """
        # bytes-like segment: payload only
        if isinstance(segment_info, (bytes, bytearray, memoryview)):
            return (bytes(segment_info), 0, 0, {})

        if isinstance(segment_info, tuple):
            if len(segment_info) == 0:
                return (b"", 0, 0, {})

            data = segment_info[0]
            if not isinstance(data, (bytes, bytearray, memoryview)):
                return (b"", 0, 0, {})
            data_b = bytes(data)

            # Canonical SegmentTuple: (payload: bytes, seq_offset: int, options: dict)
            seq_offset = 0
            delay_ms = 0
            options: Dict[str, Any] = {}

            if len(segment_info) == 1:
                return (data_b, 0, 0, {})

            # (data, seq_offset)
            if len(segment_info) == 2:
                second = segment_info[1]
                if isinstance(second, dict):
                    options = second
                    seq_offset = int(options.get("seq_offset", 0) or 0)
                    delay_ms = int(options.get("delay_ms", 0) or 0)
                else:
                    try:
                        seq_offset = int(second or 0)
                    except Exception:
                        seq_offset = 0
                return (data_b, seq_offset, delay_ms, options)

            # (data, seq_offset, options_dict) OR (data, seq_offset, delay_ms)
            if len(segment_info) == 3:
                second = segment_info[1]
                third = segment_info[2]
                try:
                    seq_offset = int(second or 0)
                except Exception:
                    seq_offset = 0

                if isinstance(third, dict):
                    options = third
                    delay_ms = int(options.get("delay_ms", 0) or 0)
                else:
                    try:
                        delay_ms = int(third or 0)
                    except Exception:
                        delay_ms = 0
                return (data_b, seq_offset, delay_ms, options)

            # tolerate legacy extended: (data, seq_offset, delay_ms, options_dict)
            second = segment_info[1]
            third = segment_info[2]
            fourth = segment_info[3] if len(segment_info) >= 4 else {}
            try:
                seq_offset = int(second or 0)
            except Exception:
                seq_offset = 0
            try:
                delay_ms = int(third or 0)
            except Exception:
                delay_ms = 0
            if isinstance(fourth, dict):
                options = fourth
                # options delay overrides explicit delay if provided
                try:
                    delay_ms = int(options.get("delay_ms", delay_ms) or delay_ms)
                except Exception:
                    pass
            return (data_b, seq_offset, delay_ms, options)

        LOG.warning(f"Неизвестный формат сегмента: {type(segment_info)}. Пропускаем.")
        return (b"", 0, 0, {})
