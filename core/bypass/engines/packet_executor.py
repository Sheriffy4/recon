"""
Интеллектуальный исполнитель пакетов, который транслирует
результаты атак в реальные сетевые пакеты с помощью PacketBuilder.
"""
import pydivert
import logging
import random
from typing import Tuple, Dict, Any, Union
from recon.core.bypass.attacks.base import AttackResult, AttackStatus, AttackContext
from recon.core.packet_builder import EnhancedPacketBuilder
from core.windivert_filter import WinDivertFilterGenerator
LOG = logging.getLogger('PacketExecutor')

class IntelligentPacketExecutor:
    """
    Исполняет отправку пакетов, описанных в AttackResult,
    интерпретируя метаданные для точной сборки пакетов.
    """

    def __init__(self, debug: bool=False):
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
        if result.status != AttackStatus.SUCCESS or not result.metadata.get('segments'):
            LOG.debug('Нет сегментов для отправки или атака не была успешной.')
            return False
        segments = result.metadata['segments']
        try:
            normalized_ip = self._filter_gen.normalize_ip(context.dst_ip)
        except Exception:
            normalized_ip = context.dst_ip
        filter_str = self._filter_gen.generate(target_ips=[normalized_ip], target_ports=[context.dst_port], direction='outbound', protocols=('tcp',))
        try:
            try:
                w = pydivert.WinDivert(filter_str)
                w.open()
            except Exception as e:
                LOG.warning(f"Failed to create WinDivert handle with filter '{filter_str}': {e}")
                simple_filter = 'outbound and tcp'
                LOG.info(f'Trying simplified filter: {simple_filter}')
                w = pydivert.WinDivert(simple_filter)
                w.open()
            try:
                base_seq = context.seq or 0
                base_ack = context.ack or 0
                for i, segment_info in enumerate(segments):
                    segment_data, seq_offset, delay_ms, options = self._parse_segment_info(segment_info)
                    packet_params = {'src_ip': context.src_ip or '127.0.0.1', 'dst_ip': context.dst_ip, 'src_port': context.src_port or random.randint(49152, 65535), 'dst_port': context.dst_port, 'seq': base_seq + seq_offset & 4294967295, 'ack': base_ack, 'flags': 'PA' if i == len(segments) - 1 else 'A', 'payload': segment_data}
                    packet_mods = options.get('packet_mods', {})
                    if 'bad_checksum' in packet_mods:
                        packet_params['override_tcp_checksum'] = 57005
                    if options:
                        packet_params['ttl'] = options.get('ttl', 64)
                        packet_params['ip_id'] = options.get('ip_id', 0)
                        packet_params['tcp_options'] = options.get('tcp_options', b'')
                        if 'bad_checksum' in options:
                            packet_params['override_tcp_checksum'] = options['bad_checksum']
                        if 'seq_increment' in options:
                            packet_params['seq'] = packet_params['seq'] + options['seq_increment'] & 4294967295
                        if 'md5_signature' in options:
                            packet_params['tcp_options'] += options['md5_signature']
                    packet_result = self.packet_builder.create_tcp_packet(**packet_params)
                    if packet_result is None:
                        LOG.warning(f'PacketBuilder returned None for segment {i + 1}')
                        continue
                    if hasattr(packet_result, 'build'):
                        packet_bytes = bytes(packet_result.build())
                    elif isinstance(packet_result, bytes):
                        packet_bytes = packet_result
                    else:
                        LOG.warning(f'Unknown packet type: {type(packet_result)}')
                        continue
                    pydivert_packet = pydivert.Packet(packet_bytes, (0, 0), pydivert.Direction.OUTBOUND)
                    w.send(pydivert_packet)
                    LOG.debug(f'Отправлен сегмент {i + 1}/{len(segments)} размером {len(segment_data)} байт.')
                return True
            finally:
                w.close()
        except Exception as e:
            LOG.error(f'Критическая ошибка при отправке пакетов: {type(e).__name__}: {str(e)}')
            LOG.error(f'Полная информация об ошибке: {repr(e)}')
            LOG.error('Возможные причины: отсутствуют права администратора или проблема с драйвером WinDivert.')
            import traceback
            LOG.debug(f'Traceback: {traceback.format_exc()}')
            return False

    def _parse_segment_info(self, segment_info: Union[tuple, bytes]) -> Tuple[bytes, int, int, Dict[str, Any]]:
        """
        Парсит информацию о сегменте в унифицированный формат.
        Возвращает: (data, seq_offset, delay_ms, options_dict)
        """
        if isinstance(segment_info, bytes):
            return (segment_info, 0, 0, {})
        if isinstance(segment_info, tuple):
            data = segment_info[0]
            offset_or_delay = segment_info[1] if len(segment_info) > 1 else 0
            options = segment_info[2] if len(segment_info) > 2 else {}
            seq_offset = offset_or_delay
            delay_ms = options.get('delay_ms', 0)
            packet_mods = options.get('packet_mods', {})
            return (data, seq_offset, delay_ms, options)
        LOG.warning(f'Неизвестный формат сегмента: {type(segment_info)}. Пропускаем.')
        return (b'', 0, 0, {})