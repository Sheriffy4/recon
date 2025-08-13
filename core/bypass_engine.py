#!/usr/bin/env python3
"""
Центральный движок обхода DPI, основанный на рабочей реализации из final_packet_bypass.py.
Этот движок является универсальным и может быть использован как для тестирования стратегий,
так и для постоянной работы в качестве системной службы.
"""

import pydivert
import time
import threading
import logging
import socket
import struct
import random
from typing import List, Dict, Any, Optional, Tuple, Set

# =================================================================================
# Класс с "атомарными" техниками обхода.
# =================================================================================
class BypassTechniques:
    """Библиотека продвинутых техник обхода DPI."""

    @staticmethod
    def apply_fakeddisorder(payload: bytes, split_pos: int = 3) -> List[Tuple[bytes, int]]:
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1, part2 = payload[:split_pos], payload[split_pos:]
        return [(part2, split_pos), (part1, 0)]

    @staticmethod
    def apply_multisplit(payload: bytes, positions: List[int]) -> List[Tuple[bytes, int]]:
        if not positions:
            return [(payload, 0)]
        segments, last_pos = [], 0
        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos))
                last_pos = pos
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos))
        return segments

    @staticmethod
    def apply_multidisorder(payload: bytes, positions: List[int]) -> List[Tuple[bytes, int]]:
        segments = BypassTechniques.apply_multisplit(payload, positions)
        return segments[::-1] if len(segments) > 1 else segments

    @staticmethod
    def apply_seqovl(payload: bytes, split_pos: int = 3, overlap_size: int = 10) -> List[Tuple[bytes, int]]:
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1, part2 = payload[:split_pos], payload[split_pos:]
        overlap_data = b'\x00' * overlap_size
        part1_with_overlap = overlap_data + part1
        return [(part2, split_pos), (part1_with_overlap, -overlap_size)]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        if split_pos >= len(payload) or split_pos < 5:
            return payload
        tls_data = payload[5:] if payload.startswith(b'\x16\x03\x01') else payload
        part1, part2 = tls_data[:split_pos], tls_data[split_pos:]
        record1 = b'\x16\x03\x01' + len(part1).to_bytes(2, 'big') + part1
        record2 = b'\x16\x03\x01' + len(part2).to_bytes(2, 'big') + part2
        return record1 + record2

    @staticmethod
    def apply_wssize_limit(payload: bytes, window_size: int = 1) -> List[Tuple[bytes, int]]:
        segments, pos = [], 0
        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos:pos + chunk_size]
            segments.append((chunk, pos))
            pos += chunk_size
        return segments

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos:tcp_checksum_pos+2] = struct.pack('!H', 0xdead)
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos:tcp_checksum_pos+2] = struct.pack('!H', 0xbeef)
        return packet_data

# =================================================================================
# Основной класс движка обхода.
# =================================================================================
class BypassEngine:
    def __init__(self, debug=True):
        self.debug = debug
        self.running = False
        self.techniques = BypassTechniques()
        self.logger = logging.getLogger("BypassEngine")
        if debug:
            # Устанавливаем уровень логирования и обработчик, если их нет
            if self.logger.level == logging.NOTSET:
                self.logger.setLevel(logging.DEBUG)
            if not any(isinstance(h, logging.StreamHandler) for h in self.logger.handlers):
                 logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)-7s] %(name)s: %(message)s')

        self.stats = {'packets_captured': 0, 'tls_packets_bypassed': 0, 'fragments_sent': 0, 'fake_packets_sent': 0}
        self.cloudflare_prefixes = ('104.', '172.64.', '172.67.', '162.158.', '162.159.')

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        """Запускает движок обхода в отдельном потоке."""
        self.running = True
        self.logger.info("🚀 Запуск универсального движка обхода DPI...")
        thread = threading.Thread(target=self._run_bypass_loop, args=(target_ips, strategy_map), daemon=True)
        thread.start()
        return thread
    
    def start_with_config(self, config: dict):
        """Запускает движок обхода с упрощенной конфигурацией для службы."""
        # Создаем стратегию на основе конфигурации
        strategy_task = self._config_to_strategy_task(config)
        
        # Используем универсальные целевые IP (все Cloudflare и популярные CDN)
        target_ips = set()
        
        # Создаем карту стратегий с default стратегией для всех IP
        strategy_map = {'default': strategy_task}
        
        self.logger.info(f"🚀 Starting service mode with strategy: {strategy_task}")
        
        return self.start(target_ips, strategy_map)
    
    def _config_to_strategy_task(self, config: dict) -> dict:
        """Конвертирует упрощенную конфигурацию в задачу стратегии."""
        desync_method = config.get('desync_method', 'fake')
        
        # Определяем тип задачи на основе метода
        if desync_method == 'multisplit':
            task_type = 'multisplit'
            params = {
                'positions': [1, config.get('split_pos', 3), config.get('split_pos', 3) + 5]
            }
            if 'split_count' in config:
                # Создаем позиции на основе количества разбиений
                split_count = config['split_count']
                positions = [i * 2 + 1 for i in range(split_count)]
                params['positions'] = positions
        
        elif desync_method == 'fake' or desync_method == 'fakeddisorder':
            if config.get('fooling') == 'badsum':
                task_type = 'badsum_race'
            elif config.get('fooling') == 'md5sig':
                task_type = 'md5sig_race'
            else:
                task_type = 'fakedisorder'
            params = {
                'split_pos': config.get('split_pos', 3),
                'ttl': config.get('ttl', 3)
            }
        
        elif desync_method == 'seqovl':
            task_type = 'seqovl'
            params = {
                'split_pos': config.get('split_pos', 3),
                'overlap_size': config.get('overlap_size', 10),
                'ttl': config.get('ttl', 3)
            }
        
        else:
            # Fallback к простой стратегии
            task_type = 'fakedisorder'
            params = {
                'split_pos': config.get('split_pos', 3),
                'ttl': config.get('ttl', 3)
            }
        
        return {
            'type': task_type,
            'params': params
        }

    def stop(self):
        """Останавливает движок обхода."""
        self.running = False
        self.logger.info("🛑 Остановка движка обхода DPI...")

    def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
        """
        ИСПРАВЛЕНИЕ: Проверяет, является ли IP-адрес целью для обхода.
        Теперь проверка на Cloudflare работает всегда, а не только если в target_ips уже есть IP оттуда.
        """
        if ip_str in target_ips:
            return True
        
        # Если target_ips пустой (режим службы), применяем обход ко всем подозрительным IP
        if not target_ips:
            # В режиме службы применяем обход к популярным CDN и хостингам
            suspicious_prefixes = (
                '104.',      # Cloudflare
                '172.64.',   # Cloudflare
                '172.67.',   # Cloudflare  
                '162.158.',  # Cloudflare
                '162.159.',  # Cloudflare
                '185.199.',  # GitHub Pages
                '151.101.',  # Fastly
                '199.232.',  # Akamai
                '23.', '104.', '185.'  # Другие популярные CDN
            )
            if ip_str.startswith(suspicious_prefixes):
                self.logger.debug(f"IP {ip_str} соответствует подозрительному префиксу, применяем обход.")
                return True
        
        # Всегда проверяем на принадлежность к известным подсетям, так как CDN могут резолвить разные IP
        if ip_str.startswith(self.cloudflare_prefixes):
            self.logger.debug(f"IP {ip_str} соответствует префиксу Cloudflare, применяем обход.")
            return True
            
        return False

    def _resolve_midsld_pos(self, payload: bytes) -> Optional[int]:
        """Находит позицию середины домена второго уровня в SNI."""
        try:
            # Ищем начало SNI расширения (type = 0x0000)
            pos = payload.find(b'\x00\x00')
            while pos != -1:
                # Проверяем, что это действительно начало расширения
                if pos + 9 < len(payload):
                    ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                    list_len = int.from_bytes(payload[pos+4:pos+6], 'big')
                    name_type = payload[pos+6]

                    if name_type == 0 and ext_len == list_len + 2 and list_len > 0:
                        name_len = int.from_bytes(payload[pos+7:pos+9], 'big')
                        name_start = pos + 9
                        if name_start + name_len <= len(payload):
                            domain_bytes = payload[name_start : name_start + name_len]
                            # ИСПРАВЛЕНИЕ: Используем 'strict' вместо 'ignore' для большей точности
                            domain_str = domain_bytes.decode('idna', errors='strict')
                            parts = domain_str.split('.')
                            if len(parts) >= 2:
                                sld_start_in_domain = domain_str.rfind(parts[-2])
                                sld_mid_pos = sld_start_in_domain + len(parts[-2]) // 2
                                return name_start + sld_mid_pos
                pos = payload.find(b'\x00\x00', pos + 1)
        except Exception as e:
            self.logger.debug(f"Error resolving midsld: {e}")
        return None
    
    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        """Основной цикл перехвата и обработки пакетов."""
        # ИСПРАВЛЕНИЕ: Убираем PayloadLength > 0 из фильтра, чтобы ловить и SYN пакеты
        filter_str = "outbound and tcp.DstPort == 443"
        self.logger.info(f"🔍 Фильтр pydivert: {filter_str}")
        
        try:
            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert запущен успешно.")
                while self.running:
                    packet = w.recv()
                    if packet is None:
                        continue
                    
                    self.stats['packets_captured'] += 1
                    
                    # ИСПРАВЛЕНИЕ: Применяем стратегию только если это целевой IP И есть payload (ClientHello)
                    if self._is_target_ip(packet.dst_addr, target_ips) and packet.payload:
                        # Используем IP назначения для поиска стратегии, если она задана для конкретного IP
                        # Иначе используем 'default'
                        strategy_task = strategy_map.get(packet.dst_addr) or strategy_map.get('default')
                        
                        if strategy_task and self._is_tls_clienthello(packet.payload):
                            self.stats['tls_packets_bypassed'] += 1
                            self.logger.info(f"Обнаружен TLS ClientHello к {packet.dst_addr}. Применяем bypass...")
                            self.apply_bypass(packet, w, strategy_task)
                        else:
                            # Пакет с данными, но не ClientHello, пропускаем
                            w.send(packet)
                    else:
                        # Пакет не к целевому IP или без данных (SYN, ACK, FIN), отправляем как есть
                        w.send(packet)
        except Exception as e:
            if self.running:
                self.logger.error(f"❌ Критическая ошибка в цикле WinDivert: {e}", exc_info=self.debug)
            self.running = False

    def _is_tls_clienthello(self, payload: Optional[bytes]) -> bool:
        """Проверяет, является ли payload сообщением TLS ClientHello."""
        return (payload and len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x01)

    def apply_bypass(self, packet: pydivert.Packet, w: pydivert.WinDivert, strategy_task: Dict):
        """
        ИСПРАВЛЕНИЕ: Полностью переписанный диспетчер стратегий.
        Теперь он корректно обрабатывает все типы задач.
        """
        try:
            task_type = strategy_task.get("type")
            # Копируем, чтобы безопасно изменять, не влияя на другие потоки
            params = strategy_task.get("params", {}).copy() 
            
            self.logger.info(f"🎯 Применяем обход для {packet.dst_addr} -> Тип: {task_type}, Параметры: {params}")
            payload = bytes(packet.payload)
            success = False
            ttl = params.get('ttl')

            # Динамически разрешаем 'midsld' прямо перед применением стратегии
            if params.get('split_pos') == 'midsld':
                resolved_pos = self._resolve_midsld_pos(payload)
                if resolved_pos:
                    params['split_pos'] = resolved_pos
                    self.logger.debug(f"Resolved 'midsld' to absolute position: {resolved_pos}")
                else:
                    self.logger.warning("Could not resolve 'midsld', falling back to default position 3.")
                    params['split_pos'] = 3

            # Основной диспетчер стратегий
            if task_type == 'fakedisorder':
                self._send_fake_packet(packet, w, ttl=ttl if ttl else 2)
                segments = self.techniques.apply_fakeddisorder(payload, params.get('split_pos', 3))
                success = self._send_segments(packet, w, segments)
            elif task_type == 'multisplit':
                segments = self.techniques.apply_multisplit(payload, params.get('positions', [1, 3, 10]))
                success = self._send_segments(packet, w, segments)
            elif task_type == 'multidisorder':
                self._send_fake_packet(packet, w, ttl=ttl if ttl else 2)
                segments = self.techniques.apply_multidisorder(payload, params.get('positions', [1, 5, 10]))
                success = self._send_segments(packet, w, segments)
            elif task_type == 'seqovl':
                self._send_fake_packet(packet, w, ttl=ttl if ttl else 2)
                segments = self.techniques.apply_seqovl(payload, params.get('split_pos', 3), params.get('overlap_size', 10))
                success = self._send_segments(packet, w, segments)
            elif task_type == 'tlsrec_split':
                modified_payload = self.techniques.apply_tlsrec_split(payload, params.get('split_pos', 5))
                success = self._send_modified_packet(packet, w, modified_payload)
            elif task_type == 'wssize_limit':
                segments = self.techniques.apply_wssize_limit(payload, params.get('window_size', 2))
                success = self._send_segments_with_window(packet, w, segments)
            elif task_type == 'badsum_race':
                self._send_fake_packet_with_badsum(packet, w, ttl=ttl if ttl else 2)
                time.sleep(0.005)
                w.send(packet)
                success = True
            elif task_type == 'md5sig_race':
                self._send_fake_packet_with_md5sig(packet, w, ttl=ttl if ttl else 3)
                time.sleep(0.007)
                w.send(packet)
                success = True
            else:
                self.logger.warning(f"Неизвестный тип задачи '{task_type}', применяем простую фрагментацию.")
                self._send_fragmented_fallback(packet, w)
                success = True

            if not success:
                self.logger.error("Не удалось применить стратегию, отправляем оригинальный пакет.")
                w.send(packet)
        except Exception as e:
            self.logger.error(f"❌ Ошибка применения bypass: {e}", exc_info=self.debug)
            w.send(packet)

    def _send_segments(self, original_packet, w, segments: List[Tuple[bytes, int]]):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            tcp_seq_start = ip_header_len + 4
            base_seq = struct.unpack('!I', raw_data[tcp_seq_start:tcp_seq_start+4])[0]
            for i, (segment_data, seq_offset) in enumerate(segments):
                if not segment_data: continue
                seg_raw = bytearray(raw_data[:payload_start])
                seg_raw.extend(segment_data)
                new_seq = (base_seq + seq_offset) & 0xFFFFFFFF
                seg_raw[tcp_seq_start:tcp_seq_start+4] = struct.pack('!I', new_seq)
                seg_raw[2:4] = struct.pack('!H', len(seg_raw))
                if i == len(segments) - 1:
                    seg_raw[ip_header_len + 13] |= 0x08
                seg_packet = pydivert.Packet(bytes(seg_raw), original_packet.interface, original_packet.direction)
                w.send(seg_packet)
                self.stats['fragments_sent'] += 1
                if i < len(segments) - 1: time.sleep(0.002)
            self.logger.debug(f"✨ Отправлено {len(segments)} сегментов")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка отправки сегментов: {e}", exc_info=self.debug)
            return False

    def _send_fake_packet(self, original_packet, w, ttl: Optional[int] = 2):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            fake_raw = raw_data[:payload_start] + fake_payload[:20]
            if ttl:
                fake_raw[8] = ttl
            fake_raw[2:4] = struct.pack('!H', len(fake_raw))
            fake_packet = pydivert.Packet(bytes(fake_raw), original_packet.interface, original_packet.direction)
            w.send(fake_packet)
            self.stats['fake_packets_sent'] += 1
            time.sleep(0.002)
        except Exception as e:
            self.logger.debug(f"Ошибка отправки fake packet: {e}")

    def _send_fake_packet_with_badsum(self, original_packet, w, ttl: Optional[int] = 2):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            fake_raw = raw_data[:payload_start] + fake_payload[:20]
            if ttl:
                fake_raw[8] = ttl
            fake_raw = self.techniques.apply_badsum_fooling(fake_raw)
            fake_raw[2:4] = struct.pack('!H', len(fake_raw))
            fake_packet = pydivert.Packet(bytes(fake_raw), original_packet.interface, original_packet.direction)
            w.send(fake_packet)
            self.stats['fake_packets_sent'] += 1
        except Exception as e:
            self.logger.debug(f"Ошибка fake packet with badsum: {e}")

    def _send_fake_packet_with_md5sig(self, original_packet, w, ttl: Optional[int] = 3):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            fake_payload = b"EHLO example.com\r\n"
            fake_raw = raw_data[:payload_start] + fake_payload
            if ttl:
                fake_raw[8] = ttl
            fake_raw = self.techniques.apply_md5sig_fooling(fake_raw)
            fake_raw[2:4] = struct.pack('!H', len(fake_raw))
            fake_packet = pydivert.Packet(bytes(fake_raw), original_packet.interface, original_packet.direction)
            w.send(fake_packet)
            self.stats['fake_packets_sent'] += 1
        except Exception as e:
            self.logger.debug(f"Ошибка fake packet with md5sig: {e}")

    def _send_modified_packet(self, original_packet, w, modified_payload):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            new_raw = raw_data[:payload_start] + modified_payload
            new_raw[2:4] = struct.pack('!H', len(new_raw))
            new_packet = pydivert.Packet(bytes(new_raw), original_packet.interface, original_packet.direction)
            w.send(new_packet)
            self.stats['fragments_sent'] += 1
            return True
        except Exception as e:
            self.logger.error(f"Ошибка отправки модифицированного пакета: {e}", exc_info=self.debug)
            return False

    def _send_segments_with_window(self, original_packet, w, segments):
        try:
            raw_data = bytearray(original_packet.raw)
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len
            tcp_seq_start = ip_header_len + 4
            tcp_window_start = ip_header_len + 14
            base_seq = struct.unpack('!I', raw_data[tcp_seq_start:tcp_seq_start+4])[0]
            for i, (segment_data, seq_offset) in enumerate(segments):
                if not segment_data: continue
                seg_raw = bytearray(raw_data[:payload_start])
                seg_raw.extend(segment_data)
                new_seq = (base_seq + seq_offset) & 0xFFFFFFFF
                seg_raw[tcp_seq_start:tcp_seq_start+4] = struct.pack('!I', new_seq)
                window_size = min(len(segment_data), 2)
                seg_raw[tcp_window_start:tcp_window_start+2] = struct.pack('!H', window_size)
                seg_raw[2:4] = struct.pack('!H', len(seg_raw))
                if i == len(segments) - 1:
                    seg_raw[ip_header_len + 13] |= 0x08
                seg_packet = pydivert.Packet(bytes(seg_raw), original_packet.interface, original_packet.direction)
                w.send(seg_packet)
                self.stats['fragments_sent'] += 1
                if i < len(segments) - 1: time.sleep(0.05)
            return True
        except Exception as e:
            self.logger.error(f"Ошибка отправки сегментов с window: {e}", exc_info=self.debug)
            return False

    def _send_fragmented_fallback(self, packet, w):
        """Резервный метод простой фрагментации."""
        payload = bytes(packet.payload)
        fragments = [(payload[0:1], 0), (payload[1:3], 1), (payload[3:], 3)]
        self._send_segments(packet, w, fragments)