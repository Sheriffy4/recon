#!/usr/bin/env python3
"""
Финальный рабочий DPI bypass с интегрированными продвинутыми техниками.
"""

import pydivert
import time
import threading
import logging
import socket
import struct
import random
import os
import json
from datetime import datetime
from typing import List, Tuple
from core.bypass.techniques.primitives import BypassTechniques
import warnings

warnings.warn(
    "final_packet_bypass.AdvancedBypassTechniques is deprecated; use core.bypass.techniques.primitives.BypassTechniques",
    DeprecationWarning,
    stacklevel=2,
)

class AdvancedBypassTechniques(BypassTechniques):
    """Продвинутые техники обхода DPI из zapret и engine.py.
    Наследуется от единых примитивов; переопределяем только уникальные/специфичные методы.
    """

    @staticmethod
    def apply_fakeddisorder(
        payload: bytes, split_pos: int = 3
    ) -> List[Tuple[bytes, int]]:
        """Техника fake disorder - отправляем части в обратном порядке (семантика final_packet_bypass)."""
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        return [(part2, split_pos), (part1, 0)]

    @staticmethod
    def apply_badseq_fooling(
        packet_data: bytearray, seq_offset: int = -10000
    ) -> bytearray:
        """Применяет bad sequence number."""
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_seq_pos = ip_header_len + 4
        if len(packet_data) > tcp_seq_pos + 3:
            current_seq = struct.unpack("!I", packet_data[tcp_seq_pos : tcp_seq_pos + 4])[0]
            new_seq = (current_seq + seq_offset) & 0xFFFFFFFF
            packet_data[tcp_seq_pos : tcp_seq_pos + 4] = struct.pack("!I", new_seq)
        return packet_data

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        """Техника multisplit - разбиваем на несколько частей."""
        if not positions:
            return [(payload, 0)]

        segments = []
        last_pos = 0

        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos))
                last_pos = pos

        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos))

        return segments

    @staticmethod
    def apply_multidisorder(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        """Техника multidisorder - разбиваем и отправляем в обратном порядке."""
        segments = AdvancedBypassTechniques.apply_multisplit(payload, positions)

        # Отправляем сегменты в обратном порядке (кроме последнего)
        if len(segments) > 1:
            return segments[::-1]

        return segments

    @staticmethod
    def apply_seqovl(
        payload: bytes, split_pos: int = 3, overlap_size: int = 10
    ) -> List[Tuple[bytes, int]]:
        """Техника sequence overlap."""
        if split_pos >= len(payload):
            return [(payload, 0)]

        part1 = payload[:split_pos]
        part2 = payload[split_pos:]

        # Добавляем overlap к первой части
        overlap_data = b"\x00" * overlap_size
        part1_with_overlap = overlap_data + part1

        return [(part2, split_pos), (part1_with_overlap, -overlap_size)]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        """Техника TLS record split - разбиваем на два TLS record."""
        if split_pos >= len(payload) or split_pos < 5:
            return payload

        # Убираем оригинальный TLS header
        if payload[:3] == b"\x16\x03\x01":
            tls_data = payload[5:]  # Пропускаем TLS header (5 байт)
        else:
            tls_data = payload

        part1 = tls_data[:split_pos]
        part2 = tls_data[split_pos:]

        # Создаем два TLS record
        record1_header = b"\x16\x03\x01" + len(part1).to_bytes(2, "big")
        record2_header = b"\x16\x03\x01" + len(part2).to_bytes(2, "big")

        return record1_header + part1 + record2_header + part2

    @staticmethod
    def apply_wssize_limit(
        payload: bytes, window_size: int = 1
    ) -> List[Tuple[bytes, int]]:
        """Техника window size - ограничиваем размер окна."""
        segments = []
        pos = 0

        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos))
            pos += chunk_size

        return segments

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        """Применяет bad checksum."""
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_checksum_pos = ip_header_len + 16

        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 0xDEAD
            )

        return packet_data

    

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        """Применяет MD5 signature fooling."""
        ip_header_len = (packet_data[0] & 0x0F) * 4
        tcp_header_start = ip_header_len

        # Добавляем фейковую MD5 опцию в TCP заголовок
        if len(packet_data) > tcp_header_start + 20:
            # Простая реализация - меняем checksum на специальное значение
            tcp_checksum_pos = tcp_header_start + 16
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 0xBEEF
            )

        return packet_data

    @staticmethod
    def apply_ipfrag(payload: bytes, frag_size: int = 24) -> List[bytes]:
        """Техника IP fragmentation (упрощенная версия)."""
        fragments = []
        pos = 0
        frag_id = random.randint(1000, 65535)
        while pos < len(payload):
            chunk = payload[pos : pos + frag_size]
            fragments.append(chunk)
            pos += frag_size
        return fragments

    @staticmethod
    def build_client_hello(domain: str) -> bytes:
        """Строит TLS ClientHello для домена (из engine.py)."""
        # Базовый шаблон TLS ClientHello
        template = bytearray(
            [
                # TLS Record Header
                0x16,
                0x03,
                0x01,
                0x00,
                0xF8,  # Content Type, Version, Length
                # Handshake Header
                0x01,
                0x00,
                0x00,
                0xF4,  # Handshake Type (ClientHello), Length
                # TLS Version
                0x03,
                0x03,
                # Random (32 bytes)
                0x00,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0A,
                0x0B,
                0x0C,
                0x0D,
                0x0E,
                0x0F,
                0x10,
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
                0x17,
                0x18,
                0x19,
                0x1A,
                0x1B,
                0x1C,
                0x1D,
                0x1E,
                0x1F,
                # Session ID Length
                0x20,
                # Session ID (32 bytes)
                0x00,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                0x09,
                0x0A,
                0x0B,
                0x0C,
                0x0D,
                0x0E,
                0x0F,
                0x10,
                0x11,
                0x12,
                0x13,
                0x14,
                0x15,
                0x16,
                0x17,
                0x18,
                0x19,
                0x1A,
                0x1B,
                0x1C,
                0x1D,
                0x1E,
                0x1F,
                # Cipher Suites Length
                0x00,
                0x1A,
                # Cipher Suites
                0x13,
                0x01,
                0x13,
                0x02,
                0x13,
                0x03,
                0xC0,
                0x2F,
                0xC0,
                0x30,
                0xC0,
                0x2B,
                0xCC,
                0xA9,
                0xCC,
                0xA8,
                0xC0,
                0x13,
                0xC0,
                0x14,
                0x00,
                0x9C,
                0x00,
                0x9D,
                0x00,
                0x2F,
                0x00,
                0x35,
                # Compression Methods Length
                0x01,
                # Compression Methods
                0x00,
                # Extensions Length (будет обновлено)
                0x00,
                0x93,
                # SNI Extension
                0x00,
                0x00,  # Extension Type (SNI)
                0x00,
                0x18,  # Extension Length (будет обновлено)
                0x00,
                0x16,  # Server Name List Length (будет обновлено)
                0x00,  # Name Type (hostname)
                0x00,
                0x13,  # Name Length (будет обновлено)
            ]
        )

        # Добавляем домен
        old_domain = b"example.com"
        domain_bytes = domain.encode("utf-8")

        # Добавляем домен к шаблону
        template.extend(domain_bytes)

        # Добавляем остальные расширения (упрощенно)
        remaining_extensions = bytes(
            [
                # Другие расширения...
                0x00,
                0x17,
                0x00,
                0x00,  # Extended Master Secret
                0x00,
                0x23,
                0x00,
                0x00,  # Session Ticket
                0x00,
                0x0D,
                0x00,
                0x14,
                0x00,
                0x12,  # Signature Algorithms
                0x04,
                0x03,
                0x08,
                0x04,
                0x04,
                0x01,
                0x05,
                0x03,
                0x08,
                0x05,
                0x05,
                0x01,
                0x08,
                0x06,
                0x06,
                0x01,
                0x02,
                0x01,
            ]
        )

        template.extend(remaining_extensions)

        # Обновляем длины
        domain_len = len(domain_bytes)

        # Обновляем длину имени
        template[119] = (domain_len >> 8) & 0xFF
        template[120] = domain_len & 0xFF

        # Обновляем длину списка имен
        sni_list_len = domain_len + 3
        template[116] = (sni_list_len >> 8) & 0xFF
        template[117] = sni_list_len & 0xFF

        # Обновляем длину SNI расширения
        sni_ext_len = sni_list_len + 2
        template[114] = (sni_ext_len >> 8) & 0xFF
        template[115] = sni_ext_len & 0xFF

        # Обновляем общие длины
        total_ext_len = len(template) - 108
        template[106] = (total_ext_len >> 8) & 0xFF
        template[107] = total_ext_len & 0xFF

        handshake_len = len(template) - 9
        template[6] = (handshake_len >> 16) & 0xFF
        template[7] = (handshake_len >> 8) & 0xFF
        template[8] = handshake_len & 0xFF

        record_len = len(template) - 5
        template[3] = (record_len >> 8) & 0xFF
        template[4] = record_len & 0xFF

        return bytes(template)


class FinalWorkingBypass:
    """Финальный рабочий DPI bypass с продвинутыми техниками."""

    def __init__(self, debug=True):
        self.debug = debug
        self.running = False

        self.stats = {
            "packets_captured": 0,
            "tls_packets_found": 0,
            "bypasses_applied": 0,
            "fragments_sent": 0,
            "fake_packets_sent": 0,
            "advanced_techniques_used": 0,
        }

        self.logger = logging.getLogger("final_bypass")
        if debug:
            logging.basicConfig(
                level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
            )

        # Заблокированные домены (загружаем из файла)
        self.blocked_domains = self._load_domains_from_file()

        # IP адреса (включая Cloudflare)
        self.blocked_ips = set()
        self.cloudflare_prefixes = [
            "104.",
            "172.64.",
            "172.67.",
            "162.158.",
            "162.159.",
        ]

        # Продвинутые техники
        self.techniques = AdvancedBypassTechniques()

        # Стратегии обхода (от простых к сложным)
        self.bypass_strategies = [
            "simple_fragment",
            "fake_disorder",
            "multisplit",
            "multidisorder",
            "seqovl",
            "tlsrec_split",
            "wssize_limit",
            "badsum_race",
            "md5sig_race",
            "ipfrag_attack",
            "combo_advanced",
            "zapret_style_combo",
        ]
        self.current_strategy_index = 0

        # Загружаем лучшую стратегию если есть
        self.best_strategy = self._load_best_strategy()
        self.use_best_strategy = self.best_strategy is not None

        self._resolve_domains()

    def _load_domains_from_file(self, filename="sites.txt"):
        """Загружает домены из текстового файла. Если файла нет, создает его с примерами."""
        domains = set()

        try:
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        # Игнорируем пустые строки и комментарии
                        if line and not line.startswith("#"):
                            domains.add(line.lower())

                self.logger.info(f"📁 Загружено {len(domains)} доменов из {filename}")
            else:
                # Если файла нет, используем домены по умолчанию и создаем файл
                self.logger.warning(
                    f"⚠️ Файл {filename} не найден, используем домены по умолчанию и создаем файл."
                )
                domains = {"rutracker.org", "nnmclub.to", "kinozal.tv", "rutor.info"}
                self._create_default_sites_file(filename, domains)

        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки доменов из {filename}: {e}")
            # В случае ошибки используем домены по умолчанию
            domains = {"rutracker.org", "nnmclub.to", "kinozal.tv", "rutor.info"}

        return domains

    def _create_default_sites_file(self, filename, default_domains):
        """Создает файл sites.txt с доменами по умолчанию."""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("# Список заблокированных доменов для обхода DPI\n")
                f.write("# Каждый домен на отдельной строке\n")
                f.write("# Строки начинающиеся с # игнорируются\n\n")
                f.write("# Торрент трекеры\n")
                for domain in default_domains:
                    f.write(f"{domain}\n")
                f.write("\n# Социальные сети (если заблокированы)\n")
                f.write("# facebook.com\n# instagram.com\n# twitter.com\n")
            self.logger.info(f"✅ Создан файл {filename} с доменами по умолчанию")
        except Exception as e:
            self.logger.error(f"❌ Не удалось создать {filename}: {e}")

    def _load_best_strategy(self, filename="best_strategy.json"):
        """Загружает лучшую стратегию из файла."""
        try:
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as f:
                    data = json.load(f)

                strategy = data.get("strategy")
                success_rate = data.get("success_rate", 0)

                # Используем только если успешность > 50%
                if strategy and success_rate > 0.5:
                    self.logger.info(
                        f"🎯 Загружена лучшая стратегия: {strategy} (успешность: {success_rate:.1%})"
                    )
                    return strategy

        except Exception as e:
            self.logger.debug(f"Не удалось загрузить лучшую стратегию: {e}")

        return None

    def _save_best_strategy(
        self, strategy, success_rate, avg_latency, filename="best_strategy.json"
    ):
        """Сохраняет лучшую стратегию в файл."""
        try:
            data = {
                "strategy": strategy,
                "success_rate": success_rate,
                "avg_latency": avg_latency,
                "timestamp": datetime.now().isoformat(),
                "domains_tested": list(self.blocked_domains),
            }

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.info(
                f"💾 Сохранена лучшая стратегия: {strategy} (успешность: {success_rate:.1%})"
            )

        except Exception as e:
            self.logger.error(f"❌ Не удалось сохранить стратегию: {e}")

    def set_custom_strategy(self, strategy):
        """Устанавливает пользовательскую стратегию."""
        if strategy in self.bypass_strategies:
            self.best_strategy = strategy
            self.use_best_strategy = True
            self.logger.info(f"🎯 Установлена пользовательская стратегия: {strategy}")
        else:
            self.logger.error(f"❌ Неизвестная стратегия: {strategy}")
            self.logger.info(
                f"💡 Доступные стратегии: {', '.join(self.bypass_strategies)}"
            )

    def _load_domains_from_file(self):
        """Загружает домены из файла sites.txt."""
        domains = set()
        sites_file = "sites.txt"

        try:
            if os.path.exists(sites_file):
                with open(sites_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        # Игнорируем пустые строки и комментарии
                        if line and not line.startswith("#"):
                            domains.add(line.lower())

                self.logger.info(f"📋 Загружено {len(domains)} доменов из {sites_file}")
            else:
                # Если файла нет, используем домены по умолчанию
                domains = {"rutracker.org", "nnmclub.to", "kinozal.tv", "rutor.info"}
                self.logger.warning(
                    f"⚠️ Файл {sites_file} не найден, используем домены по умолчанию"
                )

                # Создаем файл с доменами по умолчанию
                self._create_default_sites_file(sites_file)

        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки доменов: {e}")
            # В случае ошибки используем домены по умолчанию
            domains = {"rutracker.org", "nnmclub.to", "kinozal.tv", "rutor.info"}

        return domains

    def _create_default_sites_file(self, filename):
        """Создает файл sites.txt с доменами по умолчанию."""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(
                    """# Список заблокированных доменов для обхода DPI
# Каждый домен на отдельной строке
# Строки начинающиеся с # игнорируются

# Торрент трекеры
rutracker.org
nnmclub.to
kinozal.tv
rutor.info

# Социальные сети (если заблокированы)
# facebook.com
# instagram.com
# twitter.com

# Другие сайты
# your-domain.com
# another-site.org
"""
                )
            self.logger.info(f"✅ Создан файл {filename} с доменами по умолчанию")
        except Exception as e:
            self.logger.error(f"❌ Не удалось создать {filename}: {e}")

    def _load_best_strategy(self):
        """Загружает лучшую стратегию из файла."""
        strategy_file = "best_strategy.json"

        try:
            if os.path.exists(strategy_file):
                with open(strategy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    strategy = data.get("strategy")
                    success_rate = data.get("success_rate", 0)

                    if (
                        strategy and success_rate > 0.5
                    ):  # Используем только если успешность > 50%
                        self.logger.info(
                            f"🎯 Загружена лучшая стратегия: {strategy} (успешность: {success_rate:.1%})"
                        )
                        return strategy

        except Exception as e:
            self.logger.debug(f"Не удалось загрузить лучшую стратегию: {e}")

        return None

    def _save_best_strategy(self, strategy, success_rate, avg_latency):
        """Сохраняет лучшую стратегию в файл."""
        strategy_file = "best_strategy.json"

        try:
            data = {
                "strategy": strategy,
                "success_rate": success_rate,
                "avg_latency": avg_latency,
                "timestamp": datetime.now().isoformat(),
                "domains_tested": list(self.blocked_domains),
            }

            with open(strategy_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.info(
                f"💾 Сохранена лучшая стратегия: {strategy} (успешность: {success_rate:.1%})"
            )

        except Exception as e:
            self.logger.error(f"❌ Не удалось сохранить стратегию: {e}")

    def _resolve_domains(self):
        """Резолвит домены."""
        for domain in self.blocked_domains:
            try:
                addrinfo = socket.getaddrinfo(domain, 443, socket.AF_INET)
                ips = set([addr[4][0] for addr in addrinfo])
                for ip in ips:
                    self.blocked_ips.add(ip)
                    self.logger.info(f"🎯 {domain} -> {ip}")
            except Exception as e:
                self.logger.error(f"Ошибка резолва {domain}: {e}")

        self.logger.info(f"📋 Всего IP: {len(self.blocked_ips)}")

    def _is_target_ip(self, ip_str):
        """Проверяет, нужен ли bypass для IP."""
        if ip_str in self.blocked_ips:
            return True

        for prefix in self.cloudflare_prefixes:
            if ip_str.startswith(prefix):
                return True

        return False

    def start(self):
        """Запускает bypass."""
        try:
            self.running = True
            self.stats["start_time"] = datetime.now()

            self.logger.info("🚀 Запуск Final Working DPI Bypass")

            bypass_thread = threading.Thread(target=self._run_bypass, daemon=True)
            bypass_thread.start()

            return True

        except Exception as e:
            self.logger.error(f"Ошибка запуска: {e}")
            return False

    def _run_bypass(self):
        """Основной цикл bypass."""
        try:
            filter_str = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0"

            self.logger.info(f"🔍 Фильтр: {filter_str}")

            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert запущен")

                for packet in w:
                    if not self.running:
                        break

                    self.stats["packets_captured"] += 1

                    if self._should_bypass(packet):
                        self._apply_working_bypass(packet, w)
                    else:
                        w.send(packet)

                    if self.stats["packets_captured"] % 50 == 0:
                        self.logger.debug(
                            f"Обработано: {self.stats['packets_captured']}"
                        )

        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}")

    def _should_bypass(self, packet):
        """Определяет, нужен ли bypass."""
        try:
            dst_ip = str(packet.dst_addr)

            if not self._is_target_ip(dst_ip):
                return False

            if not hasattr(packet, "payload") or not packet.payload:
                return False

            payload = bytes(packet.payload)

            if self._is_tls_clienthello(payload):
                self.stats["tls_packets_found"] += 1
                self.logger.info(f"🔒 TLS ClientHello к {dst_ip}")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Ошибка анализа: {e}")
            return False

    def _is_tls_clienthello(self, payload):
        """Проверяет TLS ClientHello."""
        return (
            len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x01  # Handshake
        )  # ClientHello

    def _apply_working_bypass(self, packet, w):
        """Применяет продвинутые техники bypass."""
        try:
            self.logger.info(f"🎯 Bypass для {packet.src_addr} -> {packet.dst_addr}")

            # Выбираем стратегию (лучшую или циклическую)
            if self.best_strategy:
                strategy = self.best_strategy
                self.logger.info(f"🎯 Лучшая стратегия: {strategy}")
            else:
                strategy = self.bypass_strategies[
                    self.current_strategy_index % len(self.bypass_strategies)
                ]
                self.logger.info(f"📋 Циклическая стратегия: {strategy}")
                # Переключаем стратегию для следующего пакета только в циклическом режиме
                self.current_strategy_index += 1

            success = False

            if strategy == "simple_fragment":
                success = self._apply_simple_fragment(packet, w)
            elif strategy == "fake_disorder":
                success = self._apply_fake_disorder(packet, w)
            elif strategy == "multisplit":
                success = self._apply_multisplit_strategy(packet, w)
            elif strategy == "multidisorder":
                success = self._apply_multidisorder_strategy(packet, w)
            elif strategy == "seqovl":
                success = self._apply_seqovl_strategy(packet, w)
            elif strategy == "tlsrec_split":
                success = self._apply_tlsrec_split_strategy(packet, w)
            elif strategy == "wssize_limit":
                success = self._apply_wssize_strategy(packet, w)
            elif strategy == "badsum_race":
                success = self._apply_badsum_race(packet, w)
            elif strategy == "md5sig_race":
                success = self._apply_md5sig_race(packet, w)
            elif strategy == "ipfrag_attack":
                success = self._apply_ipfrag_strategy(packet, w)
            elif strategy == "combo_advanced":
                success = self._apply_combo_advanced(packet, w)
            elif strategy == "zapret_style_combo":
                success = self._apply_zapret_style_combo(packet, w)

            if success:
                self.stats["bypasses_applied"] += 1
                self.stats["advanced_techniques_used"] += 1
            else:
                # Fallback к простой фрагментации
                self._send_fragmented_correct(packet, w)
                self.stats["bypasses_applied"] += 1

        except Exception as e:
            self.logger.error(f"Ошибка bypass: {e}")
            w.send(packet)

    def _send_fake_packet(self, original_packet, w):
        """Отправляет фейковый пакет с низким TTL."""
        try:
            # Получаем raw данные
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            # Меняем payload на фейковый
            fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            # Находим начало payload
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            # Создаем новый пакет с фейковым payload
            fake_raw = raw_data[:payload_start] + fake_payload[:20]

            # Устанавливаем низкий TTL
            fake_raw[8] = 2

            # Обновляем длину IP пакета
            new_ip_len = len(fake_raw)
            fake_raw[2:4] = struct.pack("!H", new_ip_len)

            # Создаем новый пакет - правильный способ
            fake_packet = pydivert.Packet(
                bytes(fake_raw), original_packet.interface, original_packet.direction
            )

            # Отправляем
            w.send(fake_packet)
            self.stats["fake_packets_sent"] += 1

            # Задержка
            time.sleep(0.002)

        except Exception as e:
            self.logger.debug(f"Ошибка fake packet: {e}")

    def _apply_simple_fragment(self, packet, w):
        """Простая фрагментация (оригинальный метод)."""
        try:
            # Отправляем фейковый пакет
            self._send_fake_packet(packet, w)
            # Фрагментируем оригинальный
            self._send_fragmented_correct(packet, w)
            return True
        except Exception as e:
            self.logger.error(f"Ошибка simple_fragment: {e}")
            return False

    def _apply_fake_disorder(self, packet, w):
        """Техника fake disorder."""
        try:
            payload = bytes(packet.payload)

            # Отправляем фейковый пакет с низким TTL
            self._send_fake_packet(packet, w)

            # Применяем fake disorder
            segments = self.techniques.apply_fakeddisorder(payload, split_pos=3)

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка fake_disorder: {e}")
            return False

    def _apply_multisplit_strategy(self, packet, w):
        """Техника multisplit."""
        try:
            payload = bytes(packet.payload)

            # Позиции для разбиения
            positions = [1, 3, 10, len(payload) // 2]
            segments = self.techniques.apply_multisplit(payload, positions)

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка multisplit: {e}")
            return False

    def _apply_seqovl_strategy(self, packet, w):
        """Техника sequence overlap."""
        try:
            payload = bytes(packet.payload)

            segments = self.techniques.apply_seqovl(
                payload, split_pos=3, overlap_size=10
            )

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка seqovl: {e}")
            return False

    def _apply_badsum_race(self, packet, w):
        """Техника bad checksum race."""
        try:
            # Отправляем фейковый пакет с плохой контрольной суммой
            self._send_fake_packet_with_badsum(packet, w)

            # Отправляем правильный пакет
            time.sleep(0.005)
            w.send(packet)

            return True

        except Exception as e:
            self.logger.error(f"Ошибка badsum_race: {e}")
            return False

    def _apply_multidisorder_strategy(self, packet, w):
        """Техника multidisorder."""
        try:
            payload = bytes(packet.payload)

            # Позиции для разбиения
            positions = [1, 3, 10, len(payload) // 3, len(payload) // 2]
            segments = self.techniques.apply_multidisorder(payload, positions)

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка multidisorder: {e}")
            return False

    def _apply_tlsrec_split_strategy(self, packet, w):
        """Техника TLS record split."""
        try:
            payload = bytes(packet.payload)

            # Применяем TLS record split
            modified_payload = self.techniques.apply_tlsrec_split(payload, split_pos=5)

            # Отправляем модифицированный пакет
            return self._send_modified_packet(packet, w, modified_payload)

        except Exception as e:
            self.logger.error(f"Ошибка tlsrec_split: {e}")
            return False

    def _apply_wssize_strategy(self, packet, w):
        """Техника window size limit."""
        try:
            payload = bytes(packet.payload)

            # Применяем ограничение размера окна
            segments = self.techniques.apply_wssize_limit(payload, window_size=2)

            return self._send_segments_with_window(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка wssize: {e}")
            return False

    def _apply_md5sig_race(self, packet, w):
        """Техника MD5 signature race."""
        try:
            # Отправляем фейковый пакет с MD5 signature fooling
            self._send_fake_packet_with_md5sig(packet, w)

            # Отправляем правильный пакет
            time.sleep(0.007)
            w.send(packet)

            return True

        except Exception as e:
            self.logger.error(f"Ошибка md5sig_race: {e}")
            return False

    def _apply_ipfrag_strategy(self, packet, w):
        """Техника IP fragmentation."""
        try:
            payload = bytes(packet.payload)

            # Применяем IP фрагментацию
            fragments = self.techniques.apply_ipfrag(payload, frag_size=16)

            return self._send_ip_fragments(packet, w, fragments)

        except Exception as e:
            self.logger.error(f"Ошибка ipfrag: {e}")
            return False

    def _apply_combo_advanced(self, packet, w):
        """Комбинированная продвинутая техника."""
        try:
            payload = bytes(packet.payload)

            # 1. Фейковый пакет с bad checksum и низким TTL
            self._send_fake_packet_with_badsum(packet, w)

            # 2. Применяем fake disorder + seqovl
            segments = self.techniques.apply_seqovl(
                payload, split_pos=3, overlap_size=5
            )

            # 3. Отправляем сегменты в обратном порядке
            if len(segments) > 1:
                segments = segments[::-1]

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка combo_advanced: {e}")
            return False

    def _apply_zapret_style_combo(self, packet, w):
        """Комбинированная техника в стиле zapret."""
        try:
            payload = bytes(packet.payload)

            # 1. Отправляем несколько фейковых пакетов с разными техниками
            self._send_fake_packet_with_badsum(packet, w)
            time.sleep(0.002)
            self._send_fake_packet_with_md5sig(packet, w)
            time.sleep(0.002)

            # 2. Применяем multidisorder с seqovl
            segments = self.techniques.apply_seqovl(
                payload, split_pos=2, overlap_size=8
            )
            segments = [(seg_data, seq_offset) for seg_data, seq_offset in segments]

            # 3. Отправляем в обратном порядке
            if len(segments) > 1:
                segments = segments[::-1]

            return self._send_segments(packet, w, segments)

        except Exception as e:
            self.logger.error(f"Ошибка zapret_style_combo: {e}")
            return False

    def _send_segments(self, original_packet, w, segments: List[Tuple[bytes, int]]):
        """Отправляет сегменты пакета."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            # Получаем параметры из заголовков
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            # TCP sequence number
            tcp_seq_start = ip_header_len + 4
            base_seq = struct.unpack("!I", raw_data[tcp_seq_start : tcp_seq_start + 4])[
                0
            ]

            for i, (segment_data, seq_offset) in enumerate(segments):
                if not segment_data:
                    continue

                # Создаем новый пакет для сегмента
                seg_raw = bytearray(raw_data[:payload_start])
                seg_raw.extend(segment_data)

                # Обновляем sequence number с учетом offset
                new_seq = (base_seq + seq_offset) & 0xFFFFFFFF
                seg_raw[tcp_seq_start : tcp_seq_start + 4] = struct.pack("!I", new_seq)

                # Обновляем длину IP пакета
                new_ip_len = len(seg_raw)
                seg_raw[2:4] = struct.pack("!H", new_ip_len)

                # PSH флаг для последнего сегмента
                if i == len(segments) - 1:
                    tcp_flags_pos = ip_header_len + 13
                    seg_raw[tcp_flags_pos] |= 0x08  # PSH flag

                # Создаем и отправляем пакет
                seg_packet = pydivert.Packet(
                    bytes(seg_raw), original_packet.interface, original_packet.direction
                )

                w.send(seg_packet)
                self.stats["fragments_sent"] += 1

                # Задержка между сегментами
                if i < len(segments) - 1:
                    time.sleep(0.002)

            self.logger.debug(f"✨ Отправлено {len(segments)} сегментов")
            return True

        except Exception as e:
            self.logger.error(f"Ошибка отправки сегментов: {e}")
            return False

    def _send_fake_packet_with_badsum(self, original_packet, w):
        """Отправляет фейковый пакет с плохой контрольной суммой."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            # Меняем payload на фейковый
            fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            fake_raw = raw_data[:payload_start] + fake_payload[:20]

            # Устанавливаем низкий TTL
            fake_raw[8] = 2

            # Применяем bad checksum
            fake_raw = self.techniques.apply_badsum_fooling(fake_raw)

            # Обновляем длину IP пакета
            new_ip_len = len(fake_raw)
            fake_raw[2:4] = struct.pack("!H", new_ip_len)

            fake_packet = pydivert.Packet(
                bytes(fake_raw), original_packet.interface, original_packet.direction
            )

            w.send(fake_packet)
            self.stats["fake_packets_sent"] += 1

            time.sleep(0.003)

        except Exception as e:
            self.logger.debug(f"Ошибка fake packet with badsum: {e}")

    def _send_fake_packet_with_md5sig(self, original_packet, w):
        """Отправляет фейковый пакет с MD5 signature fooling."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            # Меняем payload на фейковый
            fake_payload = b"EHLO example.com\r\n"

            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            fake_raw = raw_data[:payload_start] + fake_payload

            # Устанавливаем низкий TTL
            fake_raw[8] = 3

            # Применяем MD5 signature fooling
            fake_raw = self.techniques.apply_md5sig_fooling(fake_raw)

            # Обновляем длину IP пакета
            new_ip_len = len(fake_raw)
            fake_raw[2:4] = struct.pack("!H", new_ip_len)

            fake_packet = pydivert.Packet(
                bytes(fake_raw), original_packet.interface, original_packet.direction
            )

            w.send(fake_packet)
            self.stats["fake_packets_sent"] += 1

            time.sleep(0.004)

        except Exception as e:
            self.logger.debug(f"Ошибка fake packet with md5sig: {e}")

    def _send_modified_packet(self, original_packet, w, modified_payload):
        """Отправляет пакет с модифицированным payload."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            # Создаем новый пакет с модифицированным payload
            new_raw = raw_data[:payload_start] + modified_payload

            # Обновляем длину IP пакета
            new_ip_len = len(new_raw)
            new_raw[2:4] = struct.pack("!H", new_ip_len)

            new_packet = pydivert.Packet(
                bytes(new_raw), original_packet.interface, original_packet.direction
            )

            w.send(new_packet)
            self.stats["fragments_sent"] += 1

            return True

        except Exception as e:
            self.logger.error(f"Ошибка отправки модифицированного пакета: {e}")
            return False

    def _send_segments_with_window(self, original_packet, w, segments):
        """Отправляет сегменты с ограничением размера окна."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            tcp_seq_start = ip_header_len + 4
            tcp_window_start = ip_header_len + 14
            base_seq = struct.unpack("!I", raw_data[tcp_seq_start : tcp_seq_start + 4])[
                0
            ]

            for i, (segment_data, seq_offset) in enumerate(segments):
                if not segment_data:
                    continue

                seg_raw = bytearray(raw_data[:payload_start])
                seg_raw.extend(segment_data)

                # Обновляем sequence number
                new_seq = (base_seq + seq_offset) & 0xFFFFFFFF
                seg_raw[tcp_seq_start : tcp_seq_start + 4] = struct.pack("!I", new_seq)

                # Устанавливаем маленький размер окна
                window_size = min(len(segment_data), 2)
                seg_raw[tcp_window_start : tcp_window_start + 2] = struct.pack(
                    "!H", window_size
                )

                # Обновляем длину IP пакета
                new_ip_len = len(seg_raw)
                seg_raw[2:4] = struct.pack("!H", new_ip_len)

                # PSH флаг для последнего сегмента
                if i == len(segments) - 1:
                    tcp_flags_pos = ip_header_len + 13
                    seg_raw[tcp_flags_pos] |= 0x08  # PSH flag

                seg_packet = pydivert.Packet(
                    bytes(seg_raw), original_packet.interface, original_packet.direction
                )

                w.send(seg_packet)
                self.stats["fragments_sent"] += 1

                # Увеличенная задержка для window size техники
                if i < len(segments) - 1:
                    time.sleep(0.05)

            return True

        except Exception as e:
            self.logger.error(f"Ошибка отправки сегментов с window: {e}")
            return False

    def _send_ip_fragments(self, original_packet, w, fragments):
        """Отправляет IP фрагменты."""
        try:
            if hasattr(original_packet.raw, "tobytes"):
                raw_data = bytearray(original_packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(original_packet.raw))

            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            frag_id = random.randint(1000, 65535)

            for i, fragment_data in enumerate(fragments):
                if not fragment_data:
                    continue

                frag_raw = bytearray(raw_data[:payload_start])
                frag_raw.extend(fragment_data)

                # Устанавливаем ID фрагмента
                frag_raw[4:6] = struct.pack("!H", frag_id)

                # Устанавливаем флаги фрагментации (упрощенно)
                if i < len(fragments) - 1:
                    # More Fragments flag
                    frag_raw[6] |= 0x20

                # Обновляем длину IP пакета
                new_ip_len = len(frag_raw)
                frag_raw[2:4] = struct.pack("!H", new_ip_len)

                frag_packet = pydivert.Packet(
                    bytes(frag_raw),
                    original_packet.interface,
                    original_packet.direction,
                )

                w.send(frag_packet)
                self.stats["fragments_sent"] += 1

                if i < len(fragments) - 1:
                    time.sleep(0.003)

            return True

        except Exception as e:
            self.logger.error(f"Ошибка отправки IP фрагментов: {e}")
            return False

    def _send_fragmented_correct(self, packet, w):
        """Правильная фрагментация (fallback метод)."""
        try:
            payload = bytes(packet.payload)

            # Получаем raw данные
            if hasattr(packet.raw, "tobytes"):
                raw_data = bytearray(packet.raw.tobytes())
            else:
                raw_data = bytearray(bytes(packet.raw))

            # Позиции фрагментации
            fragments = [
                (0, 1),  # Первый байт (0x16)
                (1, 3),  # TLS version
                (3, 10),  # Начало handshake
                (10, None),  # Остальное
            ]

            # Получаем параметры из заголовков
            ip_header_len = (raw_data[0] & 0x0F) * 4
            tcp_header_len = ((raw_data[ip_header_len + 12] >> 4) & 0x0F) * 4
            payload_start = ip_header_len + tcp_header_len

            # TCP sequence number
            tcp_seq_start = ip_header_len + 4
            base_seq = struct.unpack("!I", raw_data[tcp_seq_start : tcp_seq_start + 4])[
                0
            ]

            for i, (start, end) in enumerate(fragments):
                # Извлекаем часть payload
                if end is None:
                    fragment_data = payload[start:]
                else:
                    fragment_data = payload[start:end]

                if not fragment_data:
                    continue

                # Создаем новый пакет для фрагмента
                frag_raw = bytearray(raw_data[:payload_start])  # Копируем заголовки
                frag_raw.extend(fragment_data)  # Добавляем данные фрагмента

                # Обновляем sequence number
                new_seq = (base_seq + start) & 0xFFFFFFFF
                frag_raw[tcp_seq_start : tcp_seq_start + 4] = struct.pack("!I", new_seq)

                # Обновляем длину IP пакета
                new_ip_len = len(frag_raw)
                frag_raw[2:4] = struct.pack("!H", new_ip_len)

                # Устанавливаем PSH флаг для последнего фрагмента
                if i == len(fragments) - 1:
                    tcp_flags_pos = ip_header_len + 13
                    frag_raw[tcp_flags_pos] |= 0x08  # PSH flag

                # Создаем новый пакет - правильный способ
                frag_packet = pydivert.Packet(
                    bytes(frag_raw), packet.interface, packet.direction
                )

                # Отправляем фрагмент
                w.send(frag_packet)
                self.stats["fragments_sent"] += 1

                # Микрозадержка между фрагментами
                if i < len(fragments) - 1:
                    time.sleep(0.001)

            self.logger.debug(
                f"✨ Отправлено {len([f for f in fragments if f[1] is None or f[1] > f[0]])} фрагментов"
            )

        except Exception as e:
            self.logger.error(f"Ошибка фрагментации: {e}")
            # В случае ошибки отправляем оригинал
            w.send(packet)

    def stop(self):
        """Останавливает bypass."""
        self.running = False
        self.logger.info("🛑 Final Working Bypass остановлен")

    def get_stats(self):
        """Возвращает статистику."""
        return self.stats


def test_final_working():
    """Тестирует финальный рабочий bypass с продвинутыми техниками."""
    print("🚀 Тест Advanced DPI Bypass с продвинутыми техниками")
    print("=" * 70)

    bypass = FinalWorkingBypass(debug=True)

    if not bypass.start():
        print("❌ Не удалось запустить bypass")
        return

    try:
        print("✅ Advanced DPI Bypass запущен")
        print("\n🎯 Продвинутые техники из zapret и engine.py:")
        print("   • Simple Fragment: базовая фрагментация")
        print("   • Fake Disorder: обратный порядок сегментов")
        print("   • Multisplit: множественная фрагментация")
        print("   • Multidisorder: фрагментация в обратном порядке")
        print("   • SeqOvl: перекрытие последовательностей")
        print("   • TLS Record Split: разбиение TLS записей")
        print("   • WSSize Limit: ограничение размера окна")
        print("   • BadSum Race: гонка с плохой контрольной суммой")
        print("   • MD5Sig Race: гонка с MD5 signature fooling")
        print("   • IP Fragmentation: фрагментация на IP уровне")
        print("   • Combo Advanced: комбинированные техники")
        print("   • Zapret Style Combo: комбо в стиле zapret")

        print("\n💡 Теперь откройте браузер и попробуйте:")
        print("   • https://rutracker.org")
        print("   • https://nnmclub.to")

        # Мониторим 40 секунд
        for i in range(40):
            time.sleep(1)

            if i % 10 == 0:
                stats = bypass.get_stats()
                print(
                    f"\n📊 [{i}s] Пакетов: {stats['packets_captured']}, "
                    f"TLS: {stats['tls_packets_found']}, "
                    f"Bypass: {stats['bypasses_applied']}, "
                    f"Fake: {stats['fake_packets_sent']}, "
                    f"Fragments: {stats['fragments_sent']}"
                )

        # Финальная статистика
        stats = bypass.get_stats()
        print("\n📊 ИТОГО:")
        print(f"   • Bypass применен: {stats['bypasses_applied']} раз")
        print(f"   • Продвинутых техник: {stats['advanced_techniques_used']}")
        print(f"   • Фейковых пакетов: {stats['fake_packets_sent']}")
        print(f"   • Фрагментов отправлено: {stats['fragments_sent']}")

        if stats["bypasses_applied"] > 0 and stats["fragments_sent"] > 0:
            print("\n🎉 Продвинутый DPI bypass работает!")
            print("🔧 Интегрированные техники из zapret и engine.py:")
            print("   • Fake disorder (обратный порядок сегментов)")
            print("   • Multisplit/Multidisorder (множественная фрагментация)")
            print("   • Sequence overlap (перекрытие последовательностей)")
            print("   • TLS record split (разбиение TLS записей)")
            print("   • Window size limit (ограничение размера окна)")
            print("   • Bad checksum/MD5sig race (гонки с fooling)")
            print("   • IP fragmentation (фрагментация на IP уровне)")
            print("   • Zapret style combo (комбинированные техники)")
            print("\n💡 Если сайты все еще не открываются:")
            print("   • Попробуйте другие позиции фрагментации")
            print("   • Используйте GoodbyeDPI: goodbyedpi.exe -5")
            print("   • Измените DNS на 1.1.1.1")

    except KeyboardInterrupt:
        print("\n🛑 Прервано")
    finally:
        bypass.stop()


if __name__ == "__main__":
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("❌ Требуются права администратора!")
    else:
        test_final_working()

    input("\nНажмите Enter...")
