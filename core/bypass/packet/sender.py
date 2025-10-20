# File: core/bypass/packet/sender.py

import time
import logging
import pydivert
import struct
import threading
from typing import List, Optional, Tuple
from contextlib import contextmanager

from .builder import PacketBuilder
from .types import TCPSegmentSpec


class PacketSender:
    """
    Отвечает за оркестрацию отправки пакетов, используя PacketBuilder.
    Управляет задержками и логикой ретраев.
    
    ВКЛЮЧЕНО:
    - Жёсткий санитайзер пакетов перед отправкой:
      * гарантированное удаление FIN на всех путях
      * мимикрия real-сегментов под ОС (TTL и TCP-флаги как у оригинального CH)
    """

    def __init__(self, builder: PacketBuilder, logger: logging.Logger, inject_mark: int):
        self.builder = builder
        self.logger = logger
        self._INJECT_MARK = inject_mark

    def _strip_fin_and_normalize(self, pkt_bytes: bytes, original_packet: "pydivert.Packet", is_fake: bool) -> bytes:
        """
        Финальный "санитайзер" пакета перед отправкой.
        - ВСЕГДА удаляет флаг FIN.
        - Для real-сегментов нормализует TTL и TCP-флаги под оригинальный пакет ОС.
        """
        try:
            if not pkt_bytes or not original_packet or not hasattr(original_packet, "raw"):
                return pkt_bytes

            buf = bytearray(pkt_bytes)
            # IPv4 header length в байтах
            ip_hl = (buf[0] & 0x0F) * 4

            # 1) Жёстко убираем FIN
            if len(buf) > ip_hl + 13:
                buf[ip_hl + 13] &= ~0x01  # очистить бит FIN (0x01)

            # 2) Мимикрия real-сегментов под ОС
            if not is_fake:
                # TTL = как у оригинала
                if len(buf) > 8 and len(original_packet.raw) > 8:
                    buf[8] = original_packet.raw[8]
                # TCP flags = как у оригинала (6 младших бит)
                if len(buf) > ip_hl + 13 and len(original_packet.raw) > ip_hl + 13:
                    buf[ip_hl + 13] = original_packet.raw[ip_hl + 13] & 0x3F

            return bytes(buf)
        except Exception as e:
            self.logger.warning(f"normalize failed: {e}", exc_info=self.logger.level == logging.DEBUG)
            return pkt_bytes

    def send_tcp_segments(self, w, original_packet, specs, window_div=1, ipid_step=2048):
        """
        Send TCP segments with enhanced error handling.
        
        - Валидация входных параметров
        - Батч-сборка и отправка
        - Санитайзер FIN/TTL/flags перед отправкой
        - Ретраи при 258 (timeout)
        
        Args:
            w: WinDivert handle
            original_packet: Original packet to base segments on
            specs: List of TCPSegmentSpec objects
            window_div: Window division factor
            ipid_step: IP ID step for multiple packets
            
        Returns:
            bool: True if all segments sent successfully, False on error
        """
        try:
            # Validate input parameters
            if not w:
                self.logger.error("send_tcp_segments: WinDivert handle is None")
                return False
                
            if not original_packet:
                self.logger.error("send_tcp_segments: original_packet is None")
                return False
                
            if not specs:
                self.logger.error("send_tcp_segments: specs list is empty")
                return False
                
            if not isinstance(specs, (list, tuple)):
                self.logger.error(f"send_tcp_segments: invalid specs type {type(specs)}, expected list")
                return False
                
            if not isinstance(window_div, int) or window_div < 1:
                self.logger.error(f"send_tcp_segments: invalid window_div {window_div}, must be positive integer")
                return False
                
            if not isinstance(ipid_step, int):
                self.logger.error(f"send_tcp_segments: invalid ipid_step type {type(ipid_step)}, expected int")
                return False
                
            # Validate original packet has required data
            if not hasattr(original_packet, 'raw') or len(original_packet.raw) < 6:
                self.logger.error("send_tcp_segments: original_packet missing or invalid raw data")
                return False
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            
            # Блокируем ретрансмит ОС на время инъекции
            with self._create_tcp_retransmission_blocker(original_packet) as blocker:
                # Даем блокировщику время на инициализацию
                if blocker:
                    #time.sleep(0.005)  # 5ms для гарантированного запуска
                    self.logger.debug("✅ Retransmission blocker initialized")
                
                packets_to_send = []
                
                # Сборка всех сегментов заранее (batch)
                for i, spec in enumerate(specs):
                    try:
                        # Validate individual spec
                        if not spec:
                            self.logger.error(f"send_tcp_segments: spec {i} is None")
                            return False
                            
                        ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                        pkt_bytes = self.builder.build_tcp_segment(
                            original_packet, spec, window_div=window_div, ip_id=ip_id
                        )
                        if not pkt_bytes:
                            self.logger.error(f"send_tcp_segments: Segment {i} build failed - PacketBuilder returned None")
                            self.logger.error(f"send_tcp_segments: Failed spec details - rel_seq={getattr(spec, 'rel_seq', 'N/A')}, "
                                            f"payload_len={len(getattr(spec, 'payload', b'')) if hasattr(spec, 'payload') and spec.payload else 0}, "
                                            f"ttl={getattr(spec, 'ttl', 'N/A')}, flags={getattr(spec, 'flags', 'N/A')}")
                            return False

                        # ✅ Жёсткая нормализация (убираем FIN, мимикрируем real TTL/flags)
                        pkt_bytes = self._strip_fin_and_normalize(pkt_bytes, original_packet, getattr(spec, "is_fake", False))

                    except Exception as e:
                        self.logger.error(f"send_tcp_segments: Error building segment {i} - {e}", exc_info=True)
                        return False
                        
                    pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                    
                    # Убедиться, что метка установлена
                    try:
                        pkt.mark = self._INJECT_MARK
                        self.logger.debug(f"Packet {i} marked with {self._INJECT_MARK}")
                    except Exception as e:
                        self.logger.warning(f"Failed to mark packet {i}: {e}")
                        
                    packets_to_send.append((pkt, spec))
                
                # Отправка с правильными задержками
                for i, (pkt, spec) in enumerate(packets_to_send):
                    allow_fix = not spec.corrupt_tcp_checksum
                    
                    # Логирование
                    packet_type = "FAKE" if getattr(spec, 'is_fake', False) else "REAL"
                    try:
                        plen = len(pkt.payload) if getattr(pkt, "payload", None) else 0
                    except Exception:
                        plen = 0
                    # Извлекаем seq/ack и флаги из сырых байт (для диагностики)
                    try:
                        raw = pkt.raw
                        ip_hl = (raw[0] & 0x0F) * 4
                        seq_v = struct.unpack('!I', raw[ip_hl+4:ip_hl+8])[0]
                        ack_v = struct.unpack('!I', raw[ip_hl+8:ip_hl+12])[0]
                        flags_v = raw[ip_hl+13]
                        seq_str = f"seq=0x{seq_v:08X} ack=0x{ack_v:08X} flags=0x{flags_v:02X}"
                    except Exception:
                        seq_str = "seq=?, ack=?, flags=?"
                    self.logger.info(
                        f"📤 {packet_type} [{i+1}/{len(packets_to_send)}] "
                        f"dst={getattr(pkt,'dst_addr','?')}:{getattr(pkt,'dst_port','?')} "
                        f"len={plen} {seq_str}"
                    )
                    
                    if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                        self.logger.error(f"send_tcp_segments: Segment {i} send failed")
                        self.logger.error(f"send_tcp_segments: Failed packet details - dst={getattr(pkt, 'dst_addr', 'N/A')}:"
                                        f"{getattr(pkt, 'dst_port', 'N/A')}, size={len(getattr(pkt, 'raw', b''))}")
                        return False
                    
                    # Добавляем задержку после фейкового пакета (если есть)
                    if spec.delay_ms_after > 0:
                        delay_s = spec.delay_ms_after / 1000.0
                        self.logger.debug(f"⏱️ Delaying {spec.delay_ms_after}ms after packet {i+1}")
                        time.sleep(delay_s)
                
                self.logger.debug(f"send_tcp_segments: Successfully sent {len(specs)} segments")
                return True
                
        except ValueError as e:
            self.logger.error(f"send_tcp_segments: Parameter validation error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return False
        except OSError as e:
            self.logger.error(f"send_tcp_segments: Network/OS error - {e}", exc_info=self.logger.level <= logging.DEBUG)
            return False
        except MemoryError as e:
            self.logger.error(f"send_tcp_segments: Memory allocation error - {e}")
            return False
        except Exception as e:
            self.logger.error(f"send_tcp_segments: Unexpected error - {e}", exc_info=True)
            return False

    def send_udp_datagrams(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        datagrams: List[Tuple[bytes, int]],
        ipid_step: int = 2048
    ) -> bool:
        try:
            # Ручное извлечение IP ID
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]

            for i, (data, delay_ms) in enumerate(datagrams):
                ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                pkt_bytes = self.builder.build_udp_datagram(original_packet, data, ip_id=ip_id)
                if not pkt_bytes:
                    self.logger.error(f"Datagram {i} build failed, aborting send sequence.")
                    return False
                if not self.safe_send(w, pkt_bytes, original_packet):
                    self.logger.error(f"Datagram {i} send failed, aborting send sequence.")
                    return False
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_udp_datagrams error: {e}", exc_info=True)
            return False

    def safe_send(self, w: "pydivert.WinDivert", pkt_bytes: bytes, original_packet: "pydivert.Packet", allow_fix_checksums: bool = True) -> bool:
        """
        Универсальная отправка сырых байтов как pydivert.Packet (используется в UDP).
        """
        try:
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
            try:
                pkt.mark = self._INJECT_MARK
            except Exception:
                pass
            w.send(pkt)
            return True
        except OSError as e:
            if getattr(e, "winerror", None) == 258 and allow_fix_checksums:
                self.logger.debug("WinDivert send timeout (258). Retrying with checksum helper...")
                time.sleep(0.001)
                try:
                    buf = bytearray(pkt_bytes)
                    # UDP: FIN отсутствует, но для унификации ничего не делаем
                    from pydivert.windivert import WinDivertHelper, WinDivertLayer
                    WinDivertHelper.calc_checksums(buf, WinDivertLayer.NETWORK)
                    pkt2 = pydivert.Packet(bytes(buf), original_packet.interface, original_packet.direction)
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e2:
                    self.logger.error(f"WinDivert retry failed after 258: {e2}")
                    return False
            elif getattr(e, "winerror", None) == 258 and not allow_fix_checksums:
                self.logger.debug("WinDivert send timeout (258) on no-fix packet. Retrying without fix...")
                time.sleep(0.001)
                try:
                    pkt2 = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e3:
                    self.logger.error(f"WinDivert no-fix retry failed after 258: {e3}")
                    return False
            self.logger.error(f"WinDivert send error: {e}", exc_info=self.logger.level == logging.DEBUG)
            return False
        except Exception as e:
            self.logger.error(f"Unexpected send error: {e}", exc_info=True)
            return False

    @contextmanager
    def _create_tcp_retransmission_blocker(self, original_packet: "pydivert.Packet"):
        """
        Версия 2.0: Устранена гонка состояний при старте с помощью threading.Event.
        """
        blocker = None
        stop_event = threading.Event()
        start_event = threading.Event()  # <--- ДОБАВЛЕНО СОБЫТИЕ СТАРТА
        
        try:
            src_ip = original_packet.src_addr
            dst_ip = original_packet.dst_addr
            src_port = original_packet.src_port
            dst_port = original_packet.dst_port

            filter_str = (
                f"outbound and tcp and "
                f"ip.SrcAddr == {src_ip} and ip.DstAddr == {dst_ip} and "
                f"tcp.SrcPort == {src_port} and tcp.DstPort == {dst_port} and "
                f"tcp.Rst == 0"
            )
            self.logger.debug(f"🛡️ Creating TCP retransmission blocker with filter: {filter_str}")

            blocker = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK, priority=-100)
            blocker.open()

            blocker_thread = threading.Thread(
                target=self._retransmission_blocker_worker,
                args=(blocker, stop_event, start_event), # <--- ПЕРЕДАЕМ СОБЫТИЕ В ВОРКЕР
                daemon=True
            )
            blocker_thread.start()

            # Ждем сигнала от воркера, что он готов (максимум 20мс)
            if not start_event.wait(timeout=0.02):
                self.logger.warning("Blocker thread did not start in time!")

            self.logger.debug("🛡️ TCP retransmission blocker active")
            yield blocker

        except Exception as e:
            self.logger.warning(f"Failed to create TCP retransmission blocker: {e}")
            yield None
        finally:
            stop_event.set()
            if blocker:
                try:
                    blocker.close()
                    self.logger.debug("🛡️ TCP retransmission blocker closed")
                except Exception as e:
                    self.logger.debug(f"Error closing retransmission blocker: {e}")

    def _retransmission_blocker_worker(self, blocker, stop_event, start_event):
        """
        Версия 2.0: Сигнализирует о готовности и правильно проверяет mark.
        """
        blocked_count = 0
        passed_count = 0
        
        try:
            # Сигнализируем основному потоку, что мы готовы к работе
            start_event.set()
            
            while not stop_event.is_set():
                try:
                    packet = blocker.recv(timeout=100)
                    if not packet:
                        continue
                        
                    if getattr(packet, "mark", 0) == self._INJECT_MARK:
                        blocker.send(packet)
                        passed_count += 1
                        self.logger.debug(f"✅ Passed marked packet #{passed_count}")
                        continue
                        
                    # Служебные TCP без payload - пропускаем
                    if not packet.payload or len(packet.payload) == 0:
                        blocker.send(packet)
                        continue
                        
                    # SYN/FIN/RST - пропускаем
                    if packet.tcp and (packet.tcp.syn or packet.tcp.fin or packet.tcp.rst):
                        blocker.send(packet)
                        continue
                        
                    # Иначе - это данные от ОС: блокируем
                    is_pure_ack = packet.tcp and packet.tcp.ack and not packet.payload
                    if packet.tcp and (packet.tcp.syn or packet.tcp.fin or packet.tcp.rst or is_pure_ack):
                        blocker.send(packet)
                        continue

                    # Иначе - это данные от ОС (ClientHello или его ретрансмиссии): блокируем
                    blocked_count += 1
                    seq_num = packet.tcp.seq if packet.tcp else 0
                    self.logger.debug(
                        f"🛡️ BLOCKED OS retransmit #{blocked_count}: "
                        f"seq=0x{seq_num:08X}, " # <--- Добавлено
                        f"{packet.src_addr}:{packet.src_port} -> "
                        f"{packet.dst_addr}:{packet.dst_port} "
                        f"(payload={len(packet.payload)} bytes)"
                    )
                    
                except Exception as e:
                    if hasattr(e, 'args') and e.args and e.args[0] == 258:
                        continue  # Timeout - нормально
                    if "timeout" not in str(e).lower():
                        self.logger.debug(f"Blocker error: {e}")
                        break
                        
        finally:
            if blocked_count > 0 or passed_count > 0:
                self.logger.info(
                    f"📊 Blocker stats: {blocked_count} blocked, {passed_count} passed"
                )

    def _batch_safe_send(self, w: "pydivert.WinDivert", pkt: "pydivert.Packet", allow_fix_checksums: bool = True) -> bool:
        """
        Оптимизированная отправка с правильной обработкой checksum.
        """
        try:
            # Используем параметр recalculate_checksum=False, чтобы сохранить "плохую" чек-сумму
            w.send(pkt, recalculate_checksum=allow_fix_checksums)
            if not allow_fix_checksums:
                self.logger.debug("✅ Sent packet with checksum recalculation disabled.")
            return True
        except OSError as e:
            # Здесь можно оставить вашу логику обработки ошибок WinDivert, если она есть
            self.logger.error(f"WinDivert batch send error: {e}", exc_info=self.logger.level == logging.DEBUG)
            return False
        except Exception as e:
            self.logger.error(f"Unexpected batch send error: {e}", exc_info=True)
            return False

    def send_tcp_segments_async(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        specs: List[TCPSegmentSpec],
        window_div: int = 1,
        ipid_step: int = 2048
    ) -> bool:
        """
        Асинхронная версия (сейчас — потоковая), чтобы не блокировать основной цикл.
        """
        try:
            return self._send_tcp_segments_threaded(w, original_packet, specs, window_div, ipid_step)
        except Exception as e:
            self.logger.error(f"send_tcp_segments_async error: {e}", exc_info=True)
            return False

    def _send_tcp_segments_threaded(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        specs: List[TCPSegmentSpec],
        window_div: int = 1,
        ipid_step: int = 2048
    ) -> bool:
        try:
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            result_container = {"success": False, "error": None}

            def send_worker():
                try:
                    with self._create_tcp_retransmission_blocker(original_packet):
                        packets_to_send = []
                        for i, spec in enumerate(specs):
                            ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                            pkt_bytes = self.builder.build_tcp_segment(
                                original_packet, spec, window_div=window_div, ip_id=ip_id
                            )
                            if not pkt_bytes:
                                result_container["error"] = f"Segment {i} build failed"
                                return

                            # ✅ Жёсткая нормализация в threaded-ветке
                            pkt_bytes = self._strip_fin_and_normalize(pkt_bytes, original_packet, getattr(spec, "is_fake", False))

                            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                            try:
                                pkt.mark = self._INJECT_MARK
                            except Exception:
                                pass
                            packets_to_send.append((pkt, spec))

                        for i, (pkt, spec) in enumerate(packets_to_send):
                            allow_fix = not spec.corrupt_tcp_checksum
                            if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                                result_container["error"] = f"Segment {i} send failed in threaded mode"
                                return
                            # при необходимости можно добавить минимальные задержки здесь

                        result_container["success"] = True
                except Exception as e:
                    result_container["error"] = str(e)

            worker_thread = threading.Thread(target=send_worker, daemon=True)
            worker_thread.start()
            worker_thread.join(timeout=10.0)

            if worker_thread.is_alive():
                self.logger.error("Threaded packet sending timed out")
                return False

            if result_container["error"]:
                self.logger.error(f"Threaded packet sending failed: {result_container['error']}")
                return False

            return bool(result_container["success"])
        except Exception as e:
            self.logger.error(f"_send_tcp_segments_threaded error: {e}", exc_info=True)
            return False