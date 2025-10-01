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
    """
    def __init__(self, builder: PacketBuilder, logger: logging.Logger, inject_mark: int):
        self.builder = builder
        self.logger = logger
        self._INJECT_MARK = inject_mark

    def send_tcp_segments(self, w, original_packet, specs, window_div=1, ipid_step=2048):
        try:
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            
            # Блокируем ретрансмит ОС на время инъекции
            with self._create_tcp_retransmission_blocker(original_packet) as blocker:
                # ⚡ CRITICAL: Даем блокировщику время на инициализацию
                if blocker and not isinstance(blocker, bool):
                    time.sleep(0.005)  # 5ms для гарантированного запуска
                    self.logger.debug("✅ Retransmission blocker initialized")
                
                packets_to_send = []
                
                # Сборка всех сегментов заранее (batch)
                for i, spec in enumerate(specs):
                    ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    pkt_bytes = self.builder.build_tcp_segment(
                        original_packet, spec, window_div=window_div, ip_id=ip_id
                    )
                    if not pkt_bytes:
                        self.logger.error(f"Segment {i} build failed")
                        return False
                        
                    pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                    
                    # ⚡ CRITICAL: Убедиться, что метка установлена
                    try:
                        pkt.mark = self._INJECT_MARK
                        self.logger.debug(f"Packet {i} marked with {self._INJECT_MARK}")
                    except Exception as e:
                        self.logger.warning(f"Failed to mark packet {i}: {e}")
                        
                    packets_to_send.append((pkt, spec))
                
                # Отправка с правильными задержками
                for i, (pkt, spec) in enumerate(packets_to_send):
                    packet_start = time.perf_counter()
                    allow_fix = not spec.corrupt_tcp_checksum
                    
                    # Логируем тип пакета и параметры — удобно сопоставлять с PCAP
                    packet_type = "FAKE" if getattr(spec, 'is_fake', False) else "REAL"
                    try:
                        plen = len(pkt.payload) if getattr(pkt, "payload", None) else 0
                    except Exception:
                        plen = 0
                    ttl_show = spec.ttl if spec.ttl is not None else "orig"
                    # Извлекаем seq/ack из сырых байт
                    try:
                        raw = pkt.raw
                        ip_hl = (raw[0] & 0x0F) * 4
                        seq_v = struct.unpack('!I', raw[ip_hl+4:ip_hl+8])[0]
                        ack_v = struct.unpack('!I', raw[ip_hl+8:ip_hl+12])[0]
                        seq_str = f"seq=0x{seq_v:08X} ack=0x{ack_v:08X}"
                    except Exception:
                        seq_str = "seq=?, ack=?"
                    self.logger.info(
                        f"📤 {packet_type} [{i+1}/{len(packets_to_send)}] "
                        f"dst={getattr(pkt,'dst_addr','?')}:{getattr(pkt,'dst_port','?')} "
                        f"len={plen} ttl={ttl_show} badsum={bool(spec.corrupt_tcp_checksum)} "
                        f"{seq_str}"
                    )
                    
                    if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                        self.logger.error(f"Segment {i} send failed")
                        return False
                    
                    # ⚡ CRITICAL: Добавляем задержку после фейкового пакета
                    if spec.delay_ms_after > 0:
                        delay_s = spec.delay_ms_after / 1000.0
                        self.logger.debug(f"⏱️ Delaying {spec.delay_ms_after}ms after packet {i+1}")
                        time.sleep(delay_s)
                
                return True
        except Exception as e:
            self.logger.error(f"send_tcp_segments error: {e}", exc_info=True)
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
        Создаёт WinDivert-контекст, который на время инъекции блокирует TCP-ретрансмиты ОС
        по этому соединению. Наши инъекции (mark) пропускаются.
        
        ИСПРАВЛЕННАЯ ВЕРСИЯ 2.0:
        1.  Устранена микро-гонка при старте с помощью threading.Event.
        2.  Фильтр возвращен к рабочему состоянию (без `mark`).
        3.  Проверка на `mark` возвращена в воркер.
        """
        blocker = None
        stop_event = threading.Event()
        # Этот Event по-прежнему нужен для устранения гонки состояний.
        start_event = threading.Event()
        
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
                args=(blocker, stop_event, start_event),
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
            try:
                stop_event.set()
            except Exception:
                pass
            if blocker:
                try:
                    blocker.close()
                    self.logger.debug("🛡️ TCP retransmission blocker closed")
                except Exception as e:
                    self.logger.debug(f"Error closing retransmission blocker: {e}")

    def _retransmission_blocker_worker(self, blocker, stop_event, start_event):
        """
        Воркер-блокировщик.
        
        ИСПРАВЛЕННАЯ ВЕРСИЯ 2.0:
        1.  Сигнализирует о готовности через start_event.
        2.  Возвращена проверка на `mark`, так как фильтр снова перехватывает всё.
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
                    blocked_count += 1
                    self.logger.debug(
                        f"🛡️ BLOCKED OS retransmit #{blocked_count}: "
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
        Оптимизированная отправка для батч-операций.
        """
        try:
            w.send(pkt)
            return True
        except OSError as e:
            if getattr(e, "winerror", None) == 258 and allow_fix_checksums:
                self.logger.debug("WinDivert batch send timeout (258). Retrying with checksum helper...")
                time.sleep(0.001)
                try:
                    buf = bytearray(pkt.raw)
                    from pydivert.windivert import WinDivertHelper, WinDivertLayer
                    WinDivertHelper.calc_checksums(buf, WinDivertLayer.NETWORK)
                    pkt2 = pydivert.Packet(bytes(buf), pkt.interface, pkt.direction)
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e2:
                    self.logger.error(f"WinDivert batch retry failed after 258: {e2}")
                    return False
            elif getattr(e, "winerror", None) == 258 and not allow_fix_checksums:
                self.logger.debug("WinDivert batch send timeout (258) on no-fix packet. Retrying without fix...")
                time.sleep(0.001)
                try:
                    pkt2 = pydivert.Packet(pkt.raw, pkt.interface, pkt.direction)
                    try:
                        pkt2.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    w.send(pkt2)
                    return True
                except Exception as e3:
                    self.logger.error(f"WinDivert batch no-fix retry failed after 258: {e3}")
                    return False
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