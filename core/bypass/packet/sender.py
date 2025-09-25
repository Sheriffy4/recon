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

    def send_tcp_segments(
        self,
        w: "pydivert.WinDivert",
        original_packet: "pydivert.Packet",
        specs: List[TCPSegmentSpec],
        window_div: int = 1,
        ipid_step: int = 2048
    ) -> bool:
        try:
            # Ручное извлечение IP ID
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]

            # Блокируем ретрансмит ОС на время инъекции
            with self._create_tcp_retransmission_blocker(original_packet):
                packets_to_send = []

                # Сборка всех сегментов заранее (batch)
                for i, spec in enumerate(specs):
                    ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    pkt_bytes = self.builder.build_tcp_segment(
                        original_packet, spec, window_div=window_div, ip_id=ip_id
                    )
                    if not pkt_bytes:
                        self.logger.error(f"Segment {i} build failed, aborting send sequence.")
                        return False

                    pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                    try:
                        pkt.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    packets_to_send.append((pkt, spec))

                self.logger.info(f"🚀 Batch sending {len(packets_to_send)} TCP segments")
                start_time = time.perf_counter()

                # Отправляем максимально быстро
                for i, (pkt, spec) in enumerate(packets_to_send):
                    packet_start = time.perf_counter()
                    allow_fix = not spec.corrupt_tcp_checksum
                    if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                        self.logger.error(f"Segment {i} send failed, aborting send sequence.")
                        return False
                    packet_time = (time.perf_counter() - packet_start) * 1000
                    self.logger.debug(f"Packet {i+1} sent in {packet_time:.2f}ms")

                    # Если понадобится — вернём минимальные задержки; пока шлём без пауз

                total_time = (time.perf_counter() - start_time) * 1000
                self.logger.info(
                    f"✅ Batch injection completed in {total_time:.2f}ms "
                    f"(avg: {total_time/len(packets_to_send):.2f}ms per packet)"
                )
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
        """
        blocker = None
        stop_event = threading.Event()
        try:
            src_ip = original_packet.src_addr
            dst_ip = original_packet.dst_addr
            src_port = original_packet.src_port
            dst_port = original_packet.dst_port

            # Узкий фильтр на конкретный поток. Остальное решаем в воркере.
            filter_str = (
                f"outbound and tcp and "
                f"ip.SrcAddr == {src_ip} and ip.DstAddr == {dst_ip} and "
                f"tcp.SrcPort == {src_port} and tcp.DstPort == {dst_port} and "
                f"tcp.Rst == 0"
            )

            self.logger.debug(f"🛡️ Creating TCP retransmission blocker with filter: {filter_str}")

            # Высокий приоритет (меньше число = выше приоритет), выше, чем основной 1000
            blocker = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK, priority=-100)
            blocker.open()

            # Фоновой поток, который отфильтрует только OS data
            blocker_thread = threading.Thread(
                target=self._retransmission_blocker_worker,
                args=(blocker, stop_event),
                daemon=True
            )
            blocker_thread.start()

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

    def _retransmission_blocker_worker(self, blocker: "pydivert.WinDivert", stop_event: threading.Event):
        """
        Дропает потенциальные TCP-повторные передачи ОС; наши инъекции (mark) пропускает.
        """
        try:
            while not stop_event.is_set():
                try:
                    # Небольшой таймаут, чтобы проверять stop_event
                    packet = blocker.recv(timeout=100)  # 100 ms
                    if not packet:
                        continue

                    # 1) Наши инъекции? Пропустить.
                    if getattr(packet, "mark", 0) == self._INJECT_MARK:
                        try:
                            blocker.send(packet)
                        except Exception:
                            pass
                        continue

                    # 2) Служебные TCP без payload (чистые ACK) — пропускаем
                    if not packet.payload or len(packet.payload) == 0:
                        try:
                            blocker.send(packet)
                        except Exception:
                            pass
                        continue

                    # 3) SYN/FIN/RST — пропускаем
                    if packet.tcp and (packet.tcp.syn or packet.tcp.fin or packet.tcp.rst):
                        try:
                            blocker.send(packet)
                        except Exception:
                            pass
                        continue

                    # 4) Иначе — это исходящие TCP-данные от ОС по этому потоку: дропаем
                    self.logger.debug(
                        f"🛡️ Dropped OS TCP data: {packet.src_addr}:{packet.src_port} -> "
                        f"{packet.dst_addr}:{packet.dst_port} (len={len(packet.payload) if packet.payload else 0})"
                    )

                except Exception as e:
                    # WinDivert timeout (258) — ок, продолжаем
                    if hasattr(e, 'args') and e.args and e.args[0] == 258:
                        continue
                    if "timeout" in str(e).lower() or "258" in str(e):
                        continue
                    self.logger.debug(f"Blocker recv error: {e}")
                    break
        except Exception as e:
            self.logger.debug(f"Blocker worker thread error: {e}")
            
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