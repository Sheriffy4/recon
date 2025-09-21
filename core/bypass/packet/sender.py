# File: core/bypass/packet/sender.py

import time
import logging
import pydivert
import struct  # <--- ДОБАВЛЕН ИМПОРТ
from typing import List, Optional, Tuple

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
            # ================== НАЧАЛО ИСПРАВЛЕНИЯ ==================
            # Ручное извлечение IP ID, т.к. pydivert.util.get_ip_id отсутствует
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            # =================== КОНЕЦ ИСПРАВЛЕНИЯ ===================
            
            for i, spec in enumerate(specs):
                ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                
                pkt_bytes = self.builder.build_tcp_segment(
                    original_packet, spec, window_div=window_div, ip_id=ip_id
                )

                if not pkt_bytes:
                    self.logger.error(f"Segment {i} build failed, aborting send sequence.")
                    return False

                # ИСПРАВЛЕНИЕ: Выбираем метод отправки в зависимости от флага
                allow_fix = not spec.corrupt_tcp_checksum
                if not self.safe_send(w, pkt_bytes, original_packet, allow_fix_checksums=allow_fix):
                    self.logger.error(f"Segment {i} send failed, aborting send sequence.")
                    return False

                if spec.delay_ms_after > 0:
                    time.sleep(spec.delay_ms_after / 1000.0)
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
            # ================== НАЧАЛО ИСПРАВЛЕНИЯ ==================
            # Ручное извлечение IP ID
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            # =================== КОНЕЦ ИСПРАВЛЕНИЯ ===================
            
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
                    try: pkt2.mark = self._INJECT_MARK
                    except Exception: pass
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
                    try: pkt2.mark = self._INJECT_MARK
                    except Exception: pass
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