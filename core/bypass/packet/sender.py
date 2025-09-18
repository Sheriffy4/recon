import time
import logging
from typing import List, Any, Tuple

class PacketSender:
    def __init__(self, builder, logger: logging.Logger, inject_mark: int):
        self.builder = builder
        self.logger = logger
        self.inject_mark = inject_mark

    def safe_send(self, w: Any, pkt_bytes: bytes, original_packet: Any) -> bool:
        try:
            import pydivert
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
            try:
                pkt.mark = self.inject_mark
            except Exception:
                pass
            w.send(pkt)
            return True
        except OSError as e:
            if getattr(e, "winerror", None) == 258:
                self.logger.debug("WinDivert send timeout (258). Retrying once...")
                time.sleep(0.001)
                try:
                    w.send(pkt)
                    return True
                except Exception as e2:
                    self.logger.error(f"WinDivert retry failed after 258: {e2}")
                    return False
            self.logger.error(f"WinDivert send error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected send error: {e}")
            return False

    def send_tcp_segments(self, w: Any, original_packet: Any, specs: List[Any], window_div: int, ipid_step: int) -> bool:
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big")
            try:
                self.logger.debug("PacketSender specs summary: " + ", ".join([f"#{i}(ttl={getattr(s,'ttl',None)},flags={hex(getattr(s,'flags',0))},seq_extra={getattr(s,'seq_extra',0)},bad={getattr(s,'corrupt_tcp_checksum',False)})" for i,s in enumerate(specs)]))
            except Exception: pass
            for i, spec in enumerate(specs):
                ip_id = (base_ip_id + i * int(ipid_step)) & 0xFFFF
                pkt = self.builder.build_tcp_segment(raw, spec, window_div=window_div, ip_id=ip_id)
                if not self.safe_send(w, pkt, original_packet):
                    return False
                if getattr(spec, "delay_ms_after", 0) and i < len(specs) - 1:
                    time.sleep(spec.delay_ms_after / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_tcp_segments error: {e}", exc_info=True)
            return False

    def send_udp_datagrams(self, w: Any, original_packet: Any, items: List[Tuple[bytes, int]], ipid_step: int) -> bool:
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big")
            for i, item in enumerate(items):
                if isinstance(item, tuple):
                    data = item[0]; delay_ms = int(item[1]) if len(item) >= 2 else 0
                else:
                    data = item; delay_ms = 0
                if not data:
                    continue
                ip_id = (base_ip_id + i * int(ipid_step)) & 0xFFFF
                pkt = self.builder.build_udp_datagram(raw, data, ip_id=ip_id)
                if not self.safe_send(w, pkt, original_packet):
                    return False
                if i < len(items) - 1 and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            return True
        except Exception as e:
            self.logger.error(f"send_udp_datagrams error: {e}", exc_info=True)
            return False
