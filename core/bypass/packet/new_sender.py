# File: core/bypass/packet/sender.py

import time
import logging
import pydivert
import struct  # <--- ДОБАВЛЕН ИМПОРТ
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
            # ================== НАЧАЛО ИСПРАВЛЕНИЯ ==================
            # Ручное извлечение IP ID, т.к. pydivert.util.get_ip_id отсутствует
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            # =================== КОНЕЦ ИСПРАВЛЕНИЯ ===================
            
            # TCP Retransmission Mitigation: Use blocking context and batch sending
            with self._create_tcp_retransmission_blocker(original_packet) as blocker:
                # Build all packets first for batch sending
                packets_to_send = []
                
                for i, spec in enumerate(specs):
                    ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    
                    pkt_bytes = self.builder.build_tcp_segment(
                        original_packet, spec, window_div=window_div, ip_id=ip_id
                    )

                    if not pkt_bytes:
                        self.logger.error(f"Segment {i} build failed, aborting send sequence.")
                        return False

                    # Create packet object for batch sending
                    pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                    try:
                        pkt.mark = self._INJECT_MARK
                    except Exception:
                        pass
                    
                    packets_to_send.append((pkt, spec))

                # Batch send all packets to minimize timing gaps
                self.logger.debug(f"🚀 Batch sending {len(packets_to_send)} TCP segments with retransmission blocking")
                
                for i, (pkt, spec) in enumerate(packets_to_send):
                    allow_fix = not spec.corrupt_tcp_checksum
                    if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                        self.logger.error(f"Segment {i} send failed, aborting send sequence.")
                        return False

                    # Only add delay between packets, not after the last one
                    if i < len(packets_to_send) - 1 and spec.delay_ms_after > 0:
                        time.sleep(spec.delay_ms_after / 1000.0)
                
                self.logger.debug(f"✅ Successfully sent {len(packets_to_send)} segments with TCP retransmission mitigation")
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

    @contextmanager
    def _create_tcp_retransmission_blocker(self, original_packet: "pydivert.Packet"):
        """
        Creates a WinDivert context that blocks TCP retransmissions from the OS
        during our packet injection to prevent interference.
        """
        blocker = None
        try:
            # Extract connection details for specific filtering
            src_ip = original_packet.src_addr
            dst_ip = original_packet.dst_addr
            src_port = original_packet.src_port
            dst_port = original_packet.dst_port
            
            # Create a very specific filter to catch only TCP retransmissions for this flow
            # Priority 1000 ensures this blocker has higher priority than the main capture
            filter_str = (
                f"outbound and tcp and "
                f"ip.SrcAddr == {src_ip} and ip.DstAddr == {dst_ip} and "
                f"tcp.SrcPort == {src_port} and tcp.DstPort == {dst_port} and "
                f"tcp.Rst == 0"  # Don't block RST packets
            )
            
            self.logger.debug(f"🛡️ Creating TCP retransmission blocker with filter: {filter_str}")
            
            # Open blocker with higher priority to intercept retransmissions
            blocker = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK, priority=1000)
            blocker.open()
            
            # Start a background thread to drop intercepted retransmissions
            stop_event = threading.Event()
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
            # If blocker creation fails, yield None and continue without blocking
            yield None
            
        finally:
            if blocker:
                try:
                    stop_event.set()
                    blocker.close()
                    self.logger.debug("🛡️ TCP retransmission blocker closed")
                except Exception as e:
                    self.logger.debug(f"Error closing retransmission blocker: {e}")

    def _retransmission_blocker_worker(self, blocker: "pydivert.WinDivert", stop_event: threading.Event):
        """
        Worker thread that drops TCP retransmissions intercepted by the blocker.
        """
        try:
            while not stop_event.is_set():
                try:
                    # Use a short timeout to allow checking stop_event
                    packet = blocker.recv(timeout=100)  # 100ms timeout
                    if packet:
                        # Drop the packet (don't send it) - this prevents OS retransmission
                        self.logger.debug(f"🛡️ Blocked OS TCP retransmission: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
                except Exception as e:
                    # Handle timeout (error code 258) and other WinDivert errors
                    if hasattr(e, 'args') and len(e.args) > 0 and e.args[0] == 258:  # Timeout
                        continue
                    elif "timeout" in str(e).lower() or "258" in str(e):  # Timeout by message
                        continue
                    else:
                        self.logger.debug(f"Blocker recv error: {e}")
                        break
                except Exception as e:
                    self.logger.debug(f"Blocker worker error: {e}")
                    break
        except Exception as e:
            self.logger.debug(f"Blocker worker thread error: {e}")

    def _batch_safe_send(self, w: "pydivert.WinDivert", pkt: "pydivert.Packet", allow_fix_checksums: bool = True) -> bool:
        """
        Optimized packet sending for batch operations.
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
        Async version of send_tcp_segments for improved performance.
        Uses threading to minimize blocking and improve responsiveness.
        """
        try:
            # Check if async WinDivert is available
            try:
                import asyncio
                # For now, we'll use threading as a fallback since async pydivert may not be available
                return self._send_tcp_segments_threaded(w, original_packet, specs, window_div, ipid_step)
            except ImportError:
                # Fall back to regular synchronous sending
                self.logger.debug("Asyncio not available, falling back to synchronous sending")
                return self.send_tcp_segments(w, original_packet, specs, window_div, ipid_step)
                
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
        """
        Threaded implementation for improved performance.
        Sends packets in a separate thread to minimize blocking.
        """
        try:
            base_ip_id = struct.unpack("!H", original_packet.raw[4:6])[0]
            
            # Use a thread to handle the actual sending
            result_container = {"success": False, "error": None}
            
            def send_worker():
                try:
                    with self._create_tcp_retransmission_blocker(original_packet) as blocker:
                        packets_to_send = []
                        
                        for i, spec in enumerate(specs):
                            ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                            
                            pkt_bytes = self.builder.build_tcp_segment(
                                original_packet, spec, window_div=window_div, ip_id=ip_id
                            )

                            if not pkt_bytes:
                                self.logger.error(f"Segment {i} build failed in threaded mode")
                                result_container["error"] = f"Segment {i} build failed"
                                return

                            pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                            try:
                                pkt.mark = self._INJECT_MARK
                            except Exception:
                                pass
                            
                            packets_to_send.append((pkt, spec))

                        # Send all packets with minimal delays
                        self.logger.debug(f"🚀 Threaded batch sending {len(packets_to_send)} TCP segments")
                        
                        for i, (pkt, spec) in enumerate(packets_to_send):
                            allow_fix = not spec.corrupt_tcp_checksum
                            if not self._batch_safe_send(w, pkt, allow_fix_checksums=allow_fix):
                                result_container["error"] = f"Segment {i} send failed in threaded mode"
                                return

                            if i < len(packets_to_send) - 1 and spec.delay_ms_after > 0:
                                time.sleep(spec.delay_ms_after / 1000.0)
                        
                        result_container["success"] = True
                        
                except Exception as e:
                    result_container["error"] = str(e)
            
            # Start the worker thread
            worker_thread = threading.Thread(target=send_worker, daemon=True)
            worker_thread.start()
            
            # Wait for completion with timeout
            worker_thread.join(timeout=10.0)  # 10 second timeout
            
            if worker_thread.is_alive():
                self.logger.error("Threaded packet sending timed out")
                return False
            
            if result_container["error"]:
                self.logger.error(f"Threaded packet sending failed: {result_container['error']}")
                return False
            
            if result_container["success"]:
                self.logger.debug("✅ Threaded packet sending completed successfully")
                return True
            else:
                self.logger.error("Threaded packet sending completed without success flag")
                return False
                
        except Exception as e:
            self.logger.error(f"_send_tcp_segments_threaded error: {e}", exc_info=True)
            return False