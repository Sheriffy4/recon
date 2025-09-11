"""Packet sending functionality with platform abstraction."""

import time
import logging
import threading
from typing import List, Any, Tuple, Optional, Dict
from .builder import PacketBuilder
from .types import TCPSegmentSpec, UDPDatagramSpec


class PacketSender:
    """
    Responsible for safe packet transmission through diverter objects.
    Isolates platform-dependent sending logic.
    """

    def __init__(self, builder: PacketBuilder, logger: logging.Logger,
                 inject_mark: int = 0xC0DE, debug: bool = False):
        self.builder = builder
        self.logger = logger
        self.inject_mark = inject_mark
        self.debug = debug
        self._send_lock = threading.Lock()
        self._stats = {
            'tcp_sent': 0,
            'udp_sent': 0,
            'send_errors': 0,
            'timeouts': 0,
            'retries': 0
        }

    def send_tcp_segments(self, w: Any, original_packet: Any,
                         specs: List[TCPSegmentSpec],
                         window_div: int = 8,
                         ipid_step: int = 2048) -> bool:
        """
        Send multiple TCP segments based on specifications.

        Args:
            w: WinDivert handle
            original_packet: Original packet object
            specs: List of TCP segment specifications
            window_div: Window division factor
            ipid_step: IP ID increment step

        Returns:
            True if all segments sent successfully
        """
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big") if len(raw) > 6 else 0

            for i, spec in enumerate(specs):
                if not spec.payload and not spec.tcp_options:
                    continue  # Skip empty segments

                ip_id = (base_ip_id + i * ipid_step) & 0xFFFF

                # Build packet bytes
                pkt_bytes = self.builder.build_tcp_segment(raw, spec, window_div, ip_id)

                # Send packet
                if not self._safe_send(w, pkt_bytes, original_packet):
                    self.logger.error(f"Failed to send TCP segment {i+1}/{len(specs)}")
                    return False

                self._stats['tcp_sent'] += 1

                # Apply delay if specified
                if spec.delay_ms_after > 0:
                    time.sleep(spec.delay_ms_after / 1000.0)

            return True

        except Exception as e:
            self.logger.error(f"send_tcp_segments error: {e}", exc_info=self.debug)
            self._stats['send_errors'] += 1
            return False

    def send_udp_datagrams(self, w: Any, original_packet: Any,
                          items: List[Tuple[bytes, int]],
                          ipid_step: int = 2048) -> bool:
        """
        Send multiple UDP datagrams.

        Args:
            w: WinDivert handle
            original_packet: Original packet object
            items: List of (payload, delay_ms) tuples
            ipid_step: IP ID increment step

        Returns:
            True if all datagrams sent successfully
        """
        try:
            raw = bytes(original_packet.raw)
            base_ip_id = int.from_bytes(raw[4:6], "big") if len(raw) > 6 else 0

            for i, (data, delay_ms) in enumerate(items):
                if not data:
                    continue

                ip_id = (base_ip_id + i * ipid_step) & 0xFFFF

                # Create specification
                spec = UDPDatagramSpec(
                    payload=data,
                    delay_ms_after=delay_ms if i < len(items) - 1 else 0
                )

                # Build packet bytes
                pkt_bytes = self.builder.build_udp_datagram(raw, spec, ip_id)

                # Send packet
                if not self._safe_send(w, pkt_bytes, original_packet):
                    self.logger.error(f"Failed to send UDP datagram {i+1}/{len(items)}")
                    return False

                self._stats['udp_sent'] += 1

                # Apply delay if specified
                if spec.delay_ms_after > 0:
                    time.sleep(spec.delay_ms_after / 1000.0)

            return True

        except Exception as e:
            self.logger.error(f"send_udp_datagrams error: {e}", exc_info=self.debug)
            self._stats['send_errors'] += 1
            return False

    def send_fake_packet(self, w: Any, original_packet: Any,
                    fake_payload: bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    ttl: int = 2,
                    fooling: List[str] = None) -> bool:
        """
        Send a fake packet with specified fooling techniques.

        Args:
            w: WinDivert handle
            original_packet: Original packet object
            fake_payload: Fake payload to send
            ttl: TTL for fake packet
            fooling: List of fooling techniques ('badsum', 'md5sig', 'badseq')

        Returns:
            True if sent successfully
        """
        fooling = fooling or []

        # Build fake segment specification
        spec = TCPSegmentSpec(
            payload=fake_payload[:20],  # Limit fake payload size
            ttl=ttl,
            flags=0x18,  # PSH|ACK
            corrupt_tcp_checksum='badsum' in fooling,
            add_md5sig_option='md5sig' in fooling,
            seq_extra=-10000 if 'badseq' in fooling else 0
        )

        # Send as single segment
        return self.send_tcp_segments(w, original_packet, [spec])

    def _safe_send(self, w: Any, pkt_bytes: bytes, original_packet: Any) -> bool:
        """
        Safely send packet with retry logic for WinDivert.

        Args:
            w: WinDivert handle
            pkt_bytes: Packet bytes to send
            original_packet: Original packet for interface/direction info

        Returns:
            True if sent successfully
        """
        try:
            # Import platform-specific module
            import platform
            if platform.system() != "Windows":
                self.logger.warning("PacketSender only supports Windows currently")
                return False

            import pydivert

            # Create packet object
            pkt = pydivert.Packet(pkt_bytes, original_packet.interface,
                                original_packet.direction)

            # Mark packet to avoid re-capture
            try:
                pkt.mark = self.inject_mark
            except Exception:
                pass  # Mark not supported in this version

            # Send packet
            with self._send_lock:
                w.send(pkt)

            return True

        except OSError as e:
            if getattr(e, "winerror", 0) == 258:  # Timeout error
                self._stats['timeouts'] += 1
                self.logger.debug("WinDivert send timeout (258). Retrying once...")
                time.sleep(0.001)

                try:
                    # Retry with checksum recalculation
                    buf = bytearray(pkt_bytes)
                    try:
                        from pydivert.windivert import WinDivertHelper, WinDivertLayer
                        WinDivertHelper.calc_checksums(buf, WinDivertLayer.NETWORK)
                        pkt2 = pydivert.Packet(bytes(buf), original_packet.interface,
                                              original_packet.direction)
                    except ImportError:
                        # Helper not available, use original bytes
                        pkt2 = pydivert.Packet(pkt_bytes, original_packet.interface,
                                              original_packet.direction)

                    try:
                        pkt2.mark = self.inject_mark
                    except Exception:
                        pass

                    with self._send_lock:
                        w.send(pkt2)

                    self._stats['retries'] += 1
                    return True

                except Exception as e2:
                    self.logger.error(f"WinDivert retry failed: {e2}")
                    self._stats['send_errors'] += 1
                    return False
            else:
                self.logger.error(f"WinDivert send OS error: {e}")
                self._stats['send_errors'] += 1
                return False

        except Exception as e:
            self.logger.error(f"Unexpected send error: {e}", exc_info=self.debug)
            self._stats['send_errors'] += 1
            return False

    def is_injected(self, packet: Any) -> bool:
        """
        Check if packet is our own injection to avoid loops.

        Args:
            packet: Packet object to check

        Returns:
            True if packet was injected by us
        """
        try:
            pkt_mark = getattr(packet, "mark", 0)
            return pkt_mark == self.inject_mark
        except Exception:
            return False

    def get_stats(self) -> Dict[str, int]:
        """Get sending statistics."""
        return self._stats.copy()
