"""
TLS ServerHello detector for reliable DPI bypass success detection.

Monitors inbound traffic for TLS ServerHello packets to determine if an attack
successfully bypassed DPI, independent of curl/application-level success.
"""

from __future__ import annotations

import time
import logging
import threading
import struct
from typing import Optional

try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False


def _looks_like_tls_server_hello(payload: bytes) -> bool:
    """
    Robust TLS record parser to detect ServerHello.

    TLSPlaintext structure:
      ContentType(1) = 22 (handshake)
      Version(2) = 0x0300..0x0303 (TLS1.0..TLS1.2; TLS1.3 uses legacy 0x0303)
      Length(2)
    Handshake structure:
      msg_type(1) = 2 (server_hello)
      msg_len(3)

    Args:
        payload: TCP payload bytes

    Returns:
        True if payload appears to contain TLS ServerHello
    """
    # Need at least:
    # TLS record header (5) + handshake type (1) => 6 bytes
    if not payload or len(payload) < 6:
        return False

    # We scan for TLS Handshake record:
    #   ContentType = 0x16
    #   Version major = 0x03
    #   Version minor = 0x00..0x03 (TLS1.0..TLS1.2; TLS1.3 uses legacy 0x03 0x03)
    #   Length (2 bytes)
    #
    # Then inside record we expect Handshake header:
    #   msg_type (1) == 0x02 (ServerHello / HelloRetryRequest)
    #   msg_len (3 bytes) present (we validate bounds)
    n = len(payload)
    start = 0
    while True:
        idx = payload.find(b"\x16\x03", start)
        if idx < 0:
            return False
        # Need full TLS record header
        if idx + 5 > n:
            return False

        ver_minor = payload[idx + 2]
        if ver_minor > 0x03:
            start = idx + 1
            continue

        try:
            rec_len = struct.unpack("!H", payload[idx + 3 : idx + 5])[0]
        except Exception:
            start = idx + 1
            continue

        # Need at least handshake header (type+len3) inside record
        if rec_len < 4:
            start = idx + 1
            continue

        rec_end = idx + 5 + rec_len
        if rec_end > n:
            # Payload may be truncated; rolling buffer in detector helps, but if still not enough - skip this idx
            start = idx + 1
            continue

        hs_type = payload[idx + 5]
        if hs_type != 0x02:
            start = idx + 1
            continue

        # Validate handshake length fits inside record
        # Handshake header is: type(1) + len(3)
        try:
            hs_len = int.from_bytes(payload[idx + 6 : idx + 9], "big")
        except Exception:
            return True  # We already have strong evidence; avoid false negatives

        if hs_len <= (rec_len - 4):
            return True

        # If inconsistent, treat as non-match to avoid false positives
        start = idx + 1


class TLSServerHelloDetector:
    """
    Detector for TLS ServerHello packets on specific TCP flows.

    Used to reliably determine if a DPI bypass attack succeeded in getting
    a server response, even if the application-level connection (curl) times out.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize detector.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("TLSServerHelloDetector")

        if not PYDIVERT_AVAILABLE:
            self.logger.warning("pydivert not available - ServerHello detection disabled")

    def wait(
        self,
        *,
        target_ip: str,
        timeout_s: float = 12.0,
        target_port: int = 443,
        expected_dst_port: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        ready_event: Optional[threading.Event] = None,
    ) -> tuple[bool, dict[str, any]]:
        """
        Watches inbound packets from target_ip:target_port.
        Returns (ok, evidence).

        IMPORTANT:
        - Use SNIFF mode if available to avoid diverting packets.
        - If sniff is not available, we must forward packets immediately (send back),
          otherwise we break the connection and curl will timeout.

        Args:
            target_ip: Target server IP address
            timeout_s: Timeout in seconds (default 12.0)
            target_port: Target server port (default 443)
            expected_dst_port: Optional client ephemeral port to filter for specific flow
            stop_event: Optional threading.Event to stop detection early
            ready_event: Optional threading.Event to signal when detector is ready

        Returns:
            Tuple of (success: bool, evidence: dict)
        """
        if not PYDIVERT_AVAILABLE:
            self.logger.warning("⚠️ pydivert not available - cannot detect ServerHello")
            return False, {"error": "pydivert not available"}

        self.logger.info(
            f"🎯 ServerHello detector starting: target={target_ip}:{target_port}, timeout={timeout_s}s, expected_dst_port={expected_dst_port}"
        )

        # Build WinDivert filter
        # If we know the client port, make filter more specific
        if expected_dst_port is not None:
            flt = f"inbound and tcp and ip.SrcAddr == {target_ip} and tcp.SrcPort == {target_port} and tcp.DstPort == {expected_dst_port}"
        else:
            flt = f"inbound and tcp and ip.SrcAddr == {target_ip} and tcp.SrcPort == {target_port}"

        t_end = time.time() + float(timeout_s)

        flags = 0
        sniff_supported = False
        try:
            # pydivert exposes Flag.SNIFF in many builds
            flags = int(getattr(pydivert, "Flag").SNIFF)
            sniff_supported = True
        except Exception:
            flags = 0

        w = None
        packets_seen = 0  # Initialize before try block
        evidence: dict[str, any] = {"filter": flt, "sniff": sniff_supported}
        tail = b""  # rolling buffer for split TLS records

        try:
            self.logger.info(
                f"🔍 Starting ServerHello detection: target={target_ip}:{target_port}, timeout={timeout_s}s, sniff={sniff_supported}"
            )
            # WinDivert priority range: -1000 to 1000
            # Use priority 1000 (maximum) to ensure we see packets before any modifications
            priority = 1000 if sniff_supported else 0
            self.logger.info(f"🔧 Using WinDivert priority={priority} for ServerHello detection")

            try:
                w = pydivert.WinDivert(flt, priority=priority, flags=flags)
                w.open()
                self.logger.info(
                    f"✅ WinDivert opened for ServerHello detection with filter: {flt}"
                )

                # Signal that detector is ready to capture packets
                if ready_event is not None:
                    ready_event.set()
                    self.logger.debug(f"🚦 Detector ready signal sent")

            except OSError as e:
                if e.winerror == 87:  # ERROR_INVALID_PARAMETER
                    self.logger.error(
                        f"❌ WinDivert open failed with invalid parameter (priority={priority}, flags={flags})"
                    )
                    self.logger.error(
                        f"   This might be due to priority out of range or invalid flags"
                    )
                    # Try fallback with lower priority
                    self.logger.info(f"🔄 Retrying with priority=0 (fallback)")
                    priority = 0
                    w = pydivert.WinDivert(flt, priority=priority, flags=flags)
                    w.open()
                    self.logger.info(f"✅ WinDivert opened with fallback priority={priority}")

                    # Signal ready even after fallback
                    if ready_event is not None:
                        ready_event.set()
                        self.logger.debug(f"🚦 Detector ready signal sent (after fallback)")
                else:
                    raise

            packets_seen = 0

            # CRITICAL: pydivert 2.1.0 recv() does NOT support timeout parameter!
            # recv() blocks indefinitely, so we need to close handle from another thread to stop it

            # Create a timer thread that will close the handle after timeout
            def timeout_closer():
                time.sleep(timeout_s)
                if w is not None:
                    try:
                        w.close()
                        self.logger.debug(f"⏰ Timeout reached, closed WinDivert handle")
                    except Exception:
                        pass

            timeout_thread = threading.Thread(target=timeout_closer, daemon=True)
            timeout_thread.start()

            while True:
                if stop_event is not None and stop_event.is_set():
                    break

                try:
                    # recv() blocks until packet arrives or handle is closed
                    # Use larger buffer to handle coalesced packets
                    pkt = w.recv(0xFFFF)  # 65535 bytes - maximum IP packet size

                    packets_seen += 1
                    if packets_seen == 1:
                        self.logger.info(f"📦 First packet received! Total packets: {packets_seen}")
                    elif packets_seen % 10 == 0:
                        self.logger.debug(
                            f"📊 ServerHello detector: {packets_seen} packets seen so far"
                        )

                except Exception as e:  # nosec B112 - Expected errors when handle is closed
                    # recv() throws exception when handle is closed (timeout or stop_event)
                    if packets_seen == 0:
                        # Log first exception to diagnose
                        self.logger.debug(f"recv() stopped: {type(e).__name__}: {e}")
                    break

                if not pkt or not getattr(pkt, "tcp", None):
                    if (not sniff_supported) and pkt:
                        try:
                            w.send(pkt)
                        except (
                            Exception
                        ):  # nosec B110 - Ignore send errors, packet already captured
                            pass
                    continue

                # In non-sniff mode: always forward immediately
                if not sniff_supported:
                    try:
                        w.send(pkt)
                    except Exception:  # nosec B110 - Ignore send errors, packet already captured
                        pass

                pl = b""
                try:
                    if pkt.tcp.payload:
                        pl = bytes(pkt.tcp.payload)
                except Exception:
                    pl = b""

                if not pl:
                    continue

                # Debug: log first packets with payload to diagnose
                if packets_seen <= 30:
                    self.logger.debug(
                        "TCP %s:%s -> %s:%s payload_len=%d head=%s",
                        getattr(pkt, "src_addr", "?"),
                        getattr(pkt.tcp, "src_port", "?"),
                        getattr(pkt, "dst_addr", "?"),
                        getattr(pkt.tcp, "dst_port", "?"),
                        len(pl),
                        pl[:16].hex() if len(pl) >= 16 else pl.hex(),
                    )

                # CRITICAL FIX: Check current payload FIRST (ServerHello is at the START, not end!)
                if _looks_like_tls_server_hello(pl):
                    # Record dst_port (this is client's ephemeral port; useful for correlation)
                    try:
                        dst_port = pkt.tcp.dst_port
                    except Exception:
                        dst_port = None

                    # If we know client's ephemeral port, ignore ServerHello from other flows
                    if expected_dst_port is not None and dst_port is not None:
                        try:
                            if int(dst_port) != int(expected_dst_port):
                                continue
                        except Exception:  # nosec B110 - Ignore type conversion errors
                            pass

                    evidence.update(
                        {
                            "ts": time.time(),
                            "src_ip": getattr(pkt, "src_addr", None),
                            "dst_ip": getattr(pkt, "dst_addr", None),
                            "dst_port": dst_port,
                        }
                    )
                    self.logger.info("✅ TLS ServerHello detected in current payload: %s", evidence)
                    return True, evidence

                # Also check rolling buffer for split records (ServerHello spanning TCP segments)
                # Use BEGINNING of combined buffer, not end!
                combo = (tail + pl)[:2048]
                if _looks_like_tls_server_hello(combo):
                    # Record dst_port (this is client's ephemeral port; useful for correlation)
                    try:
                        dst_port = pkt.tcp.dst_port
                    except Exception:
                        dst_port = None

                    # If we know client's ephemeral port, ignore ServerHello from other flows
                    if expected_dst_port is not None and dst_port is not None:
                        try:
                            if int(dst_port) != int(expected_dst_port):
                                continue
                        except Exception:  # nosec B110 - Ignore type conversion errors
                            pass

                    evidence.update(
                        {
                            "ts": time.time(),
                            "src_ip": getattr(pkt, "src_addr", None),
                            "dst_ip": getattr(pkt, "dst_addr", None),
                            "dst_port": dst_port,
                        }
                    )
                    self.logger.info("✅ TLS ServerHello detected in rolling buffer: %s", evidence)
                    return True, evidence

                # Keep rolling buffer for next iteration (keep last 1024 bytes)
                tail = (tail + pl)[-1024:]

            self.logger.warning(
                f"⏱️ ServerHello detection timeout after {timeout_s}s, packets_seen={packets_seen}"
            )
            return False, evidence
        finally:
            try:
                if w is not None:
                    self.logger.info(
                        f"🔒 Closing ServerHello detector (packets_seen={packets_seen})"
                    )
                    w.close()
            except Exception:  # nosec B110 - Ignore cleanup errors
                pass
