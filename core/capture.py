# recon/core/capture.py

import time
import logging
import contextlib
import threading
import platform
import queue
from typing import List, Tuple, Generator, Optional

# Отключаем лишний вывод от scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import AsyncSniffer, Packet as ScapyPacket
from scapy.config import conf

# Важная настройка для Windows и общего поведения
conf.verb = 0

# PyDivert support
try:
    import pydivert
    from pydivert.packet import Direction

    PYDIVERT_AVAILABLE = True and platform.system() == "Windows"
except ImportError:
    PYDIVERT_AVAILABLE = False
    pydivert = None
    Direction = None

LOG = logging.getLogger("capture")

# Enhanced error handling constants
COMMON_PYDIVERT_ERRORS = {
    "87": "Invalid parameter - Check filter syntax and ensure WinDivert driver is properly installed",
    "5": "Access denied - Run as Administrator to use PyDivert",
    "2": "File not found - WinDivert driver not found or not installed",
    "1275": "Driver not loaded - WinDivert driver failed to load",
    "577": "Invalid address - Network interface or address issue",
    "1814": "Resource not available - Network resource temporarily unavailable",
}


def _get_error_message(error_str: str) -> str:
    """
    Get a user-friendly error message for common PyDivert errors.

    Args:
        error_str: The error string from the exception

    Returns:
        User-friendly error message with troubleshooting hints
    """
    error_lower = error_str.lower()

    # Check for specific Windows error codes
    for code, message in COMMON_PYDIVERT_ERRORS.items():
        if f"[winerror {code}]" in error_lower or f"error {code}" in error_lower:
            return f"WinError {code}: {message}"

    # Check for common error patterns
    if "parameter" in error_lower and "invalid" in error_lower:
        return "Invalid parameter - Check filter syntax and ensure proper WinDivert installation"
    elif "access" in error_lower and "denied" in error_lower:
        return "Access denied - Administrator privileges required for packet capture"
    elif "driver" in error_lower:
        return "Driver issue - WinDivert driver not loaded or corrupted"
    elif "timeout" in error_lower:
        return "Operation timeout - Network or system resource issue"
    elif "handle" in error_lower and ("invalid" in error_lower or "closed" in error_lower):
        return "Handle error - WinDivert handle was closed or became invalid"
    else:
        return f"PyDivert error: {error_str}"


def _log_packet_details(packet, description: str, log_level: int = logging.DEBUG) -> None:
    """
    Log detailed packet information for debugging purposes.

    Args:
        packet: Scapy packet to analyze
        description: Description of the packet context
        log_level: Logging level to use
    """
    if not LOG.isEnabledFor(log_level):
        return

    try:
        LOG.log(log_level, f"=== {description} ===")

        if hasattr(packet, "src") and hasattr(packet, "dst"):
            LOG.log(log_level, f"  IP: {packet.src} -> {packet.dst}")

        if hasattr(packet, "sport") and hasattr(packet, "dport"):
            LOG.log(log_level, f"  TCP: {packet.sport} -> {packet.dport}")

        if hasattr(packet, "flags"):
            LOG.log(log_level, f"  Flags: {packet.flags}")

        if hasattr(packet, "seq") and hasattr(packet, "ack"):
            LOG.log(log_level, f"  Seq/Ack: {packet.seq}/{packet.ack}")

        packet_len = len(bytes(packet)) if packet else 0
        LOG.log(log_level, f"  Length: {packet_len} bytes")

        # Log payload preview if present
        if hasattr(packet, "load") and packet.load:
            payload_preview = (
                packet.load[:32].hex() if len(packet.load) >= 32 else packet.load.hex()
            )
            LOG.log(log_level, f"  Payload preview: {payload_preview}...")

    except Exception as e:
        LOG.debug(f"Error logging packet details: {e}")


def _log_operation_stats(operation: str, start_time: float, success: bool, **kwargs) -> None:
    """
    Log operation statistics for performance monitoring.

    Args:
        operation: Name of the operation
        start_time: Operation start time (from time.perf_counter())
        success: Whether the operation succeeded
        **kwargs: Additional statistics to log
    """
    try:
        elapsed = time.perf_counter() - start_time
        status = "SUCCESS" if success else "FAILED"

        stats_str = f"{operation} {status} in {elapsed:.3f}s"
        if kwargs:
            stats_parts = [f"{k}={v}" for k, v in kwargs.items()]
            stats_str += f" ({', '.join(stats_parts)})"

        LOG.info(stats_str)

    except Exception as e:
        LOG.debug(f"Error logging operation stats: {e}")


def _test_pydivert_availability() -> bool:
    """
    Test if PyDivert is actually working by trying to create a simple handle.

    Returns:
        True if PyDivert is working, False otherwise
    """
    if not PYDIVERT_AVAILABLE:
        LOG.debug("PyDivert not available - module not imported or not on Windows")
        return False

    start_time = time.perf_counter()

    try:
        LOG.debug("Testing PyDivert availability with simple TCP filter...")

        # Try to create a simple WinDivert handle
        test_handle = pydivert.WinDivert("tcp")
        test_handle.open()
        test_handle.close()

        _log_operation_stats("PyDivert availability test", start_time, True)
        LOG.debug("PyDivert is available and working")
        return True

    except Exception as e:
        error_msg = _get_error_message(str(e))
        LOG.warning(f"PyDivert availability test failed: {error_msg}")

        # Log specific troubleshooting advice based on error type
        error_str = str(e).lower()
        if "87" in error_str or "parameter" in error_str:
            LOG.info(
                "Troubleshooting: Ensure WinDivert is properly installed and filter syntax is correct"
            )
        elif "access" in error_str or "denied" in error_str:
            LOG.info("Troubleshooting: Run the application as Administrator to use PyDivert")
        elif "driver" in error_str:
            LOG.info(
                "Troubleshooting: Reinstall WinDivert or check if antivirus is blocking the driver"
            )

        _log_operation_stats("PyDivert availability test", start_time, False, error=error_msg)
        return False


def _convert_bpf_to_windivert(bpf_filter: str) -> str:
    """
    Convert common BPF filter expressions to WinDivert format.

    Args:
        bpf_filter: BPF-style filter expression

    Returns:
        WinDivert-compatible filter expression
    """
    import re
    import socket

    # Helper function to resolve hostname to IP if needed
    def resolve_host_value(host_value):
        """Resolve hostname to IP address, or return the IP if already an IP."""
        # Remove trailing dots from hostnames
        host_value = host_value.rstrip(".")

        # Check if it's already an IP address
        try:
            socket.inet_aton(host_value)
            return host_value
        except socket.error:
            # It's a hostname, try to resolve it
            try:
                ip_address = socket.gethostbyname(host_value)
                LOG.debug(f"Resolved hostname {host_value} to {ip_address} for filter")
                return ip_address
            except socket.error as e:
                LOG.warning(f"Could not resolve hostname {host_value} in filter: {e}")
                # Return None to indicate resolution failed
                return None

    # Start with the original filter
    windivert_filter = bpf_filter

    # Handle "tcp and host <hostname/ip>" pattern
    def replace_tcp_host(match):
        host_value = match.group(1)
        ip_address = resolve_host_value(host_value)
        if ip_address:
            return f"tcp and (ip.SrcAddr == {ip_address} or ip.DstAddr == {ip_address})"
        else:
            return "false"  # Filter that matches nothing

    windivert_filter = re.sub(
        r"tcp and host ([^\s]+)",
        replace_tcp_host,
        windivert_filter,
        flags=re.IGNORECASE,
    )

    # Handle "udp and host <hostname/ip>" pattern
    def replace_udp_host(match):
        host_value = match.group(1)
        ip_address = resolve_host_value(host_value)
        if ip_address:
            return f"udp and (ip.SrcAddr == {ip_address} or ip.DstAddr == {ip_address})"
        else:
            return "false"  # Filter that matches nothing

    windivert_filter = re.sub(
        r"udp and host ([^\s]+)",
        replace_udp_host,
        windivert_filter,
        flags=re.IGNORECASE,
    )

    # Handle standalone "host <hostname/ip>" pattern (not preceded by tcp/udp)
    def replace_host_only(match):
        host_value = match.group(1)
        ip_address = resolve_host_value(host_value)
        if ip_address:
            return f"ip.SrcAddr == {ip_address} or ip.DstAddr == {ip_address}"
        else:
            return "false"  # Filter that matches nothing

    windivert_filter = re.sub(
        r"(?<!tcp )(?<!udp )host ([^\s]+)",
        replace_host_only,
        windivert_filter,
        flags=re.IGNORECASE,
    )

    # Convert remaining BPF patterns to WinDivert syntax
    conversions = {
        r"tcp and port (\d+)": r"tcp.DstPort == \1 or tcp.SrcPort == \1",
        r"udp and port (\d+)": r"udp.DstPort == \1 or udp.SrcPort == \1",
        r"port (\d+)": r"tcp.DstPort == \1 or tcp.SrcPort == \1 or udp.DstPort == \1 or udp.SrcPort == \1",
        r"src port (\d+)": r"tcp.SrcPort == \1 or udp.SrcPort == \1",
        r"dst port (\d+)": r"tcp.DstPort == \1 or udp.DstPort == \1",
    }

    for bpf_pattern, windivert_pattern in conversions.items():
        windivert_filter = re.sub(
            bpf_pattern, windivert_pattern, windivert_filter, flags=re.IGNORECASE
        )

    return windivert_filter


class PacketQueueProcessor:
    """Thread-safe packet queue processor for moving packets from queue to lists."""

    def __init__(
        self,
        packet_queue: queue.Queue,
        packets_list: List,
        timestamps_list: List,
        stop_event: threading.Event,
    ):
        """
        Initialize packet queue processor.

        Args:
            packet_queue: Thread-safe queue containing captured packets
            packets_list: List to store processed packets
            timestamps_list: List to store packet timestamps
            stop_event: Event to signal processor to stop
        """
        self.packet_queue = packet_queue
        self.packets_list = packets_list
        self.timestamps_list = timestamps_list
        self.stop_event = stop_event
        self.processor_thread = None
        self.is_running = False
        self._error_count = 0
        self._max_errors = 10  # Maximum consecutive errors before stopping

    def start(self) -> None:
        """Start the queue processor thread."""
        if self.is_running:
            LOG.warning("PacketQueueProcessor is already running")
            return

        self.processor_thread = threading.Thread(target=self.run, daemon=True)
        self.is_running = True
        self.processor_thread.start()

        # Give the thread a moment to initialize and check for immediate failures
        time.sleep(0.05)

        # Check if thread is still alive and running
        if not self.processor_thread.is_alive() or not self.is_running:
            self.is_running = False
            raise RuntimeError("PacketQueueProcessor thread failed to start or crashed immediately")

        LOG.debug("PacketQueueProcessor started")

    def run(self) -> None:
        """Main processor thread function for moving packets from queue to lists."""
        try:
            LOG.debug("PacketQueueProcessor thread started successfully")

            # Validate initialization parameters
            if self.packets_list is None:
                raise ValueError("packets_list is None")
            if self.timestamps_list is None:
                raise ValueError("timestamps_list is None")
            if self.packet_queue is None:
                raise ValueError("packet_queue is None")
            if self.stop_event is None:
                raise ValueError("stop_event is None")

            LOG.debug("PacketQueueProcessor initialization validation passed")

            while not self.stop_event.is_set() or not self.packet_queue.empty():
                try:
                    # Get packet from queue with timeout
                    packet, timestamp = self.packet_queue.get(timeout=0.1)

                    # Add packet and timestamp to lists (thread-safe operation)
                    self.packets_list.append(packet)
                    self.timestamps_list.append(timestamp)

                    # Reset error count on successful processing
                    self._error_count = 0

                    # Mark task as done for queue
                    self.packet_queue.task_done()

                except queue.Empty:
                    # Timeout occurred - continue checking stop event
                    continue

                except Exception as e:
                    self._error_count += 1
                    LOG.debug(f"PacketQueueProcessor error: {e}")

                    # Stop processing if too many consecutive errors
                    if self._error_count >= self._max_errors:
                        LOG.error(
                            f"PacketQueueProcessor stopping due to {self._max_errors} consecutive errors"
                        )
                        break

                    time.sleep(0.01)  # Brief pause to prevent tight error loop

        except Exception as e:
            LOG.error(f"PacketQueueProcessor critical error: {e}")
            # Set is_running to False immediately on critical error
            self.is_running = False
        finally:
            self._cleanup_remaining_packets()
            self.is_running = False
            LOG.debug("PacketQueueProcessor stopped")

    def stop(self) -> None:
        """Stop the queue processor and cleanup resources."""
        if not self.is_running:
            return

        LOG.debug("Stopping PacketQueueProcessor")
        self.stop_event.set()

        # Wait for processor thread to finish gracefully
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=2.0)
            if self.processor_thread.is_alive():
                LOG.warning("PacketQueueProcessor thread did not stop gracefully")

        self._cleanup_remaining_packets()
        self.is_running = False
        LOG.debug("PacketQueueProcessor stopped")

    def _cleanup_remaining_packets(self) -> None:
        """Process any remaining packets in the queue during cleanup."""
        processed_count = 0
        try:
            while not self.packet_queue.empty():
                try:
                    packet, timestamp = self.packet_queue.get_nowait()
                    self.packets_list.append(packet)
                    self.timestamps_list.append(timestamp)
                    self.packet_queue.task_done()
                    processed_count += 1
                except queue.Empty:
                    break
                except Exception as e:
                    LOG.debug(f"Error processing remaining packet during cleanup: {e}")
                    break

            if processed_count > 0:
                LOG.debug(f"Processed {processed_count} remaining packets during cleanup")

        except Exception as e:
            LOG.debug(f"Error during packet queue cleanup: {e}")

    def get_stats(self) -> dict:
        """Get processor statistics."""
        return {
            "is_running": self.is_running,
            "queue_size": self.packet_queue.qsize(),
            "packets_processed": len(self.packets_list),
            "error_count": self._error_count,
        }


class PyDivertCaptureWorker:
    """Thread-safe packet capture worker using PyDivert."""

    def __init__(self, filter_expr: str, packet_queue: queue.Queue, stop_event: threading.Event):
        """
        Initialize PyDivert capture worker.

        Args:
            filter_expr: WinDivert filter expression
            packet_queue: Thread-safe queue for captured packets
            stop_event: Event to signal worker to stop
        """
        self.filter_expr = filter_expr
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.windivert_handle = None
        self.worker_thread = None
        self.is_running = False

    def start(self) -> None:
        """Start the capture worker thread."""
        if self.is_running:
            LOG.warning("PyDivert capture worker is already running")
            return

        self.worker_thread = threading.Thread(target=self.run, daemon=True)
        self.is_running = True
        self.worker_thread.start()
        LOG.debug(f"PyDivert capture worker started with filter: '{self.filter_expr}'")

    def run(self) -> None:
        """Main worker thread function for packet capture."""
        try:
            # Create WinDivert handle with proper error handling
            self._create_windivert_handle()

            while not self.stop_event.is_set():
                try:
                    # Use non-blocking packet reception with threading
                    packet = self._recv_packet_nonblocking()
                    if packet:
                        # Convert PyDivert packet to Scapy format with error handling
                        scapy_packet = self._convert_packet_to_scapy(packet)
                        if scapy_packet:
                            timestamp = time.perf_counter()
                            self.packet_queue.put((scapy_packet, timestamp))

                except Exception as e:
                    if (
                        not self.stop_event.is_set()
                    ):  # Only log if we're still supposed to be capturing
                        LOG.debug(f"PyDivert capture error: {e}")
                    time.sleep(0.01)  # Brief pause to prevent tight error loop

        except Exception as e:
            LOG.error(f"PyDivert capture worker error: {e}")
            # Set is_running to False immediately on initialization error
            self.is_running = False
        finally:
            self._cleanup_resources()
            self.is_running = False

    def stop(self) -> None:
        """Stop the capture worker and cleanup resources."""
        if not self.is_running:
            return

        LOG.debug("Stopping PyDivert capture worker")
        self.stop_event.set()

        # Wait for worker thread to finish gracefully
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
            if self.worker_thread.is_alive():
                LOG.warning("PyDivert capture worker thread did not stop gracefully")

        self._cleanup_resources()
        self.is_running = False
        LOG.debug("PyDivert capture worker stopped")

    def _create_windivert_handle(self) -> None:
        """Create and open WinDivert handle with comprehensive error handling."""
        start_time = time.perf_counter()

        try:
            LOG.debug(f"Creating WinDivert handle with filter: '{self.filter_expr}'")

            # Validate filter expression before creating handle
            if not self.filter_expr or not self.filter_expr.strip():
                raise ValueError("Empty or invalid filter expression")

            # Пробуем валидировать и упрощать фильтр перед открытием
            try:
                from core.windivert_filter import WinDivertFilterGenerator

                gen = WinDivertFilterGenerator()
                ok, err = gen.validate_syntax(self.filter_expr)
                if not ok:
                    LOG.warning(f"Filter syntax warning: {err}. Trying progressive candidates.")
                    # Попробуем построить кандидаты по портам из фильтра (простое извлечение) и без IP
                    import re

                    ports = [
                        int(p) for p in re.findall(r"tcp\.DstPort\s*==\s*(\d+)", self.filter_expr)
                    ]
                    ports = ports or [80, 443]
                    candidates = gen.progressive_candidates(
                        target_ports=ports,
                        direction="outbound",
                        protocols=("tcp",),
                    )
                else:
                    candidates = [self.filter_expr]
                    # Если длина слишком большая, добавим упрощения
                    if not gen._is_valid_length(self.filter_expr):
                        LOG.warning("Filter too long, using progressive simplification")
                        import re

                        ports = [
                            int(p)
                            for p in re.findall(r"tcp\.DstPort\s*==\s*(\d+)", self.filter_expr)
                        ]
                        ports = ports or [80, 443]
                        candidates = gen.progressive_candidates(
                            target_ports=ports,
                            direction="outbound",
                            protocols=("tcp",),
                        )
            except Exception as ve:
                LOG.debug(f"Filter generator validation exception: {ve}")
                candidates = [self.filter_expr]

            last_error = None
            handle = None
            for cand in candidates:
                try:
                    handle = pydivert.WinDivert(cand)
                    handle.open()
                    self.filter_expr = cand  # зафиксировать реальный используемый фильтр
                    break
                except Exception as e:
                    last_error = e
                    handle = None
                    LOG.warning(f"Failed to open WinDivert with candidate filter '{cand}': {e}")
            if handle is None:
                # Финальный fallback — безопасный общий
                simple_filter = "outbound and tcp"
                LOG.info(f"Trying simplified filter: {simple_filter}")
                handle = pydivert.WinDivert(simple_filter)
                handle.open()
                self.filter_expr = simple_filter

            # Сохранить handle
            self.windivert_handle = handle

            _log_operation_stats(
                "WinDivert handle creation", start_time, True, filter=self.filter_expr
            )
            LOG.debug(f"WinDivert handle created successfully with filter: '{self.filter_expr}'")

        except Exception as e:
            error_msg = _get_error_message(str(e))
            LOG.error(f"Failed to create WinDivert handle: {error_msg}")

            # Log detailed troubleshooting information
            error_str = str(e).lower()
            if "87" in error_str or "parameter" in error_str:
                LOG.error(f"Filter validation failed for: '{self.filter_expr}'")
                LOG.info("Common filter issues:")
                LOG.info("  - Check syntax: use 'tcp.DstPort == 80' not 'dst port 80'")
                LOG.info("  - Ensure proper boolean operators: 'and', 'or', 'not'")
                LOG.info("  - Validate IP addresses and port ranges")
            elif "access" in error_str or "denied" in error_str:
                LOG.info("Administrator privileges required for packet capture")
                LOG.info("  - Right-click and 'Run as Administrator'")
                LOG.info("  - Or run from elevated command prompt")
            elif "driver" in error_str:
                LOG.info("WinDivert driver issues detected")
                LOG.info("  - Reinstall PyDivert: pip uninstall pydivert && pip install pydivert")
                LOG.info("  - Check if antivirus is blocking WinDivert.sys")
                LOG.info("  - Ensure Windows version compatibility")

            _log_operation_stats(
                "WinDivert handle creation",
                start_time,
                False,
                filter=self.filter_expr,
                error=error_msg,
            )
            raise

    def _recv_packet_nonblocking(self) -> Optional["pydivert.Packet"]:
        """
        Receive packet using non-blocking approach with threading and enhanced error handling.

        Returns:
            PyDivert packet or None if timeout/error occurred
        """
        packet_result = queue.Queue()
        recv_active = threading.Event()
        recv_active.set()

        def recv_thread():
            """Thread to handle blocking recv() call with comprehensive error handling."""
            thread_start = time.perf_counter()

            try:
                if recv_active.is_set() and self.windivert_handle:
                    LOG.debug("Starting packet reception...")

                    # Remove timeout parameter - PyDivert recv() doesn't support it
                    packet = self.windivert_handle.recv()  # This blocks until packet arrives

                    if recv_active.is_set():  # Check again to avoid race condition
                        recv_time = time.perf_counter() - thread_start
                        LOG.debug(f"Packet received in {recv_time:.3f}s")

                        # Log packet details for debugging
                        if LOG.isEnabledFor(logging.DEBUG):
                            try:
                                packet_info = {
                                    "direction": ("inbound" if packet.is_inbound else "outbound"),
                                    "size": (
                                        len(packet.raw) if hasattr(packet, "raw") else "unknown"
                                    ),
                                    "protocol": ("TCP" if hasattr(packet, "tcp") else "other"),
                                }
                                LOG.debug(f"Packet details: {packet_info}")
                            except Exception as detail_error:
                                LOG.debug(f"Could not log packet details: {detail_error}")

                        packet_result.put(("packet", packet))
                    else:
                        LOG.debug("Packet received but capture was stopped")

            except Exception as e:
                if recv_active.is_set():
                    error_msg = _get_error_message(str(e))
                    LOG.debug(f"PyDivert recv error: {error_msg}")

                    # Log specific error patterns for troubleshooting
                    error_str = str(e).lower()
                    if "handle" in error_str and ("invalid" in error_str or "closed" in error_str):
                        LOG.warning("WinDivert handle became invalid during packet reception")
                    elif "timeout" in error_str:
                        LOG.debug("Packet reception timeout (expected behavior)")
                    elif "access" in error_str:
                        LOG.error(
                            "Access denied during packet reception - check administrator privileges"
                        )

                    packet_result.put(("error", error_msg))

        # Start recv in separate thread
        recv_worker = threading.Thread(target=recv_thread, daemon=True, name="PyDivert-Recv")
        recv_worker.start()

        # Wait for result with timeout using queue.Queue
        try:
            result_type, result_data = packet_result.get(timeout=0.1)
            recv_active.clear()  # Signal recv thread to stop

            if result_type == "packet" and result_data:
                return result_data
            elif result_type == "error":
                # Error already logged in recv_thread
                return None

        except queue.Empty:
            # Timeout occurred - this is normal behavior
            recv_active.clear()
            LOG.debug("Packet reception timeout (no packets available)")
            return None

    def _convert_packet_to_scapy(self, pydivert_packet: "pydivert.Packet") -> Optional[ScapyPacket]:
        """
        Convert PyDivert packet to Scapy format with comprehensive error handling.

        Args:
            pydivert_packet: PyDivert packet to convert

        Returns:
            Scapy packet or None if conversion failed
        """
        conversion_start = time.perf_counter()

        try:
            # Validate input packet
            if not pydivert_packet:
                LOG.debug("Cannot convert None packet")
                return None

            if not hasattr(pydivert_packet, "raw"):
                LOG.debug("PyDivert packet missing raw data attribute")
                return None

            raw_data = pydivert_packet.raw
            if not raw_data:
                LOG.debug("PyDivert packet has empty raw data")
                return None

            # Log packet conversion details for debugging
            if LOG.isEnabledFor(logging.DEBUG):
                packet_size = len(raw_data)
                direction = "inbound" if pydivert_packet.is_inbound else "outbound"
                LOG.debug(f"Converting {direction} packet ({packet_size} bytes)")

            # Convert PyDivert packet to Scapy packet for compatibility
            scapy_packet = ScapyPacket(raw_data)

            # Validate the converted packet
            if not scapy_packet:
                LOG.debug("Scapy packet conversion resulted in None")
                return None

            # Log successful conversion details
            conversion_time = time.perf_counter() - conversion_start
            if LOG.isEnabledFor(logging.DEBUG):
                _log_packet_details(scapy_packet, "Converted packet", logging.DEBUG)
                LOG.debug(f"Packet conversion completed in {conversion_time:.4f}s")

            return scapy_packet

        except Exception as e:
            conversion_time = time.perf_counter() - conversion_start
            error_msg = str(e)

            LOG.debug(f"Packet conversion failed after {conversion_time:.4f}s: {error_msg}")

            # Log specific error patterns for troubleshooting
            if "malformed" in error_msg.lower() or "invalid" in error_msg.lower():
                LOG.debug("Packet appears to be malformed or corrupted")
            elif "memory" in error_msg.lower():
                LOG.warning("Memory error during packet conversion - possible resource exhaustion")
            elif "decode" in error_msg.lower() or "parse" in error_msg.lower():
                LOG.debug("Packet parsing error - unsupported protocol or format")

            # Log raw packet data for debugging if enabled
            if LOG.isEnabledFor(logging.DEBUG) and hasattr(pydivert_packet, "raw"):
                try:
                    raw_preview = (
                        pydivert_packet.raw[:32].hex()
                        if len(pydivert_packet.raw) >= 32
                        else pydivert_packet.raw.hex()
                    )
                    LOG.debug(f"Failed packet raw data preview: {raw_preview}...")
                except Exception as preview_error:
                    LOG.debug(f"Could not preview raw packet data: {preview_error}")

            return None

    def _cleanup_resources(self) -> None:
        """Cleanup WinDivert handle and other resources with comprehensive error handling."""
        cleanup_start = time.perf_counter()
        cleanup_success = True

        if self.windivert_handle:
            try:
                LOG.debug("Closing WinDivert handle...")
                self.windivert_handle.close()
                LOG.debug("WinDivert handle closed successfully")

            except Exception as e:
                cleanup_success = False
                error_msg = _get_error_message(str(e))
                LOG.warning(f"Error closing WinDivert handle: {error_msg}")

                # Log specific cleanup error patterns
                error_str = str(e).lower()
                if "handle" in error_str and ("invalid" in error_str or "closed" in error_str):
                    LOG.debug("Handle was already closed or invalid")
                elif "access" in error_str:
                    LOG.warning("Access denied during handle cleanup")
                elif "resource" in error_str:
                    LOG.warning("Resource cleanup issue - possible system resource leak")

            finally:
                self.windivert_handle = None
                LOG.debug("WinDivert handle reference cleared")
        else:
            LOG.debug("No WinDivert handle to cleanup")

        # Log cleanup statistics
        cleanup_time = time.perf_counter() - cleanup_start
        _log_operation_stats(
            "Resource cleanup",
            cleanup_start,
            cleanup_success,
            cleanup_time=f"{cleanup_time:.4f}s",
        )


@contextlib.contextmanager
def session(
    filter_expr: str, iface: Optional[str] = None, use_pydivert: bool = None
) -> Generator[Tuple[List, List], None, None]:
    """
    Context manager for packet capture sessions with auto-detection and fallback support.
    Collects packets and their timestamps with proper resource cleanup.

    Args:
        filter_expr: BPF filter expression for Scapy or WinDivert filter for PyDivert
        iface: Network interface (only used with Scapy)
        use_pydivert: Force PyDivert usage (auto-detect if None)

    Yields:
        Tuple of (packets_list, timestamps_list) for captured packets
    """
    session_start = time.perf_counter()
    session_success = False
    capture_method = "unknown"
    pydivert_error = None
    scapy_error = None

    try:
        LOG.info(f"Starting capture session with filter: '{filter_expr}'")

        # Validate filter expression
        if not filter_expr or not filter_expr.strip():
            raise ValueError("Empty or invalid filter expression provided")

        # Auto-detect capture method based on platform and availability
        if use_pydivert is None:
            use_pydivert = PYDIVERT_AVAILABLE and _test_pydivert_availability()
            LOG.debug(f"Auto-detected PyDivert usage: {use_pydivert}")

        pydivert_failed = False

        # Try PyDivert first if requested/available, with fallback to Scapy
        if use_pydivert and PYDIVERT_AVAILABLE:
            try:
                capture_method = "PyDivert"
                LOG.info(f"Attempting PyDivert capture with filter: '{filter_expr}'")

                with _pydivert_session(filter_expr) as (packets, timestamps):
                    session_success = True
                    _log_operation_stats(
                        "PyDivert capture session",
                        session_start,
                        True,
                        packets_captured=len(packets),
                        method=capture_method,
                    )
                    LOG.info(
                        f"PyDivert capture session completed successfully - {len(packets)} packets captured"
                    )
                    yield packets, timestamps
                    return

            except Exception as e:
                pydivert_error = _get_error_message(str(e))
                LOG.warning(f"PyDivert capture failed: {pydivert_error}")

                # Log specific troubleshooting advice
                error_str = str(e).lower()
                if "87" in error_str or "parameter" in error_str:
                    LOG.info(
                        "PyDivert filter issue - will attempt Scapy with BPF filter conversion"
                    )
                elif "access" in error_str or "denied" in error_str:
                    LOG.info(
                        "PyDivert access denied - falling back to Scapy (may have limited functionality)"
                    )
                elif "driver" in error_str:
                    LOG.info("PyDivert driver issue - falling back to Scapy")

                pydivert_failed = True
                # Continue to Scapy fallback below

        # Use Scapy capture (either as primary choice or fallback)
        try:
            capture_method = "Scapy" + (" (fallback)" if pydivert_failed else "")

            if pydivert_failed:
                LOG.info(f"Using Scapy fallback with filter: '{filter_expr}'")
            else:
                LOG.info(f"Using Scapy capture with filter: '{filter_expr}'")

            with _scapy_session(filter_expr, iface) as (packets, timestamps):
                session_success = True
                _log_operation_stats(
                    "Scapy capture session",
                    session_start,
                    True,
                    packets_captured=len(packets),
                    method=capture_method,
                )
                LOG.info(
                    f"Scapy capture session completed successfully - {len(packets)} packets captured"
                )
                yield packets, timestamps

        except Exception as e:
            scapy_error = _get_error_message(str(e))

            if pydivert_failed:
                LOG.error("Both PyDivert and Scapy capture failed:")
                LOG.error(f"  PyDivert error: {pydivert_error}")
                LOG.error(f"  Scapy error: {scapy_error}")
                LOG.error(
                    "No capture methods available - check network permissions and filter syntax"
                )
            else:
                LOG.error(f"Scapy capture failed: {scapy_error}")

            # Yield empty results rather than crashing
            yield [], []

    except Exception as e:
        session_error = _get_error_message(str(e))
        LOG.error(f"Capture session initialization failed: {session_error}")
        yield [], []

    finally:
        # Log final session statistics
        session_time = time.perf_counter() - session_start
        if not session_success:
            _log_operation_stats(
                "Capture session",
                session_start,
                False,
                method=capture_method,
                duration=f"{session_time:.3f}s",
            )

        LOG.debug(f"Capture session cleanup completed in {session_time:.3f}s")


@contextlib.contextmanager
def _scapy_session(
    filter_expr: str, iface: Optional[str] = None
) -> Generator[Tuple[List, List], None, None]:
    """
    Scapy-based capture session with proper resource cleanup.
    Used as fallback when PyDivert is unavailable or fails.
    """
    packets = []
    timestamps = []
    sniffer = None

    def _packet_callback(packet):
        """Thread-safe packet callback for Scapy sniffer."""
        try:
            packets.append(packet)
            timestamps.append(time.perf_counter())
        except Exception as e:
            LOG.debug(f"Error in packet callback: {e}")

    try:
        # Create and start Scapy sniffer
        sniffer = AsyncSniffer(filter=filter_expr, prn=_packet_callback, store=False, iface=iface)
        sniffer.start()
        LOG.debug(f"Scapy capture session started with filter: '{filter_expr}', interface: {iface}")

        yield packets, timestamps

    except Exception as e:
        LOG.error(f"Scapy capture session error: {e}")
        raise
    finally:
        # Ensure proper sniffer cleanup in all cases
        if sniffer:
            try:
                # Check if sniffer is running before attempting to stop
                if hasattr(sniffer, "running") and sniffer.running:
                    LOG.debug("Stopping Scapy sniffer")
                    sniffer.stop()

                    # Wait for sniffer thread to finish gracefully
                    if hasattr(sniffer, "thread") and sniffer.thread and sniffer.thread.is_alive():
                        sniffer.thread.join(timeout=2.0)
                        if sniffer.thread.is_alive():
                            LOG.warning("Scapy sniffer thread did not stop gracefully")

            except Exception as e:
                # Scapy may raise exceptions if socket is already closed or unavailable
                LOG.debug(f"Error during Scapy sniffer cleanup: {e}")

        LOG.debug(f"Scapy capture session cleanup complete. Captured {len(packets)} packets.")


@contextlib.contextmanager
def _pydivert_session(filter_expr: str) -> Generator[Tuple[List, List], None, None]:
    """
    PyDivert-based capture session using PyDivertCaptureWorker and PacketQueueProcessor.
    Implements comprehensive resource cleanup and error handling.
    """
    session_start = time.perf_counter()
    packets = []
    timestamps = []
    capture_active = None
    packet_queue = None
    capture_worker = None
    queue_processor = None
    initialization_success = False

    try:
        LOG.debug(f"Initializing PyDivert capture session with filter: '{filter_expr}'")

        # Initialize thread synchronization and data structures
        capture_active = threading.Event()  # Event starts as False (not set)
        packet_queue = queue.Queue(maxsize=1000)  # Prevent memory overflow

        # Convert BPF filter to WinDivert format if needed
        windivert_filter = _convert_bpf_to_windivert(filter_expr)
        if windivert_filter != filter_expr:
            LOG.info(
                f"Converted BPF filter '{filter_expr}' to WinDivert filter '{windivert_filter}'"
            )

        # Validate converted filter
        if not windivert_filter or not windivert_filter.strip():
            raise ValueError(f"Filter conversion resulted in empty filter from: '{filter_expr}'")

        # Create PyDivert capture worker
        LOG.debug("Creating PyDivert capture worker...")
        capture_worker = PyDivertCaptureWorker(windivert_filter, packet_queue, capture_active)

        # Create packet queue processor
        LOG.debug("Creating packet queue processor...")
        queue_processor = PacketQueueProcessor(packet_queue, packets, timestamps, capture_active)

        # Start worker threads with comprehensive error handling
        try:
            LOG.debug("Starting packet queue processor...")
            queue_processor.start()

            # Additional check after a brief moment to ensure stability
            time.sleep(0.1)
            if not queue_processor.is_running:
                raise RuntimeError(
                    "Packet queue processor failed to start or crashed during initialization"
                )

            LOG.debug("Starting PyDivert capture worker...")
            capture_worker.start()

            # Wait for initialization with timeout
            initialization_timeout = 2.0
            initialization_start = time.perf_counter()

            while (time.perf_counter() - initialization_start) < initialization_timeout:
                if capture_worker.is_running:
                    initialization_success = True
                    break
                time.sleep(0.1)

            # Check if the capture worker encountered an initialization error
            if not initialization_success or not capture_worker.is_running:
                raise RuntimeError("PyDivert capture worker failed to initialize within timeout")

            init_time = time.perf_counter() - session_start
            LOG.info(f"PyDivert capture session initialized successfully in {init_time:.3f}s")

        except Exception as e:
            error_msg = _get_error_message(str(e))
            LOG.error(f"Failed to start PyDivert capture threads: {error_msg}")

            # Provide specific troubleshooting advice
            if "timeout" in str(e).lower():
                LOG.info("Initialization timeout - check if WinDivert driver is responding")
            elif "worker" in str(e).lower():
                LOG.info("Worker thread issue - check system resources and permissions")

            raise

        yield packets, timestamps

    except Exception as e:
        session_error = _get_error_message(str(e))
        LOG.error(f"PyDivert capture session error: {session_error}")

        # Log session statistics on error
        session_time = time.perf_counter() - session_start
        _log_operation_stats(
            "PyDivert session (failed)",
            session_start,
            False,
            duration=f"{session_time:.3f}s",
            error=session_error,
        )
        raise

    finally:
        cleanup_start = time.perf_counter()
        cleanup_errors = []

        # Ensure proper resource cleanup in all cases
        try:
            if capture_active:
                capture_active.set()  # Signal threads to stop
                LOG.debug("Capture stop event set")
        except Exception as e:
            cleanup_errors.append(f"stop event: {e}")

        # Stop capture worker with timeout
        if capture_worker:
            try:
                LOG.debug("Stopping capture worker...")
                capture_worker.stop()
                LOG.debug("Capture worker stopped successfully")
            except Exception as e:
                cleanup_errors.append(f"capture worker: {e}")

        # Stop queue processor with timeout
        if queue_processor:
            try:
                LOG.debug("Stopping queue processor...")
                queue_processor.stop()
                LOG.debug("Queue processor stopped successfully")
            except Exception as e:
                cleanup_errors.append(f"queue processor: {e}")

        # Final cleanup of any remaining resources
        remaining_packets = 0
        if packet_queue:
            try:
                # Clear any remaining packets to prevent memory leaks
                while not packet_queue.empty():
                    try:
                        packet_queue.get_nowait()
                        remaining_packets += 1
                    except queue.Empty:
                        break

                if remaining_packets > 0:
                    LOG.debug(f"Cleared {remaining_packets} remaining packets from queue")

            except Exception as e:
                cleanup_errors.append(f"queue cleanup: {e}")

        # Log cleanup results
        cleanup_time = time.perf_counter() - cleanup_start
        session_time = time.perf_counter() - session_start

        if cleanup_errors:
            LOG.warning(
                f"PyDivert session cleanup completed with errors in {cleanup_time:.3f}s: {'; '.join(cleanup_errors)}"
            )
        else:
            LOG.debug(f"PyDivert session cleanup completed successfully in {cleanup_time:.3f}s")

        # Log final session statistics
        _log_operation_stats(
            "PyDivert session",
            session_start,
            initialization_success,
            packets_captured=len(packets),
            session_time=f"{session_time:.3f}s",
            remaining_packets=remaining_packets,
        )
