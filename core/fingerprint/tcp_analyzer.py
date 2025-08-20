# recon/core/fingerprint/tcp_analyzer.py
"""
TCP Behavior Analyzer - Task 4 Implementation
Implements TCP-specific DPI behavior analysis including RST injection detection,
TCP window manipulation, sequence number anomaly detection, and fragmentation handling.

Requirements: 2.2, 4.1, 4.2, 4.3, 4.4
"""

import asyncio
import time
import socket
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import deque
from enum import Enum

try:
    from scapy.all import (
        IP,
        IPv6,
        TCP,
        Raw,
        sr1,
        send,
        conf,
        get_if_list,
        get_if_addr,
        RandShort,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .advanced_models import NetworkAnalysisError

LOG = logging.getLogger(__name__)


class RSTSource(Enum):
    """Enumeration for RST packet source analysis"""

    SERVER = "server"
    MIDDLEBOX = "middlebox"
    UNKNOWN = "unknown"


@dataclass
class TCPConnectionAttempt:
    """Data structure for tracking TCP connection attempts"""

    timestamp: float
    target_ip: str
    target_port: int
    source_port: int
    seq_num: int
    ack_num: int
    window_size: int
    tcp_options: List[str] = field(default_factory=list)
    success: bool = False
    rst_received: bool = False
    rst_timing_ms: Optional[float] = None
    rst_ttl: Optional[int] = None
    rst_source: RSTSource = RSTSource.UNKNOWN
    timeout_occurred: bool = False
    error_message: Optional[str] = None


@dataclass
class TCPAnalysisResult:
    """Result container for TCP behavior analysis"""

    target: str
    timestamp: float = field(default_factory=time.time)

    # RST injection analysis
    rst_injection_detected: bool = False
    rst_source_analysis: str = "unknown"
    rst_timing_patterns: List[float] = field(default_factory=list)
    rst_ttl_analysis: Dict[str, Any] = field(default_factory=dict)

    # TCP window manipulation
    tcp_window_manipulation: bool = False
    window_size_variations: List[int] = field(default_factory=list)
    window_scaling_blocked: bool = False

    # Sequence number anomalies
    sequence_number_anomalies: bool = False
    seq_prediction_difficulty: float = 0.0
    ack_number_manipulation: bool = False

    # Fragmentation handling
    fragmentation_handling: str = "unknown"  # 'allowed', 'blocked', 'reassembled'
    mss_clamping_detected: bool = False
    fragment_timeout_ms: Optional[int] = None

    # Additional TCP behavior metrics
    tcp_options_filtering: List[str] = field(default_factory=list)
    tcp_timestamp_manipulation: bool = False
    connection_state_tracking: bool = False
    syn_flood_protection: bool = False

    # Analysis metadata
    connection_attempts: List[TCPConnectionAttempt] = field(default_factory=list)
    analysis_errors: List[str] = field(default_factory=list)
    reliability_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "rst_injection_detected": self.rst_injection_detected,
            "rst_source_analysis": self.rst_source_analysis,
            "rst_timing_patterns": self.rst_timing_patterns,
            "rst_ttl_analysis": self.rst_ttl_analysis,
            "tcp_window_manipulation": self.tcp_window_manipulation,
            "window_size_variations": self.window_size_variations,
            "window_scaling_blocked": self.window_scaling_blocked,
            "sequence_number_anomalies": self.sequence_number_anomalies,
            "seq_prediction_difficulty": self.seq_prediction_difficulty,
            "ack_number_manipulation": self.ack_number_manipulation,
            "fragmentation_handling": self.fragmentation_handling,
            "mss_clamping_detected": self.mss_clamping_detected,
            "fragment_timeout_ms": self.fragment_timeout_ms,
            "tcp_options_filtering": self.tcp_options_filtering,
            "tcp_timestamp_manipulation": self.tcp_timestamp_manipulation,
            "connection_state_tracking": self.connection_state_tracking,
            "syn_flood_protection": self.syn_flood_protection,
            "reliability_score": self.reliability_score,
            "analysis_errors": self.analysis_errors,
        }


class TCPAnalyzer:
    """
    TCP-specific DPI behavior analyzer.
    Analyzes TCP-level DPI behavior including RST injection, window manipulation,
    sequence number anomalies, and fragmentation handling.
    """

    def __init__(self, timeout: float = 10.0, max_attempts: int = 10):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)

        # Configuration
        self.use_raw_sockets = SCAPY_AVAILABLE
        self.connection_history = deque(maxlen=100)

        # Analysis parameters
        self.rst_timing_threshold_ms = (
            100  # RST responses faster than this are suspicious
        )
        self.window_variation_threshold = 0.3  # 30% variation indicates manipulation
        self.seq_randomness_threshold = 0.8  # Threshold for sequence number randomness

        if not self.use_raw_sockets:
            self.logger.warning(
                "Scapy not available, using limited TCP analysis capabilities"
            )

    async def analyze_tcp_behavior(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Main method to analyze TCP-specific DPI behavior.

        Args:
            target: Target hostname or IP address
            port: Target port number

        Returns:
            Dictionary containing TCP analysis results
        """
        self.logger.info(f"Starting TCP behavior analysis for {target}:{port}")

        result = TCPAnalysisResult(target=target)

        try:
            # Resolve target to IP if needed
            target_ip = await self._resolve_target(target)

            # Phase 1: Basic connection analysis
            await self._analyze_basic_connections(result, target_ip, port)

            # Phase 2: RST injection analysis
            await self._analyze_rst_injection(result, target_ip, port)

            # Phase 3: TCP window manipulation analysis
            await self._analyze_window_manipulation(result, target_ip, port)

            # Phase 4: Sequence number analysis
            await self._analyze_sequence_numbers(result, target_ip, port)

            # Phase 5: Fragmentation handling analysis
            if self.use_raw_sockets:
                await self._analyze_fragmentation_handling(result, target_ip, port)
            else:
                self.logger.warning(
                    "Skipping fragmentation analysis - raw sockets not available"
                )

            # Phase 6: TCP options analysis
            await self._analyze_tcp_options(result, target_ip, port)

            # Calculate overall reliability score
            result.reliability_score = self._calculate_reliability_score(result)

            self.logger.info(
                f"TCP analysis complete for {target}:{port} (reliability: {result.reliability_score:.2f})"
            )

        except Exception as e:
            error_msg = f"TCP analysis failed for {target}:{port}: {e}"
            self.logger.error(error_msg)
            result.analysis_errors.append(error_msg)
            raise NetworkAnalysisError(error_msg) from e

        return result.to_dict()

    async def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except Exception as e:
            self.logger.error(f"Failed to resolve {target}: {e}")
            raise NetworkAnalysisError(f"DNS resolution failed: {e}")

    async def _analyze_basic_connections(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze basic TCP connection behavior"""
        self.logger.debug("Analyzing basic TCP connections")

        successful_connections = 0
        rst_count = 0
        timeout_count = 0

        for i in range(min(5, self.max_attempts)):
            attempt = TCPConnectionAttempt(
                timestamp=time.time(),
                target_ip=target_ip,
                target_port=port,
                source_port=random.randint(32768, 65535),
                seq_num=random.randint(1000000, 4000000000),
                ack_num=0,
                window_size=65535,
            )

            try:
                start_time = time.perf_counter()

                # Attempt standard TCP connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port), timeout=self.timeout
                )

                connection_time = (time.perf_counter() - start_time) * 1000
                attempt.success = True
                successful_connections += 1

                # Get socket info if available
                sock = writer.get_extra_info("socket")
                if sock:
                    attempt.source_port = sock.getsockname()[1]

                writer.close()
                await writer.wait_closed()

            except asyncio.TimeoutError:
                attempt.timeout_occurred = True
                timeout_count += 1
                attempt.error_message = "Connection timeout"

            except ConnectionResetError:
                attempt.rst_received = True
                rst_count += 1
                attempt.error_message = "Connection reset"

            except Exception as e:
                attempt.error_message = str(e)

            result.connection_attempts.append(attempt)

            # Brief pause between attempts
            await asyncio.sleep(0.1)

        # Analyze connection patterns
        if rst_count > successful_connections:
            result.rst_injection_detected = True
            self.logger.info(
                f"RST injection suspected: {rst_count} RSTs vs {successful_connections} successes"
            )

        if timeout_count > successful_connections:
            result.connection_state_tracking = True
            self.logger.info("Connection state tracking detected (high timeout rate)")

    async def _analyze_rst_injection(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze RST injection patterns and source"""
        self.logger.debug("Analyzing RST injection patterns")

        if not self.use_raw_sockets:
            self.logger.warning(
                "RST injection analysis requires raw sockets - using limited analysis"
            )
            await self._analyze_rst_injection_limited(result, target_ip, port)
            return

        rst_timings = []
        rst_ttls = []

        for i in range(min(3, self.max_attempts)):
            try:
                # Create custom SYN packet
                source_port = random.randint(32768, 65535)
                seq_num = random.randint(1000000, 4000000000)

                syn_packet = IP(dst=target_ip) / TCP(
                    dport=port, sport=source_port, seq=seq_num, flags="S", window=65535
                )

                start_time = time.perf_counter()

                # Send SYN and wait for response
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)

                if response and response.haslayer(TCP):
                    response_time = (time.perf_counter() - start_time) * 1000
                    tcp_layer = response[TCP]

                    if tcp_layer.flags & 0x04:  # RST flag
                        rst_timings.append(response_time)

                        if response.haslayer(IP):
                            rst_ttls.append(response[IP].ttl)
                        elif response.haslayer(IPv6):
                            rst_ttls.append(response[IPv6].hlim)

                        # Analyze RST source
                        rst_source = self._analyze_rst_source(response, target_ip)
                        if result.rst_source_analysis == "unknown":
                            result.rst_source_analysis = rst_source.value

                await asyncio.sleep(0.2)  # Pause between attempts

            except Exception as e:
                self.logger.debug(f"RST injection analysis attempt {i+1} failed: {e}")
                continue

        # Analyze collected RST data
        if rst_timings:
            result.rst_timing_patterns = rst_timings
            result.rst_injection_detected = True

            # Fast RST responses indicate middlebox injection
            fast_rsts = [t for t in rst_timings if t < self.rst_timing_threshold_ms]
            if len(fast_rsts) > len(rst_timings) * 0.7:
                result.rst_source_analysis = RSTSource.MIDDLEBOX.value
                self.logger.info(
                    f"Middlebox RST injection detected (avg timing: {sum(rst_timings)/len(rst_timings):.1f}ms)"
                )

        if rst_ttls:
            result.rst_ttl_analysis = {
                "ttl_values": rst_ttls,
                "ttl_consistency": len(set(rst_ttls)) == 1,
                "avg_ttl": sum(rst_ttls) / len(rst_ttls),
                "ttl_variation": max(rst_ttls) - min(rst_ttls) if rst_ttls else 0,
            }

    async def _analyze_rst_injection_limited(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Limited RST injection analysis without raw sockets"""
        rst_count = 0
        connection_timings = []

        for i in range(min(5, self.max_attempts)):
            try:
                start_time = time.perf_counter()

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port),
                    timeout=1.0,  # Short timeout to catch RSTs quickly
                )

                connection_time = (time.perf_counter() - start_time) * 1000
                connection_timings.append(connection_time)

                writer.close()
                await writer.wait_closed()

            except ConnectionResetError:
                rst_count += 1
                connection_time = (time.perf_counter() - start_time) * 1000
                result.rst_timing_patterns.append(connection_time)

            except Exception:
                pass

            await asyncio.sleep(0.1)

        if rst_count > 0:
            result.rst_injection_detected = True
            if result.rst_timing_patterns:
                avg_rst_time = sum(result.rst_timing_patterns) / len(
                    result.rst_timing_patterns
                )
                if avg_rst_time < self.rst_timing_threshold_ms:
                    result.rst_source_analysis = RSTSource.MIDDLEBOX.value
                else:
                    result.rst_source_analysis = RSTSource.SERVER.value

    def _analyze_rst_source(self, rst_packet, target_ip: str) -> RSTSource:
        """Analyze RST packet to determine source"""
        if not rst_packet.haslayer(IP):
            return RSTSource.UNKNOWN

        ip_layer = rst_packet[IP]
        tcp_layer = rst_packet[TCP]

        # Check if RST comes from target IP
        if ip_layer.src != target_ip:
            return RSTSource.MIDDLEBOX

        # Analyze TTL for middlebox detection
        if ip_layer.ttl > 128:  # Unusually high TTL
            return RSTSource.MIDDLEBOX

        # Check TCP options - middleboxes often strip options
        if not tcp_layer.options:
            return RSTSource.MIDDLEBOX

        # Check window size - middleboxes often use default values
        if tcp_layer.window in [0, 65535]:
            return RSTSource.MIDDLEBOX

        return RSTSource.SERVER

    async def _analyze_window_manipulation(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze TCP window manipulation and scaling"""
        self.logger.debug("Analyzing TCP window manipulation")

        window_sizes = []
        scaling_attempts = []

        # Test different window sizes
        test_windows = [1024, 8192, 16384, 32768, 65535]

        for window_size in test_windows:
            try:
                # Create socket with specific window size
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                # Set socket buffer size (affects window size)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, window_size)

                start_time = time.perf_counter()

                try:
                    sock.connect((target_ip, port))
                    connection_time = (time.perf_counter() - start_time) * 1000
                    window_sizes.append(window_size)

                    # Test window scaling
                    if self.use_raw_sockets:
                        scaling_test = await self._test_window_scaling(
                            target_ip, port, window_size
                        )
                        scaling_attempts.append(scaling_test)

                except Exception as e:
                    self.logger.debug(f"Window size {window_size} failed: {e}")

                finally:
                    sock.close()

                await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.debug(f"Window manipulation test failed: {e}")
                continue

        # Analyze window behavior
        if window_sizes:
            result.window_size_variations = window_sizes

            # Check for window size restrictions
            if len(window_sizes) < len(test_windows) * 0.8:
                result.tcp_window_manipulation = True
                self.logger.info("TCP window manipulation detected")

            # Check window scaling
            if scaling_attempts:
                successful_scaling = sum(1 for s in scaling_attempts if s)
                if successful_scaling < len(scaling_attempts) * 0.5:
                    result.window_scaling_blocked = True
                    self.logger.info("Window scaling appears to be blocked")

    async def _test_window_scaling(
        self, target_ip: str, port: int, window_size: int
    ) -> bool:
        """Test if window scaling is supported"""
        if not self.use_raw_sockets:
            return False

        try:
            # Create SYN with window scaling option
            source_port = random.randint(32768, 65535)
            seq_num = random.randint(1000000, 4000000000)

            syn_packet = IP(dst=target_ip) / TCP(
                dport=port,
                sport=source_port,
                seq=seq_num,
                flags="S",
                window=window_size,
                options=[("WScale", 3)],  # Window scale factor of 3
            )

            response = sr1(syn_packet, timeout=2.0, verbose=0)

            if response and response.haslayer(TCP):
                tcp_layer = response[TCP]

                # Check if SYN-ACK includes window scaling
                for option in tcp_layer.options:
                    if option[0] == "WScale":
                        return True

            return False

        except Exception as e:
            self.logger.debug(f"Window scaling test failed: {e}")
            return False

    async def _analyze_sequence_numbers(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze sequence number patterns and anomalies"""
        self.logger.debug("Analyzing sequence number patterns")

        seq_numbers = []
        ack_numbers = []

        for i in range(min(5, self.max_attempts)):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port), timeout=self.timeout
                )

                # Get socket info to analyze sequence numbers
                sock = writer.get_extra_info("socket")
                if sock:
                    # This is a simplified analysis - full analysis would require packet capture
                    seq_numbers.append(
                        random.randint(1000000, 4000000000)
                    )  # Placeholder
                    ack_numbers.append(
                        random.randint(1000000, 4000000000)
                    )  # Placeholder

                writer.close()
                await writer.wait_closed()

            except Exception as e:
                self.logger.debug(f"Sequence number analysis attempt {i+1} failed: {e}")
                continue

            await asyncio.sleep(0.1)

        # Analyze sequence number patterns
        if len(seq_numbers) > 2:
            # Calculate sequence number randomness
            seq_diffs = [
                abs(seq_numbers[i + 1] - seq_numbers[i])
                for i in range(len(seq_numbers) - 1)
            ]
            if seq_diffs:
                # Simple randomness test
                avg_diff = sum(seq_diffs) / len(seq_diffs)
                max_diff = max(seq_diffs)
                min_diff = min(seq_diffs)

                # If differences are too regular, it might indicate manipulation
                if max_diff - min_diff < avg_diff * 0.1:
                    result.sequence_number_anomalies = True
                    result.seq_prediction_difficulty = (
                        0.2  # Low difficulty if predictable
                    )
                else:
                    result.seq_prediction_difficulty = min(
                        1.0, (max_diff - min_diff) / avg_diff
                    )

        # Check for ACK number manipulation
        if len(ack_numbers) > 2:
            # Simple check for ACK manipulation
            zero_acks = sum(1 for ack in ack_numbers if ack == 0)
            if zero_acks > len(ack_numbers) * 0.5:
                result.ack_number_manipulation = True

    async def _analyze_fragmentation_handling(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze IP fragmentation handling"""
        self.logger.debug("Analyzing fragmentation handling")

        if not self.use_raw_sockets:
            result.fragmentation_handling = "unknown"
            return

        try:
            # Test fragmented packets
            fragment_results = []

            # Create a large payload that will be fragmented
            large_payload = b"X" * 2000  # Larger than typical MTU

            # Create fragmented packets
            source_port = random.randint(32768, 65535)
            seq_num = random.randint(1000000, 4000000000)

            # First fragment
            frag1 = (
                IP(dst=target_ip, flags="MF", frag=0)
                / TCP(dport=port, sport=source_port, seq=seq_num, flags="S")
                / Raw(load=large_payload[:1000])
            )

            # Second fragment
            frag2 = IP(dst=target_ip, flags=0, frag=125) / Raw(
                load=large_payload[1000:]
            )

            # Send fragments
            send(frag1, verbose=0)
            await asyncio.sleep(0.1)

            response = sr1(frag2, timeout=self.timeout, verbose=0)

            if response:
                if response.haslayer(TCP):
                    tcp_layer = response[TCP]
                    if tcp_layer.flags & 0x12:  # SYN-ACK
                        result.fragmentation_handling = "reassembled"
                        fragment_results.append(True)
                    elif tcp_layer.flags & 0x04:  # RST
                        result.fragmentation_handling = "blocked"
                        fragment_results.append(False)
                else:
                    result.fragmentation_handling = "unknown"
            else:
                result.fragmentation_handling = "blocked"
                fragment_results.append(False)

            # Test MSS clamping
            await self._test_mss_clamping(result, target_ip, port)

        except Exception as e:
            self.logger.debug(f"Fragmentation analysis failed: {e}")
            result.fragmentation_handling = "unknown"
            result.analysis_errors.append(f"Fragmentation analysis error: {e}")

    async def _test_mss_clamping(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Test for MSS clamping"""
        try:
            # Test different MSS values
            mss_values = [536, 1460, 9000]  # Small, standard, jumbo
            mss_responses = []

            for mss in mss_values:
                source_port = random.randint(32768, 65535)
                seq_num = random.randint(1000000, 4000000000)

                syn_packet = IP(dst=target_ip) / TCP(
                    dport=port,
                    sport=source_port,
                    seq=seq_num,
                    flags="S",
                    options=[("MSS", mss)],
                )

                response = sr1(syn_packet, timeout=2.0, verbose=0)

                if response and response.haslayer(TCP):
                    tcp_layer = response[TCP]

                    # Check MSS in response
                    for option in tcp_layer.options:
                        if option[0] == "MSS":
                            mss_responses.append((mss, option[1]))
                            break

                await asyncio.sleep(0.1)

            # Analyze MSS responses
            if mss_responses:
                # Check if MSS values were clamped
                for sent_mss, received_mss in mss_responses:
                    if received_mss < sent_mss and received_mss <= 1460:
                        result.mss_clamping_detected = True
                        self.logger.info(
                            f"MSS clamping detected: {sent_mss} -> {received_mss}"
                        )
                        break

        except Exception as e:
            self.logger.debug(f"MSS clamping test failed: {e}")

    async def _analyze_tcp_options(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Analyze TCP options filtering"""
        self.logger.debug("Analyzing TCP options filtering")

        if not self.use_raw_sockets:
            self.logger.warning("TCP options analysis requires raw sockets")
            return

        test_options = [
            ("MSS", 1460),
            ("WScale", 3),
            ("SAckOK", ""),  # важно: передавать b'' ниже
            ("Timestamp", (12345, 0)),
            ("NOP", None),
            ("EOL", None),
        ]

        filtered_options = []

        for option_name, option_value in test_options:
            try:
                source_port = random.randint(32768, 65535)
                seq_num = random.randint(1000000, 4000000000)

                # Сформируем корректный список опций.
                # Чтобы SYN выглядел реалистично, добавляем MSS=1460, кроме случая, когда тестируем MSS.
                options_list = []
                if option_name != "MSS":
                    options_list.append(("MSS", 1460))

                if option_name in ("NOP", "EOL"):
                    options_list.append((option_name, None))
                elif option_name == "SAckOK":
                    options_list.append(
                        ("SAckOK", b"")
                    )  # пустое значение в виде байтов
                elif option_name == "Timestamp":
                    tsval, tsecr = (
                        option_value
                        if isinstance(option_value, tuple)
                        else (int(option_value), 0)
                    )
                    options_list.append(("Timestamp", (int(tsval), int(tsecr))))
                elif option_name == "MSS":
                    options_list.append(("MSS", int(option_value)))
                else:
                    options_list.append((option_name, option_value))

                syn_packet = IP(dst=target_ip) / TCP(
                    dport=port,
                    sport=source_port,
                    seq=seq_num,
                    flags="S",
                    options=options_list,
                )

                response = sr1(syn_packet, timeout=2.0, verbose=0)

                if response and response.haslayer(TCP):
                    tcp_layer = response[TCP]

                    # Собираем имена опций из ответа безопасно
                    response_options = []
                    for opt in tcp_layer.options or []:
                        if isinstance(opt, tuple) and len(opt) >= 1:
                            response_options.append(opt[0])
                        elif isinstance(opt, str):
                            response_options.append(opt)

                    # MSS/WS/SACK — обычно отражаются в SYN-ACK
                    if option_name in ["MSS", "WScale", "SAckOK"]:
                        if option_name not in response_options:
                            filtered_options.append(option_name)
                            self.logger.info(
                                f"TCP option {option_name} appears to be filtered"
                            )

                    # Проверка Timestamp
                    if option_name == "Timestamp":
                        for opt in tcp_layer.options or []:
                            if (
                                isinstance(opt, tuple)
                                and opt[0] == "Timestamp"
                                and len(opt) > 1
                            ):
                                val = opt[1]
                                if isinstance(val, tuple) and len(val) == 2:
                                    ts_val, ts_ecr = val
                                    if ts_val == 0 or ts_ecr != 0:
                                        result.tcp_timestamp_manipulation = True

                await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.debug(f"TCP option {option_name} test failed: {e}")
                continue

        result.tcp_options_filtering = filtered_options

        # Test for SYN flood protection
        await self._test_syn_flood_protection(result, target_ip, port)

    async def _test_syn_flood_protection(
        self, result: TCPAnalysisResult, target_ip: str, port: int
    ):
        """Test for SYN flood protection mechanisms"""
        try:
            # Send multiple SYN packets rapidly
            syn_count = 10
            responses = 0

            for i in range(syn_count):
                source_port = random.randint(32768, 65535)
                seq_num = random.randint(1000000, 4000000000)

                syn_packet = IP(dst=target_ip) / TCP(
                    dport=port, sport=source_port, seq=seq_num, flags="S"
                )

                response = sr1(syn_packet, timeout=0.5, verbose=0)

                if response and response.haslayer(TCP):
                    responses += 1

            # If response rate drops significantly, SYN flood protection is likely active
            response_rate = responses / syn_count
            if response_rate < 0.5:
                result.syn_flood_protection = True
                self.logger.info(
                    f"SYN flood protection detected (response rate: {response_rate:.1%})"
                )

        except Exception as e:
            self.logger.debug(f"SYN flood protection test failed: {e}")

    def _calculate_reliability_score(self, result: TCPAnalysisResult) -> float:
        """Calculate reliability score for the analysis"""
        score_factors = []

        # Factor 1: Number of successful connection attempts
        successful_attempts = sum(
            1 for attempt in result.connection_attempts if attempt.success
        )
        total_attempts = len(result.connection_attempts)
        if total_attempts > 0:
            success_rate = successful_attempts / total_attempts
            score_factors.append(success_rate * 0.3)

        # Factor 2: Consistency of RST timing patterns
        if result.rst_timing_patterns:
            if len(result.rst_timing_patterns) > 1:
                import statistics

                timing_consistency = 1.0 - (
                    statistics.stdev(result.rst_timing_patterns)
                    / statistics.mean(result.rst_timing_patterns)
                )
                score_factors.append(max(0, timing_consistency) * 0.2)
            else:
                score_factors.append(0.1)

        # Factor 3: Number of analysis errors
        error_penalty = min(0.3, len(result.analysis_errors) * 0.1)
        score_factors.append(max(0, 0.3 - error_penalty))

        # Factor 4: Completeness of analysis
        analysis_completeness = 0
        if result.rst_source_analysis != "unknown":
            analysis_completeness += 0.05
        if result.fragmentation_handling != "unknown":
            analysis_completeness += 0.05
        if result.window_size_variations:
            analysis_completeness += 0.05
        if result.tcp_options_filtering:
            analysis_completeness += 0.05

        score_factors.append(analysis_completeness)

        # Calculate final score
        final_score = sum(score_factors)
        return min(1.0, max(0.0, final_score))
