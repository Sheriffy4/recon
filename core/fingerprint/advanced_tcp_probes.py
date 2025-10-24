"""
Advanced TCP/IP Probes for DPI Detection - Task 23 Implementation
Implements sophisticated TCP/IP level probes to detect DPI behavior patterns.

This module extends the basic TCP analyzer with advanced probing techniques:
- Packet reordering tolerance testing
- IP fragmentation overlap analysis
- Exotic TCP flags and options testing
- TTL distance analysis for DPI detection
"""

import asyncio
import socket
import time
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

try:
    from scapy.all import (
        IP,
        TCP,
        Raw,
        sr1,
        send,
        sr,
        fragment,
        conf,
        get_if_list,
        get_if_addr,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG = logging.getLogger(__name__)


@dataclass
class AdvancedTCPProbeResult:
    """Results from advanced TCP/IP probing"""

    target: str
    port: int
    timestamp: float = field(default_factory=time.time)

    # Packet Reordering Tests
    packet_reordering_tolerance: bool = False
    reordering_window_size: Optional[int] = None

    # IP Fragmentation Tests
    ip_fragmentation_overlap_handling: str = (
        "unknown"  # "vulnerable", "blocked", "unknown"
    )
    fragment_reassembly_timeout: Optional[float] = None

    # Exotic TCP Flags and Options
    exotic_tcp_flags_response: Dict[str, str] = field(default_factory=dict)
    tcp_options_filtering: List[str] = field(default_factory=list)

    # TTL Distance Analysis
    dpi_distance_hops: Optional[int] = None
    ttl_manipulation_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class AdvancedTCPProber:
    """
    Advanced TCP/IP probing for sophisticated DPI detection.

    This class implements advanced probing techniques to detect DPI behavior:
    - Packet reordering tolerance testing
    - IP fragmentation overlap analysis
    - Exotic TCP flags and options testing
    - TTL distance analysis for DPI detection
    """

    def __init__(self, timeout: float = 5.0, max_attempts: int = 2):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        self.is_available = SCAPY_AVAILABLE

        if not self.is_available:
            self.logger.warning("Scapy not available - advanced TCP probes disabled")

    async def run_advanced_tcp_probes(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Run all advanced TCP/IP probes against the target.

        Args:
            target: Target hostname or IP
            port: Target port (default 443 for HTTPS)

        Returns:
            Dictionary with probe results
        """
        if not self.is_available:
            return {}

        self.logger.info(f"Starting advanced TCP probes for {target}:{port}")

        result = AdvancedTCPProbeResult(target=target, port=port)

        try:
            target_ip = await self._resolve_target(target)

            # Run all probe categories
            await asyncio.gather(
                self._probe_packet_reordering(result, target_ip, port),
                self._probe_ip_fragmentation_overlap(result, target_ip, port),
                self._probe_exotic_tcp_flags(result, target_ip, port),
                self._probe_ttl_distance(result, target_ip, port),
                return_exceptions=True,
            )
            self.logger.info(
                f"Advanced TCP probes for {target}:{port} completed. Reordering tolerance: {result.packet_reordering_tolerance}"
            )
        except Exception as e:
            self.logger.error(
                f"Advanced TCP probes failed for {target}: {e}", exc_info=True
            )

        return result.to_dict()

    async def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {target}: {e}")
            return target  # Assume it's already an IP

    async def _probe_packet_reordering(
        self, result: AdvancedTCPProbeResult, target_ip: str, port: int
    ):
        """
        Test DPI tolerance to packet reordering.

        Sends TCP segments out of order to see if DPI can handle reordering.
        Many DPI systems fail when packets arrive out of sequence.
        """

        def probe():
            try:
                # Create a sequence of TCP segments that would form a valid connection
                # but send them out of order
                sport = random.randint(10000, 65000)
                seq_base = random.randint(1000000, 9000000)

                # Segment 1: SYN (should be first)
                syn_pkt = IP(dst=target_ip) / TCP(
                    sport=sport, dport=port, seq=seq_base, flags="S"
                )

                # Segment 2: Data segment (should be third)
                data_pkt = (
                    IP(dst=target_ip)
                    / TCP(sport=sport, dport=port, seq=seq_base + 2, flags="PA")
                    / Raw(b"GET / HTTP/1.1\r\n")
                )

                # Segment 3: ACK (should be second)
                ack_pkt = IP(dst=target_ip) / TCP(
                    sport=sport, dport=port, seq=seq_base + 1, flags="A"
                )

                # Send packets in wrong order: Data, SYN, ACK
                responses = sr(
                    [data_pkt, syn_pkt, ack_pkt], timeout=self.timeout, verbose=0
                )

                # Analyze responses to detect reordering tolerance
                if responses[0]:  # Got responses
                    # If we get proper responses despite wrong order, DPI tolerates reordering
                    result.packet_reordering_tolerance = True
                    result.reordering_window_size = 3  # We tested with 3 packets
                    self.logger.debug(
                        f"Packet reordering tolerance detected for {target_ip}"
                    )
                else:
                    result.packet_reordering_tolerance = False
                    self.logger.debug(f"No packet reordering tolerance for {target_ip}")

            except Exception as e:
                self.logger.debug(f"Packet reordering probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)

    async def _probe_ip_fragmentation_overlap(
        self, result: AdvancedTCPProbeResult, target_ip: str, port: int
    ):
        """
        Test DPI handling of overlapping IP fragments.

        Creates overlapping IP fragments to confuse DPI reassembly logic.
        This can reveal how DPI handles fragment overlap resolution.
        """

        def probe():
            try:
                # Create a large payload that will be fragmented
                large_payload = b"A" * 1400 + b"SENSITIVE_DATA" + b"B" * 1400

                # Create base packet
                base_pkt = (
                    IP(dst=target_ip)
                    / TCP(dport=port, sport=random.randint(10000, 65000), flags="S")
                    / Raw(large_payload)
                )

                # Fragment the packet
                fragments = fragment(base_pkt, fragsize=500)

                if len(fragments) >= 2:
                    # Create overlapping fragments by modifying fragment offsets
                    frag1 = fragments[0]
                    frag2 = fragments[1]

                    # Make fragment 2 overlap with fragment 1
                    if frag2.haslayer(IP):
                        frag2[IP].frag = frag1[IP].frag + 30  # Overlap by 30 bytes

                    # Send overlapping fragments
                    send([frag1, frag2], verbose=0)

                    # Test if connection still works after overlap
                    test_response = sr1(
                        IP(dst=target_ip) / TCP(dport=port, flags="S"),
                        timeout=2.0,
                        verbose=0,
                    )

                    if test_response and test_response.haslayer(TCP):
                        if test_response[TCP].flags & 0x12:  # SYN-ACK
                            result.ip_fragmentation_overlap_handling = "vulnerable"
                        elif test_response[TCP].flags & 0x04:  # RST
                            result.ip_fragmentation_overlap_handling = "blocked"
                    else:
                        result.ip_fragmentation_overlap_handling = "unknown"

                    self.logger.debug(
                        f"IP fragmentation overlap test: {result.ip_fragmentation_overlap_handling}"
                    )

            except Exception as e:
                self.logger.debug(f"IP fragmentation overlap probe failed: {e}")
                result.ip_fragmentation_overlap_handling = "unknown"

        await asyncio.get_event_loop().run_in_executor(None, probe)

    async def _probe_exotic_tcp_flags(
        self, result: AdvancedTCPProbeResult, target_ip: str, port: int
    ):
        """
        Test DPI reaction to exotic TCP flags and options.

        Sends packets with unusual TCP flag combinations and options
        to see how DPI systems react.
        """

        def probe():
            try:
                sport = random.randint(10000, 65000)

                # Test various exotic flag combinations
                exotic_flags = {
                    "syn_fin": "SF",  # SYN+FIN (invalid combination)
                    "syn_rst": "SR",  # SYN+RST (invalid combination)
                    "fin_rst": "FR",  # FIN+RST (invalid combination)
                    "all_flags": "FSRPAU",  # All flags set
                    "no_flags": "",  # No flags set
                    "urg_only": "U",  # Only URG flag
                }

                for flag_name, flags in exotic_flags.items():
                    try:
                        pkt = IP(dst=target_ip) / TCP(
                            sport=sport, dport=port, flags=flags
                        )

                        response = sr1(pkt, timeout=1.0, verbose=0)

                        if response and response.haslayer(TCP):
                            tcp_flags = response[TCP].flags
                            if tcp_flags & 0x04:  # RST
                                result.exotic_tcp_flags_response[flag_name] = "rst"
                            elif tcp_flags & 0x12:  # SYN-ACK
                                result.exotic_tcp_flags_response[flag_name] = "syn_ack"
                            else:
                                result.exotic_tcp_flags_response[flag_name] = (
                                    f"flags_{tcp_flags}"
                                )
                        else:
                            result.exotic_tcp_flags_response[flag_name] = "no_response"

                        # Small delay between tests
                        time.sleep(0.1)

                    except Exception as e:
                        self.logger.debug(f"Exotic flag test {flag_name} failed: {e}")
                        result.exotic_tcp_flags_response[flag_name] = "error"

                # Test exotic TCP options
                exotic_options = [
                    [("MSS", 65535)],  # Maximum MSS
                    [("MSS", 1)],  # Minimum MSS
                    [("WScale", 255)],  # Maximum window scale
                    [("Timestamp", (0xFFFFFFFF, 0xFFFFFFFF))],  # Max timestamps
                    [("UTO", 1800)],  # User timeout option
                    [("AltChkSum", 1)],  # Alternative checksum
                ]

                for i, options in enumerate(exotic_options):
                    try:
                        pkt = IP(dst=target_ip) / TCP(
                            sport=sport + i, dport=port, flags="S", options=options
                        )

                        response = sr1(pkt, timeout=1.0, verbose=0)

                        if response and response.haslayer(TCP):
                            # Check if options were filtered/modified
                            response_opts = [opt[0] for opt in response[TCP].options]
                            sent_opts = [opt[0] for opt in options]

                            filtered_opts = set(sent_opts) - set(response_opts)
                            if filtered_opts:
                                result.tcp_options_filtering.extend(list(filtered_opts))

                        time.sleep(0.1)

                    except Exception as e:
                        self.logger.debug(f"Exotic options test {i} failed: {e}")

                self.logger.debug(
                    f"Exotic TCP flags/options test completed for {target_ip}"
                )

            except Exception as e:
                self.logger.debug(f"Exotic TCP flags probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)

    async def _probe_ttl_distance(
        self, result: AdvancedTCPProbeResult, target_ip: str, port: int
    ):
        """
        Analyze TTL to determine distance to DPI device.

        Uses TTL analysis to estimate how many hops away the DPI device is.
        This helps in crafting TTL-based bypass attacks.
        """

        def probe():
            try:
                # Send packets with incrementing TTL to find DPI distance
                initial_ttl = 64
                sport = random.randint(10000, 65000)

                # Test with different TTL values
                ttl_responses = {}

                for ttl in range(1, 20):  # Test TTL 1-19
                    try:
                        pkt = IP(dst=target_ip, ttl=ttl) / TCP(
                            sport=sport, dport=port, flags="S"
                        )

                        response = sr1(pkt, timeout=1.0, verbose=0)

                        if response:
                            if response.haslayer(TCP):
                                tcp_flags = response[TCP].flags
                                if tcp_flags & 0x04:  # RST
                                    ttl_responses[ttl] = "rst"
                                elif tcp_flags & 0x12:  # SYN-ACK
                                    ttl_responses[ttl] = "syn_ack"
                                else:
                                    ttl_responses[ttl] = f"tcp_flags_{tcp_flags}"
                            elif response.haslayer("ICMP"):
                                ttl_responses[ttl] = "icmp_ttl_exceeded"
                        else:
                            ttl_responses[ttl] = "no_response"

                        time.sleep(0.05)  # Small delay

                    except Exception as e:
                        self.logger.debug(f"TTL {ttl} test failed: {e}")
                        ttl_responses[ttl] = "error"

                # Analyze TTL responses to find DPI distance
                # Look for pattern changes that indicate DPI intervention
                rst_ttls = [ttl for ttl, resp in ttl_responses.items() if resp == "rst"]
                synack_ttls = [
                    ttl for ttl, resp in ttl_responses.items() if resp == "syn_ack"
                ]

                if rst_ttls and synack_ttls:
                    # If we get RST for low TTL and SYN-ACK for high TTL,
                    # the transition point indicates DPI distance
                    min_synack_ttl = min(synack_ttls)
                    max_rst_ttl = max(
                        [ttl for ttl in rst_ttls if ttl < min_synack_ttl], default=0
                    )

                    if max_rst_ttl > 0:
                        result.dpi_distance_hops = max_rst_ttl + 1
                        result.ttl_manipulation_detected = True
                        self.logger.debug(
                            f"DPI distance estimated at {result.dpi_distance_hops} hops"
                        )

                # Also test if DPI modifies TTL in responses
                normal_response = sr1(
                    IP(dst=target_ip) / TCP(sport=sport + 100, dport=port, flags="S"),
                    timeout=2.0,
                    verbose=0,
                )

                if normal_response and normal_response.haslayer(IP):
                    response_ttl = normal_response[IP].ttl
                    # Common initial TTL values are 64, 128, 255
                    # If we see unusual values, it might indicate TTL manipulation
                    if response_ttl not in [
                        64,
                        63,
                        62,
                        61,
                        128,
                        127,
                        126,
                        125,
                        255,
                        254,
                        253,
                        252,
                    ]:
                        result.ttl_manipulation_detected = True
                        self.logger.debug(
                            f"Unusual response TTL detected: {response_ttl}"
                        )

            except Exception as e:
                self.logger.debug(f"TTL distance probe failed: {e}")

        await asyncio.get_event_loop().run_in_executor(None, probe)
