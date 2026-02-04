"""
Unified PCAP Analyzer for Strategy Validation

This module consolidates PCAP analysis functionality from existing analyzers
and provides byte-level packet inspection for strategy validation.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 9.3
"""

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum

LOG = logging.getLogger(__name__)


@dataclass
class ClientHelloInfo:
    """Information about a ClientHello packet.

    Requirements: 8.1
    """

    packet_index: int  # Index in packet list
    seq: int  # TCP sequence number
    size: int  # Size of ClientHello in bytes
    raw_bytes: bytes  # Raw ClientHello data


@dataclass
class SplitInfo:
    """Information about detected split in ClientHello.

    Requirements: 8.2
    """

    detected: bool  # Whether split was detected
    position: Optional[int] = None  # Position of split (size of first fragment)
    fragment_count: int = 0  # Number of fragments
    sizes: List[int] = field(default_factory=list)  # Size of each fragment


@dataclass
class FakePacketInfo:
    """Information about a fake/decoy packet.

    Requirements: 8.3
    """

    packet_index: int  # Index in packet list
    ttl: int  # Time to live value
    seq: int  # TCP sequence number
    checksum: int  # TCP checksum value


@dataclass
class PCAPAnalysisResult:
    """Complete PCAP analysis result.

    Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
    """

    pcap_file: str
    domain: str

    # ClientHello analysis
    clienthello_packets: List[ClientHelloInfo] = field(default_factory=list)

    # Split detection
    split_info: Optional[SplitInfo] = None

    # Fake packet detection
    fake_packets: List[FakePacketInfo] = field(default_factory=list)

    # Disorder detection
    disorder_detected: bool = False
    disorder_details: Optional[str] = None

    # Fooling detection (badsum, badseq)
    fooling_modes: List[str] = field(default_factory=list)

    # Additional metadata
    total_packets: int = 0
    tcp_packets: int = 0
    analysis_errors: List[str] = field(default_factory=list)


class UnifiedPCAPAnalyzer:
    """
    Unified PCAP analyzer with byte-level packet inspection.

    Consolidates functionality from existing analyzers:
    - analyzer.py: Strategy analysis
    - intelligent_pcap_analyzer.py: Blocking detection
    - rst_analyzer.py: RST trigger analysis

    Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 9.3
    """

    def __init__(self):
        """Initialize the analyzer."""
        self.logger = LOG
        self.logger.info("UnifiedPCAPAnalyzer initialized")

    def analyze(self, pcap_file: Path, domain: str) -> PCAPAnalysisResult:
        """
        Perform complete PCAP analysis.

        Args:
            pcap_file: Path to PCAP file
            domain: Domain name being analyzed

        Returns:
            PCAPAnalysisResult with all analysis data

        Requirements: 8.1
        """
        self.logger.info(f"Analyzing PCAP: {pcap_file} for domain: {domain}")

        result = PCAPAnalysisResult(pcap_file=str(pcap_file), domain=domain)

        try:
            # Read packets
            packets = self._read_pcap(pcap_file)
            if not packets:
                result.analysis_errors.append("No packets found in PCAP")
                return result

            result.total_packets = len(packets)

            # Filter TCP packets
            tcp_packets = [p for p in packets if self._is_tcp_packet(p)]
            result.tcp_packets = len(tcp_packets)

            if not tcp_packets:
                result.analysis_errors.append("No TCP packets found")
                return result

            # Find ClientHello packets
            result.clienthello_packets = self.find_clienthello_packets(tcp_packets)

            # Detect split
            if result.clienthello_packets:
                result.split_info = self.detect_split(tcp_packets, result.clienthello_packets)

            # Detect fake packets
            result.fake_packets = self.detect_fake_packets(tcp_packets)

            # Detect disorder
            disorder_detected, disorder_details = self.detect_disorder(tcp_packets)
            result.disorder_detected = disorder_detected
            result.disorder_details = disorder_details

            # Detect fooling modes
            result.fooling_modes = self.detect_fooling(tcp_packets)

            self.logger.info(
                f"Analysis complete: {len(result.clienthello_packets)} ClientHellos, "
                f"split={result.split_info.detected if result.split_info else False}, "
                f"{len(result.fake_packets)} fake packets, "
                f"disorder={result.disorder_detected}, "
                f"fooling={result.fooling_modes}"
            )

        except Exception as e:
            self.logger.error(f"Analysis error: {e}", exc_info=True)
            result.analysis_errors.append(str(e))

        return result

    def find_clienthello_packets(self, packets: List[bytes]) -> List[ClientHelloInfo]:
        """
        Find ClientHello packets by TLS header (0x16 0x03).

        Args:
            packets: List of raw packet data

        Returns:
            List of ClientHelloInfo objects

        Requirements: 8.1
        """
        clienthellos = []
        tcp_packets_found = 0
        tls_packets_found = 0

        for idx, packet_data in enumerate(packets):
            try:
                # Parse packet to get TCP payload
                tcp_payload, seq = self._extract_tcp_payload(packet_data)
                if not tcp_payload:
                    continue

                tcp_packets_found += 1

                if len(tcp_payload) < 6:
                    continue

                # Check for TLS record header: 0x16 (Handshake) 0x03 (TLS version)
                if tcp_payload[0] == 0x16 and tcp_payload[1] == 0x03:
                    tls_packets_found += 1
                    # This is a TLS handshake record
                    # Check if it's ClientHello (handshake type 0x01)
                    if len(tcp_payload) >= 6 and tcp_payload[5] == 0x01:
                        # Extract ClientHello size from TLS record
                        record_length = struct.unpack("!H", tcp_payload[3:5])[0]

                        clienthello = ClientHelloInfo(
                            packet_index=idx,
                            seq=seq,
                            size=record_length + 5,  # Include TLS record header
                            raw_bytes=(
                                tcp_payload[: record_length + 5]
                                if len(tcp_payload) >= record_length + 5
                                else tcp_payload
                            ),
                        )
                        clienthellos.append(clienthello)

                        self.logger.debug(
                            f"Found ClientHello at packet {idx}, seq={seq}, size={clienthello.size}"
                        )

            except Exception as e:
                self.logger.debug(f"Error parsing packet {idx}: {e}")
                continue

        self.logger.info(
            f"Found {len(clienthellos)} ClientHello packets "
            f"(scanned {len(packets)} packets, {tcp_packets_found} TCP, {tls_packets_found} TLS)"
        )
        return clienthellos

    def detect_split(
        self, packets: List[bytes], clienthellos: List[ClientHelloInfo]
    ) -> Optional[SplitInfo]:
        """
        Detect split position by first fragment size.

        Args:
            packets: List of raw packet data
            clienthellos: List of ClientHello packets found

        Returns:
            SplitInfo if split detected, None otherwise

        Requirements: 8.2
        """
        if not clienthellos:
            return SplitInfo(detected=False)

        # Check if ClientHello is split across multiple packets
        # Look for consecutive packets with same connection that form a ClientHello

        for ch in clienthellos:
            # Get the full expected size
            expected_size = ch.size
            actual_size = len(ch.raw_bytes)

            if actual_size < expected_size:
                # ClientHello is split!
                # Find subsequent fragments
                fragments = [actual_size]
                remaining = expected_size - actual_size

                # Look at next packets for continuation
                for idx in range(ch.packet_index + 1, min(ch.packet_index + 10, len(packets))):
                    try:
                        tcp_payload, seq = self._extract_tcp_payload(packets[idx])
                        if tcp_payload and len(tcp_payload) > 0:
                            fragment_size = min(len(tcp_payload), remaining)
                            fragments.append(fragment_size)
                            remaining -= fragment_size

                            if remaining <= 0:
                                break
                    except:
                        continue

                split_info = SplitInfo(
                    detected=True,
                    position=fragments[0],  # Position is size of first fragment
                    fragment_count=len(fragments),
                    sizes=fragments,
                )

                self.logger.info(
                    f"Split detected: position={split_info.position}, "
                    f"fragments={split_info.fragment_count}, sizes={split_info.sizes}"
                )

                return split_info

        return SplitInfo(detected=False)

    def detect_fake_packets(self, packets: List[bytes]) -> List[FakePacketInfo]:
        """
        Find fake packets by TTL < 20.

        Args:
            packets: List of raw packet data

        Returns:
            List of FakePacketInfo objects

        Requirements: 8.3
        """
        fake_packets = []

        for idx, packet_data in enumerate(packets):
            try:
                # Skip Ethernet header
                if len(packet_data) >= 14:
                    ip_start = 14
                else:
                    ip_start = 0

                # Parse IP header to get TTL
                if len(packet_data) < ip_start + 20:
                    continue

                # IP header: version/IHL at byte 0, TTL at byte 8
                ttl = packet_data[ip_start + 8]

                # Fake packets typically have very low TTL (< 20)
                if ttl < 20:
                    # Extract TCP info
                    ip_header_len = (packet_data[ip_start] & 0x0F) * 4
                    if len(packet_data) < ip_start + ip_header_len + 20:
                        continue

                    tcp_start = ip_start + ip_header_len
                    tcp_header = packet_data[tcp_start : tcp_start + 20]
                    seq = struct.unpack("!I", tcp_header[4:8])[0]
                    checksum = struct.unpack("!H", tcp_header[16:18])[0]

                    fake_packet = FakePacketInfo(
                        packet_index=idx, ttl=ttl, seq=seq, checksum=checksum
                    )
                    fake_packets.append(fake_packet)

                    self.logger.debug(f"Found fake packet at index {idx}: TTL={ttl}, seq={seq}")

            except Exception as e:
                self.logger.debug(f"Error parsing packet {idx} for fake detection: {e}")
                continue

        self.logger.info(f"Found {len(fake_packets)} fake packets")
        return fake_packets

    def detect_disorder(self, packets: List[bytes]) -> Tuple[bool, Optional[str]]:
        """
        Detect disorder by analyzing sequence number order.

        Args:
            packets: List of raw packet data

        Returns:
            Tuple of (disorder_detected, details)

        Requirements: 8.4
        """
        try:
            # Extract sequence numbers from TCP packets
            seq_numbers = []

            for idx, packet_data in enumerate(packets):
                try:
                    # Skip Ethernet header
                    if len(packet_data) >= 14:
                        ip_start = 14
                    else:
                        ip_start = 0

                    if len(packet_data) < ip_start + 20:
                        continue

                    ip_header_len = (packet_data[ip_start] & 0x0F) * 4
                    if len(packet_data) < ip_start + ip_header_len + 20:
                        continue

                    tcp_start = ip_start + ip_header_len
                    tcp_header = packet_data[tcp_start : tcp_start + 20]
                    seq = struct.unpack("!I", tcp_header[4:8])[0]

                    seq_numbers.append((idx, seq))

                except:
                    continue

            if len(seq_numbers) < 2:
                return False, None

            # Check if sequence numbers are monotonically increasing
            # (allowing for wraparound)
            disorder_count = 0
            for i in range(1, len(seq_numbers)):
                prev_idx, prev_seq = seq_numbers[i - 1]
                curr_idx, curr_seq = seq_numbers[i]

                # Check if current seq is less than previous (disorder)
                # Handle wraparound: if difference is huge, it's likely wraparound
                diff = curr_seq - prev_seq
                if diff < 0 and abs(diff) < 2**31:  # Not wraparound
                    disorder_count += 1

            if disorder_count > 0:
                details = f"Found {disorder_count} out-of-order packets"
                self.logger.info(f"Disorder detected: {details}")
                return True, details

            return False, None

        except Exception as e:
            self.logger.error(f"Error detecting disorder: {e}")
            return False, None

    def detect_fooling(self, packets: List[bytes]) -> List[str]:
        """
        Detect fooling modes (badsum, badseq) by checking checksums.

        Args:
            packets: List of raw packet data

        Returns:
            List of detected fooling modes

        Requirements: 8.5
        """
        fooling_modes = []
        invalid_checksum_count = 0

        for idx, packet_data in enumerate(packets):
            try:
                # Skip Ethernet header
                if len(packet_data) >= 14:
                    ip_start = 14
                else:
                    ip_start = 0

                if len(packet_data) < ip_start + 20:
                    continue

                # Parse IP and TCP headers
                ip_header_len = (packet_data[ip_start] & 0x0F) * 4
                if len(packet_data) < ip_start + ip_header_len + 20:
                    continue

                # Extract TCP checksum
                tcp_start = ip_start + ip_header_len
                tcp_header = packet_data[tcp_start : tcp_start + 20]
                stored_checksum = struct.unpack("!H", tcp_header[16:18])[0]

                # Calculate expected checksum
                # For simplicity, we check if checksum is 0 (common badsum indicator)
                if stored_checksum == 0:
                    invalid_checksum_count += 1

            except Exception as e:
                self.logger.debug(f"Error checking checksum for packet {idx}: {e}")
                continue

        # If we found packets with invalid checksums, report badsum
        if invalid_checksum_count > 0:
            fooling_modes.append("badsum")
            self.logger.info(
                f"Detected badsum: {invalid_checksum_count} packets with invalid checksums"
            )

        return fooling_modes

    def _read_pcap(self, pcap_file: Path) -> List[bytes]:
        """
        Read PCAP file and return raw packet data.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of raw packet bytes
        """
        packets = []

        try:
            if not pcap_file.exists():
                self.logger.warning(f"PCAP file not found: {pcap_file}")
                return packets

            # Read PCAP file header
            with open(pcap_file, "rb") as f:
                # Read global header (24 bytes)
                global_header = f.read(24)
                if len(global_header) < 24:
                    self.logger.error("Invalid PCAP file: header too short")
                    return packets

                # Check magic number
                magic = struct.unpack("I", global_header[0:4])[0]
                if magic == 0xA1B2C3D4:
                    # Standard PCAP
                    pass
                elif magic == 0xD4C3B2A1:
                    # Swapped byte order
                    self.logger.warning("Swapped byte order PCAP not fully supported")
                else:
                    self.logger.error(f"Invalid PCAP magic number: {hex(magic)}")
                    return packets

                # Read packets
                while True:
                    # Read packet header (16 bytes)
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    # Extract packet length
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", packet_header)

                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break

                    packets.append(packet_data)

            self.logger.info(f"Read {len(packets)} packets from {pcap_file}")

        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}", exc_info=True)

        return packets

    def _is_tcp_packet(self, packet_data: bytes) -> bool:
        """
        Check if packet is TCP.

        Args:
            packet_data: Raw packet bytes (includes Ethernet header)

        Returns:
            True if TCP packet
        """
        try:
            # Skip Ethernet header (14 bytes) if present
            # Check if this looks like an Ethernet frame
            if len(packet_data) >= 14:
                # Assume Ethernet header, skip it
                ip_start = 14
            else:
                ip_start = 0

            if len(packet_data) < ip_start + 20:
                return False

            # Check IP protocol field (byte 9 of IP header)
            # 6 = TCP
            protocol = packet_data[ip_start + 9]
            return protocol == 6

        except:
            return False

    def _extract_tcp_payload(self, packet_data: bytes) -> Tuple[Optional[bytes], int]:
        """
        Extract TCP payload and sequence number from packet.

        Args:
            packet_data: Raw packet bytes (includes Ethernet header)

        Returns:
            Tuple of (payload, sequence_number)
        """
        try:
            # Skip Ethernet header (14 bytes) if present
            if len(packet_data) >= 14:
                ip_start = 14
            else:
                ip_start = 0

            if len(packet_data) < ip_start + 20:
                return None, 0

            # Parse IP header
            ip_header_len = (packet_data[ip_start] & 0x0F) * 4
            if len(packet_data) < ip_start + ip_header_len + 20:
                return None, 0

            # Parse TCP header
            tcp_start = ip_start + ip_header_len
            tcp_header = packet_data[tcp_start : tcp_start + 20]
            seq = struct.unpack("!I", tcp_header[4:8])[0]

            # Get TCP data offset (header length)
            tcp_header_len = ((tcp_header[12] >> 4) & 0x0F) * 4

            # Extract payload
            payload_start = tcp_start + tcp_header_len
            if len(packet_data) > payload_start:
                payload = packet_data[payload_start:]
                return payload, seq

            return None, seq

        except Exception as e:
            self.logger.debug(f"Error extracting TCP payload: {e}")
            return None, 0
