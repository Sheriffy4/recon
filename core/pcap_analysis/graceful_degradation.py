"""
Graceful degradation mechanisms for PCAP analysis.

This module provides fallback strategies and partial analysis capabilities
when PCAP files are corrupted, incomplete, or otherwise problematic.
"""

import logging
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import struct
import socket

from .packet_info import PacketInfo, TLSInfo
from .error_handling import (
    PCAPParsingError,
    PartialResult,
)
from .diagnostics import get_debug_logger
from core.packet.raw_pcap_reader import RawPCAPReader, CorruptedPacketError
from core.packet.raw_packet_engine import RawPacket


@dataclass
class PCAPFileInfo:
    """Information about a PCAP file."""

    filepath: str
    size_bytes: int
    is_readable: bool
    header_valid: bool
    packet_count_estimate: int
    corruption_detected: bool
    corruption_details: List[str] = field(default_factory=list)
    readable_portion: float = 1.0  # 0.0 to 1.0


@dataclass
class FallbackStrategy:
    """Represents a fallback parsing strategy."""

    name: str
    description: str
    priority: int
    min_success_rate: float = 0.3
    max_retries: int = 3


class GracefulPCAPParser:
    """PCAP parser with graceful degradation capabilities."""

    def __init__(self):
        self.logger = logging.getLogger("pcap_analysis.graceful_parser")
        self.debug_logger = get_debug_logger()
        self.pcap_reader = RawPCAPReader()  # Use RawPCAPReader instead of Scapy
        self.fallback_strategies = self._setup_fallback_strategies()
        self.parsing_stats = {
            "total_files": 0,
            "successful_parses": 0,
            "partial_parses": 0,
            "failed_parses": 0,
            "fallback_uses": 0,
        }

    def _setup_fallback_strategies(self) -> List[FallbackStrategy]:
        """Setup fallback parsing strategies with RawPCAPReader as primary."""
        return [
            FallbackStrategy(
                name="skip_corrupted_packets",
                description="Skip corrupted packets using RawPCAPReader streaming",
                priority=1,
                min_success_rate=0.7,
            ),
            FallbackStrategy(
                name="partial_file_parsing",
                description="Parse only the readable portion using RawPCAPReader",
                priority=2,
                min_success_rate=0.5,
            ),
            FallbackStrategy(
                name="raw_packet_extraction",
                description="Extract packets using RawPacketEngine",
                priority=3,
                min_success_rate=0.4,
            ),
            FallbackStrategy(
                name="alternative_parser",
                description="Use alternative parsing library (dpkt) as last resort",
                priority=4,
                min_success_rate=0.3,
            ),
            FallbackStrategy(
                name="metadata_only",
                description="Extract only basic metadata without full packet parsing",
                priority=5,
                min_success_rate=0.1,
            ),
        ]

    def analyze_pcap_file(self, filepath: str) -> PCAPFileInfo:
        """Analyze PCAP file for potential issues."""
        self.debug_logger.start_operation("analyze_pcap_file", filepath=filepath)

        try:
            path = Path(filepath)
            if not path.exists():
                return PCAPFileInfo(
                    filepath=filepath,
                    size_bytes=0,
                    is_readable=False,
                    header_valid=False,
                    packet_count_estimate=0,
                    corruption_detected=True,
                    corruption_details=["File does not exist"],
                )

            size_bytes = path.stat().st_size
            corruption_details = []

            # Check file size
            if size_bytes == 0:
                corruption_details.append("File is empty")
            elif size_bytes < 24:  # Minimum PCAP header size
                corruption_details.append("File too small to contain valid PCAP header")

            # Try to read PCAP header
            header_valid = False
            packet_count_estimate = 0
            readable_portion = 0.0

            try:
                with open(filepath, "rb") as f:
                    # Read PCAP global header
                    header = f.read(24)
                    if len(header) == 24:
                        # Check magic number
                        magic = struct.unpack("<I", header[:4])[0]
                        if magic in [0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1]:
                            header_valid = True

                            # Estimate packet count by scanning file
                            packet_count_estimate, readable_portion = self._estimate_packet_count(f)
                        else:
                            corruption_details.append(f"Invalid PCAP magic number: 0x{magic:08x}")
                    else:
                        corruption_details.append("Incomplete PCAP header")

            except Exception as e:
                corruption_details.append(f"Error reading file: {e}")

            corruption_detected = len(corruption_details) > 0 or readable_portion < 1.0

            file_info = PCAPFileInfo(
                filepath=filepath,
                size_bytes=size_bytes,
                is_readable=size_bytes > 0,
                header_valid=header_valid,
                packet_count_estimate=packet_count_estimate,
                corruption_detected=corruption_detected,
                corruption_details=corruption_details,
                readable_portion=readable_portion,
            )

            self.debug_logger.end_operation("analyze_pcap_file", file_info=file_info.__dict__)
            return file_info

        except Exception as e:
            self.debug_logger.log_error_details(e, "analyze_pcap_file")
            return PCAPFileInfo(
                filepath=filepath,
                size_bytes=0,
                is_readable=False,
                header_valid=False,
                packet_count_estimate=0,
                corruption_detected=True,
                corruption_details=[f"Analysis failed: {e}"],
            )

    def _estimate_packet_count(self, file_handle) -> Tuple[int, float]:
        """Estimate packet count and readable portion of file."""
        try:
            file_handle.seek(24)  # Skip global header
            packet_count = 0
            bytes_read = 24
            file_size = file_handle.seek(0, 2)  # Get file size
            file_handle.seek(24)  # Reset to after header

            while True:
                # Read packet record header (16 bytes)
                packet_header = file_handle.read(16)
                if len(packet_header) < 16:
                    break

                try:
                    # Parse packet header
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", packet_header)

                    # Sanity checks
                    if incl_len > 65535 or orig_len > 65535 or incl_len > orig_len:
                        # Likely corruption, stop here
                        break

                    # Skip packet data
                    file_handle.seek(incl_len, 1)
                    packet_count += 1
                    bytes_read += 16 + incl_len

                    # Limit scanning to avoid long delays
                    if packet_count > 10000:
                        break

                except struct.error:
                    # Corrupted packet header
                    break
                except Exception:
                    # Other errors
                    break

            readable_portion = bytes_read / file_size if file_size > 0 else 0.0
            return packet_count, readable_portion

        except Exception as e:
            self.logger.warning(f"Error estimating packet count: {e}")
            return 0, 0.0

    def parse_with_degradation(self, filepath: str, min_success_rate: float = 0.5) -> PartialResult:
        """Parse PCAP file with graceful degradation."""
        self.parsing_stats["total_files"] += 1

        self.debug_logger.start_operation(
            "parse_with_degradation",
            filepath=filepath,
            min_success_rate=min_success_rate,
        )

        try:
            # First, analyze the file
            file_info = self.analyze_pcap_file(filepath)

            if not file_info.is_readable:
                self.parsing_stats["failed_parses"] += 1
                return PartialResult(
                    success=False,
                    data=None,
                    errors=[
                        PCAPParsingError(
                            f"File is not readable: {'; '.join(file_info.corruption_details)}",
                            filepath,
                        )
                    ],
                    completeness=0.0,
                )

            # Try normal parsing first
            if not file_info.corruption_detected:
                try:
                    packets = self._parse_normal(filepath)
                    self.parsing_stats["successful_parses"] += 1
                    return PartialResult(
                        success=True,
                        data=packets,
                        completeness=1.0,
                        metadata={
                            "parsing_method": "normal",
                            "file_info": file_info.__dict__,
                        },
                    )
                except Exception as e:
                    self.logger.warning(f"Normal parsing failed: {e}")

            # Try fallback strategies
            for strategy in self.fallback_strategies:
                if strategy.min_success_rate > min_success_rate:
                    continue

                self.logger.info(f"Trying fallback strategy: {strategy.name}")
                self.parsing_stats["fallback_uses"] += 1

                try:
                    result = self._apply_fallback_strategy(strategy, filepath, file_info)
                    if result.success and result.completeness >= strategy.min_success_rate:
                        self.parsing_stats["partial_parses"] += 1
                        self.debug_logger.end_operation(
                            "parse_with_degradation",
                            strategy=strategy.name,
                            completeness=result.completeness,
                        )
                        return result
                except Exception as e:
                    self.logger.warning(f"Fallback strategy {strategy.name} failed: {e}")

            # All strategies failed
            self.parsing_stats["failed_parses"] += 1
            return PartialResult(
                success=False,
                data=None,
                errors=[
                    PCAPParsingError(f"All parsing strategies failed for {filepath}", filepath)
                ],
                completeness=0.0,
                metadata={"file_info": file_info.__dict__},
            )

        except Exception as e:
            self.debug_logger.log_error_details(e, "parse_with_degradation")
            self.parsing_stats["failed_parses"] += 1
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(str(e), filepath, original_error=e)],
                completeness=0.0,
            )

    def _parse_normal(self, filepath: str) -> List[PacketInfo]:
        """Normal PCAP parsing using RawPCAPReader."""
        try:
            self.logger.info("ℹ️ Используется RawPCAPReader для парсинга PCAP")

            # Use RawPCAPReader to read packets
            raw_packets = self.pcap_reader.read_pcap_file(filepath)
            packet_infos = []

            for i, raw_packet in enumerate(raw_packets):
                try:
                    # Convert RawPacket to PacketInfo
                    packet_info = self._raw_packet_to_packet_info(raw_packet, i)
                    if packet_info:
                        packet_infos.append(packet_info)
                except Exception as e:
                    self.logger.warning(f"Error processing packet {i}: {e}")
                    continue

            self.logger.info(f"✅ Успешно обработано {len(packet_infos)} пакетов")
            return packet_infos

        except Exception as e:
            raise PCAPParsingError(f"Normal parsing failed: {e}", filepath, original_error=e)

    def _apply_fallback_strategy(
        self, strategy: FallbackStrategy, filepath: str, file_info: PCAPFileInfo
    ) -> PartialResult:
        """Apply a specific fallback strategy."""

        if strategy.name == "skip_corrupted_packets":
            return self._skip_corrupted_packets(filepath, file_info)
        elif strategy.name == "partial_file_parsing":
            return self._partial_file_parsing(filepath, file_info)
        elif strategy.name == "alternative_parser":
            return self._alternative_parser(filepath, file_info)
        elif strategy.name == "raw_packet_extraction":
            return self._raw_packet_extraction(filepath, file_info)
        elif strategy.name == "metadata_only":
            return self._metadata_only(filepath, file_info)
        else:
            raise ValueError(f"Unknown fallback strategy: {strategy.name}")

    def _skip_corrupted_packets(self, filepath: str, file_info: PCAPFileInfo) -> PartialResult:
        """Skip corrupted packets and continue parsing using RawPCAPReader streaming."""
        try:
            self.logger.info("ℹ️ Используется RawPCAPReader с пропуском поврежденных пакетов")

            packet_infos = []
            skipped_count = 0
            total_count = 0

            # Use iterate_packets for streaming (handles corrupted packets gracefully)
            for raw_packet in self.pcap_reader.iterate_packets(filepath):
                total_count += 1
                try:
                    packet_info = self._raw_packet_to_packet_info(raw_packet, total_count - 1)
                    if packet_info:
                        packet_infos.append(packet_info)
                except Exception as e:
                    skipped_count += 1
                    self.logger.debug(f"Skipped corrupted packet {total_count}: {e}")
                    continue

            success_rate = (total_count - skipped_count) / max(1, total_count)

            return PartialResult(
                success=True,
                data=packet_infos,
                warnings=[f"Skipped {skipped_count} corrupted packets out of {total_count}"],
                completeness=success_rate,
                metadata={
                    "parsing_method": "skip_corrupted_raw",
                    "total_packets": total_count,
                    "skipped_packets": skipped_count,
                    "success_rate": success_rate,
                },
            )

        except Exception as e:
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(f"Skip corrupted strategy failed: {e}", filepath)],
                completeness=0.0,
            )

    def _partial_file_parsing(self, filepath: str, file_info: PCAPFileInfo) -> PartialResult:
        """Parse only the readable portion of the file using RawPCAPReader."""
        try:
            self.logger.info(
                f"ℹ️ Парсинг частичного файла ({file_info.readable_portion:.1%}) с RawPCAPReader"
            )

            # Create a temporary file with only the readable portion
            readable_bytes = int(file_info.size_bytes * file_info.readable_portion)

            temp_filepath = f"{filepath}.partial"
            with open(filepath, "rb") as src, open(temp_filepath, "wb") as dst:
                dst.write(src.read(readable_bytes))

            try:
                # Parse the partial file using RawPCAPReader
                packet_infos = self._parse_normal(temp_filepath)

                return PartialResult(
                    success=True,
                    data=packet_infos,
                    warnings=[
                        f"Parsed only {file_info.readable_portion:.1%} of file using RawPCAPReader"
                    ],
                    completeness=file_info.readable_portion,
                    metadata={
                        "parsing_method": "partial_file_raw",
                        "readable_portion": file_info.readable_portion,
                        "readable_bytes": readable_bytes,
                    },
                )
            finally:
                # Clean up temporary file
                try:
                    Path(temp_filepath).unlink()
                except Exception:
                    pass

        except Exception as e:
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(f"Partial file parsing failed: {e}", filepath)],
                completeness=0.0,
            )

    def _alternative_parser(self, filepath: str, file_info: PCAPFileInfo) -> PartialResult:
        """Use alternative parsing library (dpkt) as last resort fallback."""
        try:
            self.logger.info("ℹ️ Используется альтернативный парсер (dpkt) как последний fallback")

            import dpkt
            import socket

            packet_infos = []

            with open(filepath, "rb") as f:
                pcap = dpkt.pcap.Reader(f)

                for i, (timestamp, buf) in enumerate(pcap):
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp = ip.data

                                packet_info = PacketInfo(
                                    timestamp=timestamp,
                                    src_ip=socket.inet_ntoa(ip.src),
                                    dst_ip=socket.inet_ntoa(ip.dst),
                                    src_port=tcp.sport,
                                    dst_port=tcp.dport,
                                    sequence_num=tcp.seq,
                                    ack_num=tcp.ack,
                                    ttl=ip.ttl,
                                    flags=self._parse_tcp_flags_dpkt(tcp.flags),
                                    payload_length=len(tcp.data),
                                    payload_hex=tcp.data.hex() if tcp.data else "",
                                    checksum=tcp.sum,
                                    checksum_valid=True,  # dpkt doesn't validate by default
                                    is_client_hello=self._is_tls_client_hello(tcp.data),
                                )
                                packet_infos.append(packet_info)
                    except Exception as e:
                        self.logger.debug(f"Error parsing packet {i} with dpkt: {e}")
                        continue

            return PartialResult(
                success=True,
                data=packet_infos,
                warnings=["Used alternative parser (dpkt) as fallback"],
                completeness=0.7,  # Lower priority than RawPCAPReader
                metadata={"parsing_method": "dpkt_fallback"},
            )

        except ImportError:
            self.logger.warning("⚠️ dpkt не доступен для альтернативного парсинга")
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError("dpkt not available", filepath)],
                completeness=0.0,
            )
        except Exception as e:
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(f"Alternative parser failed: {e}", filepath)],
                completeness=0.0,
            )

    def _raw_packet_extraction(self, filepath: str, file_info: PCAPFileInfo) -> PartialResult:
        """Extract packets using RawPacketEngine.parse_packet_sync()."""
        try:
            self.logger.info("ℹ️ Используется RawPacketEngine для извлечения пакетов")

            packet_infos = []

            with open(filepath, "rb") as f:
                # Parse PCAP header to get byte order
                try:
                    pcap_header = self.pcap_reader.parse_pcap_header(f)
                    endian = "<" if pcap_header.byte_order == "little" else ">"
                except Exception as e:
                    self.logger.warning(f"Failed to parse PCAP header, using default: {e}")
                    # Skip to packet data
                    f.seek(24)
                    endian = "<"

                packet_index = 0
                while True:
                    # Read packet record header
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break

                    try:
                        format_str = f"{endian}IIII"
                        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                            format_str, packet_header
                        )

                        # Basic sanity checks
                        if incl_len > 65535 or orig_len > 65535:
                            break

                        # Read packet data
                        packet_data = f.read(incl_len)
                        if len(packet_data) < incl_len:
                            break

                        # Use RawPacketEngine to parse packet
                        try:
                            raw_packet = self.pcap_reader.engine.parse_packet_sync(packet_data)
                            timestamp = ts_sec + ts_usec / 1000000.0
                            packet_info = self._raw_packet_to_packet_info(
                                raw_packet, packet_index, timestamp
                            )
                            if packet_info:
                                packet_infos.append(packet_info)
                        except Exception as e:
                            self.logger.debug(
                                f"Failed to parse packet {packet_index} with RawPacketEngine: {e}"
                            )
                            # Fallback to basic extraction
                            packet_info = self._extract_basic_info_raw(
                                packet_data, ts_sec + ts_usec / 1000000.0, packet_index
                            )
                            if packet_info:
                                packet_infos.append(packet_info)

                        packet_index += 1

                        # Limit to avoid long processing
                        if packet_index > 10000:
                            break

                    except Exception as e:
                        self.logger.debug(f"Error in raw extraction at packet {packet_index}: {e}")
                        break

            return PartialResult(
                success=True,
                data=packet_infos,
                warnings=["Used RawPacketEngine for packet extraction"],
                completeness=0.6,  # Higher completeness with RawPacketEngine
                metadata={
                    "parsing_method": "raw_packet_engine",
                    "packets_extracted": len(packet_infos),
                },
            )

        except Exception as e:
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(f"Raw extraction failed: {e}", filepath)],
                completeness=0.0,
            )

    def _metadata_only(self, filepath: str, file_info: PCAPFileInfo) -> PartialResult:
        """Extract only basic metadata without full packet parsing."""
        try:
            metadata = {
                "file_size": file_info.size_bytes,
                "estimated_packets": file_info.packet_count_estimate,
                "readable_portion": file_info.readable_portion,
                "corruption_detected": file_info.corruption_detected,
                "corruption_details": file_info.corruption_details,
            }

            return PartialResult(
                success=True,
                data=metadata,
                warnings=["Only metadata extracted - no packet details available"],
                completeness=0.1,
                metadata={"parsing_method": "metadata_only"},
            )

        except Exception as e:
            return PartialResult(
                success=False,
                data=None,
                errors=[PCAPParsingError(f"Metadata extraction failed: {e}", filepath)],
                completeness=0.0,
            )

    def _raw_packet_to_packet_info(
        self, raw_packet: RawPacket, index: int, timestamp: Optional[float] = None
    ) -> Optional[PacketInfo]:
        """
        Convert RawPacket to PacketInfo.

        Args:
            raw_packet: RawPacket from RawPCAPReader
            index: Packet index
            timestamp: Optional timestamp (if not available, use 0.0)

        Returns:
            PacketInfo or None if conversion fails
        """
        try:
            # Extract TCP header information from raw packet data
            if len(raw_packet.data) < 34:  # Minimum Ethernet + IP + TCP
                return None

            # Skip Ethernet header (14 bytes) and parse IP header
            ip_start = 14
            ip_header = raw_packet.data[ip_start : ip_start + 20]

            if len(ip_header) < 20:
                return None

            # Parse IP header fields
            version_ihl = ip_header[0]
            ihl = (version_ihl & 0x0F) * 4
            ttl = ip_header[8]
            protocol = ip_header[9]

            if protocol != 6:  # Not TCP
                return None

            # Parse TCP header
            tcp_start = ip_start + ihl
            tcp_header = raw_packet.data[tcp_start : tcp_start + 20]

            if len(tcp_header) < 20:
                return None

            seq_num = struct.unpack(">I", tcp_header[4:8])[0]
            ack_num = struct.unpack(">I", tcp_header[8:12])[0]

            # TCP flags
            flags_byte = tcp_header[13]
            flags = []
            flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
            for i, flag_name in enumerate(flag_names):
                if flags_byte & (1 << i):
                    flags.append(flag_name)

            # Window size
            window_size = struct.unpack(">H", tcp_header[14:16])[0]

            # Checksum
            checksum = struct.unpack(">H", tcp_header[16:18])[0]

            # TCP header length
            tcp_header_len = ((tcp_header[12] >> 4) & 0xF) * 4

            # Payload
            payload = raw_packet.payload if raw_packet.payload else b""

            # Check for TLS ClientHello
            is_client_hello = self._is_tls_client_hello(payload)
            tls_info = None
            if is_client_hello:
                tls_info = TLSInfo.from_payload(payload)

            return PacketInfo(
                timestamp=timestamp if timestamp is not None else 0.0,
                src_ip=raw_packet.src_ip,
                dst_ip=raw_packet.dst_ip,
                src_port=raw_packet.src_port or 0,
                dst_port=raw_packet.dst_port or 0,
                sequence_num=seq_num,
                ack_num=ack_num,
                ttl=ttl,
                flags=flags,
                window_size=window_size,
                payload_length=len(payload),
                payload=payload,
                payload_hex=payload.hex() if payload else "",
                checksum=checksum,
                checksum_valid=True,  # TODO: Implement checksum validation
                is_client_hello=is_client_hello,
                tls_info=tls_info,
                packet_size=len(raw_packet.data),
                raw_data=raw_packet.data,
            )

        except Exception as e:
            self.logger.debug(f"Error converting RawPacket to PacketInfo for packet {index}: {e}")
            return None

    # Removed _extract_packet_info - replaced by _raw_packet_to_packet_info which uses RawPCAPReader

    def _extract_basic_info_raw(
        self, packet_data: bytes, timestamp: float, index: int
    ) -> Optional[PacketInfo]:
        """Extract basic packet info from raw packet data."""
        try:
            # This is a simplified extraction - would need more sophisticated parsing
            # for production use
            if len(packet_data) < 54:  # Minimum Ethernet + IP + TCP header size
                return None

            # Skip Ethernet header (14 bytes) and parse IP header
            ip_header = packet_data[14:34]
            if len(ip_header) < 20:
                return None

            # Basic IP header parsing
            (
                version_ihl,
                tos,
                total_len,
                id_field,
                flags_frag,
                ttl,
                protocol,
                checksum,
                src_ip,
                dst_ip,
            ) = struct.unpack("!BBHHHBBH4s4s", ip_header)

            if protocol != 6:  # Not TCP
                return None

            # Parse TCP header
            tcp_start = 14 + ((version_ihl & 0x0F) * 4)
            tcp_header = packet_data[tcp_start : tcp_start + 20]
            if len(tcp_header) < 20:
                return None

            (
                src_port,
                dst_port,
                seq_num,
                ack_num,
                offset_flags,
                window,
                tcp_checksum,
                urgent,
            ) = struct.unpack("!HHIIHHH", tcp_header)

            return PacketInfo(
                timestamp=timestamp,
                src_ip=socket.inet_ntoa(src_ip),
                dst_ip=socket.inet_ntoa(dst_ip),
                src_port=src_port,
                dst_port=dst_port,
                sequence_num=seq_num,
                ack_num=ack_num,
                ttl=ttl,
                flags=[],  # Would need more parsing
                payload_length=0,  # Would need calculation
                payload_hex="",
                checksum=tcp_checksum,
                checksum_valid=True,
                is_client_hello=False,
            )

        except Exception as e:
            self.logger.debug(f"Error in raw packet extraction: {e}")
            return None

    # Removed _parse_tcp_flags_scapy - TCP flags are now parsed in _raw_packet_to_packet_info

    def _parse_tcp_flags_dpkt(self, flags) -> List[str]:
        """Parse TCP flags from dpkt."""
        flag_names = []
        if flags & dpkt.tcp.TH_FIN:
            flag_names.append("FIN")
        if flags & dpkt.tcp.TH_SYN:
            flag_names.append("SYN")
        if flags & dpkt.tcp.TH_RST:
            flag_names.append("RST")
        if flags & dpkt.tcp.TH_PUSH:
            flag_names.append("PSH")
        if flags & dpkt.tcp.TH_ACK:
            flag_names.append("ACK")
        if flags & dpkt.tcp.TH_URG:
            flag_names.append("URG")
        return flag_names

    def _is_tls_client_hello(self, payload: bytes) -> bool:
        """Check if payload contains TLS ClientHello."""
        if len(payload) < 6:
            return False

        # Check for TLS record header
        if payload[0] == 0x16:  # Handshake
            if len(payload) > 5 and payload[5] == 0x01:  # ClientHello
                return True

        return False

    # Removed _extract_tls_info - TLS info is now extracted in _raw_packet_to_packet_info using TLSInfo.from_payload()

    def get_parsing_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        total = self.parsing_stats["total_files"]
        if total == 0:
            return {"message": "No files parsed yet"}

        return {
            "total_files": total,
            "successful_parses": self.parsing_stats["successful_parses"],
            "partial_parses": self.parsing_stats["partial_parses"],
            "failed_parses": self.parsing_stats["failed_parses"],
            "fallback_uses": self.parsing_stats["fallback_uses"],
            "success_rate": (
                self.parsing_stats["successful_parses"] + self.parsing_stats["partial_parses"]
            )
            / total,
            "fallback_rate": self.parsing_stats["fallback_uses"] / total,
        }


# Global instance
_graceful_parser = None


def get_graceful_parser() -> GracefulPCAPParser:
    """Get global graceful parser instance."""
    global _graceful_parser
    if _graceful_parser is None:
        _graceful_parser = GracefulPCAPParser()
    return _graceful_parser


def parse_pcap_with_fallback(filepath: str, min_success_rate: float = 0.5) -> PartialResult:
    """Parse PCAP file with graceful degradation."""
    return get_graceful_parser().parse_with_degradation(filepath, min_success_rate)
