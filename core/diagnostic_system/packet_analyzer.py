"""
Packet Analyzer for Byte-Level Analysis
Handles IPv4/IPv6 header analysis, TCP/UDP analysis, and payload inspection.
"""

import logging
import math
import struct
from typing import Dict, Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    import pydivert


class PacketAnalyzer:
    """Performs comprehensive byte-level packet analysis."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("PacketAnalyzer")

    def analyze_packet_bytes(
        self,
        packet: "pydivert.Packet",
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive byte-level analysis of packet.

        Args:
            packet: The packet to analyze
            additional_info: Additional analysis data from processing

        Returns:
            Dictionary with byte-level analysis results
        """
        analysis = {}
        try:
            if not packet.raw:
                return analysis

            raw_data = bytes(packet.raw)
            analysis["raw_size"] = len(raw_data)

            if len(raw_data) >= 20:
                ip_version = (raw_data[0] >> 4) & 0x0F
                analysis["ip_version"] = ip_version

                if ip_version == 4:
                    analysis.update(self.analyze_ipv4_header(raw_data))
                elif ip_version == 6:
                    analysis.update(self.analyze_ipv6_header(raw_data))

            if hasattr(packet, "tcp") and packet.tcp:
                analysis.update(self.analyze_tcp_bytes(raw_data))
            elif hasattr(packet, "udp") and packet.udp:
                analysis.update(self.analyze_udp_bytes(raw_data))

            if packet.payload:
                analysis.update(self.analyze_payload_bytes(packet.payload))

            if additional_info:
                analysis["processing_info"] = additional_info

        except Exception as e:
            analysis["analysis_error"] = str(e)
            self.logger.debug(f"Byte analysis error: {e}")

        return analysis

    def analyze_ipv4_header(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze IPv4 header bytes."""
        analysis = {}
        try:
            if len(raw_data) < 20:
                return analysis

            analysis["header_length"] = (raw_data[0] & 0x0F) * 4
            analysis["tos"] = raw_data[1]
            analysis["total_length"] = struct.unpack("!H", raw_data[2:4])[0]
            analysis["identification"] = struct.unpack("!H", raw_data[4:6])[0]

            flags_and_frag = struct.unpack("!H", raw_data[6:8])[0]
            analysis["flags"] = (flags_and_frag >> 13) & 0x07
            analysis["fragment_offset"] = flags_and_frag & 0x1FFF
            analysis["is_fragmented"] = (
                analysis["fragment_offset"] > 0 or (analysis["flags"] & 0x01) != 0
            )

            analysis["ttl"] = raw_data[8]
            analysis["protocol"] = raw_data[9]
            analysis["checksum"] = struct.unpack("!H", raw_data[10:12])[0]

        except Exception as e:
            analysis["ipv4_analysis_error"] = str(e)

        return analysis

    def analyze_ipv6_header(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze IPv6 header bytes."""
        analysis = {}
        try:
            if len(raw_data) < 40:
                return analysis

            version_class_label = struct.unpack("!I", raw_data[0:4])[0]
            analysis["traffic_class"] = (version_class_label >> 20) & 0xFF
            analysis["flow_label"] = version_class_label & 0xFFFFF
            analysis["payload_length"] = struct.unpack("!H", raw_data[4:6])[0]
            analysis["next_header"] = raw_data[6]
            analysis["hop_limit"] = raw_data[7]

        except Exception as e:
            analysis["ipv6_analysis_error"] = str(e)

        return analysis

    def analyze_tcp_bytes(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze TCP header and options bytes."""
        analysis = {}
        try:
            ip_version = (raw_data[0] >> 4) & 0x0F
            ip_header_len = (raw_data[0] & 0x0F) * 4 if ip_version == 4 else 40

            if len(raw_data) < ip_header_len + 20:
                return analysis

            tcp_start = ip_header_len
            tcp_header_len = ((raw_data[tcp_start + 12] >> 4) & 0x0F) * 4
            analysis["tcp_header_length"] = tcp_header_len

            analysis["sequence_number"] = struct.unpack(
                "!I", raw_data[tcp_start + 4 : tcp_start + 8]
            )[0]
            analysis["ack_number"] = struct.unpack("!I", raw_data[tcp_start + 8 : tcp_start + 12])[
                0
            ]

            flags_byte = raw_data[tcp_start + 13]
            analysis["tcp_flags"] = {
                "FIN": bool(flags_byte & 0x01),
                "SYN": bool(flags_byte & 0x02),
                "RST": bool(flags_byte & 0x04),
                "PSH": bool(flags_byte & 0x08),
                "ACK": bool(flags_byte & 0x10),
                "URG": bool(flags_byte & 0x20),
            }

            analysis["window_size"] = struct.unpack(
                "!H", raw_data[tcp_start + 14 : tcp_start + 16]
            )[0]
            analysis["checksum"] = struct.unpack("!H", raw_data[tcp_start + 16 : tcp_start + 18])[0]
            analysis["urgent_pointer"] = struct.unpack(
                "!H", raw_data[tcp_start + 18 : tcp_start + 20]
            )[0]

            if tcp_header_len > 20:
                options_data = raw_data[tcp_start + 20 : tcp_start + tcp_header_len]
                analysis["tcp_options"] = self.analyze_tcp_options(options_data)

        except Exception as e:
            analysis["tcp_analysis_error"] = str(e)

        return analysis

    def analyze_udp_bytes(self, raw_data: bytes) -> Dict[str, Any]:
        """Analyze UDP header bytes."""
        analysis = {}
        try:
            ip_version = (raw_data[0] >> 4) & 0x0F
            ip_header_len = (raw_data[0] & 0x0F) * 4 if ip_version == 4 else 40

            if len(raw_data) < ip_header_len + 8:
                return analysis

            udp_start = ip_header_len
            analysis["udp_length"] = struct.unpack("!H", raw_data[udp_start + 4 : udp_start + 6])[0]
            analysis["udp_checksum"] = struct.unpack("!H", raw_data[udp_start + 6 : udp_start + 8])[
                0
            ]

        except Exception as e:
            analysis["udp_analysis_error"] = str(e)

        return analysis

    def analyze_payload_bytes(self, payload: bytes) -> Dict[str, Any]:
        """Analyze payload bytes for protocol detection and patterns."""
        analysis = {}
        try:
            payload_bytes = bytes(payload)
            analysis["payload_size"] = len(payload_bytes)

            if len(payload_bytes) == 0:
                return analysis

            analysis["protocol_hints"] = []

            # TLS detection
            if len(payload_bytes) >= 6:
                if payload_bytes[0] == 0x16:  # TLS Handshake
                    analysis["protocol_hints"].append("TLS")
                    analysis["tls_type"] = payload_bytes[0]
                    analysis["tls_version"] = struct.unpack("!H", payload_bytes[1:3])[0]
                    analysis["tls_length"] = struct.unpack("!H", payload_bytes[3:5])[0]
                    if len(payload_bytes) > 5 and payload_bytes[5] == 0x01:
                        analysis["protocol_hints"].append("TLS_ClientHello")

            # HTTP detection
            if (
                payload_bytes.startswith(b"GET ")
                or payload_bytes.startswith(b"POST ")
                or payload_bytes.startswith(b"PUT ")
                or payload_bytes.startswith(b"DELETE ")
            ):
                analysis["protocol_hints"].append("HTTP_Request")
            elif payload_bytes.startswith(b"HTTP/"):
                analysis["protocol_hints"].append("HTTP_Response")

            # QUIC detection
            if len(payload_bytes) >= 1:
                first_byte = payload_bytes[0]
                if first_byte & 0x80 != 0:
                    analysis["protocol_hints"].append("QUIC_Long_Header")
                elif first_byte & 0x40 != 0:
                    analysis["protocol_hints"].append("QUIC_Short_Header")

            analysis["entropy"] = self.calculate_entropy(
                payload_bytes[: min(256, len(payload_bytes))]
            )
            analysis["patterns"] = self.analyze_byte_patterns(payload_bytes)

        except Exception as e:
            analysis["payload_analysis_error"] = str(e)

        return analysis

    def analyze_tcp_options(self, options_data: bytes) -> List[Dict[str, Any]]:
        """Analyze TCP options bytes."""
        options = []
        i = 0
        try:
            while i < len(options_data):
                if options_data[i] == 0:  # End of options
                    break
                elif options_data[i] == 1:  # NOP
                    options.append(
                        {
                            "type": "NOP",
                            "value": None,
                            "no_fallbacks": True,
                            "forced": True,
                        }
                    )
                    i += 1
                else:
                    if i + 1 >= len(options_data):
                        break

                    option_type = options_data[i]
                    option_length = options_data[i + 1]

                    if option_length < 2 or i + option_length > len(options_data):
                        break

                    option_data = options_data[i + 2 : i + option_length]
                    option_info = {
                        "type": option_type,
                        "length": option_length,
                        "data": option_data.hex() if option_data else None,
                        "no_fallbacks": True,
                        "forced": True,
                    }

                    if option_type == 2 and option_length == 4:  # MSS
                        option_info["name"] = "MSS"
                        option_info["value"] = struct.unpack("!H", option_data)[0]
                    elif option_type == 3 and option_length == 3:  # Window Scale
                        option_info["name"] = "Window_Scale"
                        option_info["value"] = option_data[0]
                    elif option_type == 4 and option_length == 2:  # SACK Permitted
                        option_info["name"] = "SACK_Permitted"
                    elif option_type == 8 and option_length == 10:  # Timestamp
                        option_info["name"] = "Timestamp"
                        ts_val, ts_ecr = struct.unpack("!II", option_data)
                        option_info["value"] = {"ts_val": ts_val, "ts_ecr": ts_ecr}

                    options.append(option_info)
                    i += option_length

        except Exception as e:
            options.append({"error": str(e)})

        return options

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        try:
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    # Shannon entropy: -sum(p * log2(p))
                    entropy -= probability * math.log2(probability)

            return entropy
        except Exception:
            return 0.0

    def analyze_byte_patterns(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte patterns in payload."""
        patterns = {}
        try:
            if len(data) < 4:
                return patterns

            patterns["has_null_bytes"] = b"\x00" in data
            patterns["null_byte_count"] = data.count(b"\x00")

            # DPI trigger patterns
            dpi_patterns = [
                b"Host:",
                b"User-Agent:",
                b"Content-Type:",
                b"Accept:",
                b"Connection:",
                b"GET /",
                b"POST /",
                b"HTTP/1.1",
                b"HTTP/2.0",
            ]
            patterns["dpi_triggers"] = []
            for pattern in dpi_patterns:
                if pattern in data:
                    patterns["dpi_triggers"].append(pattern.decode("ascii", errors="ignore"))

            patterns["first_4_bytes"] = data[:4].hex()
            patterns["last_4_bytes"] = data[-4:].hex() if len(data) >= 4 else data.hex()

        except Exception as e:
            patterns["pattern_analysis_error"] = str(e)

        return patterns
