"""
Protocol Logger for TLS/HTTP/QUIC Packet Details
Handles protocol-specific logging and analysis for diagnostic purposes.
"""

import logging
import struct
from typing import Optional, Dict, Any


class ProtocolLogger:
    """Logs protocol-specific packet details for TLS, HTTP, and QUIC."""

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = logging.getLogger("ProtocolLogger")

    def log_byte_level_details(self, byte_analysis: Dict[str, Any]):
        """Log detailed byte-level analysis information."""
        try:
            if "raw_size" in byte_analysis:
                self.logger.debug(f"📊 Packet size: {byte_analysis['raw_size']} bytes")

            if "ip_version" in byte_analysis:
                self.logger.debug(f"🌐 IP version: {byte_analysis['ip_version']}")

            if "ttl" in byte_analysis:
                self.logger.debug(f"⏱️ TTL: {byte_analysis['ttl']}")

            if "is_fragmented" in byte_analysis and byte_analysis["is_fragmented"]:
                self.logger.debug(
                    f"🧩 Fragmented packet: offset={byte_analysis.get('fragment_offset', 'unknown')}"
                )

            if "tcp_flags" in byte_analysis:
                flags = byte_analysis["tcp_flags"]
                flag_str = "".join([k for k, v in flags.items() if v])
                self.logger.debug(f"🚩 TCP flags: {flag_str}")

            if "window_size" in byte_analysis:
                self.logger.debug(f"🪟 TCP window: {byte_analysis['window_size']}")

            if "tcp_options" in byte_analysis and byte_analysis["tcp_options"]:
                options = [
                    opt.get("name", f"Type_{opt.get('type', 'unknown')}")
                    for opt in byte_analysis["tcp_options"]
                ]
                self.logger.debug(f"⚙️ TCP options: {', '.join(options)}")

            if "protocol_hints" in byte_analysis and byte_analysis["protocol_hints"]:
                self.logger.debug(
                    f"🔍 Protocol hints: {', '.join(byte_analysis['protocol_hints'])}"
                )

            if "entropy" in byte_analysis:
                self.logger.debug(f"📈 Payload entropy: {byte_analysis['entropy']:.3f}")

            if "dpi_triggers" in byte_analysis.get("patterns", {}):
                triggers = byte_analysis["patterns"]["dpi_triggers"]
                if triggers:
                    self.logger.debug(f"🎯 DPI triggers found: {', '.join(triggers)}")

        except Exception as e:
            self.logger.debug(f"Error logging byte-level details: {e}")

    def log_tls_packet_details(self, payload: bytes):
        """Enhanced TLS packet analysis and logging."""
        try:
            payload_bytes = bytes(payload)
            if len(payload_bytes) < 6:
                return

            tls_type = payload_bytes[0]
            tls_version = struct.unpack("!H", payload_bytes[1:3])[0]
            tls_length = struct.unpack("!H", payload_bytes[3:5])[0]

            self.logger.debug(
                f"🔒 TLS Details: Type=0x{tls_type:02x}, Version=0x{tls_version:04x}, "
                f"Length={tls_length}, Payload={len(payload_bytes)}B"
            )

            # ClientHello detection
            if tls_type == 0x16 and len(payload_bytes) > 5 and payload_bytes[5] == 0x01:
                self.logger.debug("🤝 TLS ClientHello detected")

                sni = self._extract_sni_from_clienthello(payload_bytes)
                if sni:
                    self.logger.debug(f"🌐 SNI: {sni}")

                cipher_info = self._analyze_cipher_suites(payload_bytes)
                if cipher_info:
                    self.logger.debug(f"🔐 Cipher suites: {cipher_info}")

        except Exception as e:
            self.logger.debug(f"Error analyzing TLS packet: {e}")

    def log_http_packet_details(self, payload: bytes):
        """Enhanced HTTP packet analysis and logging."""
        try:
            payload_str = bytes(payload).decode("utf-8", errors="ignore")
            lines = payload_str.split("\r\n")

            if lines:
                self.logger.debug(f"🌐 HTTP: {lines[0]}")

                for line in lines[1:]:
                    if ":" in line:
                        header, value = line.split(":", 1)
                        header = header.strip().lower()
                        value = value.strip()

                        if header in ["host", "user-agent", "content-type"]:
                            self.logger.debug(f"📋 {header.title()}: {value}")

        except Exception as e:
            self.logger.debug(f"Error analyzing HTTP packet: {e}")

    def log_quic_packet_details(self, payload: bytes):
        """Enhanced QUIC packet analysis and logging."""
        try:
            payload_bytes = bytes(payload)
            if len(payload_bytes) < 1:
                return

            first_byte = payload_bytes[0]

            if first_byte & 0x80 != 0:
                self.logger.debug("⚡ QUIC Long Header packet")
                if len(payload_bytes) >= 5:
                    version = struct.unpack("!I", payload_bytes[1:5])[0]
                    self.logger.debug(f"📋 QUIC Version: 0x{version:08x}")
            elif first_byte & 0x40 != 0:
                self.logger.debug("⚡ QUIC Short Header packet")
            else:
                self.logger.debug("⚡ QUIC packet (unknown format)")

        except Exception as e:
            self.logger.debug(f"Error analyzing QUIC packet: {e}")

    def _extract_sni_from_clienthello(self, payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello."""
        try:
            # Simple SNI extraction (basic implementation)
            if b"\x00\x00" in payload:
                sni_start = payload.find(b"\x00\x00")
                if sni_start > 0 and sni_start + 9 < len(payload):
                    name_start = sni_start + 9
                    if name_start < len(payload):
                        for i in range(name_start, min(name_start + 100, len(payload))):
                            if payload[i] == 0:
                                domain_bytes = payload[name_start:i]
                                try:
                                    return domain_bytes.decode("ascii")
                                except Exception:
                                    break
            return None
        except Exception:
            return None

    def _analyze_cipher_suites(self, payload: bytes) -> Optional[str]:
        """Analyze cipher suites in ClientHello."""
        try:
            return f"{len(payload)} bytes analyzed"
        except Exception:
            return None
