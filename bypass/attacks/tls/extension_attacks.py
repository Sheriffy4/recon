# recon/core/bypass/attacks/tls/extension_attacks.py (обновленная версия)

import time
import random
import struct
from typing import List, Optional, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


from ....protocols.tls import TLSParser


# Safety wrapper for AttackResult creation
def _safe_create_result(status_name: str, **kwargs):
    """Safely create AttackResult to prevent AttackStatus errors."""
    try:
        from ..safe_result_utils import safe_create_attack_result

        return safe_create_attack_result(status_name, **kwargs)
    except Exception:
        # Ultimate fallback
        try:
            from ..base import AttackResult, AttackStatus

            status = getattr(AttackStatus, status_name)
            return AttackResult(status=status, **kwargs)
        except Exception:
            return None


@register_attack
class SNIManipulationAttack(BaseAttack):
    """
    SNI Manipulation Attack - modifies Server Name Indication extension.
    """

    """
    SNI Manipulation Attack - modifies Server Name Indication extension.
    """

    @property
    def name(self) -> str:
        return "sni_manipulation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Manipulates SNI extension to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute SNI manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_type = context.params.get("manipulation_type", "case_change")

            # Check if payload looks like TLS
            if not self._is_tls_payload(payload):
                # For non-TLS payloads, create a mock TLS ClientHello with SNI
                domain = context.domain or context.params.get(
                    "target_domain", "example.com"
                )
                payload = self._create_mock_client_hello(domain)

            # Используем TLSParser для получения SNI
            original_domain = TLSParser.get_sni(payload)
            if not original_domain:
                # Fallback: use domain from context
                original_domain = context.domain or context.params.get(
                    "target_domain", "example.com"
                )

            # Apply manipulation using new methods
            if manipulation_type == "case_change":
                modified_domain = self._change_case(original_domain)
            elif manipulation_type == "random_case":
                modified_domain = self._randomize_domain_case(original_domain)
            elif manipulation_type == "subdomain_add":
                prefix = context.params.get("subdomain_prefix", "www")
                modified_domain = self._add_subdomain_prefix(original_domain, prefix)
            elif manipulation_type == "fake_tld":
                fake_tld = context.params.get("fake_tld", "local")
                modified_domain = self._add_fake_tld(original_domain, fake_tld)
            elif manipulation_type == "obfuscate":
                method = context.params.get("obfuscation_method", "mixed")
                modified_domain = self._obfuscate_domain(original_domain, method)
            elif manipulation_type == "domain_replace":
                modified_domain = context.params.get("fake_domain", "example.com")
            else:
                modified_domain = original_domain

            # Используем TLSParser для замены SNI
            modified_payload = TLSParser.replace_sni(payload, modified_domain)

            segments = [(modified_payload, 0)]

            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_type": manipulation_type,
                    "original_domain": original_domain,
                    "modified_domain": modified_domain,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _is_tls_payload(self, payload: bytes) -> bool:
        """Check if payload looks like TLS."""
        if len(payload) < 6:
            return False
        # Check for TLS record header (0x16 = Handshake, version 0x0301-0x0304)
        return (
            payload[0] == 0x16
            and payload[1] in [0x03]
            and payload[2] in [0x01, 0x02, 0x03, 0x04]
        )

    def _create_mock_client_hello(self, domain: str) -> bytes:
        """Create a mock TLS ClientHello with SNI for testing."""
        import struct

        # This is a simplified mock - in real implementation would be more complex
        sni_data = domain.encode("utf-8")
        sni_len = len(sni_data)

        # Mock TLS ClientHello with SNI extension
        mock_hello = (
            b"\x16\x03\x01"  # TLS Handshake, version 3.1
            + b"\x00\x50"  # Length (placeholder)
            + b"\x01"  # ClientHello
            + b"\x00\x00\x4c"  # Length
            + b"\x03\x03"  # Version
            + b"\x00" * 32  # Random
            + b"\x00"  # Session ID length
            + b"\x00\x02"  # Cipher suites length
            + b"\x00\x35"  # Cipher suite
            + b"\x01\x00"  # Compression methods
            + b"\x00\x1d"  # Extensions length
            + b"\x00\x00"  # SNI extension type
            + struct.pack("!H", sni_len + 5)  # Extension length
            + struct.pack("!H", sni_len + 3)  # Server name list length
            + b"\x00"  # Server name type (hostname)
            + struct.pack("!H", sni_len)  # Server name length
            + sni_data  # Server name
        )
        return mock_hello

    def _add_subdomain_prefix(self, domain: str, prefix: str = "www") -> str:
        """Add subdomain prefix to domain."""
        if not domain.startswith(prefix + "."):
            return f"{prefix}.{domain}"
        return domain

    def _randomize_domain_case(self, domain: str) -> str:
        """Randomize case of domain characters."""
        result = []
        for char in domain:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return "".join(result)

    def _add_fake_tld(self, domain: str, fake_tld: str = "local") -> str:
        """Add fake TLD to domain."""
        parts = domain.split(".")
        if len(parts) > 1:
            # Replace last part with fake TLD
            parts[-1] = fake_tld
            return ".".join(parts)
        return f"{domain}.{fake_tld}"

    def _obfuscate_domain(self, domain: str, method: str = "case") -> str:
        """Obfuscate domain using various methods."""
        if method == "case":
            return self._randomize_domain_case(domain)
        elif method == "subdomain":
            return self._add_subdomain_prefix(domain)
        elif method == "fake_tld":
            return self._add_fake_tld(domain)
        elif method == "mixed":
            # Apply multiple obfuscation methods
            obfuscated = self._add_subdomain_prefix(domain, "cdn")
            obfuscated = self._randomize_domain_case(obfuscated)
            return obfuscated
        else:
            return domain

    def _change_case(self, domain: str) -> str:
        """Change case of domain randomly."""
        result = []
        for char in domain:
            if char.isalpha():
                result.append(char.upper() if char.islower() else char.lower())
            else:
                result.append(char)
        return "".join(result)

    def _find_sni_extension(
        self, payload: bytes
    ) -> Optional[Tuple[int, int, int, int]]:
        """
        Robustly finds the SNI extension by parsing the TLS ClientHello extensions block.
        Returns a tuple: (ext_start, ext_end, domain_start, domain_end) or None.
        """
        try:
            # Basic validation for TLS Handshake / ClientHello
            if not (
                payload.startswith(b"\x16\x03")
                and len(payload) > 43
                and payload[5] == 0x01
            ):
                return None

            # --- Navigate to extensions block ---
            # Session ID
            session_id_len_pos = 43
            session_id_len = payload[session_id_len_pos]

            # Cipher Suites
            cipher_suites_len_pos = session_id_len_pos + 1 + session_id_len
            cipher_suites_len = struct.unpack(
                "!H", payload[cipher_suites_len_pos : cipher_suites_len_pos + 2]
            )[0]

            # Compression Methods
            comp_methods_len_pos = cipher_suites_len_pos + 2 + cipher_suites_len
            comp_methods_len = payload[comp_methods_len_pos]

            # Extensions block starts after compression methods
            extensions_len_pos = comp_methods_len_pos + 1 + comp_methods_len
            if extensions_len_pos + 2 > len(payload):
                return None  # No extensions block

            total_extensions_len = struct.unpack(
                "!H", payload[extensions_len_pos : extensions_len_pos + 2]
            )[0]
            extensions_start_pos = extensions_len_pos + 2

            # --- Loop through extensions ---
            current_pos = extensions_start_pos
            while current_pos < extensions_start_pos + total_extensions_len:
                # Read extension type and length
                ext_type = struct.unpack("!H", payload[current_pos : current_pos + 2])[
                    0
                ]
                ext_len = struct.unpack(
                    "!H", payload[current_pos + 2 : current_pos + 4]
                )[0]

                # Check if it's the SNI extension (type 0)
                if ext_type == 0x0000:
                    # Found it! Now parse the SNI data
                    sni_data_start = current_pos + 4

                    # Server Name list length
                    list_len = struct.unpack(
                        "!H", payload[sni_data_start : sni_data_start + 2]
                    )[0]

                    # Name Type (should be 0 for hostname)
                    name_type = payload[sni_data_start + 2]
                    if name_type != 0:
                        # Not a hostname, continue searching
                        current_pos += 4 + ext_len
                        continue

                    # Server Name length
                    name_len = struct.unpack(
                        "!H", payload[sni_data_start + 3 : sni_data_start + 5]
                    )[0]

                    # Calculate positions
                    ext_start = current_pos
                    ext_end = current_pos + 4 + ext_len
                    domain_start = sni_data_start + 5
                    domain_end = domain_start + name_len

                    if domain_end <= len(payload):
                        return (ext_start, ext_end, domain_start, domain_end)

                # Move to the next extension
                current_pos += 4 + ext_len

            return None  # SNI extension not found in the loop
        except (struct.error, IndexError):
            # Error during parsing, payload is likely malformed
            return None

    def _update_sni_lengths(self, payload: bytes, length_diff: int) -> bytes:
        """Update SNI extension lengths after modification."""
        # This is a simplified implementation
        # In practice, you'd need to update multiple length fields
        return payload


@register_attack
class ALPNManipulationAttack(BaseAttack):
    """
    ALPN Manipulation Attack - modifies Application Layer Protocol Negotiation.
    """

    @property
    def name(self) -> str:
        return "alpn_manipulation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Manipulates ALPN extension to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ALPN manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fake_protocols = context.params.get("fake_protocols", ["h2", "http/1.1"])

            # Create fake ALPN extension
            alpn_data = b""
            for protocol in fake_protocols:
                # Convert string to bytes if needed
                if isinstance(protocol, str):
                    protocol_bytes = protocol.encode("utf-8")
                else:
                    protocol_bytes = protocol
                alpn_data += bytes([len(protocol_bytes)]) + protocol_bytes

            # ALPN extension: type=0x0010, length, protocol_list_length, protocols
            alpn_extension = (
                b"\x00\x10"  # ALPN extension type
                + struct.pack("!H", len(alpn_data) + 2)  # extension length
                + struct.pack("!H", len(alpn_data))  # protocol list length
                + alpn_data
            )

            # Insert ALPN extension into TLS ClientHello
            # This is a simplified implementation - in practice you'd need to
            # find the extensions section and insert properly
            modified_payload = payload + alpn_extension

            segments = [(modified_payload, 0)]

            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fake_protocols": [
                        (
                            p.decode("utf-8", errors="ignore")
                            if isinstance(p, bytes)
                            else p
                        )
                        for p in fake_protocols
                    ],
                    "alpn_extension_size": len(alpn_extension),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class GREASEAttack(BaseAttack):
    """
    GREASE Attack - adds GREASE (Generate Random Extensions And Sustain Extensibility) values.
    """

    @property
    def name(self) -> str:
        return "grease_injection"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Injects GREASE values to test DPI robustness"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute GREASE attack."""
        start_time = time.time()

        try:
            payload = context.payload
            grease_count = context.params.get("grease_count", 3)

            # GREASE values (reserved for extensibility testing)
            grease_values = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A]

            # Add random GREASE extensions
            grease_extensions = b""
            for i in range(grease_count):
                grease_type = random.choice(grease_values)
                grease_data = b"\x00" * random.randint(0, 8)  # Random padding
                grease_ext = (
                    struct.pack("!H", grease_type)  # extension type
                    + struct.pack("!H", len(grease_data))  # extension length
                    + grease_data
                )
                grease_extensions += grease_ext

            # Append GREASE extensions to payload
            modified_payload = payload + grease_extensions

            segments = [(modified_payload, 0)]

            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "grease_count": grease_count,
                    "grease_extensions_size": len(grease_extensions),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
