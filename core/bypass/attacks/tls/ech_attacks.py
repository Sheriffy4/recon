# recon/core/bypass/attacks/tls/ech_attacks.py

import time
import random
import struct
import os
import secrets
from typing import List, Optional, Dict, Any, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack
from ....protocols.tls import TLSParser


# ECH Extension Type (draft-ietf-tls-esni)
ECH_EXTENSION_TYPE = 0xFE0D


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
class ECHFragmentationAttack(BaseAttack):
    """
    ECH Fragmentation Attack - fragments ECH (Encrypted Client Hello) data
    across multiple TLS extensions to evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "ech_fragmentation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Fragments ECH data across multiple extensions to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ECH fragmentation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fragment_count = context.params.get("fragment_count", 3)
            use_padding = context.params.get("use_padding", True)
            randomize_order = context.params.get("randomize_order", False)

            # Generate ECH data to fragment
            ech_data = self._generate_ech_data(context)

            # Fragment ECH data
            fragments = self._fragment_ech_data(ech_data, fragment_count)

            # Add padding to fragments if requested
            if use_padding:
                fragments = self._add_padding_to_fragments(fragments)

            # Randomize fragment order if requested
            if randomize_order:
                random.shuffle(fragments)

            # Insert fragments as separate extensions
            modified_payload = self._insert_fragmented_extensions(payload, fragments)

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
                    "fragment_count": len(fragments),
                    "total_ech_size": len(ech_data),
                    "fragments_padded": use_padding,
                    "order_randomized": randomize_order,
                    "original_payload_size": len(payload),
                    "modified_payload_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _generate_ech_data(self, context: AttackContext) -> bytes:
        """Generate realistic ECH data for fragmentation."""
        # ECH structure (simplified):
        # - ECH version (2 bytes)
        # - Config ID (32 bytes)
        # - Encrypted payload (variable)
        # - Authentication tag (16 bytes)

        ech_version = b"\x00\x01"  # ECH version 1
        config_id = os.urandom(32)  # Random config ID

        # Generate encrypted payload (simulated)
        inner_sni = context.params.get("inner_sni", "hidden.example.com")
        encrypted_payload = self._simulate_encrypted_payload(inner_sni)

        auth_tag = os.urandom(16)  # Authentication tag

        return ech_version + config_id + encrypted_payload + auth_tag

    def _simulate_encrypted_payload(self, inner_sni: str) -> bytes:
        """Simulate encrypted ECH inner payload."""
        # In real ECH, this would be encrypted ClientHello inner
        # For attack purposes, we generate realistic-looking encrypted data

        # Simulate inner ClientHello structure
        inner_hello_size = 200 + len(inner_sni.encode("utf-8"))

        # Add some structure to make it look like encrypted TLS data
        encrypted_data = bytearray()

        # Add some patterns that might look like encrypted TLS structures
        for i in range(0, inner_hello_size, 16):
            # Simulate AES block encryption patterns
            block = os.urandom(16)
            # Add some non-random patterns occasionally
            if i % 64 == 0:
                block = bytes([0x16, 0x03, 0x03]) + os.urandom(13)
            encrypted_data.extend(block)

        return bytes(encrypted_data[:inner_hello_size])

    def _fragment_ech_data(self, ech_data: bytes, fragment_count: int) -> List[bytes]:
        """Fragment ECH data into multiple pieces."""
        if fragment_count <= 1:
            return [ech_data]

        data_len = len(ech_data)
        fragment_size = data_len // fragment_count
        fragments = []

        for i in range(fragment_count):
            start = i * fragment_size
            if i == fragment_count - 1:
                # Last fragment gets remaining data
                end = data_len
            else:
                end = start + fragment_size

            fragment = ech_data[start:end]
            fragments.append(fragment)

        return fragments

    def _add_padding_to_fragments(self, fragments: List[bytes]) -> List[bytes]:
        """Add random padding to fragments to obscure patterns."""
        padded_fragments = []

        for fragment in fragments:
            # Add 0-15 bytes of random padding
            padding_size = random.randint(0, 15)
            padding = os.urandom(padding_size)

            # Prepend padding length and padding
            padded_fragment = bytes([padding_size]) + padding + fragment
            padded_fragments.append(padded_fragment)

        return padded_fragments

    def _insert_fragmented_extensions(
        self, payload: bytes, fragments: List[bytes]
    ) -> bytes:
        """Insert ECH fragments as separate TLS extensions."""
        result = payload

        # Use different extension types for each fragment to avoid conflicts
        base_ext_type = ECH_EXTENSION_TYPE

        for i, fragment in enumerate(fragments):
            # Use different extension types: 0xfe0d, 0xfe0e, 0xfe0f, etc.
            ext_type = base_ext_type + i

            # Add fragment index as first byte for reassembly hint
            fragment_data = bytes([i]) + fragment

            # Insert as extension
            result = TLSParser.add_extension(result, ext_type, fragment_data)

        return result


# Integration with existing TLS probes
def integrate_with_prober(prober, domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Integration function to enhance existing ECH probes in prober.py
    This function demonstrates how the attacks can be used with probes.

    Args:
        prober: The prober instance
        domain: Target domain to test
        port: Target port (default 443)

    Returns:
        Dictionary with test results
    """
    results = {}

    # Get base ClientHello template
    base_hello = prober.get_client_hello_template()

    # Test each ECH attack type
    attack_types = [
        ECHFragmentationAttack(),
        ECHGreaseAttack(),
        ECHDecoyAttack(),
        ECHOuterSNIManipulationAttack(),
        ECHAdvancedFragmentationAttack(),
    ]

    for attack in attack_types:
        context = AttackContext(
            target_ip=domain,
            target_port=port,
            payload=base_hello,
            domain=domain,
            engine_type="prober",
            params={
                "fragment_count": 5,
                "use_padding": True,
                "randomize_order": True,
                "inner_sni": domain,
                "grease_intensity": "high",
                "include_fake_ech": True,
                "manipulation_strategy": "public_suffix",
                "fragment_size_variation": True,
            },
        )

        # Execute attack
        result = attack.execute(context)

        # Store results
        results[attack.name] = {
            "success": result.status == AttackStatus.SUCCESS,
            "latency_ms": result.latency_ms,
            "packets_sent": result.packets_sent,
            "bytes_sent": result.bytes_sent,
            "metadata": result.metadata,
        }

    return results


# Helper function for testing ECH attack effectiveness
def test_ech_attack_effectiveness(
    domain: str, attack_type: str = "fragmentation"
) -> Dict[str, Any]:
    """
    Test the effectiveness of ECH attacks against a domain.

    Args:
        domain: Target domain
        attack_type: Type of ECH attack ("fragmentation" or "grease")

    Returns:
        Dictionary with test results
    """
    from ....protocols.tls import TLSHandler
    import config

    # Create TLS handler
    tls_handler = TLSHandler(config.TLS_CLIENT_HELLO_TEMPLATE)

    # Build base ClientHello
    base_hello = tls_handler.build_client_hello(domain)

    # Create attack context
    context = AttackContext(
        target_ip="1.1.1.1",  # Placeholder
        target_port=443,
        payload=base_hello,
        params={"fragment_count": 3, "grease_count": 2, "use_fake_ech": True},
    )

    # Execute attack
    if attack_type == "fragmentation":
        attack = ECHFragmentationAttack()
    else:
        attack = ECHGreaseAttack()

    result = attack.execute(context)

    return {
        "attack_type": attack_type,
        "success": result.status == AttackStatus.SUCCESS,
        "payload_size_increase": (
            result.bytes_sent - len(base_hello) if result.bytes_sent else 0
        ),
        "metadata": result.metadata,
    }


# Advanced ECH Attacks


@register_attack
class ECHGreaseAttack(BaseAttack):
    """
    ECH GREASE Attack - uses GREASE values in ECH to confuse DPI analysis.
    """

    @property
    def name(self) -> str:
        return "ech_grease"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Uses GREASE values in ECH extensions to confuse DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ECH GREASE attack."""
        start_time = time.time()

        try:
            payload = context.payload
            grease_intensity = context.params.get("grease_intensity", "medium")
            include_fake_ech = context.params.get("include_fake_ech", True)
            randomize_grease = context.params.get("randomize_grease", True)

            # Create GREASE ECH extensions
            grease_extensions = self._create_grease_ech_extensions(
                grease_intensity, include_fake_ech, randomize_grease, context
            )

            # Insert GREASE extensions into TLS handshake
            modified_payload = self._insert_grease_extensions(
                payload, grease_extensions
            )

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
                    "grease_intensity": grease_intensity,
                    "grease_extensions_count": len(grease_extensions),
                    "include_fake_ech": include_fake_ech,
                    "randomize_grease": randomize_grease,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_grease_ech_extensions(
        self,
        intensity: str,
        include_fake_ech: bool,
        randomize: bool,
        context: AttackContext,
    ) -> List[Tuple[int, bytes]]:
        """Create GREASE ECH extensions."""
        extensions = []

        # GREASE extension types (reserved values that should be ignored)
        grease_types = [
            0x0A0A,
            0x1A1A,
            0x2A2A,
            0x3A3A,
            0x4A4A,
            0x5A5A,
            0x6A6A,
            0x7A7A,
            0x8A8A,
            0x9A9A,
            0xAAAA,
            0xBABA,
            0xCACA,
            0xDADA,
            0xEAEA,
            0xFAFA,
        ]

        # Determine number of GREASE extensions based on intensity
        if intensity == "low":
            grease_count = random.randint(1, 3)
        elif intensity == "medium":
            grease_count = random.randint(3, 6)
        elif intensity == "high":
            grease_count = random.randint(6, 10)
        else:
            grease_count = 3

        # Create GREASE extensions
        for i in range(grease_count):
            if randomize:
                ext_type = random.choice(grease_types)
            else:
                ext_type = grease_types[i % len(grease_types)]

            # Generate GREASE data
            grease_data = self._generate_grease_data(ext_type, i)
            extensions.append((ext_type, grease_data))

        # Add fake ECH extension if requested
        if include_fake_ech:
            fake_ech_data = self._generate_fake_ech_data(context)
            extensions.append((ECH_EXTENSION_TYPE, fake_ech_data))

        return extensions

    def _generate_grease_data(self, ext_type: int, index: int) -> bytes:
        """Generate GREASE extension data."""
        # Generate random but structured GREASE data
        data_length = random.randint(8, 64)

        # Start with extension type as pattern
        pattern = struct.pack(">H", ext_type)

        # Repeat pattern and add random data
        grease_data = pattern * (data_length // 2)
        if data_length % 2:
            grease_data += bytes([ext_type & 0xFF])

        # Add some random bytes for variety
        random_bytes = bytes(
            [random.randint(0, 255) for _ in range(random.randint(4, 16))]
        )

        return grease_data + random_bytes

    def _generate_fake_ech_data(self, context: AttackContext) -> bytes:
        """Generate fake ECH data that looks realistic."""
        # ECH structure (simplified):
        # - ECH Type (1 byte)
        # - ECH Length (2 bytes)
        # - Config ID (1 byte)
        # - Enc (variable length encrypted data)
        # - Payload (encrypted inner ClientHello)

        ech_type = 0x01  # ECH type
        config_id = random.randint(0, 255)

        # Generate fake encrypted data
        enc_length = random.randint(32, 64)  # Typical for X25519
        enc_data = bytes([random.randint(0, 255) for _ in range(enc_length)])

        # Generate fake encrypted payload
        payload_length = random.randint(200, 500)  # Typical ClientHello size
        encrypted_payload = bytes(
            [random.randint(0, 255) for _ in range(payload_length)]
        )

        # Combine ECH data
        ech_data = struct.pack(">B", ech_type)
        ech_data += struct.pack(">H", len(enc_data) + len(encrypted_payload) + 1)
        ech_data += struct.pack(">B", config_id)
        ech_data += enc_data
        ech_data += encrypted_payload

        return ech_data

    def _insert_grease_extensions(
        self, payload: bytes, grease_extensions: List[Tuple[int, bytes]]
    ) -> bytes:
        """Insert GREASE extensions into TLS handshake."""
        # Look for TLS handshake in payload
        if len(payload) < 5:
            return payload

        # Check if this looks like a TLS handshake
        if payload[0] != 0x16:  # TLS Handshake
            return payload

        try:
            # Parse TLS record
            tls_version = struct.unpack(">H", payload[1:3])[0]
            record_length = struct.unpack(">H", payload[3:5])[0]

            if len(payload) < 5 + record_length:
                return payload

            handshake_data = payload[5 : 5 + record_length]

            # Check if this is a ClientHello
            if len(handshake_data) < 4 or handshake_data[0] != 0x01:
                return payload

            # Find extensions section
            extensions_start = self._find_extensions_start(handshake_data)
            if extensions_start == -1:
                return payload

            # Insert GREASE extensions
            modified_handshake = self._insert_extensions_at_position(
                handshake_data, extensions_start, grease_extensions
            )

            # Rebuild TLS record
            new_record_length = len(modified_handshake)
            modified_payload = payload[:3]
            modified_payload += struct.pack(">H", new_record_length)
            modified_payload += modified_handshake
            modified_payload += payload[5 + record_length :]  # Any remaining data

            return modified_payload

        except Exception:
            # If parsing fails, return original payload
            return payload

    def _find_extensions_start(self, handshake_data: bytes) -> int:
        """Find the start of extensions in ClientHello."""
        try:
            # Skip handshake header (4 bytes)
            offset = 4

            # Skip client version (2 bytes)
            offset += 2

            # Skip client random (32 bytes)
            offset += 32

            # Skip session ID
            if offset >= len(handshake_data):
                return -1
            session_id_length = handshake_data[offset]
            offset += 1 + session_id_length

            # Skip cipher suites
            if offset + 2 > len(handshake_data):
                return -1
            cipher_suites_length = struct.unpack(
                ">H", handshake_data[offset : offset + 2]
            )[0]
            offset += 2 + cipher_suites_length

            # Skip compression methods
            if offset >= len(handshake_data):
                return -1
            compression_methods_length = handshake_data[offset]
            offset += 1 + compression_methods_length

            # Extensions start here
            if offset + 2 <= len(handshake_data):
                return offset

            return -1

        except Exception:
            return -1

    def _insert_extensions_at_position(
        self,
        handshake_data: bytes,
        extensions_start: int,
        new_extensions: List[Tuple[int, bytes]],
    ) -> bytes:
        """Insert new extensions at the specified position."""
        try:
            # Get existing extensions length
            if extensions_start + 2 > len(handshake_data):
                return handshake_data

            existing_ext_length = struct.unpack(
                ">H", handshake_data[extensions_start : extensions_start + 2]
            )[0]

            # Calculate new extensions data
            new_ext_data = b""
            for ext_type, ext_data in new_extensions:
                new_ext_data += struct.pack(">H", ext_type)  # Extension type
                new_ext_data += struct.pack(">H", len(ext_data))  # Extension length
                new_ext_data += ext_data  # Extension data

            # Get existing extensions data
            existing_ext_data = handshake_data[
                extensions_start + 2 : extensions_start + 2 + existing_ext_length
            ]

            # Combine extensions
            combined_ext_data = new_ext_data + existing_ext_data
            new_ext_length = len(combined_ext_data)

            # Rebuild handshake
            result = handshake_data[:extensions_start]  # Before extensions
            result += struct.pack(">H", new_ext_length)  # New extensions length
            result += combined_ext_data  # Combined extensions data
            result += handshake_data[
                extensions_start + 2 + existing_ext_length :
            ]  # After extensions

            # Update handshake length in header
            new_handshake_length = len(result) - 4
            result = (
                result[:1] + struct.pack(">I", new_handshake_length)[1:] + result[4:]
            )

            return result

        except Exception:
            return handshake_data


@register_attack
class ECHDecoyAttack(BaseAttack):
    """
    ECH Decoy Attack - creates multiple fake ECH extensions to hide the real one.
    """

    @property
    def name(self) -> str:
        return "ech_decoy"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Creates multiple fake ECH extensions to hide the real one"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ECH decoy attack."""
        start_time = time.time()

        try:
            payload = context.payload
            decoy_count = context.params.get("decoy_count", 5)
            real_ech_position = context.params.get("real_ech_position", "random")
            vary_sizes = context.params.get("vary_sizes", True)

            # Create decoy ECH extensions
            decoy_extensions = self._create_decoy_ech_extensions(
                decoy_count, real_ech_position, vary_sizes, context
            )

            # Insert decoy extensions
            modified_payload = self._insert_decoy_extensions(payload, decoy_extensions)

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
                    "decoy_count": decoy_count,
                    "real_ech_position": real_ech_position,
                    "vary_sizes": vary_sizes,
                    "total_extensions": len(decoy_extensions),
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_decoy_ech_extensions(
        self,
        decoy_count: int,
        real_position: str,
        vary_sizes: bool,
        context: AttackContext,
    ) -> List[Tuple[int, bytes, bool]]:
        """Create decoy ECH extensions with one real one."""
        extensions = []

        # Determine position of real ECH
        if real_position == "random":
            real_index = random.randint(0, decoy_count)
        elif real_position == "first":
            real_index = 0
        elif real_position == "last":
            real_index = decoy_count
        elif real_position == "middle":
            real_index = decoy_count // 2
        else:
            real_index = random.randint(0, decoy_count)

        # Create extensions
        for i in range(decoy_count + 1):
            is_real = i == real_index

            if is_real:
                # Create real ECH extension (or realistic fake)
                ech_data = self._generate_realistic_ech_data(context)
            else:
                # Create decoy ECH extension
                ech_data = self._generate_decoy_ech_data(i, vary_sizes)

            extensions.append((ECH_EXTENSION_TYPE, ech_data, is_real))

        return extensions

    def _generate_realistic_ech_data(self, context: AttackContext) -> bytes:
        """Generate realistic ECH data."""
        # This would contain the actual ECH data in a real implementation
        # For now, generate realistic-looking fake data

        # ECH Config ID
        config_id = random.randint(1, 10)

        # KEM output (for X25519, typically 32 bytes)
        kem_output = bytes([random.randint(0, 255) for _ in range(32)])

        # Encrypted ClientHello (variable size, typically 200-800 bytes)
        encrypted_ch_size = random.randint(200, 800)
        encrypted_ch = bytes([random.randint(0, 255) for _ in range(encrypted_ch_size)])

        # Combine ECH data
        ech_data = struct.pack(">B", config_id)
        ech_data += kem_output
        ech_data += encrypted_ch

        return ech_data

    def _generate_decoy_ech_data(self, index: int, vary_sizes: bool) -> bytes:
        """Generate decoy ECH data."""
        if vary_sizes:
            size = random.randint(50, 500)
        else:
            size = 200  # Standard size

        # Create decoy data with some patterns to look realistic
        decoy_data = bytearray()

        # Add some structured patterns
        decoy_data.extend(struct.pack(">B", index % 256))  # Config ID variant
        decoy_data.extend(bytes([0x16, 0x03, 0x03]))  # TLS-like pattern

        # Fill rest with pseudo-random data
        remaining = size - len(decoy_data)
        for i in range(remaining):
            # Add some patterns based on index
            if i % 16 == 0:
                decoy_data.append((index + i) % 256)
            else:
                decoy_data.append(random.randint(0, 255))

        return bytes(decoy_data)

    def _insert_decoy_extensions(
        self, payload: bytes, decoy_extensions: List[Tuple[int, bytes, bool]]
    ) -> bytes:
        """Insert decoy ECH extensions into TLS handshake."""
        # Use the same insertion logic as ECHGreaseAttack
        grease_attack = ECHGreaseAttack()

        # Convert to format expected by grease attack
        extensions_for_insertion = [
            (ext_type, ext_data) for ext_type, ext_data, _ in decoy_extensions
        ]

        return grease_attack._insert_grease_extensions(
            payload, extensions_for_insertion
        )


@register_attack
class ECHAdvancedGreaseAttack(BaseAttack):
    """
    ECH Advanced GREASE Attack - uses sophisticated GREASE techniques.
    """

    @property
    def name(self) -> str:
        return "ech_advanced_grease"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Uses advanced GREASE techniques with ECH to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced ECH GREASE attack."""
        start_time = time.time()

        try:
            payload = context.payload
            grease_strategy = context.params.get("grease_strategy", "adaptive_grease")
            grease_density = context.params.get("grease_density", "high")
            include_malformed = context.params.get("include_malformed", True)

            # Create advanced GREASE payload
            greased_payload = self._create_advanced_grease_ech(
                payload, grease_strategy, grease_density, include_malformed, context
            )

            segments = [(greased_payload, 0)]
            packets_sent = 1
            bytes_sent = len(greased_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "grease_strategy": grease_strategy,
                    "grease_density": grease_density,
                    "include_malformed": include_malformed,
                    "original_size": len(payload),
                    "greased_size": len(greased_payload),
                    "bypass_technique": "advanced_ech_grease",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_advanced_grease_ech(
        self,
        payload: bytes,
        strategy: str,
        density: str,
        include_malformed: bool,
        context: AttackContext,
    ) -> bytes:
        """Create advanced GREASE ECH payload."""
        if strategy == "adaptive_grease":
            return self._create_adaptive_grease(
                payload, density, include_malformed, context
            )
        elif strategy == "layered_grease":
            return self._create_layered_grease(
                payload, density, include_malformed, context
            )
        elif strategy == "polymorphic_grease":
            return self._create_polymorphic_grease(
                payload, density, include_malformed, context
            )
        elif strategy == "contextual_grease":
            return self._create_contextual_grease(
                payload, density, include_malformed, context
            )
        else:
            return self._create_adaptive_grease(
                payload, density, include_malformed, context
            )

    def _create_adaptive_grease(
        self,
        payload: bytes,
        density: str,
        include_malformed: bool,
        context: AttackContext,
    ) -> bytes:
        """Create adaptive GREASE that changes based on context."""
        extensions = []

        # Determine GREASE count based on density
        if density == "low":
            grease_count = random.randint(2, 5)
        elif density == "medium":
            grease_count = random.randint(5, 10)
        elif density == "high":
            grease_count = random.randint(10, 20)
        else:
            grease_count = 8

        # Adaptive GREASE values based on context
        domain = context.domain or "example.com"
        port = context.dst_port or 443

        # Generate context-aware GREASE
        for i in range(grease_count):
            # Adapt extension type based on domain characteristics
            if "cdn" in domain.lower():
                base_type = 0xCACA  # CDN-specific GREASE
            elif "api" in domain.lower():
                base_type = 0xAAAA  # API-specific GREASE
            elif port == 443:
                base_type = 0x4A4A  # HTTPS-specific GREASE
            else:
                base_type = 0x2A2A  # Generic GREASE

            ext_type = base_type + (i * 0x1010)

            # Generate adaptive GREASE data
            grease_data = self._generate_adaptive_grease_data(ext_type, domain, i)
            extensions.append((ext_type, grease_data))

        # Add malformed extensions if requested
        if include_malformed:
            malformed_extensions = self._create_malformed_grease_extensions(context)
            extensions.extend(malformed_extensions)

        return self._insert_multiple_extensions(payload, extensions)

    def _create_layered_grease(
        self,
        payload: bytes,
        density: str,
        include_malformed: bool,
        context: AttackContext,
    ) -> bytes:
        """Create layered GREASE with multiple levels."""
        extensions = []

        # Layer 1: Basic GREASE
        basic_grease = self._create_basic_grease_layer(density)
        extensions.extend(basic_grease)

        # Layer 2: ECH-specific GREASE
        ech_grease = self._create_ech_grease_layer(density, context)
        extensions.extend(ech_grease)

        # Layer 3: Protocol-specific GREASE
        protocol_grease = self._create_protocol_grease_layer(density, context)
        extensions.extend(protocol_grease)

        # Layer 4: Malformed GREASE (if enabled)
        if include_malformed:
            malformed_grease = self._create_malformed_grease_extensions(context)
            extensions.extend(malformed_grease)

        return self._insert_multiple_extensions(payload, extensions)

    def _create_polymorphic_grease(
        self,
        payload: bytes,
        density: str,
        include_malformed: bool,
        context: AttackContext,
    ) -> bytes:
        """Create polymorphic GREASE that changes its structure."""
        extensions = []

        # Polymorphic patterns that change based on time/context
        current_time = int(time.time())
        pattern_seed = current_time % 10  # Changes every 10 seconds

        # Generate different GREASE patterns based on seed
        for i in range(self._get_grease_count(density)):
            # Polymorphic extension type
            ext_type = self._generate_polymorphic_extension_type(pattern_seed, i)

            # Polymorphic data
            grease_data = self._generate_polymorphic_grease_data(
                pattern_seed, i, context
            )

            extensions.append((ext_type, grease_data))

        return self._insert_multiple_extensions(payload, extensions)

    def _create_contextual_grease(
        self,
        payload: bytes,
        density: str,
        include_malformed: bool,
        context: AttackContext,
    ) -> bytes:
        """Create contextual GREASE based on target characteristics."""
        extensions = []

        # Analyze target context
        domain = context.domain or "example.com"
        port = context.dst_port or 443

        # Generate contextual GREASE based on target
        if self._is_cdn_domain(domain):
            extensions.extend(self._create_cdn_specific_grease(density))
        elif self._is_api_domain(domain):
            extensions.extend(self._create_api_specific_grease(density))
        elif self._is_social_media_domain(domain):
            extensions.extend(self._create_social_media_grease(density))
        else:
            extensions.extend(self._create_generic_contextual_grease(density))

        return self._insert_multiple_extensions(payload, extensions)

    def _generate_adaptive_grease_data(
        self, ext_type: int, domain: str, index: int
    ) -> bytes:
        """Generate adaptive GREASE data."""
        # Base data with extension type pattern
        data = struct.pack(">H", ext_type)

        # Add domain-specific patterns
        domain_hash = hash(domain) % 256
        data += bytes([domain_hash, (domain_hash + index) % 256])

        # Add variable-length random data
        random_length = (domain_hash + index) % 32 + 8
        data += secrets.token_bytes(random_length)

        return data

    def _create_basic_grease_layer(self, density: str) -> List[Tuple[int, bytes]]:
        """Create basic GREASE layer."""
        extensions = []
        count = self._get_grease_count(density) // 4

        basic_grease_types = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A]

        for i in range(count):
            ext_type = basic_grease_types[i % len(basic_grease_types)]
            grease_data = struct.pack(">H", ext_type) + secrets.token_bytes(
                random.randint(4, 16)
            )
            extensions.append((ext_type, grease_data))

        return extensions

    def _create_ech_grease_layer(
        self, density: str, context: AttackContext
    ) -> List[Tuple[int, bytes]]:
        """Create ECH-specific GREASE layer."""
        extensions = []
        count = self._get_grease_count(density) // 4

        # ECH-related GREASE types
        ech_grease_types = [ECH_EXTENSION_TYPE + i for i in range(10)]

        for i in range(count):
            ext_type = ech_grease_types[i % len(ech_grease_types)]

            # Generate ECH-like GREASE data
            fake_config_id = random.randint(0, 255)
            fake_kem = secrets.token_bytes(32)  # X25519 size
            fake_encrypted = secrets.token_bytes(random.randint(100, 300))

            grease_data = struct.pack(">B", fake_config_id) + fake_kem + fake_encrypted
            extensions.append((ext_type, grease_data))

        return extensions

    def _create_protocol_grease_layer(
        self, density: str, context: AttackContext
    ) -> List[Tuple[int, bytes]]:
        """Create protocol-specific GREASE layer."""
        extensions = []
        count = self._get_grease_count(density) // 4

        # Protocol-specific GREASE
        protocol_grease_types = [0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A]

        for i in range(count):
            ext_type = protocol_grease_types[i % len(protocol_grease_types)]

            # Generate protocol-specific patterns
            if context.dst_port == 443:
                # HTTPS-specific patterns
                grease_data = b"\x16\x03\x03" + secrets.token_bytes(
                    random.randint(8, 24)
                )
            elif context.dst_port == 80:
                # HTTP-specific patterns
                grease_data = b"HTTP" + secrets.token_bytes(random.randint(8, 24))
            else:
                # Generic patterns
                grease_data = secrets.token_bytes(random.randint(8, 24))

            extensions.append((ext_type, grease_data))

        return extensions

    def _create_malformed_grease_extensions(
        self, context: AttackContext
    ) -> List[Tuple[int, bytes]]:
        """Create malformed GREASE extensions to test DPI robustness."""
        extensions = []

        # Malformed extension 1: Invalid length
        extensions.append((0xBABA, b"\xff\xff" + secrets.token_bytes(10)))

        # Malformed extension 2: Zero-length data
        extensions.append((0xCACA, b""))

        # Malformed extension 3: Extremely long data
        extensions.append((0xDADA, secrets.token_bytes(1000)))

        # Malformed extension 4: Invalid ECH structure
        malformed_ech = b"\xff" + secrets.token_bytes(
            5
        )  # Invalid config ID + short data
        extensions.append((ECH_EXTENSION_TYPE, malformed_ech))

        return extensions

    def _get_grease_count(self, density: str) -> int:
        """Get GREASE count based on density."""
        if density == "low":
            return random.randint(4, 8)
        elif density == "medium":
            return random.randint(8, 16)
        elif density == "high":
            return random.randint(16, 32)
        else:
            return 12

    def _generate_polymorphic_extension_type(self, seed: int, index: int) -> int:
        """Generate polymorphic extension type."""
        # Use seed to create different patterns
        base_types = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A]
        base = base_types[(seed + index) % len(base_types)]

        # Add polymorphic variation
        variation = (seed * index) % 0x1000
        return base + variation

    def _generate_polymorphic_grease_data(
        self, seed: int, index: int, context: AttackContext
    ) -> bytes:
        """Generate polymorphic GREASE data."""
        # Pattern changes based on seed
        pattern_type = (seed + index) % 4

        if pattern_type == 0:
            # Repeating pattern
            pattern = bytes([(seed + i) % 256 for i in range(4)])
            return pattern * ((seed % 8) + 2)
        elif pattern_type == 1:
            # Random with structure
            data = struct.pack(">I", seed + index)
            data += secrets.token_bytes((seed % 16) + 8)
            return data
        elif pattern_type == 2:
            # Domain-based pattern
            domain = context.domain or "example.com"
            domain_bytes = domain.encode()[:8].ljust(8, b"\x00")
            return domain_bytes + secrets.token_bytes(seed % 16)
        else:
            # Time-based pattern
            time_bytes = struct.pack(">I", int(time.time()) + seed)
            return time_bytes + secrets.token_bytes((seed + index) % 20)

    def _is_cdn_domain(self, domain: str) -> bool:
        """Check if domain is CDN-related."""
        cdn_indicators = ["cdn", "cloudflare", "amazonaws", "azure", "fastly", "akamai"]
        return any(indicator in domain.lower() for indicator in cdn_indicators)

    def _is_api_domain(self, domain: str) -> bool:
        """Check if domain is API-related."""
        api_indicators = ["api", "rest", "graphql", "webhook"]
        return any(indicator in domain.lower() for indicator in api_indicators)

    def _is_social_media_domain(self, domain: str) -> bool:
        """Check if domain is social media related."""
        social_indicators = [
            "facebook",
            "twitter",
            "instagram",
            "linkedin",
            "tiktok",
            "youtube",
        ]
        return any(indicator in domain.lower() for indicator in social_indicators)

    def _create_cdn_specific_grease(self, density: str) -> List[Tuple[int, bytes]]:
        """Create CDN-specific GREASE."""
        extensions = []
        count = self._get_grease_count(density) // 2

        # CDN-specific patterns
        for i in range(count):
            ext_type = 0xCDCD + (i * 0x0101)  # CDN pattern
            grease_data = b"CDN" + secrets.token_bytes(random.randint(8, 32))
            extensions.append((ext_type, grease_data))

        return extensions

    def _create_api_specific_grease(self, density: str) -> List[Tuple[int, bytes]]:
        """Create API-specific GREASE."""
        extensions = []
        count = self._get_grease_count(density) // 2

        # API-specific patterns
        for i in range(count):
            ext_type = 0xA9A9 + (i * 0x0101)  # API pattern
            grease_data = b"API" + secrets.token_bytes(random.randint(8, 32))
            extensions.append((ext_type, grease_data))

        return extensions

    def _create_social_media_grease(self, density: str) -> List[Tuple[int, bytes]]:
        """Create social media specific GREASE."""
        extensions = []
        count = self._get_grease_count(density) // 2

        # Social media patterns
        for i in range(count):
            ext_type = 0x50C1 + (i * 0x0101)  # Social pattern
            grease_data = b"SOCIAL" + secrets.token_bytes(random.randint(8, 32))
            extensions.append((ext_type, grease_data))

        return extensions

    def _create_generic_contextual_grease(
        self, density: str
    ) -> List[Tuple[int, bytes]]:
        """Create generic contextual GREASE."""
        extensions = []
        count = self._get_grease_count(density) // 2

        # Generic patterns
        for i in range(count):
            ext_type = 0x6E6E + (i * 0x0101)  # Generic pattern
            grease_data = secrets.token_bytes(random.randint(8, 32))
            extensions.append((ext_type, grease_data))

        return extensions

    def _insert_multiple_extensions(
        self, payload: bytes, extensions: List[Tuple[int, bytes]]
    ) -> bytes:
        """Insert multiple extensions into TLS handshake."""
        # Use the same insertion logic as other ECH attacks
        grease_attack = ECHGreaseAttack()
        return grease_attack._insert_grease_extensions(payload, extensions)

        # Build ECH extension data
        ech_data = struct.pack(">B", 0x01)  # ECH type (outer)
        ech_data += struct.pack(">B", config_id)
        ech_data += struct.pack(">H", len(kem_output))
        ech_data += kem_output
        ech_data += struct.pack(">H", len(encrypted_ch))
        ech_data += encrypted_ch

        return ech_data

    def _generate_decoy_ech_data(self, index: int, vary_sizes: bool) -> bytes:
        """Generate decoy ECH data that looks plausible."""
        # Create decoy data with different characteristics

        if vary_sizes:
            # Vary the size to make decoys less obvious
            base_size = 250
            size_variation = random.randint(-50, 200)
            decoy_size = max(50, base_size + size_variation)
        else:
            # Use consistent size
            decoy_size = 300

        # Generate decoy data with some structure
        decoy_data = struct.pack(">B", 0x01)  # ECH type
        decoy_data += struct.pack(">B", (index + 1) % 256)  # Fake config ID

        # Add fake KEM output
        kem_size = random.choice([32, 48, 64])  # Common KEM output sizes
        decoy_data += struct.pack(">H", kem_size)
        decoy_data += bytes([random.randint(0, 255) for _ in range(kem_size)])

        # Add fake encrypted data
        remaining_size = decoy_size - len(decoy_data) - 2
        if remaining_size > 0:
            decoy_data += struct.pack(">H", remaining_size)
            decoy_data += bytes([random.randint(0, 255) for _ in range(remaining_size)])

        return decoy_data

    def _insert_decoy_extensions(
        self, payload: bytes, decoy_extensions: List[Tuple[int, bytes, bool]]
    ) -> bytes:
        """Insert decoy ECH extensions into TLS handshake."""
        # Similar to GREASE insertion but with multiple ECH extensions
        if len(payload) < 5 or payload[0] != 0x16:
            return payload

        try:
            # Parse TLS record
            record_length = struct.unpack(">H", payload[3:5])[0]
            if len(payload) < 5 + record_length:
                return payload

            handshake_data = payload[5 : 5 + record_length]
            if len(handshake_data) < 4 or handshake_data[0] != 0x01:
                return payload

            # Find extensions
            extensions_start = self._find_extensions_start(handshake_data)
            if extensions_start == -1:
                return payload

            # Convert decoy extensions to format expected by insertion function
            extensions_to_insert = [
                (ext_type, ext_data) for ext_type, ext_data, _ in decoy_extensions
            ]

            # Insert extensions
            modified_handshake = self._insert_extensions_at_position(
                handshake_data, extensions_start, extensions_to_insert
            )

            # Rebuild TLS record
            new_record_length = len(modified_handshake)
            modified_payload = payload[:3]
            modified_payload += struct.pack(">H", new_record_length)
            modified_payload += modified_handshake
            modified_payload += payload[5 + record_length :]

            return modified_payload

        except Exception:
            return payload

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate zapret command for ECH attacks."""
        attack_type = (
            params.get("attack_type", "fragmentation") if params else "fragmentation"
        )

        if attack_type == "fragmentation":
            return "zapret --ech-fragment --fake-tls --split-pos 2"
        elif attack_type == "grease":
            return "zapret --ech-grease --fake-gen --disorder"
        elif attack_type == "decoy":
            return "zapret --ech-decoy --fake-tls --split-pos random"
        else:
            return "zapret --ech-advanced --fake-tls --disorder"


@register_attack
class ECHOuterSNIManipulationAttack(BaseAttack):
    """
    ECH Outer SNI Manipulation Attack - manipulates the outer SNI to confuse DPI.
    """

    @property
    def name(self) -> str:
        return "ech_outer_sni_manipulation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Manipulates ECH outer SNI to confuse DPI analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ECH outer SNI manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_strategy = context.params.get(
                "manipulation_strategy", "public_suffix"
            )
            use_fake_ech = context.params.get("use_fake_ech", True)
            sni_count = context.params.get("sni_count", 1)

            # Manipulate outer SNI
            modified_payload = self._manipulate_outer_sni(
                payload, manipulation_strategy, use_fake_ech, sni_count, context
            )

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
                    "manipulation_strategy": manipulation_strategy,
                    "use_fake_ech": use_fake_ech,
                    "sni_count": sni_count,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _manipulate_outer_sni(
        self,
        payload: bytes,
        strategy: str,
        use_fake_ech: bool,
        sni_count: int,
        context: AttackContext,
    ) -> bytes:
        """Manipulate the outer SNI in ECH context."""
        # Generate outer SNI based on strategy
        if strategy == "public_suffix":
            outer_snis = self._generate_public_suffix_snis(context.domain, sni_count)
        elif strategy == "random_subdomain":
            outer_snis = self._generate_random_subdomain_snis(context.domain, sni_count)
        elif strategy == "popular_domains":
            outer_snis = self._generate_popular_domain_snis(sni_count)
        elif strategy == "cdn_domains":
            outer_snis = self._generate_cdn_domain_snis(sni_count)
        else:
            outer_snis = [f"example{i}.com" for i in range(sni_count)]

        # Modify TLS handshake with new SNI(s) and ECH
        return self._modify_tls_with_outer_sni(
            payload, outer_snis, use_fake_ech, context
        )

    def _generate_public_suffix_snis(
        self, original_domain: str, count: int
    ) -> List[str]:
        """Generate SNIs using public suffix of original domain."""
        if not original_domain:
            return ["example.com"] * count

        # Extract public suffix (simplified)
        parts = original_domain.split(".")
        if len(parts) >= 2:
            public_suffix = ".".join(parts[-2:])
        else:
            public_suffix = original_domain

        # Generate variations
        snis = []
        for i in range(count):
            if i == 0:
                snis.append(public_suffix)
            else:
                snis.append(f"sni{i}.{public_suffix}")

        return snis

    def _generate_random_subdomain_snis(
        self, original_domain: str, count: int
    ) -> List[str]:
        """Generate random subdomain SNIs."""
        if not original_domain:
            base_domain = "example.com"
        else:
            base_domain = original_domain

        snis = []
        for i in range(count):
            subdomain = "".join(
                random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(3, 8))
            )
            snis.append(f"{subdomain}.{base_domain}")

        return snis

    def _generate_popular_domain_snis(self, count: int) -> List[str]:
        """Generate SNIs using popular domains."""
        popular_domains = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "netflix.com",
            "twitter.com",
            "instagram.com",
            "linkedin.com",
            "youtube.com",
            "github.com",
            "stackoverflow.com",
        ]

        return random.choices(popular_domains, k=count)

    def _generate_cdn_domain_snis(self, count: int) -> List[str]:
        """Generate SNIs using CDN domains."""
        cdn_domains = [
            "cloudflare.com",
            "amazonaws.com",
            "azureedge.net",
            "fastly.com",
            "jsdelivr.net",
            "unpkg.com",
            "cdnjs.cloudflare.com",
            "maxcdn.bootstrapcdn.com",
        ]

        return random.choices(cdn_domains, k=count)

    def _modify_tls_with_outer_sni(
        self,
        payload: bytes,
        outer_snis: List[str],
        use_fake_ech: bool,
        context: AttackContext,
    ) -> bytes:
        """Modify TLS handshake with outer SNI and ECH."""
        if len(payload) < 5 or payload[0] != 0x16:
            return payload

        try:
            # Parse and modify TLS handshake
            record_length = struct.unpack(">H", payload[3:5])[0]
            if len(payload) < 5 + record_length:
                return payload

            handshake_data = payload[5 : 5 + record_length]
            if len(handshake_data) < 4 or handshake_data[0] != 0x01:
                return payload

            # Find extensions
            extensions_start = self._find_extensions_start(handshake_data)
            if extensions_start == -1:
                return payload

            # Create new extensions
            new_extensions = []

            # Add SNI extensions
            for sni in outer_snis:
                sni_data = self._create_sni_extension_data(sni)
                new_extensions.append((0x0000, sni_data))  # SNI extension type

            # Add fake ECH if requested
            if use_fake_ech:
                fake_ech_data = self._generate_fake_ech_data(context)
                new_extensions.append((ECH_EXTENSION_TYPE, fake_ech_data))

            # Insert extensions
            modified_handshake = self._insert_extensions_at_position(
                handshake_data, extensions_start, new_extensions
            )

            # Rebuild TLS record
            new_record_length = len(modified_handshake)
            modified_payload = payload[:3]
            modified_payload += struct.pack(">H", new_record_length)
            modified_payload += modified_handshake
            modified_payload += payload[5 + record_length :]

            return modified_payload

        except Exception:
            return payload

    def _create_sni_extension_data(self, sni: str) -> bytes:
        """Create SNI extension data."""
        sni_bytes = sni.encode("utf-8")

        # SNI extension format:
        # - Server Name List Length (2 bytes)
        # - Name Type (1 byte) - 0x00 for hostname
        # - Name Length (2 bytes)
        # - Name (variable)

        sni_data = struct.pack(">H", len(sni_bytes) + 3)  # List length
        sni_data += struct.pack(">B", 0x00)  # Hostname type
        sni_data += struct.pack(">H", len(sni_bytes))  # Name length
        sni_data += sni_bytes  # Name

        return sni_data


@register_attack
class ECHAdvancedFragmentationAttack(BaseAttack):
    """
    ECH Advanced Fragmentation Attack - uses sophisticated fragmentation techniques.
    """

    @property
    def name(self) -> str:
        return "ech_advanced_fragmentation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Uses advanced ECH fragmentation techniques to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced ECH fragmentation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            fragmentation_strategy = context.params.get(
                "fragmentation_strategy", "nested_extensions"
            )
            fragment_size_variation = context.params.get(
                "fragment_size_variation", True
            )
            cross_record_fragmentation = context.params.get(
                "cross_record_fragmentation", False
            )

            # Create advanced fragmented ECH payload
            fragmented_payload = self._create_advanced_fragmented_ech(
                payload,
                fragmentation_strategy,
                fragment_size_variation,
                cross_record_fragmentation,
                context,
            )

            segments = [(fragmented_payload, 0)]
            packets_sent = 1
            bytes_sent = len(fragmented_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fragmentation_strategy": fragmentation_strategy,
                    "fragment_size_variation": fragment_size_variation,
                    "cross_record_fragmentation": cross_record_fragmentation,
                    "original_size": len(payload),
                    "fragmented_size": len(fragmented_payload),
                    "bypass_technique": "advanced_ech_fragmentation",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_advanced_fragmented_ech(
        self,
        payload: bytes,
        strategy: str,
        size_variation: bool,
        cross_record: bool,
        context: AttackContext,
    ) -> bytes:
        """Create advanced fragmented ECH payload."""
        if strategy == "nested_extensions":
            return self._create_nested_extension_fragmentation(
                payload, size_variation, context
            )
        elif strategy == "interleaved_fragments":
            return self._create_interleaved_fragmentation(
                payload, size_variation, context
            )
        elif strategy == "recursive_fragmentation":
            return self._create_recursive_fragmentation(
                payload, size_variation, context
            )
        elif strategy == "steganographic_fragmentation":
            return self._create_steganographic_fragmentation(
                payload, size_variation, context
            )
        else:
            return self._create_nested_extension_fragmentation(
                payload, size_variation, context
            )

    def _create_nested_extension_fragmentation(
        self, payload: bytes, size_variation: bool, context: AttackContext
    ) -> bytes:
        """Create nested extension fragmentation."""
        # Generate ECH data
        ech_data = self._generate_realistic_ech_data(context)

        # Fragment ECH data into multiple levels
        level1_fragments = self._fragment_data(ech_data, 3, size_variation)

        # Create nested extensions - fragments within fragments
        nested_extensions = []

        for i, fragment in enumerate(level1_fragments):
            # Fragment each level1 fragment further
            level2_fragments = self._fragment_data(fragment, 2, size_variation)

            for j, subfragment in enumerate(level2_fragments):
                # Use different extension types for nested structure
                ext_type = ECH_EXTENSION_TYPE + (i * 10) + j

                # Add nesting metadata
                nesting_header = struct.pack(">BBB", i, j, len(level2_fragments))
                nested_data = nesting_header + subfragment

                nested_extensions.append((ext_type, nested_data))

        # Insert nested extensions into payload
        return self._insert_multiple_extensions(payload, nested_extensions)

    def _create_interleaved_fragmentation(
        self, payload: bytes, size_variation: bool, context: AttackContext
    ) -> bytes:
        """Create interleaved fragmentation with decoy data."""
        # Generate multiple ECH datasets
        real_ech = self._generate_realistic_ech_data(context)
        decoy_ech1 = self._generate_decoy_ech_data(1, size_variation)
        decoy_ech2 = self._generate_decoy_ech_data(2, size_variation)

        # Fragment all datasets
        real_fragments = self._fragment_data(real_ech, 4, size_variation)
        decoy1_fragments = self._fragment_data(decoy_ech1, 3, size_variation)
        decoy2_fragments = self._fragment_data(decoy_ech2, 3, size_variation)

        # Interleave fragments
        interleaved_extensions = []
        max_fragments = max(
            len(real_fragments), len(decoy1_fragments), len(decoy2_fragments)
        )

        for i in range(max_fragments):
            # Add real fragment
            if i < len(real_fragments):
                ext_type = ECH_EXTENSION_TYPE + (i * 3)
                fragment_header = struct.pack(
                    ">BBB", 0, i, len(real_fragments)
                )  # Type 0 = real
                interleaved_extensions.append(
                    (ext_type, fragment_header + real_fragments[i])
                )

            # Add decoy fragments
            if i < len(decoy1_fragments):
                ext_type = ECH_EXTENSION_TYPE + (i * 3) + 1
                fragment_header = struct.pack(
                    ">BBB", 1, i, len(decoy1_fragments)
                )  # Type 1 = decoy1
                interleaved_extensions.append(
                    (ext_type, fragment_header + decoy1_fragments[i])
                )

            if i < len(decoy2_fragments):
                ext_type = ECH_EXTENSION_TYPE + (i * 3) + 2
                fragment_header = struct.pack(
                    ">BBB", 2, i, len(decoy2_fragments)
                )  # Type 2 = decoy2
                interleaved_extensions.append(
                    (ext_type, fragment_header + decoy2_fragments[i])
                )

        return self._insert_multiple_extensions(payload, interleaved_extensions)

    def _create_recursive_fragmentation(
        self, payload: bytes, size_variation: bool, context: AttackContext
    ) -> bytes:
        """Create recursive fragmentation - fragments of fragments."""
        ech_data = self._generate_realistic_ech_data(context)

        # Recursive fragmentation with multiple levels
        current_data = ech_data
        extensions = []
        level = 0

        while len(current_data) > 50 and level < 4:  # Max 4 levels
            fragments = self._fragment_data(current_data, 3, size_variation)

            for i, fragment in enumerate(fragments):
                ext_type = ECH_EXTENSION_TYPE + (level * 100) + i

                # Add recursion metadata
                recursion_header = struct.pack(">BBB", level, i, len(fragments))
                fragment_data = recursion_header + fragment

                extensions.append((ext_type, fragment_data))

            # Use first fragment as input for next level
            current_data = fragments[0] if fragments else b""
            level += 1

        return self._insert_multiple_extensions(payload, extensions)

    def _create_steganographic_fragmentation(
        self, payload: bytes, size_variation: bool, context: AttackContext
    ) -> bytes:
        """Create steganographic fragmentation - hide fragments in other extensions."""
        ech_data = self._generate_realistic_ech_data(context)
        fragments = self._fragment_data(ech_data, 5, size_variation)

        # Hide ECH fragments inside other common extensions
        steganographic_extensions = []

        # Common TLS extension types to use as carriers
        carrier_extensions = [
            0x0000,  # server_name
            0x0001,  # max_fragment_length
            0x0005,  # status_request
            0x000A,  # supported_groups
            0x000B,  # ec_point_formats
            0x000D,  # signature_algorithms
            0x0010,  # application_layer_protocol_negotiation
            0x0012,  # signed_certificate_timestamp
            0x0015,  # padding
            0x002B,  # supported_versions
        ]

        for i, fragment in enumerate(fragments):
            carrier_type = carrier_extensions[i % len(carrier_extensions)]

            # Create legitimate-looking carrier data
            carrier_data = self._generate_carrier_extension_data(carrier_type)

            # Hide fragment in carrier data using steganography
            steganographic_data = self._hide_fragment_in_carrier(
                fragment, carrier_data, i
            )

            steganographic_extensions.append((carrier_type, steganographic_data))

        return self._insert_multiple_extensions(payload, steganographic_extensions)

    def _fragment_data(
        self, data: bytes, fragment_count: int, size_variation: bool
    ) -> List[bytes]:
        """Fragment data into specified number of pieces."""
        if fragment_count <= 1:
            return [data]

        fragments = []
        data_len = len(data)

        if size_variation:
            # Variable fragment sizes
            fragment_sizes = []
            remaining = data_len

            for i in range(fragment_count - 1):
                # Random size between 10% and 40% of remaining data
                max_size = max(1, remaining // 2)
                min_size = max(1, remaining // 10)
                size = random.randint(min_size, max_size)
                fragment_sizes.append(size)
                remaining -= size

            fragment_sizes.append(remaining)  # Last fragment gets remainder
        else:
            # Equal fragment sizes
            base_size = data_len // fragment_count
            fragment_sizes = [base_size] * fragment_count
            fragment_sizes[-1] += data_len % fragment_count  # Add remainder to last

        offset = 0
        for size in fragment_sizes:
            fragment = data[offset : offset + size]
            fragments.append(fragment)
            offset += size

        return fragments

    def _generate_realistic_ech_data(self, context: AttackContext) -> bytes:
        """Generate realistic ECH data."""
        # ECH structure with realistic components
        config_id = random.randint(1, 255)

        # KEM output (X25519 = 32 bytes, P-256 = 65 bytes)
        kem_type = random.choice([32, 65])
        kem_output = secrets.token_bytes(kem_type)

        # Encrypted ClientHello Inner
        inner_sni = context.params.get("inner_sni", "hidden.example.com")
        encrypted_inner = self._generate_encrypted_inner_hello(inner_sni)

        # Authentication tag (16 bytes for AES-GCM)
        auth_tag = secrets.token_bytes(16)

        # Combine ECH components
        ech_data = struct.pack(">B", config_id)
        ech_data += struct.pack(">B", len(kem_output)) + kem_output
        ech_data += struct.pack(">H", len(encrypted_inner)) + encrypted_inner
        ech_data += auth_tag

        return ech_data

    def _generate_encrypted_inner_hello(self, inner_sni: str) -> bytes:
        """Generate encrypted inner ClientHello."""
        # Simulate encrypted inner ClientHello structure
        inner_size = 200 + len(inner_sni.encode())

        # Create structured encrypted data
        encrypted_data = bytearray()

        # Add TLS-like patterns
        encrypted_data.extend([0x16, 0x03, 0x03])  # TLS record header pattern
        encrypted_data.extend(secrets.token_bytes(32))  # Client random

        # Add SNI-related patterns (encrypted)
        sni_bytes = inner_sni.encode()
        for i, byte in enumerate(sni_bytes):
            # Simple XOR encryption for demonstration
            encrypted_data.append(byte ^ (i % 256))

        # Fill remaining with pseudo-random data
        while len(encrypted_data) < inner_size:
            encrypted_data.extend(
                secrets.token_bytes(min(16, inner_size - len(encrypted_data)))
            )

        return bytes(encrypted_data[:inner_size])

    def _generate_decoy_ech_data(self, variant: int, size_variation: bool) -> bytes:
        """Generate decoy ECH data."""
        if size_variation:
            size = random.randint(100, 400)
        else:
            size = 250

        # Create decoy with different patterns based on variant
        decoy_data = bytearray()

        # Variant-specific patterns
        if variant == 1:
            # Pattern 1: Repeated sequences
            pattern = bytes([0xAA, 0xBB, 0xCC, 0xDD])
            decoy_data.extend(pattern * (size // len(pattern)))
            decoy_data.extend(pattern[: size % len(pattern)])
        elif variant == 2:
            # Pattern 2: Incremental sequences
            for i in range(size):
                decoy_data.append((i + variant) % 256)
        else:
            # Pattern 3: Random with structure
            for i in range(size):
                if i % 8 == 0:
                    decoy_data.append(variant)
                else:
                    decoy_data.append(random.randint(0, 255))

        return bytes(decoy_data)

    def _generate_carrier_extension_data(self, ext_type: int) -> bytes:
        """Generate legitimate-looking carrier extension data."""
        if ext_type == 0x0000:  # server_name
            return b"\x00\x0e\x00\x00\x0bexample.com"
        elif ext_type == 0x000A:  # supported_groups
            return b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
        elif ext_type == 0x000D:  # signature_algorithms
            return b"\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
        elif ext_type == 0x002B:  # supported_versions
            return b"\x03\x04\x03\x03\x03\x02"
        else:
            # Generic extension data
            return secrets.token_bytes(random.randint(8, 32))

    def _hide_fragment_in_carrier(
        self, fragment: bytes, carrier_data: bytes, fragment_index: int
    ) -> bytes:
        """Hide ECH fragment in carrier extension data using steganography."""
        # Simple LSB steganography - hide fragment bits in carrier data
        if len(carrier_data) * 8 < len(fragment) * 8:
            # Carrier too small, extend it
            carrier_data += secrets.token_bytes(len(fragment))

        hidden_data = bytearray(carrier_data)
        fragment_bits = []

        # Convert fragment to bits
        for byte in fragment:
            for i in range(8):
                fragment_bits.append((byte >> i) & 1)

        # Hide fragment bits in LSBs of carrier data
        for i, bit in enumerate(fragment_bits):
            if i < len(hidden_data):
                # Clear LSB and set to fragment bit
                hidden_data[i] = (hidden_data[i] & 0xFE) | bit

        # Add fragment index as metadata in first byte
        if hidden_data:
            hidden_data[0] = (hidden_data[0] & 0xF0) | (fragment_index & 0x0F)

        return bytes(hidden_data)

    def _insert_multiple_extensions(
        self, payload: bytes, extensions: List[Tuple[int, bytes]]
    ) -> bytes:
        """Insert multiple extensions into TLS handshake."""
        # Use the same insertion logic as other ECH attacks
        grease_attack = ECHGreaseAttack()
        return grease_attack._insert_grease_extensions(payload, extensions)
