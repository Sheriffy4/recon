"""
Comprehensive TLS Evasion Attacks Implementation

This module implements the core TLS evasion attacks required by task 7:
- TLS handshake manipulation techniques
- TLS version downgrade attacks
- TLS extension manipulation
- TLS record fragmentation attacks

These attacks are designed to evade DPI systems that analyze TLS traffic patterns.
"""
import time
import random
import struct
import os
from typing import List, Tuple
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack

@register_attack
class TLSHandshakeManipulationAttack(BaseAttack):
    """
    TLS Handshake Manipulation Attack - modifies TLS handshake structure and timing.

    This attack manipulates various aspects of the TLS handshake to evade DPI detection:
    - Handshake message ordering
    - Message fragmentation
    - Timing manipulation
    - Fake handshake messages
    """

    @property
    def name(self) -> str:
        return 'tls_handshake_manipulation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Manipulates TLS handshake structure and timing to evade DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS handshake manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get('manipulation_type', 'fragment_hello')
            fragment_size = context.params.get('fragment_size', 64)
            add_fake_messages = context.params.get('add_fake_messages', False)
            randomize_timing = context.params.get('randomize_timing', False)
            if not self._is_tls_handshake(payload):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is not a valid TLS handshake')
            if manipulation_type == 'fragment_hello':
                modified_payload, segments = self._fragment_client_hello(payload, fragment_size)
            elif manipulation_type == 'reorder_extensions':
                modified_payload, segments = self._reorder_extensions(payload)
            elif manipulation_type == 'split_handshake':
                modified_payload, segments = self._split_handshake_messages(payload)
            elif manipulation_type == 'fake_messages':
                modified_payload, segments = self._add_fake_handshake_messages(payload)
            elif manipulation_type == 'timing_manipulation':
                modified_payload, segments = self._apply_timing_manipulation(payload)
            else:
                modified_payload, segments = self._fragment_client_hello(payload, fragment_size)
            packets_sent = len(segments)
            bytes_sent = sum((len(seg[0]) for seg in segments))
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'manipulation_type': manipulation_type, 'fragment_size': fragment_size, 'segments_count': len(segments), 'add_fake_messages': add_fake_messages, 'randomize_timing': randomize_timing, 'original_size': len(payload), 'modified_size': len(modified_payload) if isinstance(modified_payload, bytes) else sum((len(seg[0]) for seg in segments)), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _is_tls_handshake(self, payload: bytes) -> bool:
        """Check if payload is a TLS handshake."""
        if len(payload) < 6:
            return False
        return payload[0] == 22 and payload[1] == 3 and (len(payload) > 5) and (payload[5] == 1)

    def _fragment_client_hello(self, payload: bytes, fragment_size: int) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Fragment ClientHello across multiple TCP segments."""
        segments = []
        offset = 0
        while offset < len(payload):
            chunk_size = min(fragment_size, len(payload) - offset)
            chunk = payload[offset:offset + chunk_size]
            segments.append((chunk, offset))
            offset += chunk_size
        return (payload, segments)

    def _reorder_extensions(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Reorder TLS extensions to confuse DPI."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return (payload, [(payload, 0)])
            modified_payload = self._randomize_extension_order(payload, extensions_start)
            return (modified_payload, [(modified_payload, 0)])
        except Exception:
            return (payload, [(payload, 0)])

    def _split_handshake_messages(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Split handshake into multiple messages."""
        segments = []
        offset = 0
        while offset < len(payload):
            if offset + 5 > len(payload):
                segments.append((payload[offset:], offset))
                break
            record_length = struct.unpack('!H', payload[offset + 3:offset + 5])[0]
            total_record_size = 5 + record_length
            if offset + total_record_size > len(payload):
                segments.append((payload[offset:], offset))
                break
            record = payload[offset:offset + total_record_size]
            segments.append((record, offset))
            offset += total_record_size
        return (payload, segments)

    def _add_fake_handshake_messages(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Add fake handshake messages to confuse DPI."""
        fake_cert = self._create_fake_certificate_message()
        fake_server_hello = self._create_fake_server_hello()
        combined_payload = payload + fake_server_hello + fake_cert
        return (combined_payload, [(combined_payload, 0)])

    def _apply_timing_manipulation(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Apply timing-based manipulation."""
        segments = []
        fragment_size = 32
        for i in range(0, len(payload), fragment_size):
            chunk = payload[i:i + fragment_size]
            delay_ms = random.randint(10, 100)
            segments.append((chunk, i, {'delay_ms': delay_ms}))
        return (payload, segments)

    def _find_extensions_offset(self, payload: bytes) -> int:
        """Find the offset of extensions in ClientHello."""
        try:
            offset = 5
            offset += 4
            offset += 2
            offset += 32
            if offset >= len(payload):
                return -1
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return -1
            cipher_suites_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len
            if offset >= len(payload):
                return -1
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if offset + 2 <= len(payload):
                return offset
            return -1
        except Exception:
            return -1

    def _randomize_extension_order(self, payload: bytes, extensions_start: int) -> bytes:
        """Randomize the order of TLS extensions."""
        try:
            extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            extensions_data = payload[extensions_start + 2:extensions_start + 2 + extensions_len]
            extensions = []
            offset = 0
            while offset < len(extensions_data):
                if offset + 4 > len(extensions_data):
                    break
                ext_type = struct.unpack('!H', extensions_data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', extensions_data[offset + 2:offset + 4])[0]
                if offset + 4 + ext_len > len(extensions_data):
                    break
                ext_data = extensions_data[offset + 4:offset + 4 + ext_len]
                extensions.append((ext_type, ext_data))
                offset += 4 + ext_len
            sni_ext = None
            other_exts = []
            for ext_type, ext_data in extensions:
                if ext_type == 0:
                    sni_ext = (ext_type, ext_data)
                else:
                    other_exts.append((ext_type, ext_data))
            random.shuffle(other_exts)
            reordered_extensions = []
            if sni_ext:
                reordered_extensions.append(sni_ext)
            reordered_extensions.extend(other_exts)
            new_extensions_data = b''
            for ext_type, ext_data in reordered_extensions:
                new_extensions_data += struct.pack('!H', ext_type)
                new_extensions_data += struct.pack('!H', len(ext_data))
                new_extensions_data += ext_data
            new_payload = payload[:extensions_start]
            new_payload += struct.pack('!H', len(new_extensions_data))
            new_payload += new_extensions_data
            new_payload += payload[extensions_start + 2 + extensions_len:]
            return new_payload
        except Exception:
            return payload

    def _create_fake_certificate_message(self) -> bytes:
        """Create a fake Certificate handshake message."""
        fake_cert_data = b'\x00\x00\x00'
        cert_msg = b'\x0b'
        cert_msg += struct.pack('!I', len(fake_cert_data))[1:]
        cert_msg += fake_cert_data
        tls_record = b'\x16'
        tls_record += b'\x03\x03'
        tls_record += struct.pack('!H', len(cert_msg))
        tls_record += cert_msg
        return tls_record

    def _create_fake_server_hello(self) -> bytes:
        """Create a fake ServerHello message."""
        server_hello = b'\x02'
        hello_data = b'\x03\x03'
        hello_data += os.urandom(32)
        hello_data += b'\x00'
        hello_data += b'\x005'
        hello_data += b'\x00'
        hello_data += b'\x00\x00'
        server_hello += struct.pack('!I', len(hello_data))[1:]
        server_hello += hello_data
        tls_record = b'\x16'
        tls_record += b'\x03\x03'
        tls_record += struct.pack('!H', len(server_hello))
        tls_record += server_hello
        return tls_record

@register_attack
class TLSVersionDowngradeAttack(BaseAttack):
    """
    TLS Version Downgrade Attack - forces downgrade to older TLS versions.

    This attack manipulates TLS version fields to force downgrade to less secure
    versions that may be easier to bypass or have known vulnerabilities.
    """

    @property
    def name(self) -> str:
        return 'tls_version_downgrade'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Forces TLS version downgrade to evade modern DPI detection'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS version downgrade attack."""
        start_time = time.time()
        try:
            payload = context.payload
            target_version = context.params.get('target_version', 'tls10')
            modify_supported_versions = context.params.get('modify_supported_versions', True)
            add_fallback_scsv = context.params.get('add_fallback_scsv', False)
            if not self._is_tls_handshake(payload):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is not a valid TLS handshake')
            version_map = {'ssl30': b'\x03\x00', 'tls10': b'\x03\x01', 'tls11': b'\x03\x02', 'tls12': b'\x03\x03', 'tls13': b'\x03\x04'}
            target_version_bytes = version_map.get(target_version, b'\x03\x01')
            modified_payload = self._apply_version_downgrade(payload, target_version_bytes, modify_supported_versions, add_fallback_scsv)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'target_version': target_version, 'target_version_bytes': target_version_bytes.hex(), 'modify_supported_versions': modify_supported_versions, 'add_fallback_scsv': add_fallback_scsv, 'original_size': len(payload), 'modified_size': len(modified_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _is_tls_handshake(self, payload: bytes) -> bool:
        """Check if payload is a TLS handshake."""
        if len(payload) < 6:
            return False
        return payload[0] == 22 and payload[1] == 3 and (len(payload) > 5) and (payload[5] == 1)

    def _apply_version_downgrade(self, payload: bytes, target_version: bytes, modify_supported_versions: bool, add_fallback_scsv: bool) -> bytes:
        """Apply TLS version downgrade to the payload."""
        try:
            modified_payload = bytearray(payload)
            modified_payload[1:3] = target_version
            if len(modified_payload) > 10:
                modified_payload[9:11] = target_version
            if modify_supported_versions:
                modified_payload = self._modify_supported_versions_extension(bytes(modified_payload), target_version)
            if add_fallback_scsv:
                modified_payload = self._add_fallback_scsv(bytes(modified_payload))
            return bytes(modified_payload)
        except Exception:
            return payload

    def _modify_supported_versions_extension(self, payload: bytes, target_version: bytes) -> bytes:
        """Modify the supported_versions extension to only include target version."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            extensions_end = extensions_start + 2 + extensions_len
            offset = extensions_start + 2
            new_extensions_data = b''
            while offset < extensions_end:
                if offset + 4 > len(payload):
                    break
                ext_type = struct.unpack('!H', payload[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
                if offset + 4 + ext_len > len(payload):
                    break
                if ext_type == 43:
                    new_ext_data = b'\x02' + target_version
                    new_extensions_data += struct.pack('!H', ext_type)
                    new_extensions_data += struct.pack('!H', len(new_ext_data))
                    new_extensions_data += new_ext_data
                else:
                    ext_data = payload[offset + 4:offset + 4 + ext_len]
                    new_extensions_data += struct.pack('!H', ext_type)
                    new_extensions_data += struct.pack('!H', ext_len)
                    new_extensions_data += ext_data
                offset += 4 + ext_len
            new_payload = payload[:extensions_start]
            new_payload += struct.pack('!H', len(new_extensions_data))
            new_payload += new_extensions_data
            new_payload += payload[extensions_end:]
            return new_payload
        except Exception:
            return payload

    def _add_fallback_scsv(self, payload: bytes) -> bytes:
        """Add TLS_FALLBACK_SCSV to cipher suites."""
        try:
            offset = 44
            if offset >= len(payload):
                return payload
            session_id_len = payload[offset - 1]
            offset += session_id_len
            if offset + 2 > len(payload):
                return payload
            cipher_suites_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            cipher_suites_data = payload[offset + 2:offset + 2 + cipher_suites_len]
            fallback_scsv = b'V\x00'
            if fallback_scsv not in cipher_suites_data:
                new_cipher_suites = cipher_suites_data + fallback_scsv
                new_cipher_suites_len = len(new_cipher_suites)
                new_payload = payload[:offset]
                new_payload += struct.pack('!H', new_cipher_suites_len)
                new_payload += new_cipher_suites
                new_payload += payload[offset + 2 + cipher_suites_len:]
                return new_payload
            return payload
        except Exception:
            return payload

    def _find_extensions_offset(self, payload: bytes) -> int:
        """Find the offset of extensions in ClientHello."""
        try:
            offset = 5
            offset += 4
            offset += 2
            offset += 32
            if offset >= len(payload):
                return -1
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return -1
            cipher_suites_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len
            if offset >= len(payload):
                return -1
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if offset + 2 <= len(payload):
                return offset
            return -1
        except Exception:
            return -1

@register_attack
class TLSExtensionManipulationAttack(BaseAttack):
    """
    TLS Extension Manipulation Attack - manipulates TLS extensions to evade DPI.

    This attack modifies, reorders, or injects TLS extensions to confuse DPI systems
    that rely on extension patterns for detection.
    """

    @property
    def name(self) -> str:
        return 'tls_extension_manipulation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Manipulates TLS extensions to evade DPI pattern detection'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS extension manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get('manipulation_type', 'inject_fake')
            fake_extension_count = context.params.get('fake_extension_count', 3)
            randomize_order = context.params.get('randomize_order', True)
            add_grease = context.params.get('add_grease', True)
            if not self._is_tls_handshake(payload):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is not a valid TLS handshake')
            if manipulation_type == 'inject_fake':
                modified_payload = self._inject_fake_extensions(payload, fake_extension_count)
            elif manipulation_type == 'randomize_order':
                modified_payload = self._randomize_extension_order(payload)
            elif manipulation_type == 'add_grease':
                modified_payload = self._add_grease_extensions(payload)
            elif manipulation_type == 'duplicate_extensions':
                modified_payload = self._duplicate_extensions(payload)
            elif manipulation_type == 'malformed_extensions':
                modified_payload = self._add_malformed_extensions(payload)
            else:
                modified_payload = self._inject_fake_extensions(payload, fake_extension_count)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'manipulation_type': manipulation_type, 'fake_extension_count': fake_extension_count, 'randomize_order': randomize_order, 'add_grease': add_grease, 'original_size': len(payload), 'modified_size': len(modified_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _is_tls_handshake(self, payload: bytes) -> bool:
        """Check if payload is a TLS handshake."""
        if len(payload) < 6:
            return False
        return payload[0] == 22 and payload[1] == 3 and (len(payload) > 5) and (payload[5] == 1)

    def _inject_fake_extensions(self, payload: bytes, count: int) -> bytes:
        """Inject fake extensions into the ClientHello."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            fake_extensions = []
            for i in range(count):
                ext_type = 4096 + i
                ext_data = os.urandom(random.randint(4, 32))
                fake_extensions.append((ext_type, ext_data))
            return self._insert_extensions(payload, extensions_start, fake_extensions)
        except Exception:
            return payload

    def _randomize_extension_order(self, payload: bytes) -> bytes:
        """Randomize the order of TLS extensions."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            extensions_data = payload[extensions_start + 2:extensions_start + 2 + extensions_len]
            extensions = []
            offset = 0
            while offset < len(extensions_data):
                if offset + 4 > len(extensions_data):
                    break
                ext_type = struct.unpack('!H', extensions_data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', extensions_data[offset + 2:offset + 4])[0]
                if offset + 4 + ext_len > len(extensions_data):
                    break
                ext_data = extensions_data[offset + 4:offset + 4 + ext_len]
                extensions.append((ext_type, ext_data))
                offset += 4 + ext_len
            sni_ext = None
            other_exts = []
            for ext_type, ext_data in extensions:
                if ext_type == 0:
                    sni_ext = (ext_type, ext_data)
                else:
                    other_exts.append((ext_type, ext_data))
            random.shuffle(other_exts)
            reordered_extensions = []
            if sni_ext:
                reordered_extensions.append(sni_ext)
            reordered_extensions.extend(other_exts)
            return self._rebuild_extensions(payload, extensions_start, reordered_extensions)
        except Exception:
            return payload

    def _add_grease_extensions(self, payload: bytes) -> bytes:
        """Add GREASE extensions to confuse DPI."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            grease_types = [2570, 6682, 10794, 14906, 19018]
            grease_extensions = []
            for grease_type in grease_types[:3]:
                grease_data = os.urandom(random.randint(0, 16))
                grease_extensions.append((grease_type, grease_data))
            return self._insert_extensions(payload, extensions_start, grease_extensions)
        except Exception:
            return payload

    def _duplicate_extensions(self, payload: bytes) -> bytes:
        """Duplicate some extensions to confuse DPI."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            extensions_data = payload[extensions_start + 2:extensions_start + 2 + extensions_len]
            extensions = []
            offset = 0
            while offset < len(extensions_data):
                if offset + 4 > len(extensions_data):
                    break
                ext_type = struct.unpack('!H', extensions_data[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', extensions_data[offset + 2:offset + 4])[0]
                if offset + 4 + ext_len > len(extensions_data):
                    break
                ext_data = extensions_data[offset + 4:offset + 4 + ext_len]
                extensions.append((ext_type, ext_data))
                if ext_type != 0 and random.random() < 0.3:
                    extensions.append((ext_type, ext_data))
                offset += 4 + ext_len
            return self._rebuild_extensions(payload, extensions_start, extensions)
        except Exception:
            return payload

    def _add_malformed_extensions(self, payload: bytes) -> bytes:
        """Add malformed extensions to test DPI robustness."""
        try:
            extensions_start = self._find_extensions_offset(payload)
            if extensions_start == -1:
                return payload
            malformed_extensions = [(65535, b''), (16, b'\xff' * 100), (35, b'\x00' * 50)]
            return self._insert_extensions(payload, extensions_start, malformed_extensions)
        except Exception:
            return payload

    def _find_extensions_offset(self, payload: bytes) -> int:
        """Find the offset of extensions in ClientHello."""
        try:
            offset = 5
            offset += 4
            offset += 2
            offset += 32
            if offset >= len(payload):
                return -1
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return -1
            cipher_suites_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len
            if offset >= len(payload):
                return -1
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if offset + 2 <= len(payload):
                return offset
            return -1
        except Exception:
            return -1

    def _insert_extensions(self, payload: bytes, extensions_start: int, new_extensions: List[Tuple[int, bytes]]) -> bytes:
        """Insert new extensions at the beginning of the extensions list."""
        try:
            extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            existing_extensions_data = payload[extensions_start + 2:extensions_start + 2 + extensions_len]
            new_extensions_data = b''
            for ext_type, ext_data in new_extensions:
                new_extensions_data += struct.pack('!H', ext_type)
                new_extensions_data += struct.pack('!H', len(ext_data))
                new_extensions_data += ext_data
            combined_extensions_data = new_extensions_data + existing_extensions_data
            new_extensions_len = len(combined_extensions_data)
            new_payload = payload[:extensions_start]
            new_payload += struct.pack('!H', new_extensions_len)
            new_payload += combined_extensions_data
            new_payload += payload[extensions_start + 2 + extensions_len:]
            return new_payload
        except Exception:
            return payload

    def _rebuild_extensions(self, payload: bytes, extensions_start: int, extensions: List[Tuple[int, bytes]]) -> bytes:
        """Rebuild the extensions section with new extension list."""
        try:
            new_extensions_data = b''
            for ext_type, ext_data in extensions:
                new_extensions_data += struct.pack('!H', ext_type)
                new_extensions_data += struct.pack('!H', len(ext_data))
                new_extensions_data += ext_data
            original_extensions_len = struct.unpack('!H', payload[extensions_start:extensions_start + 2])[0]
            new_payload = payload[:extensions_start]
            new_payload += struct.pack('!H', len(new_extensions_data))
            new_payload += new_extensions_data
            new_payload += payload[extensions_start + 2 + original_extensions_len:]
            return new_payload
        except Exception:
            return payload

@register_attack
class TLSRecordFragmentationAttack(BaseAttack):
    """
    TLS Record Fragmentation Attack - fragments TLS records to evade DPI.

    This attack fragments TLS records across multiple TCP segments or splits
    single records into multiple smaller records to confuse DPI analysis.
    """

    @property
    def name(self) -> str:
        return 'tls_record_fragmentation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Fragments TLS records to evade DPI record-level analysis'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragmentation_type = context.params.get('fragmentation_type', 'tcp_segment')
            fragment_size = context.params.get('fragment_size', 64)
            max_fragments = context.params.get('max_fragments', 10)
            randomize_sizes = context.params.get('randomize_sizes', False)
            if not self._is_tls_record(payload):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is not a valid TLS record')
            if fragmentation_type == 'tcp_segment':
                modified_payload, segments = self._fragment_tcp_segments(payload, fragment_size, randomize_sizes)
            elif fragmentation_type == 'tls_record':
                modified_payload, segments = self._fragment_tls_records(payload, fragment_size)
            elif fragmentation_type == 'mixed':
                modified_payload, segments = self._mixed_fragmentation(payload, fragment_size)
            elif fragmentation_type == 'adaptive':
                modified_payload, segments = self._adaptive_fragmentation(payload, max_fragments)
            else:
                modified_payload, segments = self._fragment_tcp_segments(payload, fragment_size, randomize_sizes)
            packets_sent = len(segments)
            bytes_sent = sum((len(seg[0]) for seg in segments))
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'fragmentation_type': fragmentation_type, 'fragment_size': fragment_size, 'max_fragments': max_fragments, 'randomize_sizes': randomize_sizes, 'segments_count': len(segments), 'original_size': len(payload), 'total_fragmented_size': bytes_sent, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _is_tls_record(self, payload: bytes) -> bool:
        """Check if payload is a TLS record."""
        if len(payload) < 5:
            return False
        content_type = payload[0]
        version = struct.unpack('!H', payload[1:3])[0]
        return content_type in [20, 21, 22, 23] and 768 <= version <= 772

    def _fragment_tcp_segments(self, payload: bytes, fragment_size: int, randomize_sizes: bool) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Fragment payload across TCP segments."""
        segments = []
        offset = 0
        while offset < len(payload):
            if randomize_sizes:
                min_rand_size = max(1, fragment_size // 2)
                max_rand_size = min(len(payload) - offset, fragment_size * 2)
                if min_rand_size >= max_rand_size:
                    current_fragment_size = max_rand_size
                else:
                    current_fragment_size = random.randint(min_rand_size, max_rand_size)
            else:
                current_fragment_size = min(fragment_size, len(payload) - offset)

            if current_fragment_size <= 0:
                break

            chunk = payload[offset:offset + current_fragment_size]
            segments.append((chunk, offset))
            offset += current_fragment_size
        return (payload, segments)

    def _fragment_tls_records(self, payload: bytes, fragment_size: int) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Fragment by splitting TLS records into smaller records."""
        try:
            new_records = []
            offset = 0
            while offset < len(payload):
                if offset + 5 > len(payload):
                    new_records.append(payload[offset:])
                    break
                content_type = payload[offset]
                version = payload[offset + 1:offset + 3]
                record_length = struct.unpack('!H', payload[offset + 3:offset + 5])[0]
                if offset + 5 + record_length > len(payload):
                    new_records.append(payload[offset:])
                    break
                record_data = payload[offset + 5:offset + 5 + record_length]
                if record_length > fragment_size:
                    data_offset = 0
                    while data_offset < len(record_data):
                        chunk_size = min(fragment_size, len(record_data) - data_offset)
                        chunk_data = record_data[data_offset:data_offset + chunk_size]
                        new_record = bytes([content_type]) + version + struct.pack('!H', len(chunk_data)) + chunk_data
                        new_records.append(new_record)
                        data_offset += chunk_size
                else:
                    new_records.append(payload[offset:offset + 5 + record_length])
                offset += 5 + record_length
            combined_payload = b''.join(new_records)
            segments = [(combined_payload, 0)]
            return (combined_payload, segments)
        except Exception:
            return self._fragment_tcp_segments(payload, fragment_size, False)

    def _mixed_fragmentation(self, payload: bytes, fragment_size: int) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Apply mixed fragmentation (both TCP and TLS record level)."""
        record_fragmented, _ = self._fragment_tls_records(payload, fragment_size * 2)
        return self._fragment_tcp_segments(record_fragmented, fragment_size, True)

    def _adaptive_fragmentation(self, payload: bytes, max_fragments: int) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Apply adaptive fragmentation based on payload characteristics."""
        payload_size = len(payload)
        if payload_size <= 100:
            fragment_size = max(20, payload_size // 2)
        elif payload_size <= 500:
            fragment_size = payload_size // min(max_fragments, 5)
        else:
            fragment_size = payload_size // max_fragments
        fragment_size = max(16, fragment_size)
        return self._fragment_tcp_segments(payload, fragment_size, True)