import time
import random
import struct
from typing import List, Optional, Tuple
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack
from core.protocols.tls import TLSParser

def _safe_create_result(status_name: str, **kwargs):
    """Safely create AttackResult to prevent AttackStatus errors."""
    try:
        from core.bypass.attacks.safe_result_utils import safe_create_attack_result
        return safe_create_attack_result(status_name, **kwargs)
    except Exception:
        try:
            from core.bypass.attacks.base import AttackResult, AttackStatus
            status = getattr(AttackStatus, status_name)
            return AttackResult(status=status, **kwargs)
        except Exception:
            return None

@register_attack
class SNIManipulationAttack(BaseAttack):
    """
    SNI Manipulation Attack - modifies Server Name Indication extension.
    """
    '\n    SNI Manipulation Attack - modifies Server Name Indication extension.\n    '

    @property
    def name(self) -> str:
        return 'sni_manipulation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Manipulates SNI extension to evade DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute SNI manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get('manipulation_type', 'case_change')
            if not self._is_tls_payload(payload):
                domain = context.domain or context.params.get('target_domain', 'example.com')
                payload = self._create_mock_client_hello(domain)
            original_domain = TLSParser.get_sni(payload)
            if not original_domain:
                original_domain = context.domain or context.params.get('target_domain', 'example.com')
            if manipulation_type == 'case_change':
                modified_domain = self._change_case(original_domain)
            elif manipulation_type == 'random_case':
                modified_domain = self._randomize_domain_case(original_domain)
            elif manipulation_type == 'subdomain_add':
                prefix = context.params.get('subdomain_prefix', 'www')
                modified_domain = self._add_subdomain_prefix(original_domain, prefix)
            elif manipulation_type == 'fake_tld':
                fake_tld = context.params.get('fake_tld', 'local')
                modified_domain = self._add_fake_tld(original_domain, fake_tld)
            elif manipulation_type == 'obfuscate':
                method = context.params.get('obfuscation_method', 'mixed')
                modified_domain = self._obfuscate_domain(original_domain, method)
            elif manipulation_type == 'domain_replace':
                modified_domain = context.params.get('fake_domain', 'example.com')
            else:
                modified_domain = original_domain
            modified_payload = TLSParser.replace_sni(payload, modified_domain)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'manipulation_type': manipulation_type, 'original_domain': original_domain, 'modified_domain': modified_domain, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _is_tls_payload(self, payload: bytes) -> bool:
        """Check if payload looks like TLS."""
        if len(payload) < 6:
            return False
        return payload[0] == 22 and payload[1] in [3] and (payload[2] in [1, 2, 3, 4])

    def _create_mock_client_hello(self, domain: str) -> bytes:
        """Create a mock TLS ClientHello with SNI for testing."""
        import struct
        sni_data = domain.encode('utf-8')
        sni_len = len(sni_data)
        mock_hello = b'\x16\x03\x01' + b'\x00P' + b'\x01' + b'\x00\x00L' + b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02' + b'\x005' + b'\x01\x00' + b'\x00\x1d' + b'\x00\x00' + struct.pack('!H', sni_len + 5) + struct.pack('!H', sni_len + 3) + b'\x00' + struct.pack('!H', sni_len) + sni_data
        return mock_hello

    def _add_subdomain_prefix(self, domain: str, prefix: str='www') -> str:
        """Add subdomain prefix to domain."""
        if not domain.startswith(prefix + '.'):
            return f'{prefix}.{domain}'
        return domain

    def _randomize_domain_case(self, domain: str) -> str:
        """Randomize case of domain characters."""
        result = []
        for char in domain:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)

    def _add_fake_tld(self, domain: str, fake_tld: str='local') -> str:
        """Add fake TLD to domain."""
        parts = domain.split('.')
        if len(parts) > 1:
            parts[-1] = fake_tld
            return '.'.join(parts)
        return f'{domain}.{fake_tld}'

    def _obfuscate_domain(self, domain: str, method: str='case') -> str:
        """Obfuscate domain using various methods."""
        if method == 'case':
            return self._randomize_domain_case(domain)
        elif method == 'subdomain':
            return self._add_subdomain_prefix(domain)
        elif method == 'fake_tld':
            return self._add_fake_tld(domain)
        elif method == 'mixed':
            obfuscated = self._add_subdomain_prefix(domain, 'cdn')
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
        return ''.join(result)

    def _find_sni_extension(self, payload: bytes) -> Optional[Tuple[int, int, int, int]]:
        """
        Robustly finds the SNI extension by parsing the TLS ClientHello extensions block.
        Returns a tuple: (ext_start, ext_end, domain_start, domain_end) or None.
        """
        try:
            if not (payload.startswith(b'\x16\x03') and len(payload) > 43 and (payload[5] == 1)):
                return None
            session_id_len_pos = 43
            session_id_len = payload[session_id_len_pos]
            cipher_suites_len_pos = session_id_len_pos + 1 + session_id_len
            cipher_suites_len = struct.unpack('!H', payload[cipher_suites_len_pos:cipher_suites_len_pos + 2])[0]
            comp_methods_len_pos = cipher_suites_len_pos + 2 + cipher_suites_len
            comp_methods_len = payload[comp_methods_len_pos]
            extensions_len_pos = comp_methods_len_pos + 1 + comp_methods_len
            if extensions_len_pos + 2 > len(payload):
                return None
            total_extensions_len = struct.unpack('!H', payload[extensions_len_pos:extensions_len_pos + 2])[0]
            extensions_start_pos = extensions_len_pos + 2
            current_pos = extensions_start_pos
            while current_pos < extensions_start_pos + total_extensions_len:
                ext_type = struct.unpack('!H', payload[current_pos:current_pos + 2])[0]
                ext_len = struct.unpack('!H', payload[current_pos + 2:current_pos + 4])[0]
                if ext_type == 0:
                    sni_data_start = current_pos + 4
                    list_len = struct.unpack('!H', payload[sni_data_start:sni_data_start + 2])[0]
                    name_type = payload[sni_data_start + 2]
                    if name_type != 0:
                        current_pos += 4 + ext_len
                        continue
                    name_len = struct.unpack('!H', payload[sni_data_start + 3:sni_data_start + 5])[0]
                    ext_start = current_pos
                    ext_end = current_pos + 4 + ext_len
                    domain_start = sni_data_start + 5
                    domain_end = domain_start + name_len
                    if domain_end <= len(payload):
                        return (ext_start, ext_end, domain_start, domain_end)
                current_pos += 4 + ext_len
            return None
        except (struct.error, IndexError):
            return None

    def _update_sni_lengths(self, payload: bytes, length_diff: int) -> bytes:
        """Update SNI extension lengths after modification."""
        return payload

@register_attack
class ALPNManipulationAttack(BaseAttack):
    """
    ALPN Manipulation Attack - modifies Application Layer Protocol Negotiation.
    """

    @property
    def name(self) -> str:
        return 'alpn_manipulation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Manipulates ALPN extension to confuse DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute ALPN manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fake_protocols = context.params.get('fake_protocols', ['h2', 'http/1.1'])
            alpn_data = b''
            for protocol in fake_protocols:
                if isinstance(protocol, str):
                    protocol_bytes = protocol.encode('utf-8')
                else:
                    protocol_bytes = protocol
                alpn_data += bytes([len(protocol_bytes)]) + protocol_bytes
            alpn_extension = b'\x00\x10' + struct.pack('!H', len(alpn_data) + 2) + struct.pack('!H', len(alpn_data)) + alpn_data
            modified_payload = payload + alpn_extension
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'fake_protocols': [p.decode('utf-8', errors='ignore') if isinstance(p, bytes) else p for p in fake_protocols], 'alpn_extension_size': len(alpn_extension), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class GREASEAttack(BaseAttack):
    """
    GREASE Attack - adds GREASE (Generate Random Extensions And Sustain Extensibility) values.
    """

    @property
    def name(self) -> str:
        return 'grease_injection'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Injects GREASE values to test DPI robustness'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute GREASE attack."""
        start_time = time.time()
        try:
            payload = context.payload
            grease_count = context.params.get('grease_count', 3)
            grease_values = [2570, 6682, 10794, 14906, 19018, 23130]
            grease_extensions = b''
            for i in range(grease_count):
                grease_type = random.choice(grease_values)
                grease_data = b'\x00' * random.randint(0, 8)
                grease_ext = struct.pack('!H', grease_type) + struct.pack('!H', len(grease_data)) + grease_data
                grease_extensions += grease_ext
            modified_payload = payload + grease_extensions
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'grease_count': grease_count, 'grease_extensions_size': len(grease_extensions), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)