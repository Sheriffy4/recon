"""
DNS Tunneling Attacks

Attacks that use DNS protocol for tunneling data to evade DPI.
"""
import time
import base64
import random
from typing import List
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.registry import register_attack

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
class DNSSubdomainTunnelingAttack(BaseAttack):
    """
    DNS Subdomain Tunneling Attack - encodes data in DNS subdomains.
    """

    @property
    def name(self) -> str:
        return 'dns_subdomain_tunneling'

    @property
    def category(self) -> str:
        return 'tunneling'

    @property
    def description(self) -> str:
        return 'Tunnels data through DNS subdomain queries'

    @property
    def supported_protocols(self) -> List[str]:
        return ['udp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute DNS subdomain tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            base_domain = context.params.get('base_domain', 'example.com')
            encoding_type = context.params.get('encoding_type', 'base32')
            max_subdomain_length = context.params.get('max_subdomain_length', 63)
            encoded_chunks = self._encode_for_dns(payload, encoding_type, max_subdomain_length)
            dns_queries = []
            for i, chunk in enumerate(encoded_chunks):
                subdomain = f'{chunk}.{i}.{base_domain}'
                dns_query = self._create_dns_query(subdomain)
                dns_queries.append(dns_query)
            combined_payload = b''.join(dns_queries)
            segments = [(query, i * 100) for i, query in enumerate(dns_queries)]
            packets_sent = len(dns_queries)
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'base_domain': base_domain, 'encoding_type': encoding_type, 'chunks_count': len(encoded_chunks), 'original_size': len(payload), 'encoded_size': len(combined_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _encode_for_dns(self, data: bytes, encoding_type: str, max_length: int) -> List[str]:
        """Encode data for DNS tunneling."""
        if encoding_type == 'base32':
            encoded = base64.b32encode(data).decode('ascii').lower().rstrip('=')
        elif encoding_type == 'base64':
            encoded = base64.b64encode(data).decode('ascii').rstrip('=')
            encoded = encoded.replace('+', '-').replace('/', '_')
        elif encoding_type == 'hex':
            encoded = data.hex()
        else:
            encoded = data.decode('utf-8', errors='ignore')
        chunks = []
        for i in range(0, len(encoded), max_length):
            chunks.append(encoded[i:i + max_length])
        return chunks

    def _create_dns_query(self, domain: str) -> bytes:
        """Create a simple DNS A record query."""
        query_id = random.randint(0, 65535).to_bytes(2, 'big')
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        domain_parts = domain.split('.')
        encoded_domain = b''
        for part in domain_parts:
            encoded_domain += len(part).to_bytes(1, 'big') + part.encode('ascii')
        encoded_domain += b'\x00'
        query_type = b'\x00\x01'
        query_class = b'\x00\x01'
        return query_id + flags + questions + answers + authority + additional + encoded_domain + query_type + query_class

@register_attack
class DNSTXTTunnelingAttack(BaseAttack):
    """
    DNS TXT Tunneling Attack - encodes data in DNS TXT records.
    """

    @property
    def name(self) -> str:
        return 'dns_txt_tunneling'

    @property
    def category(self) -> str:
        return 'tunneling'

    @property
    def description(self) -> str:
        return 'Tunnels data through DNS TXT record queries'

    @property
    def supported_protocols(self) -> List[str]:
        return ['udp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute DNS TXT tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            base_domain = context.params.get('base_domain', 'example.com')
            encoding_type = context.params.get('encoding_type', 'base64')
            if encoding_type == 'base64':
                encoded_data = base64.b64encode(payload).decode('ascii')
            elif encoding_type == 'hex':
                encoded_data = payload.hex()
            else:
                encoded_data = payload.decode('utf-8', errors='ignore')
            query_domain = f'data.{base_domain}'
            dns_query = self._create_dns_txt_query(query_domain, encoded_data)
            segments = [(dns_query, 0)]
            packets_sent = 1
            bytes_sent = len(dns_query)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'base_domain': base_domain, 'encoding_type': encoding_type, 'encoded_data_length': len(encoded_data), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _create_dns_txt_query(self, domain: str, data: str) -> bytes:
        """Create a DNS TXT record query."""
        query_id = random.randint(0, 65535).to_bytes(2, 'big')
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        domain_parts = domain.split('.')
        encoded_domain = b''
        for part in domain_parts:
            encoded_domain += len(part).to_bytes(1, 'big') + part.encode('ascii')
        encoded_domain += b'\x00'
        query_type = b'\x00\x10'
        query_class = b'\x00\x01'
        return query_id + flags + questions + answers + authority + additional + encoded_domain + query_type + query_class

@register_attack
class DNSCachePoisoningAttack(BaseAttack):
    """
    DNS Cache Poisoning Attack - attempts to poison DNS cache.
    """

    @property
    def name(self) -> str:
        return 'dns_cache_poisoning'

    @property
    def category(self) -> str:
        return 'tunneling'

    @property
    def description(self) -> str:
        return 'Attempts DNS cache poisoning to redirect traffic'

    @property
    def supported_protocols(self) -> List[str]:
        return ['udp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute DNS cache poisoning attack."""
        start_time = time.time()
        try:
            payload = context.payload
            target_domain = context.params.get('target_domain', 'blocked-site.com')
            redirect_ip = context.params.get('redirect_ip', '127.0.0.1')
            dns_response = self._create_malicious_dns_response(target_domain, redirect_ip)
            segments = [(dns_response, 0)]
            packets_sent = 1
            bytes_sent = len(dns_response)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'target_domain': target_domain, 'redirect_ip': redirect_ip, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _create_malicious_dns_response(self, domain: str, ip: str) -> bytes:
        """Create a malicious DNS response."""
        query_id = random.randint(0, 65535).to_bytes(2, 'big')
        flags = b'\x81\x80'
        questions = b'\x00\x01'
        answers = b'\x00\x01'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        domain_parts = domain.split('.')
        encoded_domain = b''
        for part in domain_parts:
            encoded_domain += len(part).to_bytes(1, 'big') + part.encode('ascii')
        encoded_domain += b'\x00'
        query_type = b'\x00\x01'
        query_class = b'\x00\x01'
        answer_name = b'\xc0\x0c'
        answer_type = b'\x00\x01'
        answer_class = b'\x00\x01'
        answer_ttl = b'\x00\x00\x01,'
        answer_length = b'\x00\x04'
        ip_parts = ip.split('.')
        answer_data = bytes([int(part) for part in ip_parts])
        return query_id + flags + questions + answers + authority + additional + encoded_domain + query_type + query_class + answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_data

@register_attack
class DNSAmplificationAttack(BaseAttack):
    """
    DNS Amplification Attack - uses DNS amplification for traffic obfuscation.
    """

    @property
    def name(self) -> str:
        return 'dns_amplification'

    @property
    def category(self) -> str:
        return 'tunneling'

    @property
    def description(self) -> str:
        return 'Uses DNS amplification to obfuscate traffic patterns'

    @property
    def supported_protocols(self) -> List[str]:
        return ['udp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute DNS amplification attack."""
        start_time = time.time()
        try:
            payload = context.payload
            amplification_factor = context.params.get('amplification_factor', 5)
            query_types = context.params.get('query_types', ['A', 'AAAA', 'MX', 'TXT', 'NS'])
            dns_queries = []
            for i in range(amplification_factor):
                query_type = random.choice(query_types)
                domain = f'amp{i}.example.com'
                dns_query = self._create_amplification_query(domain, query_type)
                dns_queries.append(dns_query)
            dns_queries.append(payload)
            combined_payload = b''.join(dns_queries)
            segments = [(query, i * 50) for i, query in enumerate(dns_queries)]
            packets_sent = len(dns_queries)
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'amplification_factor': amplification_factor, 'query_types': query_types, 'total_queries': len(dns_queries), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _create_amplification_query(self, domain: str, query_type: str) -> bytes:
        """Create DNS query for amplification."""
        query_id = random.randint(0, 65535).to_bytes(2, 'big')
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        domain_parts = domain.split('.')
        encoded_domain = b''
        for part in domain_parts:
            encoded_domain += len(part).to_bytes(1, 'big') + part.encode('ascii')
        encoded_domain += b'\x00'
        type_map = {'A': b'\x00\x01', 'AAAA': b'\x00\x1c', 'MX': b'\x00\x0f', 'TXT': b'\x00\x10', 'NS': b'\x00\x02'}
        query_type_bytes = type_map.get(query_type, b'\x00\x01')
        query_class = b'\x00\x01'
        return query_id + flags + questions + answers + authority + additional + encoded_domain + query_type_bytes + query_class