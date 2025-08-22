"""
HTTP Header Manipulation Attacks

Attacks that manipulate HTTP headers to evade DPI detection.
"""
import time
import random
from typing import List
from recon.core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack

@register_attack
class HTTPHeaderCaseAttack(BaseAttack):
    """
    HTTP Header Case Attack - changes case of HTTP headers.
    """

    @property
    def name(self) -> str:
        return 'http_header_case'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Changes case of HTTP headers to evade DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header case attack."""
        start_time = time.time()
        try:
            payload = context.payload
            case_strategy = context.params.get('case_strategy', 'random')
            if not payload.startswith(b'GET ') and (not payload.startswith(b'POST ')):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not an HTTP request')
            lines = payload.split(b'\r\n')
            modified_lines = []
            for line in lines:
                if b':' in line and line != lines[0]:
                    header_name, header_value = line.split(b':', 1)
                    if case_strategy == 'upper':
                        header_name = header_name.upper()
                    elif case_strategy == 'lower':
                        header_name = header_name.lower()
                    elif case_strategy == 'random':
                        header_name = self._random_case(header_name)
                    elif case_strategy == 'mixed':
                        header_name = self._mixed_case(header_name)
                    modified_lines.append(header_name + b':' + header_value)
                else:
                    modified_lines.append(line)
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'case_strategy': case_strategy, 'original_size': len(payload), 'modified_size': len(modified_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _random_case(self, header_name: bytes) -> bytes:
        """Apply random case to header name."""
        result = bytearray()
        for byte in header_name:
            if 65 <= byte <= 90:
                result.append(byte + 32 if random.random() > 0.5 else byte)
            elif 97 <= byte <= 122:
                result.append(byte - 32 if random.random() > 0.5 else byte)
            else:
                result.append(byte)
        return bytes(result)

    def _mixed_case(self, header_name: bytes) -> bytes:
        """Apply mixed case pattern to header name."""
        result = bytearray()
        for i, byte in enumerate(header_name):
            if 65 <= byte <= 90:
                result.append(byte + 32 if i % 2 == 1 else byte)
            elif 97 <= byte <= 122:
                result.append(byte - 32 if i % 2 == 0 else byte)
            else:
                result.append(byte)
        return bytes(result)

@register_attack
class HTTPHeaderOrderAttack(BaseAttack):
    """
    HTTP Header Order Attack - randomizes order of HTTP headers.
    """

    @property
    def name(self) -> str:
        return 'http_header_order'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Randomizes order of HTTP headers'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header order attack."""
        start_time = time.time()
        try:
            payload = context.payload
            if not payload.startswith(b'GET ') and (not payload.startswith(b'POST ')):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not an HTTP request')
            lines = payload.split(b'\r\n')
            request_line = lines[0]
            headers = []
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == b'':
                    body_start = i + 1
                    break
                if b':' in line:
                    headers.append(line)
            random.shuffle(headers)
            modified_lines = [request_line] + headers
            if body_start > 0:
                modified_lines.append(b'')
                modified_lines.extend(lines[body_start:])
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'headers_count': len(headers), 'headers_shuffled': True, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class HTTPHeaderInjectionAttack(BaseAttack):
    """
    HTTP Header Injection Attack - injects fake headers.
    """

    @property
    def name(self) -> str:
        return 'http_header_injection'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Injects fake HTTP headers to confuse DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header injection attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fake_headers = context.params.get('fake_headers', [b'X-Forwarded-For: 127.0.0.1', b'X-Real-IP: 192.168.1.1', b'X-Custom-Header: fake-value'])
            if not payload.startswith(b'GET ') and (not payload.startswith(b'POST ')):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not an HTTP request')
            lines = payload.split(b'\r\n')
            request_line = lines[0]
            insertion_point = 1
            for i, line in enumerate(lines[1:], 1):
                if line == b'':
                    insertion_point = i
                    break
            modified_lines = lines[:insertion_point]
            modified_lines.extend(fake_headers)
            modified_lines.extend(lines[insertion_point:])
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'fake_headers_count': len(fake_headers), 'original_size': len(payload), 'modified_size': len(modified_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class HTTPHostHeaderAttack(BaseAttack):
    """
    HTTP Host Header Attack - manipulates Host header.
    """

    @property
    def name(self) -> str:
        return 'http_host_header'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Manipulates HTTP Host header to evade DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP Host header attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get('manipulation_type', 'case_change')
            fake_host = context.params.get('fake_host', b'example.com')
            if not payload.startswith(b'GET ') and (not payload.startswith(b'POST ')):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not an HTTP request')
            lines = payload.split(b'\r\n')
            modified_lines = []
            host_found = False
            for line in lines:
                if line.lower().startswith(b'host:'):
                    host_found = True
                    if manipulation_type == 'case_change':
                        modified_lines.append(b'HOST:' + line[5:])
                    elif manipulation_type == 'replace':
                        modified_lines.append(b'Host: ' + fake_host)
                    elif manipulation_type == 'duplicate':
                        modified_lines.append(line)
                        modified_lines.append(b'Host: ' + fake_host)
                    else:
                        modified_lines.append(line)
                else:
                    modified_lines.append(line)
            if not host_found and manipulation_type == 'add':
                modified_lines.insert(1, b'Host: ' + fake_host)
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'manipulation_type': manipulation_type, 'host_found': host_found, 'fake_host': fake_host.decode('utf-8', errors='ignore'), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)