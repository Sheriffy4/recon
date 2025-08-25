"""
HTTP Method Manipulation Attacks

Attacks that manipulate HTTP methods and request lines.
"""
import asyncio
import time
import random
from typing import List
from recon.core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack

@register_attack
class HTTPMethodCaseAttack(BaseAttack):
    """
    HTTP Method Case Attack - changes case of HTTP method.
    """

    @property
    def name(self) -> str:
        return 'http_method_case'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Changes case of HTTP method to evade DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method case attack."""
        start_time = time.time()
        try:
            payload = context.payload
            case_strategy = context.params.get('case_strategy', 'lower')
            lines = payload.split(b'\r\n')
            if not lines:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Empty payload')
            request_line = lines[0]
            parts = request_line.split(b' ')
            if len(parts) < 3:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Invalid HTTP request line')
            method, path, version = (parts[0], parts[1], parts[2])
            if case_strategy == 'lower':
                method = method.lower()
            elif case_strategy == 'upper':
                method = method.upper()
            elif case_strategy == 'mixed':
                method = self._mixed_case(method)
            elif case_strategy == 'random':
                method = self._random_case(method)
            modified_request_line = method + b' ' + path + b' ' + version
            modified_lines = [modified_request_line] + lines[1:]
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'case_strategy': case_strategy, 'original_method': parts[0].decode('utf-8', errors='ignore'), 'modified_method': method.decode('utf-8', errors='ignore'), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _mixed_case(self, method: bytes) -> bytes:
        """Apply mixed case pattern."""
        result = bytearray()
        for i, byte in enumerate(method):
            if 65 <= byte <= 90:
                result.append(byte + 32 if i % 2 == 1 else byte)
            elif 97 <= byte <= 122:
                result.append(byte - 32 if i % 2 == 0 else byte)
            else:
                result.append(byte)
        return bytes(result)

    def _random_case(self, method: bytes) -> bytes:
        """Apply random case."""
        result = bytearray()
        for byte in method:
            if 65 <= byte <= 90:
                result.append(byte + 32 if random.random() > 0.5 else byte)
            elif 97 <= byte <= 122:
                result.append(byte - 32 if random.random() > 0.5 else byte)
            else:
                result.append(byte)
        return bytes(result)

@register_attack
class HTTPMethodSubstitutionAttack(BaseAttack):
    """
    HTTP Method Substitution Attack - replaces HTTP method with alternative.
    """

    @property
    def name(self) -> str:
        return 'http_method_substitution'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Replaces HTTP method with alternative methods'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method substitution attack."""
        start_time = time.time()
        try:
            payload = context.payload
            substitute_method = context.params.get('substitute_method', 'POST')
            lines = payload.split(b'\r\n')
            if not lines:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Empty payload')
            request_line = lines[0]
            parts = request_line.split(b' ')
            if len(parts) < 3:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Invalid HTTP request line')
            original_method, path, version = (parts[0], parts[1], parts[2])
            new_method = substitute_method.encode('utf-8')
            modified_request_line = new_method + b' ' + path + b' ' + version
            modified_lines = [modified_request_line] + lines[1:]
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'original_method': original_method.decode('utf-8', errors='ignore'), 'substitute_method': substitute_method, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class HTTPVersionManipulationAttack(BaseAttack):
    """
    HTTP Version Manipulation Attack - modifies HTTP version.
    """

    @property
    def name(self) -> str:
        return 'http_version_manipulation'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Modifies HTTP version to confuse DPI'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP version manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            new_version = context.params.get('new_version', 'HTTP/1.0')
            lines = payload.split(b'\r\n')
            if not lines:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Empty payload')
            request_line = lines[0]
            parts = request_line.split(b' ')
            if len(parts) < 3:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Invalid HTTP request line')
            method, path, original_version = (parts[0], parts[1], parts[2])
            new_version_bytes = new_version.encode('utf-8')
            modified_request_line = method + b' ' + path + b' ' + new_version_bytes
            modified_lines = [modified_request_line] + lines[1:]
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'original_version': original_version.decode('utf-8', errors='ignore'), 'new_version': new_version, 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class HTTPPathObfuscationAttack(BaseAttack):
    """
    HTTP Path Obfuscation Attack - obfuscates request path.
    """

    @property
    def name(self) -> str:
        return 'http_path_obfuscation'

    @property
    def category(self) -> str:
        return 'http'

    @property
    def description(self) -> str:
        return 'Obfuscates HTTP request path using URL encoding'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP path obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            obfuscation_type = context.params.get('obfuscation_type', 'url_encode')
            lines = payload.split(b'\r\n')
            if not lines:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Empty payload')
            request_line = lines[0]
            parts = request_line.split(b' ')
            if len(parts) < 3:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Invalid HTTP request line')
            method, path, version = (parts[0], parts[1], parts[2])
            if obfuscation_type == 'url_encode':
                obfuscated_path = self._url_encode_path(path)
            elif obfuscation_type == 'double_slash':
                obfuscated_path = path.replace(b'/', b'//')
            elif obfuscation_type == 'dot_slash':
                obfuscated_path = path.replace(b'/', b'/./')
            else:
                obfuscated_path = path
            modified_request_line = method + b' ' + obfuscated_path + b' ' + version
            modified_lines = [modified_request_line] + lines[1:]
            modified_payload = b'\r\n'.join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'obfuscation_type': obfuscation_type, 'original_path': path.decode('utf-8', errors='ignore'), 'obfuscated_path': obfuscated_path.decode('utf-8', errors='ignore'), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

    def _url_encode_path(self, path: bytes) -> bytes:
        """URL encode specific characters in path."""
        result = path
        result = result.replace(b' ', b'%20')
        result = result.replace(b'?', b'%3F')
        result = result.replace(b'&', b'%26')
        result = result.replace(b'=', b'%3D')
        return result