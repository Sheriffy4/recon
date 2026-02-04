"""
HTTP Header Manipulation Attacks

Attacks that manipulate HTTP headers to evade DPI detection.
"""

import asyncio
import time
import random
from typing import List
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.base_classes.http_attack_base import HTTPAttackBase
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories


@register_attack(
    name="http_header_case",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={"case_strategy": "random", "headers": None, "custom_pattern": None},
    aliases=["hostcase", "header_case"],
    description="Changes case of HTTP headers to evade DPI",
)
class HTTPHeaderCaseAttack(HTTPAttackBase):
    """
    HTTP Header Case Attack - changes case of HTTP headers.

    Supports multiple case strategies:
    - random: Random case for each character
    - alternating: Alternating upper/lower case
    - upper: All uppercase
    - lower: All lowercase
    - mixed: Mix of upper, lower, and original
    - custom: Custom pattern provided by user

    Can target specific headers or all headers.
    """

    @property
    def name(self) -> str:
        return "http_header_case"

    @property
    def description(self) -> str:
        return "Changes case of HTTP headers to evade DPI"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "case_strategy": "random",
            "headers": None,  # None means all headers
            "custom_pattern": None,
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header case attack."""
        start_time = time.time()

        try:
            # Validate context
            if not self.validate_context(context):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid context for HTTP header case attack",
                    technique_used=self.name,
                )

            # Parse HTTP request
            parsed = self.parse_http_request(context.payload)
            if not parsed:
                return self.handle_http_error(
                    Exception("Failed to parse HTTP request"), context, "parse"
                )

            # Get parameters
            case_strategy = context.params.get("case_strategy", "random")
            target_headers = context.params.get("headers", None)
            custom_pattern = context.params.get("custom_pattern", None)

            # Modify header names
            modified_headers = {}
            headers_modified = 0

            for header_name, header_value in parsed["headers"].items():
                # Check if we should modify this header
                should_modify = (
                    target_headers is None
                    or header_name in target_headers
                    or header_name.lower() in [h.lower() for h in (target_headers or [])]
                )

                if should_modify:
                    # Apply case manipulation
                    if custom_pattern:
                        new_name = self._apply_custom_pattern(header_name, custom_pattern)
                    else:
                        new_name = self.randomize_header_case(header_name, case_strategy)

                    modified_headers[new_name] = header_value
                    headers_modified += 1
                else:
                    modified_headers[header_name] = header_value

            # Rebuild request
            parsed["headers"] = modified_headers
            modified_payload = self.build_http_request(parsed)

            # Validate HTTP compliance
            is_valid, error_msg = self.validate_http_compliance(modified_payload)
            if not is_valid:
                self.logger.warning(f"Modified request may not be HTTP compliant: {error_msg}")

            # Log operation
            self.log_http_operation(
                "header_case",
                parsed["method"],
                parsed["path"],
                f"{case_strategy} strategy, {headers_modified} headers modified",
            )

            # Create result
            latency = (time.time() - start_time) * 1000

            return self.create_http_result(
                modified_payload=modified_payload,
                original_payload=context.payload,
                operation=f"header_case_{case_strategy}",
                metadata={
                    "case_strategy": case_strategy,
                    "headers_modified": headers_modified,
                    "target_headers": target_headers,
                    "latency_ms": latency,
                },
            )

        except Exception as e:
            return self.handle_http_error(e, context, "header_case")

    def _apply_custom_pattern(self, header_name: str, pattern: str) -> str:
        """
        Apply custom case pattern to header name.

        Pattern format: 'UlUlU' where U=upper, l=lower, *=original

        Args:
            header_name: Original header name
            pattern: Custom pattern string

        Returns:
            Header name with custom pattern applied
        """
        result = []
        pattern_len = len(pattern)

        for i, char in enumerate(header_name):
            if i < pattern_len:
                if pattern[i] == "U":
                    result.append(char.upper())
                elif pattern[i] == "l":
                    result.append(char.lower())
                else:  # '*' or any other character
                    result.append(char)
            else:
                # Repeat pattern if header is longer
                pattern_char = pattern[i % pattern_len]
                if pattern_char == "U":
                    result.append(char.upper())
                elif pattern_char == "l":
                    result.append(char.lower())
                else:
                    result.append(char)

        return "".join(result)


@register_attack
class HTTPHeaderOrderAttack(BaseAttack):
    """
    HTTP Header Order Attack - randomizes order of HTTP headers.
    """

    @property
    def name(self) -> str:
        return "http_header_order"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Randomizes order of HTTP headers"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "randomize_all": True,  # Whether to randomize all headers or just specific ones
            "preserve_first": True,  # Whether to preserve the first line (request line)
        }

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header order attack."""
        start_time = time.time()
        try:
            payload = context.payload
            if not payload.startswith(b"GET ") and (not payload.startswith(b"POST ")):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Not an HTTP request",
                )
            lines = payload.split(b"\r\n")
            request_line = lines[0]
            headers = []
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == b"":
                    body_start = i + 1
                    break
                if b":" in line:
                    headers.append(line)
            random.shuffle(headers)
            modified_lines = [request_line] + headers
            if body_start > 0:
                modified_lines.append(b"")
                modified_lines.extend(lines[body_start:])
            modified_payload = b"\r\n".join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "headers_count": len(headers),
                    "headers_shuffled": True,
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
class HTTPHeaderInjectionAttack(BaseAttack):
    """
    HTTP Header Injection Attack - injects fake headers.
    """

    @property
    def name(self) -> str:
        return "http_header_injection"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Injects fake HTTP headers to confuse DPI"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fake_headers": ["X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1"],
            "injection_position": "before",  # "before" or "after" real headers
        }

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header injection attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fake_headers = context.params.get(
                "fake_headers",
                [
                    b"X-Forwarded-For: 127.0.0.1",
                    b"X-Real-IP: 192.168.1.1",
                    b"X-Custom-Header: fake-value",
                ],
            )
            if not payload.startswith(b"GET ") and (not payload.startswith(b"POST ")):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Not an HTTP request",
                )
            lines = payload.split(b"\r\n")
            request_line = lines[0]
            insertion_point = 1
            for i, line in enumerate(lines[1:], 1):
                if line == b"":
                    insertion_point = i
                    break
            modified_lines = lines[:insertion_point]
            modified_lines.extend(fake_headers)
            modified_lines.extend(lines[insertion_point:])
            modified_payload = b"\r\n".join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fake_headers_count": len(fake_headers),
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


@register_attack(
    name="http_host_header",
    category="http",
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"manipulation_type": "case_change", "fake_host": "example.com"},
    aliases=["hostdot", "hosttab", "hostspell"],
    description="Manipulates HTTP Host header to evade DPI",
)
class HTTPHostHeaderAttack(BaseAttack):
    """
    HTTP Host Header Attack - manipulates Host header.
    """

    @property
    def name(self) -> str:
        return "http_host_header"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Manipulates HTTP Host header to evade DPI"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "manipulation_type": "case_change",  # "case_change", "duplicate", "fake"
            "fake_host": "example.com",
        }

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP Host header attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get("manipulation_type", "case_change")
            fake_host = context.params.get("fake_host", b"example.com")
            if not payload.startswith(b"GET ") and (not payload.startswith(b"POST ")):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Not an HTTP request",
                )
            lines = payload.split(b"\r\n")
            modified_lines = []
            host_found = False
            for line in lines:
                if line.lower().startswith(b"host:"):
                    host_found = True
                    if manipulation_type == "case_change":
                        modified_lines.append(b"HOST:" + line[5:])
                    elif manipulation_type == "replace":
                        modified_lines.append(b"Host: " + fake_host)
                    elif manipulation_type == "duplicate":
                        modified_lines.append(line)
                        modified_lines.append(b"Host: " + fake_host)
                    else:
                        modified_lines.append(line)
                else:
                    modified_lines.append(line)
            if not host_found and manipulation_type == "add":
                modified_lines.insert(1, b"Host: " + fake_host)
            modified_payload = b"\r\n".join(modified_lines)
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            await asyncio.sleep(0)
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
                    "host_found": host_found,
                    "fake_host": fake_host.decode("utf-8", errors="ignore"),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
