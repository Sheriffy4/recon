"""
HTTP Method Manipulation Attacks

Attacks that manipulate HTTP methods and request lines.
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
    name="http_method_case",
    category=AttackCategories.HTTP,
    aliases=["http-method-case"],
    description="Changes case of HTTP method to evade DPI",
)
class HTTPMethodCaseAttack(BaseAttack):
    """
    HTTP Method Case Attack - changes case of HTTP method.
    """

    @property
    def name(self) -> str:
        return "http_method_case"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Changes case of HTTP method to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"case_strategy": "lower"}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method case attack."""
        start_time = time.time()
        try:
            payload = context.payload
            case_strategy = context.params.get("case_strategy", "lower")
            lines = payload.split(b"\r\n")
            if not lines:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Empty payload"
                )
            request_line = lines[0]
            parts = request_line.split(b" ")
            if len(parts) < 3:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid HTTP request line",
                )
            method, path, version = (parts[0], parts[1], parts[2])
            if case_strategy == "lower":
                method = method.lower()
            elif case_strategy == "upper":
                method = method.upper()
            elif case_strategy == "mixed":
                method = self._mixed_case(method)
            elif case_strategy == "random":
                method = self._random_case(method)
            modified_request_line = method + b" " + path + b" " + version
            modified_lines = [modified_request_line] + lines[1:]
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
                    "case_strategy": case_strategy,
                    "original_method": parts[0].decode("utf-8", errors="ignore"),
                    "modified_method": method.decode("utf-8", errors="ignore"),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

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
        return "http_method_substitution"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Replaces HTTP method with alternative methods"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"substitute_method": "POST"}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method substitution attack."""
        start_time = time.time()
        try:
            payload = context.payload
            substitute_method = context.params.get("substitute_method", "POST")
            lines = payload.split(b"\r\n")
            if not lines:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Empty payload"
                )
            request_line = lines[0]
            parts = request_line.split(b" ")
            if len(parts) < 3:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid HTTP request line",
                )
            original_method, path, version = (parts[0], parts[1], parts[2])
            new_method = substitute_method.encode("utf-8")
            modified_request_line = new_method + b" " + path + b" " + version
            modified_lines = [modified_request_line] + lines[1:]
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
                    "original_method": original_method.decode("utf-8", errors="ignore"),
                    "substitute_method": substitute_method,
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
class HTTPVersionManipulationAttack(BaseAttack):
    """
    HTTP Version Manipulation Attack - modifies HTTP version.
    """

    @property
    def name(self) -> str:
        return "http_version_manipulation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Modifies HTTP version to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"new_version": "HTTP/1.0"}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP version manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            new_version = context.params.get("new_version", "HTTP/1.0")
            lines = payload.split(b"\r\n")
            if not lines:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Empty payload"
                )
            request_line = lines[0]
            parts = request_line.split(b" ")
            if len(parts) < 3:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid HTTP request line",
                )
            method, path, original_version = (parts[0], parts[1], parts[2])
            new_version_bytes = new_version.encode("utf-8")
            modified_request_line = method + b" " + path + b" " + new_version_bytes
            modified_lines = [modified_request_line] + lines[1:]
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
                    "original_version": original_version.decode("utf-8", errors="ignore"),
                    "new_version": new_version,
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
    name="http_path_obfuscation",
    category=AttackCategories.HTTP,
    aliases=["http-url-path-case", "http-url-path-dot"],
    description="Obfuscates HTTP request path using URL encoding",
)
class HTTPPathObfuscationAttack(BaseAttack):
    """
    HTTP Path Obfuscation Attack - obfuscates request path.
    """

    @property
    def name(self) -> str:
        return "http_path_obfuscation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Obfuscates HTTP request path using URL encoding"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"obfuscation_type": "url_encode"}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP path obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            obfuscation_type = context.params.get("obfuscation_type", "url_encode")
            lines = payload.split(b"\r\n")
            if not lines:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Empty payload"
                )
            request_line = lines[0]
            parts = request_line.split(b" ")
            if len(parts) < 3:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid HTTP request line",
                )
            method, path, version = (parts[0], parts[1], parts[2])
            if obfuscation_type == "url_encode":
                obfuscated_path = self._url_encode_path(path)
            elif obfuscation_type == "double_slash":
                obfuscated_path = path.replace(b"/", b"//")
            elif obfuscation_type == "dot_slash":
                obfuscated_path = path.replace(b"/", b"/./")
            else:
                obfuscated_path = path
            modified_request_line = method + b" " + obfuscated_path + b" " + version
            modified_lines = [modified_request_line] + lines[1:]
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
                    "obfuscation_type": obfuscation_type,
                    "original_path": path.decode("utf-8", errors="ignore"),
                    "obfuscated_path": obfuscated_path.decode("utf-8", errors="ignore"),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _url_encode_path(self, path: bytes) -> bytes:
        """URL encode specific characters in path."""
        result = path
        result = result.replace(b" ", b"%20")
        result = result.replace(b"?", b"%3F")
        result = result.replace(b"&", b"%26")
        result = result.replace(b"=", b"%3D")
        return result


@register_attack(
    name="http_method_obfuscation",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={"custom_method": None, "case_strategy": "random", "obfuscation_type": "case"},
    aliases=["method_obfuscation", "method_obfusc"],
    description="Obfuscates HTTP method using custom methods and case manipulation",
)
class HTTPMethodObfuscationAttack(HTTPAttackBase):
    """
    HTTP Method Obfuscation Attack - obfuscates HTTP method to evade DPI.

    Supports multiple obfuscation types:
    - case: Change case of method name
    - custom: Use custom HTTP method
    - whitespace: Add whitespace around method
    - combined: Combine multiple techniques

    Maintains parseability while evading detection.
    """

    @property
    def name(self) -> str:
        return "http_method_obfuscation"

    @property
    def description(self) -> str:
        return "Obfuscates HTTP method using custom methods and case manipulation"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"custom_method": None, "case_strategy": "random", "obfuscation_type": "case"}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method obfuscation attack."""
        start_time = time.time()

        try:
            # Validate context
            if not self.validate_context(context):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid context for HTTP method obfuscation attack",
                    technique_used=self.name,
                )

            # Parse HTTP request
            parsed = self.parse_http_request(context.payload)
            if not parsed:
                return self.handle_http_error(
                    Exception("Failed to parse HTTP request"), context, "parse"
                )

            # Get parameters
            obfuscation_type = context.params.get("obfuscation_type", "case")
            custom_method = context.params.get("custom_method", None)
            case_strategy = context.params.get("case_strategy", "random")

            original_method = parsed["method"]

            # Apply obfuscation based on type
            if obfuscation_type == "custom" and custom_method:
                # Use custom method
                modified_method = custom_method
            elif obfuscation_type == "case":
                # Apply case manipulation
                modified_method = self._obfuscate_method_case(original_method, case_strategy)
            elif obfuscation_type == "whitespace":
                # Add whitespace (may break some servers)
                modified_method = self._add_whitespace(original_method)
            elif obfuscation_type == "combined":
                # Combine techniques
                modified_method = self._obfuscate_method_case(original_method, case_strategy)
                if custom_method:
                    modified_method = custom_method
            else:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Unknown obfuscation type: {obfuscation_type}",
                    technique_used=self.name,
                )

            # Validate that method is still parseable
            if not self._is_valid_method(modified_method):
                self.logger.warning(f"Modified method may not be valid: {modified_method}")

            # Update parsed request
            parsed["method"] = modified_method

            # Rebuild request
            modified_payload = self.build_http_request(parsed)

            # Validate HTTP compliance
            is_valid, error_msg = self.validate_http_compliance(modified_payload)
            if not is_valid:
                self.logger.warning(f"Modified request may not be HTTP compliant: {error_msg}")

            # Log operation
            self.log_http_operation(
                "method_obfuscation",
                modified_method,
                parsed["path"],
                f"{obfuscation_type}: {original_method} -> {modified_method}",
            )

            # Create result
            latency = (time.time() - start_time) * 1000

            return self.create_http_result(
                modified_payload=modified_payload,
                original_payload=context.payload,
                operation=f"method_obfuscation_{obfuscation_type}",
                metadata={
                    "obfuscation_type": obfuscation_type,
                    "original_method": original_method,
                    "modified_method": modified_method,
                    "case_strategy": case_strategy if obfuscation_type == "case" else None,
                    "latency_ms": latency,
                },
            )

        except Exception as e:
            return self.handle_http_error(e, context, "method_obfuscation")

    def _obfuscate_method_case(self, method: str, strategy: str) -> str:
        """
        Obfuscate method name using case manipulation.

        Args:
            method: Original method name
            strategy: Case strategy (random, alternating, mixed, lower, upper)

        Returns:
            Obfuscated method name
        """
        if strategy == "upper":
            return method.upper()
        elif strategy == "lower":
            return method.lower()
        elif strategy == "alternating":
            return "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(method)])
        elif strategy == "random":
            return "".join([c.upper() if random.random() > 0.5 else c.lower() for c in method])
        elif strategy == "mixed":
            result = []
            for c in method:
                choice = random.random()
                if choice < 0.33:
                    result.append(c.upper())
                elif choice < 0.66:
                    result.append(c.lower())
                else:
                    result.append(c)
            return "".join(result)
        else:
            return method

    def _add_whitespace(self, method: str) -> str:
        """
        Add whitespace around method (may break some servers).

        Args:
            method: Original method name

        Returns:
            Method with whitespace
        """
        # Add trailing space (less likely to break)
        return method + " "

    def _is_valid_method(self, method: str) -> bool:
        """
        Check if method is valid (contains only allowed characters).

        Args:
            method: Method to validate

        Returns:
            True if method is valid
        """
        if not method:
            return False

        # HTTP methods should only contain letters and hyphens
        # Allow some flexibility for custom methods
        allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_ ")
        return all(c in allowed_chars for c in method)
