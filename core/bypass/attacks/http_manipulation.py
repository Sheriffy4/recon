#!/usr/bin/env python3
"""
HTTP Manipulation Attacks Implementation

This module implements comprehensive HTTP manipulation attacks for DPI bypass.
Based on the requirements from task 6 of the bypass engine modernization spec.

Implements:
- HTTP header modification techniques
- HTTP method manipulation attacks
- HTTP chunked encoding attacks
- HTTP pipeline manipulation techniques

All attacks follow the modern attack architecture with segments orchestration.
"""

import time
import random
import logging
import itertools
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
    SegmentTuple,
)
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories

LOG = logging.getLogger("HTTPManipulationAttacks")


@dataclass
class HTTPManipulationConfig:
    """Configuration for HTTP manipulation attacks."""

    header_modifications: Dict[str, str]
    method_override: Optional[str] = None
    chunked_encoding: bool = False
    chunk_sizes: List[int] = None
    pipeline_requests: int = 1
    header_case_modification: bool = False
    header_order_randomization: bool = False
    fake_headers: Dict[str, str] = None
    split_headers: bool = False
    header_duplication: bool = False
    space_manipulation: bool = False
    line_ending_modification: str = "\r\n"


class BaseHTTPManipulationAttack(BaseAttack):
    """Base class for all HTTP manipulation attacks."""

    @property
    def name(self) -> str:
        return "http_manipulation_base"

    @property
    def category(self) -> str:
        return AttackCategories.HTTP

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}

    def execute(self, context: AttackContext) -> AttackResult:
        """Base implementation - should be overridden by concrete classes."""
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=f"Base class {self.__class__.__name__} execute method not implemented",
        )

    def __init__(self):
        super().__init__()
        self.logger = LOG

    def _parse_http_request(self, payload: bytes) -> Dict[str, Any]:
        """
        Parse HTTP request from payload.

        Args:
            payload: Raw HTTP request bytes

        Returns:
            Dictionary with parsed HTTP components
        """
        try:
            request_str = payload.decode("utf-8", errors="ignore")
            lines = request_str.split("\r\n")

            if not lines:
                return {}

            # Parse request line
            request_line = lines[0]
            parts = request_line.split(" ", 2)

            if len(parts) < 3:
                return {}

            method, path, version = parts

            if not version.startswith("HTTP/"):
                return {}

            # Parse headers
            headers = {}
            body_start = 1

            for i, line in enumerate(lines[1:], 1):
                if line == "":  # Empty line indicates end of headers
                    body_start = i + 1
                    break

                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            # Extract body
            body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""

            return {
                "method": method,
                "path": path,
                "version": version,
                "headers": headers,
                "body": body,
                "request_line": request_line,
                "raw_headers": lines[1 : body_start - 1] if body_start > 1 else [],
            }

        except Exception as e:
            LOG.error(f"Failed to parse HTTP request: {e}")
            return {}

    def _build_http_request(self, parsed: Dict[str, Any], config: HTTPManipulationConfig) -> bytes:
        """
        Build HTTP request from parsed components with modifications.

        Args:
            parsed: Parsed HTTP components
            config: Manipulation configuration

        Returns:
            Modified HTTP request bytes
        """
        try:
            # Build request line with method override
            method = config.method_override or parsed.get("method", "GET")
            path = parsed.get("path", "/")
            version = parsed.get("version", "HTTP/1.1")

            request_line = f"{method} {path} {version}"

            # Process headers
            headers = parsed.get("headers", {}).copy()

            # Apply header modifications
            if config.header_modifications:
                headers.update(config.header_modifications)

            # Add fake headers
            if config.fake_headers:
                headers.update(config.fake_headers)

            # Modify header case
            if config.header_case_modification:
                headers = self._modify_header_case(headers)

            # Randomize header order
            header_items = list(headers.items())
            if config.header_order_randomization:
                random.shuffle(header_items)

            # Build header lines
            header_lines = []
            for key, value in header_items:
                if config.space_manipulation:
                    # Add extra spaces around colon
                    header_line = f"{key}  :  {value}"
                else:
                    header_line = f"{key}: {value}"

                header_lines.append(header_line)

                # Duplicate headers if requested
                if config.header_duplication and random.random() < 0.3:
                    header_lines.append(header_line)

            # Get body
            body = parsed.get("body", "")

            # Apply chunked encoding if requested
            if config.chunked_encoding and body:
                headers["Transfer-Encoding"] = "chunked"
                body = self._apply_chunked_encoding(body, config.chunk_sizes or [])

            # Build complete request
            line_ending = config.line_ending_modification
            request_parts = [request_line] + header_lines + ["", body]

            if config.split_headers:
                # Split headers across multiple segments
                return self._build_split_header_request(request_parts, line_ending)
            else:
                return line_ending.join(request_parts).encode("utf-8")

        except Exception as e:
            LOG.error(f"Failed to build HTTP request: {e}")
            return b""

    def _modify_header_case(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Modify header name case for evasion."""
        modified = {}

        for key, value in headers.items():
            # Randomly modify case
            if random.random() < 0.5:
                # Convert to different case patterns
                patterns = [
                    key.upper(),
                    key.lower(),
                    key.title(),
                    "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(key)),
                ]
                modified_key = random.choice(patterns)
            else:
                modified_key = key

            modified[modified_key] = value

        return modified

    def _apply_chunked_encoding(self, body: str, chunk_sizes: List[int]) -> str:
        """Apply HTTP chunked encoding to body."""
        if not chunk_sizes:
            chunk_sizes = [8, 16, 32, 64]  # Default chunk sizes

        chunks = []
        body_bytes = body.encode("utf-8")
        offset = 0

        # Use itertools.cycle to iterate through chunk sizes deterministically
        size_cycler = itertools.cycle(chunk_sizes)

        while offset < len(body_bytes):
            chunk_size = next(size_cycler)
            chunk_data = body_bytes[offset : offset + chunk_size]

            if chunk_data:
                # Format: size in hex + CRLF + data + CRLF
                chunk_hex = format(len(chunk_data), "x")
                chunks.append(f"{chunk_hex}\r\n{chunk_data.decode('utf-8')}\r\n")

            offset += chunk_size

        # Add final chunk
        chunks.append("0\r\n\r\n")

        return "".join(chunks)

    def _build_split_header_request(self, request_parts: List[str], line_ending: str) -> bytes:
        """Build request with headers split across segments."""
        # This will be handled by creating multiple segments
        # For now, return normal request
        return line_ending.join(request_parts).encode("utf-8")

    def _create_http_segments(
        self, context: AttackContext, config: HTTPManipulationConfig
    ) -> List[SegmentTuple]:
        """
        Create HTTP segments based on manipulation configuration.

        Args:
            context: Attack execution context
            config: HTTP manipulation configuration

        Returns:
            List of segment tuples for orchestrated execution
        """
        payload = context.payload
        if not payload:
            return []

        # Parse HTTP request
        parsed = self._parse_http_request(payload)
        if not parsed:
            # If parsing fails, return original payload as single segment
            return [(payload, 0, {})]

        segments = []

        if config.split_headers:
            # Split request into multiple segments
            segments = self._create_split_header_segments(parsed, config)
        elif config.pipeline_requests > 1:
            # Create pipelined requests
            segments = self._create_pipelined_segments(parsed, config)
        else:
            # Single modified request
            modified_request = self._build_http_request(parsed, config)
            if modified_request:
                segments = [(modified_request, 0, {})]

        return segments

    def _create_split_header_segments(
        self, parsed: Dict[str, Any], config: HTTPManipulationConfig
    ) -> List[SegmentTuple]:
        """Create segments with headers split across multiple packets."""
        segments = []

        # First segment: request line
        request_line = f"{parsed.get('method', 'GET')} {parsed.get('path', '/')} {parsed.get('version', 'HTTP/1.1')}\r\n"
        segments.append((request_line.encode("utf-8"), 0, {}))

        # Subsequent segments: headers (one or two per segment)
        headers = parsed.get("headers", {})
        header_items = list(headers.items())

        if config.header_order_randomization:
            random.shuffle(header_items)

        current_offset = len(request_line.encode("utf-8"))

        # Group headers into segments
        for i in range(0, len(header_items), 2):  # 2 headers per segment
            header_group = header_items[i : i + 2]
            header_lines = []

            for key, value in header_group:
                if config.header_case_modification:
                    key = self._modify_header_case({key: value})[key]

                if config.space_manipulation:
                    header_lines.append(f"{key}  :  {value}\r\n")
                else:
                    header_lines.append(f"{key}: {value}\r\n")

            header_segment = "".join(header_lines).encode("utf-8")
            segments.append((header_segment, current_offset, {"delay_ms": 1.0}))
            current_offset += len(header_segment)

        # Final segment: empty line + body
        body = parsed.get("body", "")
        if config.chunked_encoding and body:
            headers["Transfer-Encoding"] = "chunked"
            body = self._apply_chunked_encoding(body, config.chunk_sizes or [])

        final_segment = f"\r\n{body}".encode("utf-8")
        segments.append((final_segment, current_offset, {"delay_ms": 2.0}))

        return segments

    def _create_pipelined_segments(
        self, parsed: Dict[str, Any], config: HTTPManipulationConfig
    ) -> List[SegmentTuple]:
        """Create segments for HTTP pipelining."""
        segments = []

        # Create multiple requests in pipeline
        for i in range(config.pipeline_requests):
            # Modify each request slightly
            pipeline_config = HTTPManipulationConfig(
                header_modifications=(
                    config.header_modifications.copy() if config.header_modifications else {}
                ),
                method_override=config.method_override,
                chunked_encoding=config.chunked_encoding and i == 0,  # Only first request chunked
                header_case_modification=config.header_case_modification,
                header_order_randomization=config.header_order_randomization,
                fake_headers=config.fake_headers,
                space_manipulation=config.space_manipulation,
            )

            # Add request-specific headers
            if not pipeline_config.header_modifications:
                pipeline_config.header_modifications = {}
            pipeline_config.header_modifications["X-Pipeline-Request"] = str(i + 1)

            # Build request
            request_data = self._build_http_request(parsed, pipeline_config)

            if request_data:
                # Add delay between pipelined requests
                options = {"delay_ms": i * 10.0} if i > 0 else {}
                segments.append((request_data, 0, options))

        return segments


@register_attack(
    name="header_modification",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "custom_headers": {},
        "case_modification": True,
        "order_randomization": False,
        "space_manipulation": False,
    },
    aliases=["http_header_mod", "header_manip"],
    description="HTTP header modification for DPI evasion",
)
class HeaderModificationAttack(BaseHTTPManipulationAttack):
    """
    HTTP header modification attack.
    Modifies HTTP headers to evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "header_modification"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header modification attack."""
        start_time = time.time()

        try:
            # Get parameters
            custom_headers = context.params.get("custom_headers", {})
            case_modification = context.params.get("case_modification", True)
            order_randomization = context.params.get("order_randomization", False)
            space_manipulation = context.params.get("space_manipulation", False)

            # Default header modifications for evasion
            default_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }

            # Merge with custom headers
            header_modifications = {**default_headers, **custom_headers}

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications=header_modifications,
                header_case_modification=case_modification,
                header_order_randomization=order_randomization,
                space_manipulation=space_manipulation,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created - payload may be invalid HTTP",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="header_modification",
                )

            # Create successful result with segments
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="header_modification",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "header_modification")
            result.set_metadata("headers_modified", len(header_modifications))
            result.set_metadata("case_modification", case_modification)
            result.set_metadata("order_randomization", order_randomization)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Header modification failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="header_modification",
            )


@register_attack(
    name="method_manipulation",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"method": "POST", "original_method": "GET"},
    aliases=["http_method", "method_override"],
    description="HTTP method manipulation for DPI evasion",
)
class MethodManipulationAttack(BaseHTTPManipulationAttack):
    """
    HTTP method manipulation attack.
    Changes HTTP method to evade method-based DPI filtering.
    """

    @property
    def name(self) -> str:
        return "method_manipulation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP method manipulation attack."""
        start_time = time.time()

        try:
            # Get parameters
            target_method = context.params.get("target_method", "POST")
            add_override_header = context.params.get("add_override_header", True)
            fake_headers = context.params.get("fake_headers", {})

            # Parse original request to get method
            parsed = self._parse_http_request(context.payload)
            original_method = parsed.get("method", "GET")

            # Prepare header modifications
            header_modifications = fake_headers.copy() if fake_headers else {}

            # Add method override header if requested
            if add_override_header:
                header_modifications["X-HTTP-Method-Override"] = original_method
                header_modifications["X-Original-Method"] = original_method

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications=header_modifications,
                method_override=target_method,
                header_case_modification=True,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for method manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="method_manipulation",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="method_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "method_manipulation")
            result.set_metadata("original_method", original_method)
            result.set_metadata("target_method", target_method)
            result.set_metadata("override_header_added", add_override_header)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Method manipulation failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="method_manipulation",
            )


@register_attack(
    name="chunked_encoding",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"chunk_size": 8, "random_chunks": True},
    aliases=["http_chunked", "chunked_transfer"],
    description="HTTP chunked transfer encoding for DPI evasion",
)
class ChunkedEncodingAttack(BaseHTTPManipulationAttack):
    """
    HTTP chunked encoding attack.
    Uses chunked transfer encoding to fragment HTTP body.
    """

    @property
    def name(self) -> str:
        return "chunked_encoding"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP chunked encoding attack."""
        start_time = time.time()

        try:
            # Get parameters
            chunk_sizes = context.params.get("chunk_sizes", [4, 8, 16, 32])
            randomize_sizes = context.params.get("randomize_sizes", True)
            add_fake_chunks = context.params.get("add_fake_chunks", False)

            # Validate chunk sizes
            if not chunk_sizes or not isinstance(chunk_sizes, list):
                chunk_sizes = [4, 8, 16, 32]

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications={"Transfer-Encoding": "chunked"},
                chunked_encoding=True,
                chunk_sizes=chunk_sizes,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for chunked encoding",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="chunked_encoding",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="chunked_encoding",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "chunked_encoding")
            result.set_metadata("chunk_sizes", chunk_sizes)
            result.set_metadata("randomize_sizes", randomize_sizes)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Chunked encoding failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="chunked_encoding",
            )


@register_attack(
    name="pipeline_manipulation",
    aliases=["http-pipeline"],
    description="HTTP pipeline manipulation for DPI evasion",
)
class PipelineManipulationAttack(BaseHTTPManipulationAttack):
    """
    HTTP pipeline manipulation attack.
    Sends multiple HTTP requests in a pipeline to confuse DPI.
    """

    @property
    def name(self) -> str:
        return "pipeline_manipulation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP pipeline manipulation attack."""
        start_time = time.time()

        try:
            # Get parameters
            pipeline_count = context.params.get("pipeline_count", 3)
            delay_between_requests = context.params.get("delay_between_requests", 5.0)
            randomize_headers = context.params.get("randomize_headers", True)

            # Validate pipeline count
            if pipeline_count < 2:
                pipeline_count = 2
            elif pipeline_count > 10:
                pipeline_count = 10

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications={},
                pipeline_requests=pipeline_count,
                header_case_modification=randomize_headers,
                header_order_randomization=randomize_headers,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for pipeline manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="pipeline_manipulation",
                )

            # Add delays between pipelined requests
            for i, (payload, seq_offset, options) in enumerate(segments):
                if i > 0:
                    options["delay_ms"] = delay_between_requests * i

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="pipeline_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "pipeline_manipulation")
            result.set_metadata("pipeline_count", pipeline_count)
            result.set_metadata("delay_between_requests", delay_between_requests)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Pipeline manipulation failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="pipeline_manipulation",
            )


@register_attack("header_splitting")
class HeaderSplittingAttack(BaseHTTPManipulationAttack):
    """
    HTTP header splitting attack.
    Splits HTTP headers across multiple TCP segments.
    """

    @property
    def name(self) -> str:
        return "header_splitting"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP header splitting attack."""
        start_time = time.time()

        try:
            # Get parameters
            headers_per_segment = context.params.get("headers_per_segment", 2)
            delay_between_segments = context.params.get("delay_between_segments", 1.0)
            randomize_order = context.params.get("randomize_order", True)

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications={
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Split-Headers": "true",
                },
                split_headers=True,
                header_order_randomization=randomize_order,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for header splitting",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="header_splitting",
                )

            # Add delays between segments
            for i, (payload, seq_offset, options) in enumerate(segments):
                if i > 0:
                    options["delay_ms"] = delay_between_segments

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="header_splitting",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "header_splitting")
            result.set_metadata("headers_per_segment", headers_per_segment)
            result.set_metadata("total_segments", len(segments))

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Header splitting failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="header_splitting",
            )


@register_attack("case_manipulation")
class CaseManipulationAttack(BaseHTTPManipulationAttack):
    """
    HTTP case manipulation attack.
    Modifies case of HTTP headers and method to evade case-sensitive DPI.
    """

    @property
    def name(self) -> str:
        return "case_manipulation"

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP case manipulation attack."""
        start_time = time.time()

        try:
            # Get parameters
            method_case = context.params.get("method_case", "mixed")  # upper, lower, mixed
            header_case = context.params.get("header_case", "mixed")
            randomize_each_header = context.params.get("randomize_each_header", True)

            # Parse original request
            parsed = self._parse_http_request(context.payload)
            original_method = parsed.get("method", "GET")

            # Determine target method case
            if method_case == "upper":
                target_method = original_method.upper()
            elif method_case == "lower":
                target_method = original_method.lower()
            else:  # mixed
                target_method = "".join(
                    c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(original_method)
                )

            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications={},
                method_override=target_method,
                header_case_modification=True,
                header_order_randomization=randomize_each_header,
            )

            # Create segments
            segments = self._create_http_segments(context, config)

            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for case manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="case_manipulation",
                )

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="case_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments),
            )

            result.segments = segments
            result.set_metadata("manipulation_type", "case_manipulation")
            result.set_metadata("original_method", original_method)
            result.set_metadata("target_method", target_method)
            result.set_metadata("method_case", method_case)
            result.set_metadata("header_case", header_case)

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Case manipulation failed: {str(e)}",
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="case_manipulation",
            )


# HTTP manipulation attacks are auto-registered via decorators
# All orphaned code removed

# HTTP manipulation attacks are auto-registered via decorators
