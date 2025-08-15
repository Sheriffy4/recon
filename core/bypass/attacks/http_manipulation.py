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
import re
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse

from base import BaseAttack, AttackContext, AttackResult, AttackStatus, SegmentTuple
from attack_definition import AttackDefinition, AttackCategory, AttackComplexity, AttackStability, CompatibilityMode, TestCase
from registry import register_attack

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
            request_str = payload.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if not lines:
                return {}
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ', 2)
            
            if len(parts) < 3:
                return {}
            
            method, path, version = parts
            
            # Parse headers
            headers = {}
            body_start = 1
            
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # Empty line indicates end of headers
                    body_start = i + 1
                    break
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body,
                'request_line': request_line,
                'raw_headers': lines[1:body_start-1] if body_start > 1 else []
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
            method = config.method_override or parsed.get('method', 'GET')
            path = parsed.get('path', '/')
            version = parsed.get('version', 'HTTP/1.1')
            
            request_line = f"{method} {path} {version}"
            
            # Process headers
            headers = parsed.get('headers', {}).copy()
            
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
            body = parsed.get('body', '')
            
            # Apply chunked encoding if requested
            if config.chunked_encoding and body:
                headers['Transfer-Encoding'] = 'chunked'
                body = self._apply_chunked_encoding(body, config.chunk_sizes or [])
            
            # Build complete request
            line_ending = config.line_ending_modification
            request_parts = [request_line] + header_lines + ['', body]
            
            if config.split_headers:
                # Split headers across multiple segments
                return self._build_split_header_request(request_parts, line_ending)
            else:
                return line_ending.join(request_parts).encode('utf-8')
                
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
                    ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(key))
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
        body_bytes = body.encode('utf-8')
        offset = 0
        
        while offset < len(body_bytes):
            # Choose random chunk size
            chunk_size = random.choice(chunk_sizes)
            chunk_data = body_bytes[offset:offset + chunk_size]
            
            if chunk_data:
                # Format: size in hex + CRLF + data + CRLF
                chunk_hex = format(len(chunk_data), 'x')
                chunks.append(f"{chunk_hex}\r\n{chunk_data.decode('utf-8')}\r\n")
            
            offset += chunk_size
        
        # Add final chunk
        chunks.append("0\r\n\r\n")
        
        return ''.join(chunks)
    
    def _build_split_header_request(self, request_parts: List[str], line_ending: str) -> bytes:
        """Build request with headers split across segments."""
        # This will be handled by creating multiple segments
        # For now, return normal request
        return line_ending.join(request_parts).encode('utf-8')
    
    def _create_http_segments(self, context: AttackContext, config: HTTPManipulationConfig) -> List[SegmentTuple]:
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
    
    def _create_split_header_segments(self, parsed: Dict[str, Any], config: HTTPManipulationConfig) -> List[SegmentTuple]:
        """Create segments with headers split across multiple packets."""
        segments = []
        
        # First segment: request line
        request_line = f"{parsed.get('method', 'GET')} {parsed.get('path', '/')} {parsed.get('version', 'HTTP/1.1')}\r\n"
        segments.append((request_line.encode('utf-8'), 0, {}))
        
        # Subsequent segments: headers (one or two per segment)
        headers = parsed.get('headers', {})
        header_items = list(headers.items())
        
        if config.header_order_randomization:
            random.shuffle(header_items)
        
        current_offset = len(request_line.encode('utf-8'))
        
        # Group headers into segments
        for i in range(0, len(header_items), 2):  # 2 headers per segment
            header_group = header_items[i:i+2]
            header_lines = []
            
            for key, value in header_group:
                if config.header_case_modification:
                    key = self._modify_header_case({key: value})[key]
                
                if config.space_manipulation:
                    header_lines.append(f"{key}  :  {value}\r\n")
                else:
                    header_lines.append(f"{key}: {value}\r\n")
            
            header_segment = ''.join(header_lines).encode('utf-8')
            segments.append((header_segment, current_offset, {"delay_ms": 1.0}))
            current_offset += len(header_segment)
        
        # Final segment: empty line + body
        body = parsed.get('body', '')
        if config.chunked_encoding and body:
            headers['Transfer-Encoding'] = 'chunked'
            body = self._apply_chunked_encoding(body, config.chunk_sizes or [])
        
        final_segment = f"\r\n{body}".encode('utf-8')
        segments.append((final_segment, current_offset, {"delay_ms": 2.0}))
        
        return segments
    
    def _create_pipelined_segments(self, parsed: Dict[str, Any], config: HTTPManipulationConfig) -> List[SegmentTuple]:
        """Create segments for HTTP pipelining."""
        segments = []
        
        # Create multiple requests in pipeline
        for i in range(config.pipeline_requests):
            # Modify each request slightly
            pipeline_config = HTTPManipulationConfig(
                header_modifications=config.header_modifications.copy() if config.header_modifications else {},
                method_override=config.method_override,
                chunked_encoding=config.chunked_encoding and i == 0,  # Only first request chunked
                header_case_modification=config.header_case_modification,
                header_order_randomization=config.header_order_randomization,
                fake_headers=config.fake_headers,
                space_manipulation=config.space_manipulation
            )
            
            # Add request-specific headers
            if not pipeline_config.header_modifications:
                pipeline_config.header_modifications = {}
            pipeline_config.header_modifications[f'X-Pipeline-Request'] = str(i + 1)
            
            # Build request
            request_data = self._build_http_request(parsed, pipeline_config)
            
            if request_data:
                # Add delay between pipelined requests
                options = {"delay_ms": i * 10.0} if i > 0 else {}
                segments.append((request_data, 0, options))
        
        return segments


@register_attack("header_modification")
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
                "Upgrade-Insecure-Requests": "1"
            }
            
            # Merge with custom headers
            header_modifications = {**default_headers, **custom_headers}
            
            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications=header_modifications,
                header_case_modification=case_modification,
                header_order_randomization=order_randomization,
                space_manipulation=space_manipulation
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created - payload may be invalid HTTP",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="header_modification"
                )
            
            # Create successful result with segments
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="header_modification",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="header_modification"
            )


@register_attack("method_manipulation")
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
            original_method = parsed.get('method', 'GET')
            
            # Prepare header modifications
            header_modifications = fake_headers.copy() if fake_headers else {}
            
            # Add method override header if requested
            if add_override_header:
                header_modifications['X-HTTP-Method-Override'] = original_method
                header_modifications['X-Original-Method'] = original_method
            
            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications=header_modifications,
                method_override=target_method,
                header_case_modification=True
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for method manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="method_manipulation"
                )
            
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="method_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="method_manipulation"
            )


@register_attack("chunked_encoding")
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
                chunk_sizes=chunk_sizes
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for chunked encoding",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="chunked_encoding"
                )
            
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="chunked_encoding",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="chunked_encoding"
            )


@register_attack("pipeline_manipulation")
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
                header_order_randomization=randomize_headers
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for pipeline manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="pipeline_manipulation"
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
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="pipeline_manipulation"
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
                    "X-Split-Headers": "true"
                },
                split_headers=True,
                header_order_randomization=randomize_order
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for header splitting",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="header_splitting"
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
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="header_splitting"
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
            original_method = parsed.get('method', 'GET')
            
            # Determine target method case
            if method_case == "upper":
                target_method = original_method.upper()
            elif method_case == "lower":
                target_method = original_method.lower()
            else:  # mixed
                target_method = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                                      for i, c in enumerate(original_method))
            
            # Create configuration
            config = HTTPManipulationConfig(
                header_modifications={},
                method_override=target_method,
                header_case_modification=True,
                header_order_randomization=randomize_each_header
            )
            
            # Create segments
            segments = self._create_http_segments(context, config)
            
            if not segments:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No segments created for case manipulation",
                    processing_time_ms=(time.time() - start_time) * 1000,
                    technique_used="case_manipulation"
                )
            
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used="case_manipulation",
                packets_sent=len(segments),
                bytes_sent=sum(len(seg[0]) for seg in segments)
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
                technique_used="case_manipulation"
            )


# Register attack definitions with the modern registry
def register_http_manipulation_attacks():
    """Register all HTTP manipulation attacks with their definitions."""
    try:
        from modern_registry import get_modern_registry
        registry = get_modern_registry()
    except ImportError as e:
        print(f"Failed to auto-register HTTP manipulation attacks: {e}")
        return 0
    
    # Header Modification Attack
    header_modification_def = AttackDefinition(
        id="header_modification",
        name="HTTP Header Modification",
        description="Modify HTTP headers to evade DPI detection",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET, CompatibilityMode.GOODBYEDPI],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "custom_headers": {"type": "dict", "default": {}, "description": "Custom headers to add/modify"},
            "case_modification": {"type": "bool", "default": True, "description": "Modify header name case"},
            "order_randomization": {"type": "bool", "default": False, "description": "Randomize header order"},
            "space_manipulation": {"type": "bool", "default": False, "description": "Add extra spaces around colons"}
        },
        default_parameters={"custom_headers": {}, "case_modification": True, "order_randomization": False},
        external_tool_mappings={
            "zapret": "--dpi-desync=fake --dpi-desync-fake-http=0x11,0x22",
            "goodbyedpi": "--fake-from-hex 474554202F20485454502F312E310D0A486F73743A20"
        },
        tags={"http", "headers", "modification", "stable"},
        test_cases=[
            TestCase(
                id="header_modification_basic",
                name="Basic header modification test",
                description="Test header modification with default parameters",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"case_modification": True}
            ),
            TestCase(
                id="header_modification_custom",
                name="Custom headers test",
                description="Test with custom headers",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={
                    "custom_headers": {"X-Test": "bypass", "X-Custom": "header"},
                    "case_modification": True,
                    "order_randomization": True
                }
            )
        ]
    )
    
    # Method Manipulation Attack
    method_manipulation_def = AttackDefinition(
        id="method_manipulation",
        name="HTTP Method Manipulation",
        description="Change HTTP method to evade method-based DPI filtering",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "target_method": {"type": "str", "default": "POST", "description": "Target HTTP method"},
            "add_override_header": {"type": "bool", "default": True, "description": "Add method override header"},
            "fake_headers": {"type": "dict", "default": {}, "description": "Additional fake headers"}
        },
        default_parameters={"target_method": "POST", "add_override_header": True},
        external_tool_mappings={
            "zapret": "--dpi-desync=fake --dpi-desync-fake-http=method"
        },
        tags={"http", "method", "manipulation", "stable"},
        test_cases=[
            TestCase(
                id="method_manipulation_basic",
                name="Basic method manipulation test",
                description="Test method change from GET to POST",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"target_method": "POST"}
            )
        ]
    )
    
    # Chunked Encoding Attack
    chunked_encoding_def = AttackDefinition(
        id="chunked_encoding",
        name="HTTP Chunked Encoding",
        description="Use chunked transfer encoding to fragment HTTP body",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "chunk_sizes": {"type": "list", "default": [4, 8, 16, 32], "description": "List of chunk sizes"},
            "randomize_sizes": {"type": "bool", "default": True, "description": "Randomize chunk sizes"},
            "add_fake_chunks": {"type": "bool", "default": False, "description": "Add fake chunks"}
        },
        default_parameters={"chunk_sizes": [4, 8, 16, 32], "randomize_sizes": True},
        external_tool_mappings={
            "zapret": "--dpi-desync=split --dpi-desync-split-http-req=method,host"
        },
        tags={"http", "chunked", "encoding", "fragmentation"},
        test_cases=[
            TestCase(
                id="chunked_encoding_basic",
                name="Basic chunked encoding test",
                description="Test chunked encoding with default parameters",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"chunk_sizes": [8, 16]}
            )
        ]
    )
    
    # Pipeline Manipulation Attack
    pipeline_manipulation_def = AttackDefinition(
        id="pipeline_manipulation",
        name="HTTP Pipeline Manipulation",
        description="Send multiple HTTP requests in a pipeline to confuse DPI",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.MODERATE,
        stability=AttackStability.MOSTLY_STABLE,
        compatibility=[CompatibilityMode.NATIVE],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "pipeline_count": {"type": "int", "default": 3, "min": 2, "max": 10, "description": "Number of pipelined requests"},
            "delay_between_requests": {"type": "float", "default": 5.0, "min": 0.1, "max": 50.0, "description": "Delay between requests (ms)"},
            "randomize_headers": {"type": "bool", "default": True, "description": "Randomize headers in each request"}
        },
        default_parameters={"pipeline_count": 3, "delay_between_requests": 5.0},
        tags={"http", "pipeline", "multiple", "advanced"},
        test_cases=[
            TestCase(
                id="pipeline_manipulation_basic",
                name="Basic pipeline manipulation test",
                description="Test HTTP pipelining with 3 requests",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"pipeline_count": 3}
            )
        ]
    )
    
    # Header Splitting Attack
    header_splitting_def = AttackDefinition(
        id="header_splitting",
        name="HTTP Header Splitting",
        description="Split HTTP headers across multiple TCP segments",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.ADVANCED,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "headers_per_segment": {"type": "int", "default": 2, "min": 1, "max": 5, "description": "Headers per segment"},
            "delay_between_segments": {"type": "float", "default": 1.0, "min": 0.1, "max": 10.0, "description": "Delay between segments (ms)"},
            "randomize_order": {"type": "bool", "default": True, "description": "Randomize header order"}
        },
        default_parameters={"headers_per_segment": 2, "delay_between_segments": 1.0},
        tags={"http", "headers", "splitting", "segmentation"},
        test_cases=[
            TestCase(
                id="header_splitting_basic",
                name="Basic header splitting test",
                description="Test header splitting across segments",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"headers_per_segment": 2}
            )
        ]
    )
    
    # Case Manipulation Attack
    case_manipulation_def = AttackDefinition(
        id="case_manipulation",
        name="HTTP Case Manipulation",
        description="Modify case of HTTP headers and method to evade case-sensitive DPI",
        category=AttackCategory.HTTP_MANIPULATION,
        complexity=AttackComplexity.SIMPLE,
        stability=AttackStability.STABLE,
        compatibility=[CompatibilityMode.NATIVE, CompatibilityMode.ZAPRET],
        supported_protocols=["tcp"],
        supported_ports=[80, 443],
        parameters={
            "method_case": {"type": "str", "default": "mixed", "choices": ["upper", "lower", "mixed"], "description": "Method case modification"},
            "header_case": {"type": "str", "default": "mixed", "choices": ["upper", "lower", "mixed"], "description": "Header case modification"},
            "randomize_each_header": {"type": "bool", "default": True, "description": "Randomize case for each header"}
        },
        default_parameters={"method_case": "mixed", "header_case": "mixed"},
        tags={"http", "case", "manipulation", "evasion"},
        test_cases=[
            TestCase(
                id="case_manipulation_basic",
                name="Basic case manipulation test",
                description="Test case manipulation with mixed case",
                target_domain="httpbin.org",
                expected_success=True,
                test_parameters={"method_case": "mixed", "header_case": "mixed"}
            )
        ]
    )
    
    # Register all definitions
    definitions = [
        header_modification_def,
        method_manipulation_def,
        chunked_encoding_def,
        pipeline_manipulation_def,
        header_splitting_def,
        case_manipulation_def
    ]
    
    registered_count = 0
    for definition in definitions:
        try:
            # Get attack class from registry
            attack_class = None
            if definition.id == "header_modification":
                attack_class = HeaderModificationAttack
            elif definition.id == "method_manipulation":
                attack_class = MethodManipulationAttack
            elif definition.id == "chunked_encoding":
                attack_class = ChunkedEncodingAttack
            elif definition.id == "pipeline_manipulation":
                attack_class = PipelineManipulationAttack
            elif definition.id == "header_splitting":
                attack_class = HeaderSplittingAttack
            elif definition.id == "case_manipulation":
                attack_class = CaseManipulationAttack
            
            if attack_class and registry.register_attack(definition, attack_class):
                registered_count += 1
                print(f"Registered HTTP attack: {definition.id}")
            else:
                print(f"Failed to register HTTP attack: {definition.id}")
                
        except Exception as e:
            print(f"Error registering HTTP attack {definition.id}: {e}")
    
    print(f"Successfully registered {registered_count} HTTP manipulation attacks")
    return registered_count


# Auto-register attacks when module is imported
if __name__ != "__main__":
    try:
        register_http_manipulation_attacks()
    except Exception as e:
        LOG.error(f"Failed to auto-register HTTP manipulation attacks: {e}")