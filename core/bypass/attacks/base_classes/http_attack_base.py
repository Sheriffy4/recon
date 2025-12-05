"""
Base class for HTTP-layer attacks.

Provides common functionality for attacks that manipulate HTTP protocol:
- HTTP header parsing and manipulation
- HTTP/2 detection and adaptation
- Request validation for protocol compliance
- HTTP-specific logging
"""

import logging
import re
from abc import abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..metadata import AttackCategories, ValidationResult


class HTTPAttackBase(BaseAttack):
    """
    Base class for HTTP-layer attacks.
    
    Provides:
    - Abstract methods for HTTP attack execution
    - HTTP header parsing and manipulation helpers
    - HTTP/2 detection and adaptation logic
    - Request validation to ensure protocol compliance
    - Logging for HTTP-specific operations
    """

    @property
    def category(self) -> str:
        """All HTTP attacks belong to HTTP category."""
        return AttackCategories.HTTP

    @property
    def supported_protocols(self) -> List[str]:
        """HTTP attacks work with TCP."""
        return ["tcp"]

    @abstractmethod
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the HTTP attack.
        
        Args:
            context: Attack execution context with HTTP request
            
        Returns:
            AttackResult with modified HTTP request
        """
        pass

    def validate_params(self, params: Dict[str, Any]) -> ValidationResult:
        """
        Validate attack parameters.
        
        Args:
            params: Parameters to validate
            
        Returns:
            ValidationResult indicating if parameters are valid
        """
        errors = []
        warnings = []
        
        # Validate header manipulation parameters
        if "header_name" in params:
            header_name = params["header_name"]
            if not isinstance(header_name, str):
                errors.append("header_name must be a string")
            elif not header_name.strip():
                errors.append("header_name cannot be empty")
        
        # Validate case manipulation
        if "case_strategy" in params:
            strategy = params["case_strategy"]
            valid_strategies = ["random", "alternating", "upper", "lower", "mixed"]
            if strategy not in valid_strategies:
                errors.append(f"case_strategy must be one of: {valid_strategies}")
        
        # Validate HTTP version
        if "http_version" in params:
            version = params["http_version"]
            valid_versions = ["1.0", "1.1", "2.0"]
            if version not in valid_versions:
                warnings.append(f"http_version '{version}' may not be standard")
        
        if errors:
            return ValidationResult(
                is_valid=False,
                error_message="; ".join(errors),
                warnings=warnings
            )
        
        return ValidationResult(
            is_valid=True,
            warnings=warnings
        )

    def validate_context(self, context: AttackContext) -> bool:
        """
        Validate attack context before execution.
        
        Args:
            context: Attack execution context
            
        Returns:
            True if context is valid, False otherwise
        """
        if not super().validate_context(context):
            return False
        
        # HTTP attacks require payload (HTTP request)
        if not context.payload or len(context.payload) == 0:
            self.logger.warning("HTTP attack requires non-empty payload")
            return False
        
        # Check if payload looks like HTTP
        if not self.is_http_request(context.payload):
            self.logger.warning("Payload does not appear to be an HTTP request")
            return False
        
        return True

    def is_http_request(self, payload: bytes) -> bool:
        """
        Check if payload is an HTTP request.
        
        Args:
            payload: Payload to check
            
        Returns:
            True if payload appears to be HTTP request
        """
        try:
            # Check for HTTP method at start
            payload_str = payload.decode('utf-8', errors='ignore')
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT']
            
            for method in http_methods:
                if payload_str.startswith(method + ' '):
                    return True
            
            return False
        except Exception:
            return False

    def parse_http_request(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse HTTP request from payload.
        
        Args:
            payload: HTTP request payload
            
        Returns:
            Dictionary with parsed request components or None if parsing fails
        """
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
            lines = payload_str.split('\r\n')
            
            if not lines:
                return None
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            method, path, version = parts[0], parts[1], parts[2]
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Get body
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            
            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body,
                'raw_lines': lines
            }
        except Exception as e:
            self.logger.error(f"Failed to parse HTTP request: {e}")
            return None

    def build_http_request(self, parsed: Dict[str, Any]) -> bytes:
        """
        Build HTTP request from parsed components.
        
        Args:
            parsed: Parsed HTTP request dictionary
            
        Returns:
            HTTP request as bytes
        """
        lines = []
        
        # Request line
        request_line = f"{parsed['method']} {parsed['path']} {parsed['version']}"
        lines.append(request_line)
        
        # Headers
        for key, value in parsed['headers'].items():
            lines.append(f"{key}: {value}")
        
        # Empty line before body
        lines.append('')
        
        # Body
        if parsed.get('body'):
            lines.append(parsed['body'])
        
        return '\r\n'.join(lines).encode('utf-8')

    def manipulate_header(
        self,
        headers: Dict[str, str],
        header_name: str,
        new_value: Optional[str] = None,
        operation: str = "replace"
    ) -> Dict[str, str]:
        """
        Manipulate HTTP header.
        
        Args:
            headers: Dictionary of headers
            header_name: Name of header to manipulate
            new_value: New value for header (if operation requires it)
            operation: Operation to perform ("replace", "remove", "add", "duplicate")
            
        Returns:
            Modified headers dictionary
        """
        modified = headers.copy()
        
        if operation == "replace" and new_value is not None:
            modified[header_name] = new_value
        elif operation == "remove":
            modified.pop(header_name, None)
        elif operation == "add" and new_value is not None:
            modified[header_name] = new_value
        elif operation == "duplicate" and header_name in modified:
            # For duplicate, we need to handle it differently in actual HTTP
            # This is a simplified version
            modified[f"{header_name}-Duplicate"] = modified[header_name]
        
        return modified

    def randomize_header_case(self, header_name: str, strategy: str = "random") -> str:
        """
        Randomize header name casing.
        
        Args:
            header_name: Original header name
            strategy: Casing strategy ("random", "alternating", "upper", "lower", "mixed")
            
        Returns:
            Header name with modified casing
        """
        import random
        
        if strategy == "upper":
            return header_name.upper()
        elif strategy == "lower":
            return header_name.lower()
        elif strategy == "alternating":
            return ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(header_name)])
        elif strategy == "random":
            return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in header_name])
        elif strategy == "mixed":
            # Mix of upper and lower with some original
            result = []
            for c in header_name:
                choice = random.random()
                if choice < 0.33:
                    result.append(c.upper())
                elif choice < 0.66:
                    result.append(c.lower())
                else:
                    result.append(c)
            return ''.join(result)
        else:
            return header_name

    def detect_http2(self, payload: bytes) -> bool:
        """
        Detect if request is HTTP/2.
        
        Args:
            payload: Request payload
            
        Returns:
            True if HTTP/2 is detected
        """
        try:
            # HTTP/2 uses binary framing, check for connection preface
            # PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
            http2_preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
            if payload.startswith(http2_preface):
                return True
            
            # Check for HTTP/2 upgrade header
            payload_str = payload.decode('utf-8', errors='ignore')
            if 'HTTP/2' in payload_str or 'h2' in payload_str.lower():
                return True
            
            return False
        except Exception:
            return False

    def adapt_for_http2(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adapt HTTP request for HTTP/2.
        
        Args:
            parsed: Parsed HTTP request
            
        Returns:
            Modified request adapted for HTTP/2
        """
        # HTTP/2 uses pseudo-headers
        adapted = parsed.copy()
        
        # Convert to pseudo-headers
        pseudo_headers = {
            ':method': adapted['method'],
            ':path': adapted['path'],
            ':scheme': 'https',  # Assume HTTPS for HTTP/2
            ':authority': adapted['headers'].get('Host', '')
        }
        
        # Remove Host header as it's replaced by :authority
        if 'Host' in adapted['headers']:
            del adapted['headers']['Host']
        
        # Merge pseudo-headers with regular headers
        adapted['pseudo_headers'] = pseudo_headers
        adapted['version'] = 'HTTP/2.0'
        
        return adapted

    def validate_http_compliance(self, payload: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate HTTP request compliance.
        
        Args:
            payload: HTTP request payload
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = self.parse_http_request(payload)
            if not parsed:
                return False, "Failed to parse HTTP request"
            
            # Check method
            valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']
            if parsed['method'] not in valid_methods:
                return False, f"Invalid HTTP method: {parsed['method']}"
            
            # Check version
            if not parsed['version'].startswith('HTTP/'):
                return False, f"Invalid HTTP version: {parsed['version']}"
            
            # Check required headers for certain methods
            if parsed['method'] in ['POST', 'PUT', 'PATCH']:
                if 'Content-Length' not in parsed['headers'] and 'Transfer-Encoding' not in parsed['headers']:
                    return False, "POST/PUT/PATCH requires Content-Length or Transfer-Encoding header"
            
            return True, None
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def log_http_operation(self, operation: str, method: str, path: str, details: str = ""):
        """
        Log HTTP manipulation operation.
        
        Args:
            operation: Name of the operation
            method: HTTP method
            path: Request path
            details: Additional details
        """
        log_msg = f"HTTP {operation}: {method} {path}"
        if details:
            log_msg += f" - {details}"
        
        self.logger.info(log_msg)

    def handle_http_error(self, error: Exception, context: AttackContext, operation: str) -> AttackResult:
        """
        Handle errors during HTTP manipulation.
        
        Args:
            error: Exception that occurred
            context: Attack context
            operation: Operation that failed
            
        Returns:
            AttackResult with error status
        """
        error_msg = f"HTTP {operation} failed: {str(error)}"
        self.logger.error(error_msg, exc_info=context.debug)
        
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=error_msg,
            technique_used=self.name,
            metadata={"operation": operation, "error_type": type(error).__name__}
        )

    def create_http_result(
        self,
        modified_payload: bytes,
        original_payload: bytes,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AttackResult:
        """
        Create successful result for HTTP manipulation.
        
        Args:
            modified_payload: Modified HTTP request
            original_payload: Original HTTP request
            operation: Operation performed
            metadata: Additional metadata
            
        Returns:
            AttackResult with success status
        """
        result_metadata = metadata or {}
        result_metadata.update({
            "operation": operation,
            "original_size": len(original_payload),
            "modified_size": len(modified_payload)
        })
        
        # Create result with modified payload
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            modified_payload=modified_payload,
            metadata=result_metadata,
            bytes_sent=len(modified_payload),
            packets_sent=1
        )
        
        # Add as segment for orchestration
        result.add_segment(modified_payload, 0, {})
        
        return result


    def build_http2_frame(self, parsed: Dict[str, Any]) -> bytes:
        """
        Build HTTP/2 frame from parsed components.
        
        Note: This is a simplified implementation. Full HTTP/2 support
        requires proper HPACK encoding and frame construction.
        
        Args:
            parsed: Parsed HTTP request with pseudo-headers
            
        Returns:
            HTTP/2 frame as bytes
        """
        # This is a placeholder for HTTP/2 frame construction
        # In a real implementation, this would use proper HTTP/2 framing
        # and HPACK compression
        
        self.logger.warning("HTTP/2 frame construction is not fully implemented")
        
        # For now, return a basic representation
        # Real implementation would need:
        # 1. HPACK encoding for headers
        # 2. Proper frame structure (9-byte header + payload)
        # 3. Stream ID management
        # 4. Flow control
        
        return b''  # Placeholder

    def manipulate_http2_pseudo_headers(
        self,
        pseudo_headers: Dict[str, str],
        manipulation_type: str,
        **kwargs
    ) -> Dict[str, str]:
        """
        Manipulate HTTP/2 pseudo-headers.
        
        Args:
            pseudo_headers: Dictionary of pseudo-headers (:method, :path, :scheme, :authority)
            manipulation_type: Type of manipulation to apply
            **kwargs: Additional parameters for manipulation
            
        Returns:
            Modified pseudo-headers dictionary
        """
        modified = pseudo_headers.copy()
        
        if manipulation_type == "authority_manipulation":
            # Manipulate :authority pseudo-header (equivalent to Host header)
            if ':authority' in modified:
                original_authority = modified[':authority']
                fake_authority = kwargs.get('fake_authority', 'example.com')
                modified[':authority'] = fake_authority
                
                # Optionally preserve original in custom header
                if kwargs.get('preserve_original', False):
                    modified['x-original-authority'] = original_authority
        
        elif manipulation_type == "method_case":
            # HTTP/2 methods should be lowercase, but we can try variations
            if ':method' in modified:
                method = modified[':method']
                case_strategy = kwargs.get('case_strategy', 'upper')
                if case_strategy == 'upper':
                    modified[':method'] = method.upper()
                elif case_strategy == 'mixed':
                    modified[':method'] = ''.join([
                        c.upper() if i % 2 == 0 else c.lower()
                        for i, c in enumerate(method)
                    ])
        
        elif manipulation_type == "path_obfuscation":
            # Obfuscate :path pseudo-header
            if ':path' in modified:
                path = modified[':path']
                # Add trailing slash or dots
                if not path.endswith('/'):
                    modified[':path'] = path + '/'
        
        return modified

    def encode_hpack_headers(self, headers: Dict[str, str]) -> bytes:
        """
        Encode headers using HPACK compression for HTTP/2.
        
        Note: This is a placeholder. Real implementation would use
        a proper HPACK library.
        
        Args:
            headers: Dictionary of headers to encode
            
        Returns:
            HPACK-encoded headers
        """
        self.logger.warning("HPACK encoding is not fully implemented")
        
        # Placeholder - real implementation would use HPACK compression
        # This would require:
        # 1. Static table lookup
        # 2. Dynamic table management
        # 3. Huffman encoding
        # 4. Integer representation
        
        return b''  # Placeholder

    def decode_hpack_headers(self, encoded: bytes) -> Dict[str, str]:
        """
        Decode HPACK-encoded headers from HTTP/2.
        
        Note: This is a placeholder. Real implementation would use
        a proper HPACK library.
        
        Args:
            encoded: HPACK-encoded headers
            
        Returns:
            Dictionary of decoded headers
        """
        self.logger.warning("HPACK decoding is not fully implemented")
        
        # Placeholder - real implementation would use HPACK decompression
        return {}

    def supports_http2(self) -> bool:
        """
        Check if this attack supports HTTP/2.
        
        Returns:
            True if HTTP/2 is supported (default: False for base class)
        """
        # Subclasses can override this to indicate HTTP/2 support
        return False

