"""
Base class for TLS-layer attacks.

Provides common functionality for attacks that manipulate TLS protocol:
- TLS ClientHello parsing and manipulation
- Extension handling and reordering
- TLS version detection and adaptation
- Handshake validation
- TLS-specific logging
"""

import logging
import struct
from abc import abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..metadata import AttackCategories, ValidationResult


class TLSAttackBase(BaseAttack):
    """
    Base class for TLS-layer attacks.
    
    Provides:
    - Abstract methods for TLS attack execution
    - TLS ClientHello parsing and manipulation helpers
    - Extension handling (parse, reorder, add, remove)
    - TLS version detection and adaptation
    - Handshake validation to ensure successful connections
    - Logging for TLS-specific operations
    """

    @property
    def category(self) -> str:
        """All TLS attacks belong to TLS category."""
        return AttackCategories.TLS

    @property
    def supported_protocols(self) -> List[str]:
        """TLS attacks work with TCP."""
        return ["tcp"]

    @abstractmethod
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the TLS attack.
        
        Args:
            context: Attack execution context with TLS ClientHello
            
        Returns:
            AttackResult with modified ClientHello
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
        
        # Validate extension manipulation parameters
        if "extension_type" in params:
            ext_type = params["extension_type"]
            if not isinstance(ext_type, int) or ext_type < 0 or ext_type > 65535:
                errors.append("extension_type must be an integer between 0 and 65535")
        
        # Validate reorder strategy
        if "reorder_strategy" in params:
            strategy = params["reorder_strategy"]
            valid_strategies = ["random", "reverse", "custom"]
            if strategy not in valid_strategies:
                errors.append(f"reorder_strategy must be one of: {valid_strategies}")
        
        # Validate padding size
        if "padding_size" in params:
            size = params["padding_size"]
            if not isinstance(size, int) or size < 0:
                errors.append("padding_size must be a non-negative integer")
            elif size > 65535:
                warnings.append("padding_size is very large, may cause issues")
        
        # Validate GREASE parameters
        if "grease_count" in params:
            count = params["grease_count"]
            if not isinstance(count, int) or count < 0:
                errors.append("grease_count must be a non-negative integer")
            elif count > 10:
                warnings.append("grease_count is high, may look suspicious")
        
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
        
        # TLS attacks require payload (ClientHello)
        if not context.payload or len(context.payload) == 0:
            self.logger.warning("TLS attack requires non-empty payload")
            return False
        
        # Check if payload looks like TLS ClientHello
        if not self.is_tls_client_hello(context.payload):
            self.logger.warning("Payload does not appear to be a TLS ClientHello")
            return False
        
        return True

    def is_tls_client_hello(self, payload: bytes) -> bool:
        """
        Check if payload is a TLS ClientHello.
        
        Args:
            payload: Payload to check
            
        Returns:
            True if payload appears to be TLS ClientHello
        """
        if len(payload) < 6:
            return False
        
        # Check for TLS record header
        # Byte 0: Content Type (0x16 = Handshake)
        # Byte 1-2: TLS Version (0x03 0x01 = TLS 1.0, 0x03 0x03 = TLS 1.2, etc.)
        # Byte 3-4: Record Length
        # Byte 5: Handshake Type (0x01 = ClientHello)
        
        return (
            payload[0] == 0x16 and  # Handshake record
            payload[1] == 0x03 and  # TLS version major
            payload[2] in [0x01, 0x02, 0x03, 0x04] and  # TLS version minor
            len(payload) > 5 and
            payload[5] == 0x01  # ClientHello
        )

    def parse_client_hello(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse TLS ClientHello from payload.
        
        Args:
            payload: TLS ClientHello payload
            
        Returns:
            Dictionary with parsed ClientHello components or None if parsing fails
        """
        try:
            if not self.is_tls_client_hello(payload):
                return None
            
            # Parse TLS record header
            content_type = payload[0]
            tls_version = (payload[1], payload[2])
            record_length = struct.unpack('!H', payload[3:5])[0]
            
            # Parse handshake header
            handshake_type = payload[5]
            handshake_length = struct.unpack('!I', b'\x00' + payload[6:9])[0]
            
            # Parse ClientHello
            offset = 9
            
            # Client version
            client_version = (payload[offset], payload[offset + 1])
            offset += 2
            
            # Random (32 bytes)
            client_random = payload[offset:offset + 32]
            offset += 32
            
            # Session ID
            session_id_length = payload[offset]
            offset += 1
            session_id = payload[offset:offset + session_id_length]
            offset += session_id_length
            
            # Cipher suites
            cipher_suites_length = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2
            cipher_suites = payload[offset:offset + cipher_suites_length]
            offset += cipher_suites_length
            
            # Compression methods
            compression_methods_length = payload[offset]
            offset += 1
            compression_methods = payload[offset:offset + compression_methods_length]
            offset += compression_methods_length
            
            # Extensions
            extensions = []
            if offset < len(payload):
                extensions_length = struct.unpack('!H', payload[offset:offset + 2])[0]
                offset += 2
                extensions_end = offset + extensions_length
                
                while offset < extensions_end:
                    ext_type = struct.unpack('!H', payload[offset:offset + 2])[0]
                    offset += 2
                    ext_length = struct.unpack('!H', payload[offset:offset + 2])[0]
                    offset += 2
                    ext_data = payload[offset:offset + ext_length]
                    offset += ext_length
                    
                    extensions.append({
                        'type': ext_type,
                        'length': ext_length,
                        'data': ext_data
                    })
            
            return {
                'content_type': content_type,
                'tls_version': tls_version,
                'record_length': record_length,
                'handshake_type': handshake_type,
                'handshake_length': handshake_length,
                'client_version': client_version,
                'client_random': client_random,
                'session_id': session_id,
                'cipher_suites': cipher_suites,
                'compression_methods': compression_methods,
                'extensions': extensions,
                'raw_payload': payload
            }
        except Exception as e:
            self.logger.error(f"Failed to parse ClientHello: {e}")
            return None

    def build_client_hello(self, parsed: Dict[str, Any]) -> bytes:
        """
        Build TLS ClientHello from parsed components.
        
        Args:
            parsed: Parsed ClientHello dictionary
            
        Returns:
            ClientHello as bytes
        """
        try:
            # Build extensions
            extensions_data = b''
            for ext in parsed['extensions']:
                ext_type = struct.pack('!H', ext['type'])
                ext_length = struct.pack('!H', ext['length'])
                extensions_data += ext_type + ext_length + ext['data']
            
            # Build ClientHello body
            client_hello = b''
            client_hello += bytes(parsed['client_version'])
            client_hello += parsed['client_random']
            client_hello += bytes([len(parsed['session_id'])]) + parsed['session_id']
            client_hello += struct.pack('!H', len(parsed['cipher_suites'])) + parsed['cipher_suites']
            client_hello += bytes([len(parsed['compression_methods'])]) + parsed['compression_methods']
            
            if extensions_data:
                client_hello += struct.pack('!H', len(extensions_data)) + extensions_data
            
            # Build handshake header
            handshake_length = len(client_hello)
            handshake = bytes([parsed['handshake_type']])
            handshake += struct.pack('!I', handshake_length)[1:]  # 3-byte length
            handshake += client_hello
            
            # Build TLS record
            record = bytes([parsed['content_type']])
            record += bytes(parsed['tls_version'])
            record += struct.pack('!H', len(handshake))
            record += handshake
            
            return record
        except Exception as e:
            self.logger.error(f"Failed to build ClientHello: {e}")
            return parsed['raw_payload']

    def get_extension_by_type(self, extensions: List[Dict[str, Any]], ext_type: int) -> Optional[Dict[str, Any]]:
        """
        Get extension by type from extensions list.
        
        Args:
            extensions: List of extension dictionaries
            ext_type: Extension type to find
            
        Returns:
            Extension dictionary or None if not found
        """
        for ext in extensions:
            if ext['type'] == ext_type:
                return ext
        return None

    def remove_extension(self, extensions: List[Dict[str, Any]], ext_type: int) -> List[Dict[str, Any]]:
        """
        Remove extension by type from extensions list.
        
        Args:
            extensions: List of extension dictionaries
            ext_type: Extension type to remove
            
        Returns:
            New list with extension removed
        """
        return [ext for ext in extensions if ext['type'] != ext_type]

    def add_extension(self, extensions: List[Dict[str, Any]], ext_type: int, ext_data: bytes) -> List[Dict[str, Any]]:
        """
        Add extension to extensions list.
        
        Args:
            extensions: List of extension dictionaries
            ext_type: Extension type
            ext_data: Extension data
            
        Returns:
            New list with extension added
        """
        new_extensions = extensions.copy()
        new_extensions.append({
            'type': ext_type,
            'length': len(ext_data),
            'data': ext_data
        })
        return new_extensions

    def is_critical_extension(self, ext_type: int) -> bool:
        """
        Check if extension is critical for handshake.
        
        Args:
            ext_type: Extension type
            
        Returns:
            True if extension is critical
        """
        # Critical extensions that should not be removed or reordered carelessly
        critical_extensions = [
            0,      # server_name (SNI)
            10,     # supported_groups
            13,     # signature_algorithms
            43,     # supported_versions
            51,     # key_share
        ]
        return ext_type in critical_extensions

    def detect_tls_version(self, payload: bytes) -> Tuple[int, int]:
        """
        Detect TLS version from ClientHello.
        
        Args:
            payload: TLS ClientHello payload
            
        Returns:
            Tuple of (major, minor) version
        """
        if len(payload) < 3:
            return (0, 0)
        
        return (payload[1], payload[2])

    def is_tls_13(self, payload: bytes) -> bool:
        """
        Check if ClientHello is TLS 1.3.
        
        Args:
            payload: TLS ClientHello payload
            
        Returns:
            True if TLS 1.3
        """
        parsed = self.parse_client_hello(payload)
        if not parsed:
            return False
        
        # Check for supported_versions extension (type 43)
        supported_versions_ext = self.get_extension_by_type(parsed['extensions'], 43)
        if supported_versions_ext:
            # TLS 1.3 is 0x0304
            return b'\x03\x04' in supported_versions_ext['data']
        
        return False

    def validate_handshake(self, modified_payload: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate that modified ClientHello is still valid.
        
        Args:
            modified_payload: Modified ClientHello
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            if not self.is_tls_client_hello(modified_payload):
                return False, "Not a valid TLS ClientHello"
            
            parsed = self.parse_client_hello(modified_payload)
            if not parsed:
                return False, "Failed to parse modified ClientHello"
            
            # Check record length matches
            record_length = struct.unpack('!H', modified_payload[3:5])[0]
            actual_length = len(modified_payload) - 5
            if record_length != actual_length:
                return False, f"Record length mismatch: {record_length} != {actual_length}"
            
            # Check handshake length matches
            handshake_length = struct.unpack('!I', b'\x00' + modified_payload[6:9])[0]
            actual_handshake_length = len(modified_payload) - 9
            if handshake_length != actual_handshake_length:
                return False, f"Handshake length mismatch: {handshake_length} != {actual_handshake_length}"
            
            return True, None
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def log_tls_operation(self, operation: str, version: Tuple[int, int], details: str = ""):
        """
        Log TLS manipulation operation.
        
        Args:
            operation: Name of the operation
            version: TLS version tuple
            details: Additional details
        """
        version_str = f"TLS {version[0]}.{version[1]}"
        log_msg = f"TLS {operation} ({version_str})"
        if details:
            log_msg += f" - {details}"
        
        self.logger.info(log_msg)

    def handle_tls_error(self, error: Exception, context: AttackContext, operation: str) -> AttackResult:
        """
        Handle errors during TLS manipulation.
        
        Args:
            error: Exception that occurred
            context: Attack context
            operation: Operation that failed
            
        Returns:
            AttackResult with error status
        """
        error_msg = f"TLS {operation} failed: {str(error)}"
        self.logger.error(error_msg, exc_info=context.debug)
        
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=error_msg,
            technique_used=self.name,
            metadata={"operation": operation, "error_type": type(error).__name__}
        )

    def create_tls_result(
        self,
        modified_payload: bytes,
        original_payload: bytes,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AttackResult:
        """
        Create successful result for TLS manipulation.
        
        Args:
            modified_payload: Modified ClientHello
            original_payload: Original ClientHello
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
        
        # Validate the modified payload
        is_valid, error_msg = self.validate_handshake(modified_payload)
        if not is_valid:
            self.logger.warning(f"Modified ClientHello validation failed: {error_msg}")
            result_metadata["validation_warning"] = error_msg
        
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
