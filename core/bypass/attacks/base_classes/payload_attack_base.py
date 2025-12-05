"""
Base class for payload manipulation attacks.

Provides common functionality for attacks that manipulate packet payloads:
- Base64 encoding
- Padding injection
- Obfuscation techniques
- Chunk-based processing
"""

import logging
from abc import abstractmethod
from typing import Dict, Any, List, Optional
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..metadata import AttackCategories, ValidationResult


class PayloadAttackBase(BaseAttack):
    """
    Base class for payload manipulation attacks.
    
    Provides:
    - Abstract methods for attack execution
    - Common parameter validation for payload attacks
    - Logging helpers for payload manipulation
    - Error handling for payload operations
    - Support for chunk-based processing
    """

    @property
    def category(self) -> str:
        """All payload attacks belong to PAYLOAD category."""
        return AttackCategories.PAYLOAD

    @property
    def supported_protocols(self) -> List[str]:
        """Payload attacks work with TCP and UDP."""
        return ["tcp", "udp"]

    @abstractmethod
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the payload attack.
        
        Args:
            context: Attack execution context with payload and parameters
            
        Returns:
            AttackResult with modified payload or segments
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
        
        # Validate chunk_size if present
        if "chunk_size" in params:
            chunk_size = params["chunk_size"]
            if not isinstance(chunk_size, int):
                errors.append("chunk_size must be an integer")
            elif chunk_size <= 0:
                errors.append("chunk_size must be positive")
            elif chunk_size > 65535:
                warnings.append("chunk_size is very large, may cause fragmentation issues")
        
        # Validate encoding parameters
        if "encoding" in params:
            encoding = params["encoding"]
            valid_encodings = ["base64", "hex", "url", "none"]
            if encoding not in valid_encodings:
                errors.append(f"encoding must be one of: {valid_encodings}")
        
        # Validate obfuscation parameters
        if "obfuscation_key" in params:
            key = params["obfuscation_key"]
            if not isinstance(key, (bytes, str)):
                errors.append("obfuscation_key must be bytes or string")
        
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
        
        # Payload attacks require payload data
        if not context.payload or len(context.payload) == 0:
            self.logger.warning("Payload attack requires non-empty payload")
            return False
        
        return True

    def split_into_chunks(self, payload: bytes, chunk_size: int) -> List[bytes]:
        """
        Split payload into chunks of specified size.
        
        Args:
            payload: Payload to split
            chunk_size: Size of each chunk
            
        Returns:
            List of payload chunks
        """
        if chunk_size <= 0:
            return [payload]
        
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(chunk)
        
        self.logger.debug(f"Split {len(payload)} bytes into {len(chunks)} chunks of size {chunk_size}")
        return chunks

    def log_payload_operation(self, operation: str, original_size: int, modified_size: int, details: str = ""):
        """
        Log payload manipulation operation.
        
        Args:
            operation: Name of the operation
            original_size: Original payload size
            modified_size: Modified payload size
            details: Additional details
        """
        size_change = modified_size - original_size
        size_change_pct = (size_change / original_size * 100) if original_size > 0 else 0
        
        log_msg = f"Payload {operation}: {original_size}B -> {modified_size}B ({size_change:+d}B, {size_change_pct:+.1f}%)"
        if details:
            log_msg += f" - {details}"
        
        self.logger.info(log_msg)

    def handle_payload_error(self, error: Exception, context: AttackContext, operation: str) -> AttackResult:
        """
        Handle errors during payload manipulation.
        
        Args:
            error: Exception that occurred
            context: Attack context
            operation: Operation that failed
            
        Returns:
            AttackResult with error status
        """
        error_msg = f"Payload {operation} failed: {str(error)}"
        self.logger.error(error_msg, exc_info=context.debug)
        
        return AttackResult(
            status=AttackStatus.ERROR,
            error_message=error_msg,
            technique_used=self.name,
            metadata={"operation": operation, "error_type": type(error).__name__}
        )

    def create_payload_result(
        self,
        modified_payload: bytes,
        original_payload: bytes,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AttackResult:
        """
        Create successful result for payload manipulation.
        
        Args:
            modified_payload: Modified payload
            original_payload: Original payload
            operation: Operation performed
            metadata: Additional metadata
            
        Returns:
            AttackResult with success status
        """
        result_metadata = metadata or {}
        result_metadata.update({
            "operation": operation,
            "original_size": len(original_payload),
            "modified_size": len(modified_payload),
            "size_change": len(modified_payload) - len(original_payload)
        })
        
        # Log the operation
        self.log_payload_operation(
            operation,
            len(original_payload),
            len(modified_payload)
        )
        
        # Create result with modified payload as a single segment
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

    def xor_obfuscate(self, data: bytes, key: bytes) -> bytes:
        """
        Apply XOR obfuscation to data.
        
        Args:
            data: Data to obfuscate
            key: XOR key
            
        Returns:
            Obfuscated data
        """
        if not key:
            return data
        
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def rotate_bytes(self, data: bytes, shift: int) -> bytes:
        """
        Apply byte rotation obfuscation.
        
        Args:
            data: Data to obfuscate
            shift: Rotation shift amount
            
        Returns:
            Obfuscated data
        """
        return bytes([(b + shift) % 256 for b in data])

    def add_padding(self, data: bytes, padding_size: int, pattern: str = "random") -> bytes:
        """
        Add padding to data.
        
        Args:
            data: Data to pad
            padding_size: Size of padding to add
            pattern: Padding pattern ("random", "zero", "repeat")
            
        Returns:
            Padded data
        """
        import random
        
        if padding_size <= 0:
            return data
        
        if pattern == "random":
            padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
        elif pattern == "zero":
            padding = bytes(padding_size)
        elif pattern == "repeat":
            padding = (data * ((padding_size // len(data)) + 1))[:padding_size]
        else:
            padding = bytes(padding_size)
        
        return data + padding

    def remove_padding(self, data: bytes, padding_size: int) -> bytes:
        """
        Remove padding from data.
        
        Args:
            data: Padded data
            padding_size: Size of padding to remove
            
        Returns:
            Data without padding
        """
        if padding_size <= 0 or padding_size >= len(data):
            return data
        
        return data[:-padding_size]
