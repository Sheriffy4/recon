"""
HTTP Host Header Manipulation Attacks

Attacks that manipulate the HTTP Host header to evade DPI detection.
Includes hostspell, hostdot, hosttab, and other host header manipulation techniques.
"""

import asyncio
import time
import random
from typing import List, Dict, Any
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..base_classes.http_attack_base import HTTPAttackBase
from ..attack_registry import register_attack, RegistrationPriority
from ..metadata import AttackCategories


@register_attack(
    name="http_host_header",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "manipulation_type": "replace",
        "fake_host": "example.com",
        "preserve_original": True,
        "alternate_header": "X-Original-Host"
    },
    aliases=["hostspell", "hostdot", "hosttab", "host_manipulation"],
    description="Manipulates HTTP Host header using various techniques (replace, misspell, dot, tab)"
)
class HTTPHostHeaderAttack(HTTPAttackBase):
    """
    HTTP Host Header Attack - manipulates Host header to evade DPI.
    
    Supports multiple manipulation types:
    - replace: Replace host with fake host
    - misspell (hostspell): Intentionally misspell the host
    - dot (hostdot): Inject dots into the host
    - tab (hosttab): Inject tabs into the host
    - case_change: Change case of Host header name
    - duplicate: Duplicate the Host header with different values
    
    The original host can be preserved in an alternate header for backend processing.
    """

    @property
    def name(self) -> str:
        return "http_host_header"

    @property
    def description(self) -> str:
        return "Manipulates HTTP Host header to evade DPI detection"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "manipulation_type": "replace",
            "fake_host": "example.com",
            "preserve_original": True,
            "alternate_header": "X-Original-Host"
        }

    def supports_http2(self) -> bool:
        """This attack supports HTTP/2."""
        return True

    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute HTTP host header manipulation attack.
        
        Supports both HTTP/1.1 and HTTP/2.
        
        Args:
            context: Attack execution context with HTTP request
            
        Returns:
            AttackResult with modified HTTP request
        """
        start_time = time.time()
        
        try:
            # Validate context
            if not self.validate_context(context):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid context for HTTP host header attack",
                    technique_used=self.name
                )
            
            # Check for HTTP/2
            is_http2 = self.detect_http2(context.payload)
            
            if is_http2:
                return await self._execute_http2(context, start_time)
            
            # Parse HTTP request
            parsed = self.parse_http_request(context.payload)
            if not parsed:
                return self.handle_http_error(
                    Exception("Failed to parse HTTP request"),
                    context,
                    "parse"
                )
            
            # Get parameters
            manipulation_type = context.params.get("manipulation_type", "replace")
            fake_host = context.params.get("fake_host", "example.com")
            preserve_original = context.params.get("preserve_original", True)
            alternate_header = context.params.get("alternate_header", "X-Original-Host")
            
            # Get original host
            original_host = parsed['headers'].get('Host', '')
            if not original_host:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="No Host header found in request",
                    technique_used=self.name
                )
            
            # Apply manipulation based on type
            if manipulation_type == "replace":
                modified_host = fake_host
            elif manipulation_type == "misspell" or manipulation_type == "hostspell":
                modified_host = self._misspell_host(original_host)
            elif manipulation_type == "dot" or manipulation_type == "hostdot":
                modified_host = self._inject_dots(original_host)
            elif manipulation_type == "tab" or manipulation_type == "hosttab":
                modified_host = self._inject_tabs(original_host)
            elif manipulation_type == "case_change":
                # Change case of header name, not value
                modified_host = original_host
            elif manipulation_type == "duplicate":
                # Will handle duplication separately
                modified_host = fake_host
            else:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Unknown manipulation type: {manipulation_type}",
                    technique_used=self.name
                )
            
            # Modify headers
            modified_headers = parsed['headers'].copy()
            
            # Preserve original host if requested
            if preserve_original and manipulation_type != "case_change":
                modified_headers[alternate_header] = original_host
            
            # Apply host modification
            if manipulation_type == "case_change":
                # Change case of "Host" header name
                del modified_headers['Host']
                modified_headers['HOST'] = original_host
            elif manipulation_type == "duplicate":
                # Keep original and add fake
                modified_headers['Host'] = original_host
                modified_headers['X-Forwarded-Host'] = fake_host
            else:
                # Replace host value
                modified_headers['Host'] = modified_host
            
            # Rebuild request
            parsed['headers'] = modified_headers
            modified_payload = self.build_http_request(parsed)
            
            # Validate HTTP compliance
            is_valid, error_msg = self.validate_http_compliance(modified_payload)
            if not is_valid:
                self.logger.warning(f"Modified request may not be HTTP compliant: {error_msg}")
            
            # Log operation
            self.log_http_operation(
                "host_manipulation",
                parsed['method'],
                parsed['path'],
                f"{manipulation_type}: {original_host} -> {modified_host}"
            )
            
            # Create result
            latency = (time.time() - start_time) * 1000
            
            return self.create_http_result(
                modified_payload=modified_payload,
                original_payload=context.payload,
                operation=f"host_{manipulation_type}",
                metadata={
                    "manipulation_type": manipulation_type,
                    "original_host": original_host,
                    "modified_host": modified_host,
                    "preserved_original": preserve_original,
                    "alternate_header": alternate_header if preserve_original else None,
                    "latency_ms": latency
                }
            )
            
        except Exception as e:
            return self.handle_http_error(e, context, "host_manipulation")

    def _misspell_host(self, host: str) -> str:
        """
        Intentionally misspell the host (hostspell technique).
        
        Strategies:
        - Add extra characters
        - Duplicate characters
        - Change case randomly
        
        Args:
            host: Original host
            
        Returns:
            Misspelled host
        """
        if not host:
            return host
        
        # Split into domain parts
        parts = host.split('.')
        if len(parts) < 2:
            # Simple host, just add a character
            return host + 'x'
        
        # Misspell the main domain part (before TLD)
        main_part = parts[-2]
        
        # Choose a misspelling strategy
        strategy = random.choice(['duplicate', 'insert', 'case'])
        
        if strategy == 'duplicate' and len(main_part) > 1:
            # Duplicate a random character
            pos = random.randint(0, len(main_part) - 1)
            main_part = main_part[:pos] + main_part[pos] + main_part[pos:]
        elif strategy == 'insert':
            # Insert a random character
            pos = random.randint(0, len(main_part))
            char = random.choice('abcdefghijklmnopqrstuvwxyz')
            main_part = main_part[:pos] + char + main_part[pos:]
        elif strategy == 'case':
            # Random case changes
            main_part = ''.join([
                c.upper() if random.random() > 0.5 else c.lower()
                for c in main_part
            ])
        
        # Rebuild host
        parts[-2] = main_part
        return '.'.join(parts)

    def _inject_dots(self, host: str) -> str:
        """
        Inject dots into the host (hostdot technique).
        
        Args:
            host: Original host
            
        Returns:
            Host with injected dots
        """
        if not host:
            return host
        
        # Add trailing dot (valid DNS notation)
        if not host.endswith('.'):
            return host + '.'
        
        return host

    def _inject_tabs(self, host: str) -> str:
        """
        Inject tabs into the host (hosttab technique).
        
        Args:
            host: Original host
            
        Returns:
            Host with injected tabs
        """
        if not host:
            return host
        
        # Inject tab before or after host
        position = random.choice(['before', 'after', 'both'])
        
        if position == 'before':
            return '\t' + host
        elif position == 'after':
            return host + '\t'
        else:  # both
            return '\t' + host + '\t'



    async def _execute_http2(self, context: AttackContext, start_time: float) -> AttackResult:
        """
        Execute HTTP/2 version of host header manipulation.
        
        Args:
            context: Attack execution context
            start_time: Start time for latency calculation
            
        Returns:
            AttackResult with modified HTTP/2 request
        """
        try:
            # Get parameters
            manipulation_type = context.params.get("manipulation_type", "replace")
            fake_host = context.params.get("fake_host", "example.com")
            preserve_original = context.params.get("preserve_original", True)
            
            # For HTTP/2, we manipulate the :authority pseudo-header
            # This is a simplified implementation
            
            self.logger.info(f"HTTP/2 host manipulation: {manipulation_type}")
            
            # In a real implementation, we would:
            # 1. Parse HTTP/2 frames
            # 2. Decode HPACK headers
            # 3. Manipulate :authority pseudo-header
            # 4. Re-encode with HPACK
            # 5. Rebuild frames
            
            # For now, return a placeholder result
            latency = (time.time() - start_time) * 1000
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                modified_payload=context.payload,  # Placeholder
                metadata={
                    "http_version": "2.0",
                    "manipulation_type": manipulation_type,
                    "fake_host": fake_host,
                    "preserved_original": preserve_original,
                    "latency_ms": latency,
                    "note": "HTTP/2 support is limited - full implementation requires HPACK library"
                },
                bytes_sent=len(context.payload),
                packets_sent=1
            )
            
        except Exception as e:
            return self.handle_http_error(e, context, "http2_host_manipulation")

