"""
TLS Fingerprint Evasion Attacks

Implements attacks that manipulate TLS ClientHello to evade fingerprinting:
- Extension reordering (random, reverse, custom patterns)
- Extension padding injection
- GREASE value injection
- TLS 1.3 specific extension manipulation
"""

import time
import random
import struct
from typing import List, Dict, Any, Optional
from core.bypass.attacks.base_classes.tls_attack_base import TLSAttackBase
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories


@register_attack(
    name="tls_extension_reorder",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "reorder_strategy": "random",
        "preserve_critical": True,
        "custom_order": None
    },
    aliases=["extension_reorder", "tls_reorder"],
    description="Reorders TLS extensions in ClientHello to evade fingerprinting"
)
class TLSExtensionReorderAttack(TLSAttackBase):
    """
    TLS Extension Reorder Attack - reorders extensions in ClientHello.
    
    Supports multiple reordering strategies:
    - random: Randomize extension order
    - reverse: Reverse the extension order
    - custom: Use custom ordering pattern
    
    Can preserve critical extensions in their original positions to ensure
    handshake success.
    """

    @property
    def name(self) -> str:
        return "tls_extension_reorder"

    @property
    def description(self) -> str:
        return "Reorders TLS extensions to evade fingerprinting"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "reorder_strategy": "random",
            "preserve_critical": True,
            "custom_order": None
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS extension reordering attack."""
        start_time = time.time()
        
        try:
            payload = context.payload
            
            # Parse ClientHello
            parsed = self.parse_client_hello(payload)
            if not parsed:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Failed to parse TLS ClientHello",
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            # Get parameters
            reorder_strategy = context.params.get("reorder_strategy", "random")
            preserve_critical = context.params.get("preserve_critical", True)
            custom_order = context.params.get("custom_order", None)
            
            # Reorder extensions
            original_extensions = parsed['extensions'].copy()
            reordered_extensions = self._reorder_extensions(
                original_extensions,
                reorder_strategy,
                preserve_critical,
                custom_order
            )
            
            # Update parsed data with reordered extensions
            parsed['extensions'] = reordered_extensions
            
            # Rebuild ClientHello
            modified_payload = self.build_client_hello(parsed)
            
            # Validate
            is_valid, error_msg = self.validate_handshake(modified_payload)
            
            # Create result
            latency = (time.time() - start_time) * 1000
            
            result_metadata = {
                "reorder_strategy": reorder_strategy,
                "preserve_critical": preserve_critical,
                "original_extension_count": len(original_extensions),
                "reordered_extension_count": len(reordered_extensions),
                "original_order": [ext['type'] for ext in original_extensions],
                "new_order": [ext['type'] for ext in reordered_extensions],
                "validation_passed": is_valid
            }
            
            if not is_valid:
                result_metadata["validation_error"] = error_msg
            
            return self.create_tls_result(
                modified_payload,
                payload,
                "extension_reorder",
                result_metadata
            )
            
        except Exception as e:
            return self.handle_tls_error(e, context, "extension_reorder")

    def _reorder_extensions(
        self,
        extensions: List[Dict[str, Any]],
        strategy: str,
        preserve_critical: bool,
        custom_order: Optional[List[int]]
    ) -> List[Dict[str, Any]]:
        """
        Reorder extensions based on strategy.
        
        Args:
            extensions: List of extension dictionaries
            strategy: Reordering strategy ("random", "reverse", "custom")
            preserve_critical: Whether to preserve critical extension positions
            custom_order: Custom ordering (list of extension types)
            
        Returns:
            Reordered list of extensions
        """
        if not extensions:
            return extensions
        
        # Separate critical and non-critical extensions if needed
        if preserve_critical:
            critical_exts = []
            non_critical_exts = []
            
            for i, ext in enumerate(extensions):
                if self.is_critical_extension(ext['type']):
                    critical_exts.append((i, ext))
                else:
                    non_critical_exts.append(ext)
            
            # Reorder only non-critical extensions
            if strategy == "random":
                random.shuffle(non_critical_exts)
            elif strategy == "reverse":
                non_critical_exts.reverse()
            elif strategy == "custom" and custom_order:
                non_critical_exts = self._apply_custom_order(non_critical_exts, custom_order)
            
            # Reconstruct with critical extensions in original positions
            result = []
            non_critical_idx = 0
            
            for i in range(len(extensions)):
                # Check if there's a critical extension at this position
                critical_at_pos = None
                for orig_pos, ext in critical_exts:
                    if orig_pos == i:
                        critical_at_pos = ext
                        break
                
                if critical_at_pos:
                    result.append(critical_at_pos)
                elif non_critical_idx < len(non_critical_exts):
                    result.append(non_critical_exts[non_critical_idx])
                    non_critical_idx += 1
            
            return result
        else:
            # Reorder all extensions
            reordered = extensions.copy()
            
            if strategy == "random":
                random.shuffle(reordered)
            elif strategy == "reverse":
                reordered.reverse()
            elif strategy == "custom" and custom_order:
                reordered = self._apply_custom_order(reordered, custom_order)
            
            return reordered

    def _apply_custom_order(
        self,
        extensions: List[Dict[str, Any]],
        custom_order: List[int]
    ) -> List[Dict[str, Any]]:
        """
        Apply custom ordering to extensions.
        
        Args:
            extensions: List of extension dictionaries
            custom_order: Desired order (list of extension types)
            
        Returns:
            Reordered list of extensions
        """
        # Create a map of extension type to extension
        ext_map = {ext['type']: ext for ext in extensions}
        
        # Build result in custom order
        result = []
        for ext_type in custom_order:
            if ext_type in ext_map:
                result.append(ext_map[ext_type])
                del ext_map[ext_type]
        
        # Append any remaining extensions not in custom order
        result.extend(ext_map.values())
        
        return result


@register_attack(
    name="tls_extension_padding",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "padding_size": 16,
        "padding_count": 1,
        "random_content": True
    },
    aliases=["extension_padding", "tls_padding"],
    description="Adds padding extensions to TLS ClientHello"
)
class TLSExtensionPaddingAttack(TLSAttackBase):
    """
    TLS Extension Padding Attack - adds padding extensions to ClientHello.
    
    Injects padding extensions with configurable sizes to change the
    ClientHello fingerprint and evade size-based detection.
    """

    @property
    def name(self) -> str:
        return "tls_extension_padding"

    @property
    def description(self) -> str:
        return "Adds padding extensions to TLS ClientHello"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "padding_size": 16,
            "padding_count": 1,
            "random_content": True
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS extension padding attack."""
        start_time = time.time()
        
        try:
            payload = context.payload
            
            # Parse ClientHello
            parsed = self.parse_client_hello(payload)
            if not parsed:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Failed to parse TLS ClientHello",
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            # Get parameters
            padding_size = context.params.get("padding_size", 16)
            padding_count = context.params.get("padding_count", 1)
            random_content = context.params.get("random_content", True)
            
            # Add padding extensions
            original_extensions = parsed['extensions'].copy()
            
            for i in range(padding_count):
                # Generate padding data
                if random_content:
                    padding_data = bytes([random.randint(0, 255) for _ in range(padding_size)])
                else:
                    padding_data = b'\x00' * padding_size
                
                # Add padding extension (type 21 is padding extension)
                padding_ext = {
                    'type': 21,
                    'length': len(padding_data),
                    'data': padding_data
                }
                
                parsed['extensions'].append(padding_ext)
            
            # Rebuild ClientHello
            modified_payload = self.build_client_hello(parsed)
            
            # Validate
            is_valid, error_msg = self.validate_handshake(modified_payload)
            
            # Create result
            latency = (time.time() - start_time) * 1000
            
            result_metadata = {
                "padding_size": padding_size,
                "padding_count": padding_count,
                "random_content": random_content,
                "original_extension_count": len(original_extensions),
                "new_extension_count": len(parsed['extensions']),
                "total_padding_bytes": padding_size * padding_count,
                "validation_passed": is_valid
            }
            
            if not is_valid:
                result_metadata["validation_error"] = error_msg
            
            return self.create_tls_result(
                modified_payload,
                payload,
                "extension_padding",
                result_metadata
            )
            
        except Exception as e:
            return self.handle_tls_error(e, context, "extension_padding")


@register_attack(
    name="tls_grease",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "grease_count": 3,
        "inject_cipher": True,
        "inject_extension": True,
        "inject_version": True
    },
    aliases=["grease", "tls_grease_injection"],
    description="Injects GREASE values into TLS ClientHello"
)
class TLSGREASEAttack(TLSAttackBase):
    """
    TLS GREASE Attack - injects GREASE values into ClientHello.
    
    GREASE (Generate Random Extensions And Sustain Extensibility) values
    are reserved values that help maintain protocol extensibility.
    
    Injects GREASE values into:
    - Cipher suites
    - Extensions
    - Supported versions
    """

    # GREASE values as defined in RFC 8701
    GREASE_VALUES = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    ]

    @property
    def name(self) -> str:
        return "tls_grease"

    @property
    def description(self) -> str:
        return "Injects GREASE values into TLS ClientHello"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "grease_count": 3,
            "inject_cipher": True,
            "inject_extension": True,
            "inject_version": True
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS GREASE attack."""
        start_time = time.time()
        
        try:
            payload = context.payload
            
            # Parse ClientHello
            parsed = self.parse_client_hello(payload)
            if not parsed:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Failed to parse TLS ClientHello",
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            # Get parameters
            grease_count = context.params.get("grease_count", 3)
            inject_cipher = context.params.get("inject_cipher", True)
            inject_extension = context.params.get("inject_extension", True)
            inject_version = context.params.get("inject_version", True)
            
            # Select random GREASE values
            grease_values = random.sample(self.GREASE_VALUES, min(grease_count, len(self.GREASE_VALUES)))
            
            injected_locations = []
            
            # Inject into cipher suites
            if inject_cipher:
                cipher_suites = bytearray(parsed['cipher_suites'])
                for grease_val in grease_values[:1]:  # Add one GREASE cipher
                    cipher_suites = struct.pack('!H', grease_val) + cipher_suites
                parsed['cipher_suites'] = bytes(cipher_suites)
                injected_locations.append("cipher_suites")
            
            # Inject into extensions
            if inject_extension:
                for grease_val in grease_values:
                    # Create GREASE extension with random data
                    grease_data = bytes([random.randint(0, 255) for _ in range(random.randint(0, 8))])
                    grease_ext = {
                        'type': grease_val,
                        'length': len(grease_data),
                        'data': grease_data
                    }
                    parsed['extensions'].insert(0, grease_ext)
                injected_locations.append("extensions")
            
            # Inject into supported_versions extension if present
            if inject_version:
                supported_versions_ext = self.get_extension_by_type(parsed['extensions'], 43)
                if supported_versions_ext:
                    # Add GREASE version to supported versions
                    versions_data = bytearray(supported_versions_ext['data'])
                    if len(versions_data) > 0:
                        # First byte is length, insert GREASE version after it
                        grease_version = struct.pack('!H', grease_values[0])
                        versions_data = bytes([versions_data[0] + 2]) + grease_version + versions_data[1:]
                        supported_versions_ext['data'] = bytes(versions_data)
                        supported_versions_ext['length'] = len(versions_data)
                        injected_locations.append("supported_versions")
            
            # Rebuild ClientHello
            modified_payload = self.build_client_hello(parsed)
            
            # Validate
            is_valid, error_msg = self.validate_handshake(modified_payload)
            
            # Create result
            latency = (time.time() - start_time) * 1000
            
            result_metadata = {
                "grease_count": grease_count,
                "grease_values": [hex(v) for v in grease_values],
                "injected_locations": injected_locations,
                "inject_cipher": inject_cipher,
                "inject_extension": inject_extension,
                "inject_version": inject_version,
                "validation_passed": is_valid
            }
            
            if not is_valid:
                result_metadata["validation_error"] = error_msg
            
            return self.create_tls_result(
                modified_payload,
                payload,
                "grease_injection",
                result_metadata
            )
            
        except Exception as e:
            return self.handle_tls_error(e, context, "grease_injection")


@register_attack(
    name="tls13_extension_manipulation",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "manipulate_key_share": True,
        "manipulate_supported_versions": True,
        "manipulate_early_data": False,
        "manipulate_psk": False
    },
    aliases=["tls13_manipulation", "tls_1_3_extensions"],
    description="Manipulates TLS 1.3 specific extensions"
)
class TLS13ExtensionManipulationAttack(TLSAttackBase):
    """
    TLS 1.3 Extension Manipulation Attack - manipulates TLS 1.3 specific extensions.
    
    Handles TLS 1.3 specific extensions:
    - key_share (type 51)
    - supported_versions (type 43)
    - early_data (type 42)
    - pre_shared_key (type 41)
    """

    @property
    def name(self) -> str:
        return "tls13_extension_manipulation"

    @property
    def description(self) -> str:
        return "Manipulates TLS 1.3 specific extensions"

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "manipulate_key_share": True,
            "manipulate_supported_versions": True,
            "manipulate_early_data": False,
            "manipulate_psk": False
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS 1.3 extension manipulation attack."""
        start_time = time.time()
        
        try:
            payload = context.payload
            
            # Parse ClientHello
            parsed = self.parse_client_hello(payload)
            if not parsed:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Failed to parse TLS ClientHello",
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            # Check if this is TLS 1.3
            if not self.is_tls_13(payload):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Not a TLS 1.3 ClientHello",
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            # Get parameters
            manipulate_key_share = context.params.get("manipulate_key_share", True)
            manipulate_supported_versions = context.params.get("manipulate_supported_versions", True)
            manipulate_early_data = context.params.get("manipulate_early_data", False)
            manipulate_psk = context.params.get("manipulate_psk", False)
            
            manipulated_extensions = []
            
            # Manipulate key_share extension (type 51)
            if manipulate_key_share:
                key_share_ext = self.get_extension_by_type(parsed['extensions'], 51)
                if key_share_ext:
                    # Add padding to key_share data
                    modified_data = key_share_ext['data'] + b'\x00' * 4
                    key_share_ext['data'] = modified_data
                    key_share_ext['length'] = len(modified_data)
                    manipulated_extensions.append("key_share")
            
            # Manipulate supported_versions extension (type 43)
            if manipulate_supported_versions:
                supported_versions_ext = self.get_extension_by_type(parsed['extensions'], 43)
                if supported_versions_ext:
                    # Reorder versions or add additional versions
                    versions_data = bytearray(supported_versions_ext['data'])
                    if len(versions_data) > 1:
                        # Keep length byte, reverse version order
                        length = versions_data[0]
                        versions = versions_data[1:]
                        # Reverse pairs of bytes (each version is 2 bytes)
                        reversed_versions = b''.join([versions[i:i+2] for i in range(0, len(versions), 2)][::-1])
                        versions_data = bytes([length]) + reversed_versions
                        supported_versions_ext['data'] = bytes(versions_data)
                        manipulated_extensions.append("supported_versions")
            
            # Manipulate early_data extension (type 42)
            if manipulate_early_data:
                early_data_ext = self.get_extension_by_type(parsed['extensions'], 42)
                if early_data_ext:
                    # Modify early data indication
                    manipulated_extensions.append("early_data")
            
            # Manipulate pre_shared_key extension (type 41)
            if manipulate_psk:
                psk_ext = self.get_extension_by_type(parsed['extensions'], 41)
                if psk_ext:
                    # Note: PSK manipulation is complex and may break handshake
                    # This is a placeholder for future implementation
                    manipulated_extensions.append("pre_shared_key")
            
            # Rebuild ClientHello
            modified_payload = self.build_client_hello(parsed)
            
            # Validate
            is_valid, error_msg = self.validate_handshake(modified_payload)
            
            # Create result
            latency = (time.time() - start_time) * 1000
            
            result_metadata = {
                "tls_version": "1.3",
                "manipulated_extensions": manipulated_extensions,
                "manipulate_key_share": manipulate_key_share,
                "manipulate_supported_versions": manipulate_supported_versions,
                "manipulate_early_data": manipulate_early_data,
                "manipulate_psk": manipulate_psk,
                "validation_passed": is_valid
            }
            
            if not is_valid:
                result_metadata["validation_error"] = error_msg
            
            return self.create_tls_result(
                modified_payload,
                payload,
                "tls13_extension_manipulation",
                result_metadata
            )
            
        except Exception as e:
            return self.handle_tls_error(e, context, "tls13_extension_manipulation")
