"""
Examples of standardized attack registration format.

This file demonstrates the enhanced @register_attack decorator usage
with complete metadata specification and various usage patterns.
"""

from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories, AttackMetadata
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus


# Example 1: Full metadata specification (recommended for new attacks)
@register_attack(
    name="advanced_tcp_split",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=["split_pos"],
    optional_params={
        "ttl": 3,
        "fooling": ["badsum"],
        "delay_ms": 0.0,
        "window_size": 65535
    },
    aliases=["adv_tcp_split", "enhanced_split"],
    description="Advanced TCP splitting with configurable parameters and timing control"
)
class AdvancedTCPSplitAttack(BaseAttack):
    """
    Advanced TCP packet splitting attack with enhanced control.
    
    This attack splits TCP packets at specified positions with optional
    timing delays and TCP window manipulation for improved evasion.
    """

    @property
    def name(self) -> str:
        return "advanced_tcp_split"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> list:
        return ["split_pos"]

    @property
    def optional_params(self) -> dict:
        return {
            "ttl": 3,
            "fooling": ["badsum"],
            "delay_ms": 0.0,
            "window_size": 65535
        }

    def execute(self, context: AttackContext) -> AttackResult:
        split_pos = context.params.get("split_pos", len(context.payload) // 2)
        ttl = context.params.get("ttl", 3)
        delay_ms = context.params.get("delay_ms", 0.0)
        
        # Split payload
        part1 = context.payload[:split_pos]
        part2 = context.payload[split_pos:]
        
        # Create segments with options
        segments = [
            (part1, 0, {"ttl": ttl}),
            (part2, len(part1), {"delay_ms": delay_ms})
        ]
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            packets_sent=2,
            bytes_sent=len(context.payload)
        )
        result.segments = segments
        
        return result


# Example 2: Minimal decorator usage with class properties
@register_attack("simple_disorder")
class SimpleDisorderAttack(BaseAttack):
    """Simple packet reordering attack."""

    @property
    def name(self) -> str:
        return "simple_disorder"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> list:
        return ["split_pos"]

    @property
    def optional_params(self) -> dict:
        return {"ack_first": False}

    def execute(self, context: AttackContext) -> AttackResult:
        split_pos = context.params.get("split_pos", len(context.payload) // 2)
        ack_first = context.params.get("ack_first", False)
        
        part1 = context.payload[:split_pos]
        part2 = context.payload[split_pos:]
        
        # Reorder segments
        if ack_first:
            segments = [
                (part2, len(part1), {"flags": 0x10}),  # ACK first
                (part1, 0, {"flags": 0x18})            # PSH+ACK second
            ]
        else:
            segments = [
                (part2, len(part1), {}),
                (part1, 0, {})
            ]
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            packets_sent=2
        )
        result.segments = segments
        
        return result


# Example 3: TLS-specific attack with comprehensive metadata
@register_attack(
    name="tls_sni_fragmentation",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=["fragment_size"],
    optional_params={
        "sni_position": "auto",
        "fake_sni": None,
        "record_fragmentation": True,
        "timing_jitter": False
    },
    aliases=["sni_frag", "tls_fragment"],
    description="TLS SNI fragmentation with record-level splitting"
)
class TLSSNIFragmentationAttack(BaseAttack):
    """
    Fragments TLS ClientHello at SNI extension boundary.
    
    This attack specifically targets the Server Name Indication (SNI)
    extension in TLS ClientHello messages, fragmenting the packet
    to evade SNI-based blocking.
    """

    @property
    def name(self) -> str:
        return "tls_sni_fragmentation"

    @property
    def category(self) -> str:
        return AttackCategories.TLS

    @property
    def required_params(self) -> list:
        return ["fragment_size"]

    @property
    def optional_params(self) -> dict:
        return {
            "sni_position": "auto",
            "fake_sni": None,
            "record_fragmentation": True,
            "timing_jitter": False
        }

    @property
    def supported_protocols(self) -> list:
        return ["tcp", "tls"]

    def execute(self, context: AttackContext) -> AttackResult:
        fragment_size = context.params.get("fragment_size", 64)
        sni_position = context.params.get("sni_position", "auto")
        
        # Find SNI position if auto
        if sni_position == "auto":
            sni_position = self._find_sni_position(context.payload)
        
        # Fragment at SNI boundary
        segments = self._create_tls_fragments(
            context.payload, sni_position, fragment_size
        )
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            packets_sent=len(segments)
        )
        result.segments = segments
        
        return result

    def _find_sni_position(self, payload: bytes) -> int:
        """Find SNI extension position in TLS ClientHello."""
        # Simplified SNI detection (real implementation would be more robust)
        sni_marker = b'\x00\x00'  # SNI extension type
        pos = payload.find(sni_marker)
        return pos if pos > 0 else len(payload) // 2

    def _create_tls_fragments(self, payload: bytes, sni_pos: int, fragment_size: int) -> list:
        """Create TLS record fragments."""
        segments = []
        
        # Fragment before SNI
        if sni_pos > 0:
            pre_sni = payload[:sni_pos]
            for i in range(0, len(pre_sni), fragment_size):
                chunk = pre_sni[i:i + fragment_size]
                segments.append((chunk, i, {}))
        
        # Fragment SNI and after
        post_sni = payload[sni_pos:]
        for i in range(0, len(post_sni), fragment_size):
            chunk = post_sni[i:i + fragment_size]
            segments.append((chunk, sni_pos + i, {}))
        
        return segments


# Example 4: HTTP-level attack
@register_attack(
    name="http_header_case_evasion",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "case_pattern": "random",
        "header_order_shuffle": False,
        "add_dummy_headers": True
    },
    aliases=["http_case", "header_evasion"]
)
class HTTPHeaderCaseEvasionAttack(BaseAttack):
    """
    HTTP header case manipulation for DPI evasion.
    
    Modifies HTTP header capitalization and order to evade
    signature-based detection systems.
    """

    @property
    def name(self) -> str:
        return "http_header_case_evasion"

    @property
    def category(self) -> str:
        return AttackCategories.HTTP

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "case_pattern": "random",
            "header_order_shuffle": False,
            "add_dummy_headers": True
        }

    @property
    def supported_protocols(self) -> list:
        return ["tcp", "http"]

    def execute(self, context: AttackContext) -> AttackResult:
        case_pattern = context.params.get("case_pattern", "random")
        
        # Modify HTTP headers
        modified_payload = self._modify_http_headers(context.payload, case_pattern)
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            modified_payload=modified_payload,
            packets_sent=1
        )
        
        return result

    def _modify_http_headers(self, payload: bytes, case_pattern: str) -> bytes:
        """Modify HTTP header case."""
        # Simplified implementation
        payload_str = payload.decode('utf-8', errors='ignore')
        
        if case_pattern == "random":
            import random
            # Randomly capitalize headers
            lines = payload_str.split('\r\n')
            for i, line in enumerate(lines):
                if ':' in line and i > 0:  # Skip request line
                    header, value = line.split(':', 1)
                    # Random case for header name
                    header = ''.join(
                        c.upper() if random.choice([True, False]) else c.lower()
                        for c in header
                    )
                    lines[i] = f"{header}:{value}"
            
            payload_str = '\r\n'.join(lines)
        
        return payload_str.encode('utf-8')


# Example 5: Payload-level attack
@register_attack(
    name="xor_payload_obfuscation",
    category=AttackCategories.PAYLOAD,
    priority=RegistrationPriority.NORMAL,
    required_params=["xor_key"],
    optional_params={
        "key_rotation": False,
        "preserve_headers": True,
        "chunk_size": 0
    },
    aliases=["xor_obfuscation", "payload_xor"]
)
class XORPayloadObfuscationAttack(BaseAttack):
    """
    XOR-based payload obfuscation attack.
    
    Applies XOR encryption to payload data to evade
    content-based DPI detection.
    """

    @property
    def name(self) -> str:
        return "xor_payload_obfuscation"

    @property
    def category(self) -> str:
        return AttackCategories.PAYLOAD

    @property
    def required_params(self) -> list:
        return ["xor_key"]

    @property
    def optional_params(self) -> dict:
        return {
            "key_rotation": False,
            "preserve_headers": True,
            "chunk_size": 0
        }

    def execute(self, context: AttackContext) -> AttackResult:
        xor_key = context.params.get("xor_key")
        if not xor_key:
            return AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="xor_key parameter is required"
            )
        
        # Apply XOR obfuscation
        obfuscated_payload = self._xor_encrypt(context.payload, xor_key)
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            modified_payload=obfuscated_payload,
            packets_sent=1
        )
        
        return result

    def _xor_encrypt(self, data: bytes, key: str) -> bytes:
        """Apply XOR encryption with string key."""
        key_bytes = key.encode('utf-8')
        return bytes([
            data[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data))
        ])


# Example 6: Function-based registration (alternative to class-based)
@register_attack(
    name="simple_ttl_manipulation",
    category=AttackCategories.IP,
    required_params=["ttl_value"],
    optional_params={"apply_to_all": True}
)
def simple_ttl_manipulation(context: AttackContext) -> list:
    """
    Simple TTL manipulation function.
    
    Sets custom TTL value for packet transmission.
    """
    ttl_value = context.params.get("ttl_value", 64)
    apply_to_all = context.params.get("apply_to_all", True)
    
    if apply_to_all:
        # Apply TTL to entire payload
        return [(context.payload, 0, {"ttl": ttl_value})]
    else:
        # Apply TTL only to first segment
        mid = len(context.payload) // 2
        return [
            (context.payload[:mid], 0, {"ttl": ttl_value}),
            (context.payload[mid:], mid, {})
        ]


# Example 7: Parameterless decorator (uses class name)
@register_attack
class AutoNamedAttack(BaseAttack):
    """Attack with automatically determined name from class name."""
    
    @property
    def name(self) -> str:
        return "auto_named"

    @property
    def category(self) -> str:
        return AttackCategories.CUSTOM

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {}

    def execute(self, context: AttackContext) -> AttackResult:
        return AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name
        )


# Example 8: High-priority core attack (for primitives.py style attacks)
@register_attack(
    name="core_fakeddisorder",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.CORE,  # Cannot be overridden
    required_params=["split_pos"],
    optional_params={
        "fake_ttl": 3,
        "fooling_methods": ["badsum"],
        "fake_data": None
    },
    aliases=["fakeddisorder", "fake_disorder"],
    description="Core fake disorder implementation from primitives.py"
)
class CoreFakeDisorderAttack(BaseAttack):
    """
    Core fake disorder attack implementation.
    
    This is the canonical implementation that cannot be overridden
    by external attacks due to CORE priority.
    """

    @property
    def name(self) -> str:
        return "core_fakeddisorder"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> list:
        return ["split_pos"]

    @property
    def optional_params(self) -> dict:
        return {
            "fake_ttl": 3,
            "fooling_methods": ["badsum"],
            "fake_data": None
        }

    def execute(self, context: AttackContext) -> AttackResult:
        # Implementation would call primitives.py
        from core.bypass.techniques.primitives import BypassTechniques
        
        split_pos = context.params.get("split_pos")
        fake_ttl = context.params.get("fake_ttl", 3)
        fooling_methods = context.params.get("fooling_methods", ["badsum"])
        
        techniques = BypassTechniques()
        segments = techniques.apply_fakeddisorder(
            context.payload, split_pos, fake_ttl, fooling_methods
        )
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            packets_sent=len(segments)
        )
        result.segments = segments
        
        return result


# Example 9: Combo attack using multiple techniques
@register_attack(
    name="multi_layer_evasion",
    category=AttackCategories.COMBO,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "techniques": ["split", "timing", "ttl"],
        "split_pos": None,
        "delay_ms": 10.0,
        "ttl_value": 3
    },
    aliases=["combo_evasion", "layered_attack"]
)
class MultiLayerEvasionAttack(BaseAttack):
    """
    Multi-layer evasion combining multiple techniques.
    
    Applies multiple evasion techniques in sequence for
    enhanced bypass effectiveness.
    """

    @property
    def name(self) -> str:
        return "multi_layer_evasion"

    @property
    def category(self) -> str:
        return AttackCategories.COMBO

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "techniques": ["split", "timing", "ttl"],
            "split_pos": None,
            "delay_ms": 10.0,
            "ttl_value": 3
        }

    def execute(self, context: AttackContext) -> AttackResult:
        techniques = context.params.get("techniques", ["split", "timing"])
        
        segments = [(context.payload, 0, {})]  # Start with original payload
        
        # Apply each technique
        for technique in techniques:
            segments = self._apply_technique(segments, technique, context.params)
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name,
            packets_sent=len(segments)
        )
        result.segments = segments
        
        return result

    def _apply_technique(self, segments: list, technique: str, params: dict) -> list:
        """Apply a specific technique to existing segments."""
        if technique == "split":
            # Split each segment further
            new_segments = []
            for payload, offset, options in segments:
                if len(payload) > 10:  # Only split if large enough
                    mid = len(payload) // 2
                    new_segments.append((payload[:mid], offset, options))
                    new_segments.append((payload[mid:], offset + mid, options))
                else:
                    new_segments.append((payload, offset, options))
            return new_segments
        
        elif technique == "timing":
            # Add timing delays
            delay_ms = params.get("delay_ms", 10.0)
            new_segments = []
            for i, (payload, offset, options) in enumerate(segments):
                new_options = options.copy()
                if i > 0:  # Add delay to all but first segment
                    new_options["delay_ms"] = delay_ms
                new_segments.append((payload, offset, new_options))
            return new_segments
        
        elif technique == "ttl":
            # Add TTL manipulation
            ttl_value = params.get("ttl_value", 3)
            new_segments = []
            for payload, offset, options in segments:
                new_options = options.copy()
                new_options["ttl"] = ttl_value
                new_segments.append((payload, offset, new_options))
            return new_segments
        
        return segments


# Example 10: Legacy compatibility wrapper
@register_attack(
    name="legacy_wrapper_example",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.LOW,
    required_params=[],
    optional_params={"legacy_param": "default_value"},
    description="Example of wrapping legacy attack code"
)
class LegacyWrapperAttack(BaseAttack):
    """
    Example of wrapping legacy attack implementations.
    
    This shows how to integrate existing attack code that doesn't
    follow the new BaseAttack interface.
    """

    @property
    def name(self) -> str:
        return "legacy_wrapper_example"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {"legacy_param": "default_value"}

    def execute(self, context: AttackContext) -> AttackResult:
        try:
            # Call legacy attack function (example)
            # legacy_result = some_legacy_attack_function(context.payload, **context.params)
            
            # Convert legacy result to new format
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=1
            )
            
            # If legacy function returns modified payload
            # result.modified_payload = legacy_result
            
            return result
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Legacy attack failed: {e}",
                technique_used=self.name
            )


if __name__ == "__main__":
    # Example usage and testing
    from core.bypass.attacks.attack_registry import get_attack_registry
    
    registry = get_attack_registry()
    
    print("Registered attacks from examples:")
    for attack_name in registry.list_attacks():
        if any(example in attack_name for example in [
            "advanced_tcp_split", "simple_disorder", "tls_sni_fragmentation",
            "http_header_case", "xor_payload", "simple_ttl", "auto_named",
            "core_fakeddisorder", "multi_layer", "legacy_wrapper"
        ]):
            metadata = registry.get_attack_metadata(attack_name)
            print(f"  - {attack_name}: {metadata.description if metadata else 'No metadata'}")