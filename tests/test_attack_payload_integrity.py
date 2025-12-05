"""
Property-based tests for payload integrity in attack classes.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
**Validates: Requirements 6.2**
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from core.payload.attack_integration import (
    AttackPayloadProvider,
    get_attack_payload,
)
from core.payload.types import PayloadType
from core.payload.manager import PayloadManager


class TestPayloadIntegrityInAttacks:
    """
    Property-based tests for payload integrity in attack execution.
    
    **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
    **Validates: Requirements 6.2**
    
    Property: For any payload passed to an Attack class, the bytes used in 
    the attack MUST be identical to the source payload (no modification).
    """
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_direct_bytes_payload_unchanged(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
        **Validates: Requirements 6.2**
        
        Property: When a direct bytes payload is provided, the resolved payload
        MUST be identical to the input bytes.
        """
        provider = AttackPayloadProvider()
        
        # Resolve payload from direct bytes
        resolved = provider.resolve_payload(
            payload_param=payload_bytes,
            payload_type=PayloadType.TLS,
            domain=None
        )
        
        # Must be identical
        assert resolved == payload_bytes, (
            f"Payload integrity violated: original {len(payload_bytes)} bytes, "
            f"resolved {len(resolved)} bytes"
        )
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_hex_payload_unchanged(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
        **Validates: Requirements 6.2**
        
        Property: When a hex string payload is provided, the resolved payload
        MUST be identical to the original bytes.
        """
        provider = AttackPayloadProvider()
        
        # Convert to hex string
        hex_str = "0x" + payload_bytes.hex()
        
        # Resolve payload from hex string
        resolved = provider.resolve_payload(
            payload_param=hex_str,
            payload_type=PayloadType.TLS,
            domain=None
        )
        
        # Must be identical to original bytes
        assert resolved == payload_bytes, (
            f"Hex payload integrity violated: original {len(payload_bytes)} bytes, "
            f"resolved {len(resolved)} bytes"
        )
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_verify_payload_integrity_detects_changes(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
        **Validates: Requirements 6.2**
        
        Property: verify_payload_integrity() MUST return True only when
        original and used payloads are identical.
        """
        provider = AttackPayloadProvider()
        
        # Same payload should pass
        assert provider.verify_payload_integrity(payload_bytes, payload_bytes)
        
        # Different payload should fail
        if len(payload_bytes) > 0:
            # Modify one byte
            modified = bytearray(payload_bytes)
            modified[0] = (modified[0] + 1) % 256
            modified = bytes(modified)
            
            assert not provider.verify_payload_integrity(payload_bytes, modified), (
                "verify_payload_integrity should detect modified payload"
            )
    
    @given(payload_bytes=st.binary(min_size=1, max_size=2000))
    @settings(max_examples=100)
    def test_convenience_function_preserves_payload(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
        **Validates: Requirements 6.2**
        
        Property: get_attack_payload() convenience function MUST preserve
        payload bytes when direct bytes are provided.
        """
        # Use convenience function
        resolved = get_attack_payload(
            payload_param=payload_bytes,
            payload_type=PayloadType.TLS,
            domain=None
        )
        
        # Must be identical
        assert resolved == payload_bytes, (
            f"Convenience function violated payload integrity"
        )


class TestPayloadResolutionFallback:
    """
    Tests for payload resolution fallback behavior.
    
    Requirements: 6.4
    """
    
    def test_fallback_to_default_when_not_found(self, tmp_path):
        """
        Property: When payload cannot be resolved, default payload should be returned.
        
        Requirements: 6.4
        """
        # Create an empty manager to ensure no payloads are available
        empty_manager = PayloadManager(
            payload_dir=tmp_path / "empty_captured",
            bundled_dir=tmp_path / "empty_bundled"
        )
        empty_manager.load_all()  # Load nothing
        
        provider = AttackPayloadProvider(payload_manager=empty_manager)
        
        # Request with no payload param and empty manager
        resolved = provider.resolve_payload(
            payload_param=None,
            payload_type=PayloadType.TLS,
            domain="nonexistent.domain.com",
            use_default_on_failure=True
        )
        
        # Should return default payload (zeros)
        assert resolved is not None
        assert len(resolved) > 0
        assert all(b == 0 for b in resolved)
    
    def test_raises_when_not_found_and_no_fallback(self, tmp_path):
        """
        Property: When payload cannot be resolved and fallback disabled, 
        should raise ValueError.
        
        Requirements: 6.4
        """
        # Create an empty manager to ensure no payloads are available
        empty_manager = PayloadManager(
            payload_dir=tmp_path / "empty_captured",
            bundled_dir=tmp_path / "empty_bundled"
        )
        empty_manager.load_all()  # Load nothing
        
        provider = AttackPayloadProvider(payload_manager=empty_manager)
        
        with pytest.raises(ValueError):
            provider.resolve_payload(
                payload_param=None,
                payload_type=PayloadType.TLS,
                domain="nonexistent.domain.com",
                use_default_on_failure=False
            )
    
    @given(size=st.integers(min_value=100, max_value=2000))
    @settings(max_examples=20)
    def test_default_payload_has_correct_size(self, size):
        """
        Property: Default payload should have the configured size.
        
        Requirements: 6.4
        """
        provider = AttackPayloadProvider(default_payload_size=size)
        
        default = provider.get_default_payload()
        
        assert len(default) == size
        assert all(b == 0 for b in default)


class TestAttackPayloadIntegration:
    """
    Integration tests for attack payload system.
    
    These tests verify the integration between PayloadManager and attack classes.
    """
    
    @given(payload_bytes=st.binary(min_size=10, max_size=500))
    @settings(max_examples=50)
    def test_attack_uses_provided_payload_without_modification(self, payload_bytes):
        """
        **Feature: fake-payload-generation, Property 5: Payload Integrity in Attacks**
        **Validates: Requirements 6.2**
        
        Property: When FakedDisorderAttack is configured with a fake_payload,
        the attack MUST use that exact payload without modification.
        """
        # Import here to avoid circular imports during test collection
        from core.bypass.attacks.tcp.fakeddisorder_attack import (
            FakedDisorderAttack,
            FakedDisorderConfig,
        )
        from core.bypass.attacks.base import AttackContext
        
        # Create attack with custom payload
        config = FakedDisorderConfig(
            fake_payload=payload_bytes,
            randomize_fake_content=False  # Disable randomization
        )
        attack = FakedDisorderAttack(config=config)
        
        # Create context with some payload
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,  # Minimal TLS-like payload
            domain="test.example.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Verify the fake payload in segments
        assert result.segments is not None, "Attack should produce segments"
        assert len(result.segments) > 0, "Attack should have at least one segment"
        
        # First segment should be the fake packet with our payload
        fake_segment = result.segments[0]
        fake_payload_used = fake_segment[0]
        
        # The fake payload should be identical to what we provided
        assert fake_payload_used == payload_bytes, (
            f"Attack modified the payload: expected {len(payload_bytes)} bytes, "
            f"got {len(fake_payload_used)} bytes"
        )
    
    def test_attack_falls_back_to_manager_when_no_explicit_payload(self):
        """
        Property: When no explicit payload is provided, attack should use
        PayloadManager to get a payload.
        
        Requirements: 6.1
        """
        from core.bypass.attacks.tcp.fakeddisorder_attack import (
            FakedDisorderAttack,
            FakedDisorderConfig,
        )
        from core.bypass.attacks.base import AttackContext
        
        # Create attack without explicit payload
        config = FakedDisorderConfig(
            fake_payload=None,
            fake_tls="PAYLOADTLS"  # Use placeholder
        )
        attack = FakedDisorderAttack(config=config)
        
        # Create context
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="google.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Should succeed and produce segments
        assert result.segments is not None
        assert len(result.segments) > 0
        
        # First segment should have some payload (from manager or built-in)
        fake_segment = result.segments[0]
        fake_payload = fake_segment[0]
        assert len(fake_payload) > 0, "Attack should have a fake payload"
