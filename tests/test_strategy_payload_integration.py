"""
Property-based tests for Strategy Payload Integration.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 4: Strategy Generation Includes Payloads**
"""

import pytest
import tempfile
import shutil
from contextlib import contextmanager
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.payload.strategy_integration import (
    StrategyPayloadIntegration,
    create_payload_enhanced_strategies,
)
from core.payload.manager import PayloadManager
from core.payload.types import PayloadType
from core.payload.serializer import PayloadSerializer


def create_valid_tls_clienthello(random_bytes: bytes) -> bytes:
    """
    Create a valid TLS ClientHello structure with random content.
    
    Structure:
    - Byte 0: 0x16 (Handshake)
    - Bytes 1-2: 0x03 0x01 (TLS 1.0 version)
    - Bytes 3-4: Length (big-endian)
    - Byte 5: 0x01 (ClientHello handshake type)
    - Rest: random content
    """
    # Minimum content after header
    content = random_bytes if len(random_bytes) >= 38 else random_bytes + bytes(38 - len(random_bytes))
    
    # Build TLS record
    # Handshake content: type (1) + length (3) + content
    handshake_length = len(content)
    handshake = bytes([0x01]) + handshake_length.to_bytes(3, 'big') + content
    
    # TLS record: type (1) + version (2) + length (2) + handshake
    record_length = len(handshake)
    tls_record = bytes([0x16, 0x03, 0x01]) + record_length.to_bytes(2, 'big') + handshake
    
    return tls_record


@contextmanager
def temp_payload_dirs():
    """Context manager for temporary payload directories."""
    temp_dir = tempfile.mkdtemp()
    payload_dir = Path(temp_dir) / "captured"
    bundled_dir = Path(temp_dir) / "bundled"
    payload_dir.mkdir(parents=True)
    bundled_dir.mkdir(parents=True)
    
    try:
        yield payload_dir, bundled_dir
    finally:
        shutil.rmtree(temp_dir)


# Strategy generators for property tests
@st.composite
def fake_attack_strategy(draw):
    """Generate a strategy dictionary that supports fake payloads."""
    attack_types = [
        "fake",
        "fake_disorder",
        "fake,disorder",
        "fake,fakeddisorder",
        "fake,multidisorder",
        "fake,split",
    ]
    
    strategy = {
        "type": draw(st.sampled_from(attack_types)),
        "ttl": draw(st.integers(min_value=1, max_value=128)),
        "split_pos": draw(st.integers(min_value=1, max_value=20)),
        "no_fallbacks": True,
        "forced": True,
    }
    
    # Optionally add more parameters
    if draw(st.booleans()):
        strategy["fooling"] = draw(st.sampled_from(["badsum", "badseq", "md5sig"]))
    
    if draw(st.booleans()):
        strategy["repeats"] = draw(st.integers(min_value=1, max_value=5))
    
    return strategy


@st.composite
def non_fake_attack_strategy(draw):
    """Generate a strategy dictionary that does NOT support fake payloads."""
    attack_types = [
        "multisplit",
        "sequence_overlap",
        "badsum_race",
        "md5sig_race",
        "window_manipulation",
    ]
    
    strategy = {
        "type": draw(st.sampled_from(attack_types)),
        "ttl": draw(st.integers(min_value=1, max_value=128)),
        "no_fallbacks": True,
        "forced": True,
    }
    
    return strategy


class TestStrategyGenerationIncludesPayloads:
    """
    Property-based tests for strategy generation with payloads.
    
    **Feature: fake-payload-generation, Property 4: Strategy Generation Includes Payloads**
    **Validates: Requirements 3.1**
    
    Property: For any strategy generated in auto mode for TLS traffic, 
    the strategy MUST include fake-tls parameter with valid payload reference.
    """
    
    @given(
        strategy=fake_attack_strategy(),
        random_content=st.binary(min_size=38, max_size=200)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_fake_attack_strategies_include_payload(self, strategy, random_content):
        """
        **Feature: fake-payload-generation, Property 4: Strategy Generation Includes Payloads**
        **Validates: Requirements 3.1**
        
        Property: For any strategy with a fake attack type, when enhanced with
        payloads, the result MUST include a fake_tls parameter.
        """
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create a TLS payload
            payload_bytes = create_valid_tls_clienthello(random_content)
            payload_file = bundled_dir / "tls_clienthello_test_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            # Create manager and integration
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            integration = StrategyPayloadIntegration(payload_manager=manager)
            
            # Enhance strategy with payload
            enhanced = integration.add_fake_tls_to_strategy(strategy, domain="test.com")
            
            # Strategy MUST include fake_tls parameter
            assert "fake_tls" in enhanced or "fake_payload" in enhanced, (
                f"Enhanced strategy must include fake_tls or fake_payload parameter. "
                f"Strategy type: {strategy.get('type')}"
            )
            
            # The payload reference must be valid (not empty)
            payload_ref = enhanced.get("fake_tls") or enhanced.get("fake_payload")
            assert payload_ref is not None and len(str(payload_ref)) > 0, (
                "Payload reference must not be empty"
            )
    
    @given(
        strategy=fake_attack_strategy(),
        random_content=st.binary(min_size=38, max_size=200)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_payload_variations_all_have_valid_references(self, strategy, random_content):
        """
        **Feature: fake-payload-generation, Property 4: Strategy Generation Includes Payloads**
        **Validates: Requirements 3.1**
        
        Property: For any strategy variations generated, each variation with
        a payload MUST have a valid payload reference (hex, file, or placeholder).
        """
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create a TLS payload
            payload_bytes = create_valid_tls_clienthello(random_content)
            payload_file = bundled_dir / "tls_clienthello_example_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            # Create manager and integration
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            integration = StrategyPayloadIntegration(payload_manager=manager)
            serializer = PayloadSerializer()
            
            # Generate variations
            variations = integration.generate_payload_variations(
                strategy, domain="example.com", max_variations=3
            )
            
            # Must have at least one variation
            assert len(variations) >= 1, "Must generate at least one variation"
            
            # Check each variation with payload
            for var in variations:
                if integration.strategy_has_payload(var):
                    payload_ref = var.get("fake_tls") or var.get("fake_payload")
                    
                    # Payload reference must be valid type
                    is_valid = (
                        serializer.is_hex_string(payload_ref) or
                        serializer.is_placeholder(payload_ref) or
                        serializer.is_file_path(payload_ref)
                    )
                    
                    assert is_valid, (
                        f"Payload reference '{payload_ref}' must be valid hex, "
                        f"placeholder, or file path"
                    )
    
    @given(strategy=fake_attack_strategy())
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_enhance_strategies_preserves_original_params(self, strategy):
        """
        **Feature: fake-payload-generation, Property 4: Strategy Generation Includes Payloads**
        **Validates: Requirements 3.1**
        
        Property: When enhancing a strategy with payloads, all original
        parameters MUST be preserved in the enhanced strategy.
        """
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create a TLS payload
            payload_bytes = create_valid_tls_clienthello(b"test content")
            payload_file = bundled_dir / "tls_clienthello_test_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            # Create manager and integration
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            integration = StrategyPayloadIntegration(payload_manager=manager)
            
            # Enhance single strategy (no variations to avoid duplicates)
            enhanced = integration.add_fake_tls_to_strategy(strategy, domain="test.com")
            
            # All original params must be present and unchanged
            for key, value in strategy.items():
                assert key in enhanced, (
                    f"Original parameter '{key}' must be preserved"
                )
                assert enhanced[key] == value, (
                    f"Original parameter '{key}' value must be preserved. "
                    f"Expected {value}, got {enhanced[key]}"
                )


class TestStrategyPayloadIntegrationBasics:
    """Unit tests for basic StrategyPayloadIntegration operations."""
    
    def test_get_payload_for_cdn_domain(self):
        """Test payload retrieval for CDN domains."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create google.com payload
            payload_bytes = create_valid_tls_clienthello(b"google payload")
            payload_file = bundled_dir / "tls_clienthello_www_google_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            integration = StrategyPayloadIntegration(payload_manager=manager)
            
            # googlevideo.com should get google.com payload
            result = integration.get_payload_for_domain("googlevideo.com")
            assert result == payload_bytes
    
    def test_strategy_has_payload_detection(self):
        """Test detection of payload in strategy."""
        integration = StrategyPayloadIntegration()
        
        # Strategy with fake_tls
        with_tls = {"type": "fake", "fake_tls": "0x1603"}
        assert integration.strategy_has_payload(with_tls) is True
        
        # Strategy with fake_payload
        with_payload = {"type": "fake", "fake_payload": "PAYLOADTLS"}
        assert integration.strategy_has_payload(with_payload) is True
        
        # Strategy without payload
        without = {"type": "fake", "ttl": 3}
        assert integration.strategy_has_payload(without) is False
    
    def test_format_strategy_for_zapret(self):
        """Test zapret command line formatting."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            integration = StrategyPayloadIntegration(payload_manager=manager)
            
            strategy = {
                "type": "fake,disorder",
                "ttl": 3,
                "split_pos": 5,
                "fooling": "badsum",
                "fake_tls": "0x1603",
            }
            
            result = integration.format_strategy_for_zapret(strategy)
            
            assert "--dpi-desync=fake,disorder" in result
            assert "--dpi-desync-ttl=3" in result
            assert "--dpi-desync-split-pos=5" in result
            assert "--dpi-desync-fooling=badsum" in result
            assert "--dpi-desync-fake-tls=0x1603" in result
    
    def test_get_strategy_payload_info_hex(self):
        """Test payload info extraction for hex strings."""
        integration = StrategyPayloadIntegration()
        
        strategy = {"type": "fake", "fake_tls": "0x160301"}
        info = integration.get_strategy_payload_info(strategy)
        
        assert info is not None
        assert info["type"] == "hex"
        assert info["source"] == "inline"
    
    def test_get_strategy_payload_info_placeholder(self):
        """Test payload info extraction for placeholders."""
        integration = StrategyPayloadIntegration()
        
        strategy = {"type": "fake", "fake_tls": "PAYLOADTLS"}
        info = integration.get_strategy_payload_info(strategy)
        
        assert info is not None
        assert info["type"] == "placeholder"
        assert info["source"] == "placeholder"
    
    def test_non_fake_strategies_not_modified(self):
        """Test that non-fake strategies are not modified with payloads."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create a payload
            payload_bytes = create_valid_tls_clienthello(b"test")
            payload_file = bundled_dir / "tls_clienthello_test_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            integration = StrategyPayloadIntegration(payload_manager=manager)
            
            # Non-fake strategies (these don't use "fake" in their type)
            non_fake_strategies = [
                {"type": "multisplit", "split_count": 3},
                {"type": "sequence_overlap", "split_seqovl": 10},
                {"type": "badsum_race", "ttl": 4},
                {"type": "md5sig_race", "ttl": 6},
            ]
            
            for strategy in non_fake_strategies:
                # Generate variations - should return original since it doesn't support fake
                variations = integration.generate_payload_variations(strategy)
                
                # Should have exactly one variation (the original)
                assert len(variations) == 1, (
                    f"Non-fake strategy '{strategy['type']}' should have exactly 1 variation, "
                    f"got {len(variations)}"
                )
                assert variations[0] == strategy, (
                    f"Non-fake strategy '{strategy['type']}' should not be modified"
                )


class TestCreatePayloadEnhancedStrategies:
    """Tests for the convenience function."""
    
    def test_convenience_function_works(self):
        """Test that create_payload_enhanced_strategies works correctly."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create a payload
            payload_bytes = create_valid_tls_clienthello(b"convenience test")
            payload_file = bundled_dir / "tls_clienthello_test_com.bin"
            payload_file.write_bytes(payload_bytes)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            base_strategies = [
                {"type": "fake", "ttl": 3},
                {"type": "fake_disorder", "ttl": 5, "split_pos": 3},
            ]
            
            enhanced = create_payload_enhanced_strategies(
                base_strategies,
                domain="test.com",
                payload_manager=manager
            )
            
            # Should have more strategies than original (due to variations)
            assert len(enhanced) >= len(base_strategies)
            
            # At least some should have payloads
            with_payloads = [s for s in enhanced if "fake_tls" in s or "fake_payload" in s]
            assert len(with_payloads) > 0
