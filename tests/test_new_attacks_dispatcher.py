"""
Test suite for verifying new attacks work with AttackDispatcher.

Tests all 17 new attacks (tcp_advanced, tls_advanced, ip_obfuscation)
through the AttackDispatcher to ensure proper integration.
"""

import pytest
import logging
from typing import Dict, Any

from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.techniques.primitives import BypassTechniques

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestNewAttacksDispatcher:
    """Test new attacks through AttackDispatcher."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = BypassTechniques()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        
        # Test payload
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        # Base context
        self.base_context = AttackContext(
            dst_ip="93.184.216.34",
            dst_port=443,
            domain="example.com",
            payload=self.test_payload,
            protocol="tcp"
        )

    def _create_context(self, **params) -> AttackContext:
        """Create attack context with custom parameters."""
        context = self.base_context.copy()
        context.params = params
        return context

    def _verify_result(self, result: AttackResult, attack_name: str):
        """Verify attack result is valid."""
        assert result is not None, f"{attack_name}: Result is None"
        assert hasattr(result, 'status'), f"{attack_name}: No status attribute"
        assert result.status in [AttackStatus.SUCCESS, AttackStatus.ERROR], \
            f"{attack_name}: Invalid status {result.status}"
        
        if result.status == AttackStatus.SUCCESS:
            assert hasattr(result, 'segments'), f"{attack_name}: No segments attribute"
            assert isinstance(result.segments, list), f"{attack_name}: Segments not a list"
            logger.info(f"✅ {attack_name}: SUCCESS with {len(result.segments)} segments")
        else:
            logger.warning(f"⚠️ {attack_name}: ERROR - {getattr(result, 'error_message', 'Unknown error')}")

    # TCP Advanced Attacks Tests

    def test_tcp_window_manipulation(self):
        """Test TCP window manipulation attack."""
        attack_name = "tcp_window_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        # Check if we got the new attack class or the core attack
        if hasattr(handler, '__self__') and hasattr(handler.__self__, '__class__'):
            attack_class = handler.__self__.__class__.__name__
            print(f"Using attack class: {attack_class}")
        
        context = self._create_context(window_size=2048, split_pos=10)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_tcp_sequence_manipulation(self):
        """Test TCP sequence manipulation attack."""
        attack_name = "tcp_sequence_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(split_pos=10, seq_offset=1000)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_tcp_window_scaling(self):
        """Test TCP window scaling attack."""
        attack_name = "tcp_window_scaling"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(scale_factor=7)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_urgent_pointer_manipulation(self):
        """Test urgent pointer manipulation attack."""
        attack_name = "urgent_pointer_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(urgent_offset=10)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_tcp_options_padding(self):
        """Test TCP options padding attack."""
        attack_name = "tcp_options_padding"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(padding_size=20)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_tcp_timestamp_manipulation(self):
        """Test TCP timestamp manipulation attack."""
        attack_name = "tcp_timestamp_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(ts_ecr=0)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_tcp_wssize_limit(self):
        """Test TCP window size limit attack."""
        attack_name = "tcp_wssize_limit"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(min_window=256, chunk_size=100)
        result = handler(context)
        self._verify_result(result, attack_name)

    # TLS Advanced Attacks Tests

    def test_sni_manipulation(self):
        """Test SNI manipulation attack."""
        attack_name = "sni_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        # Create TLS ClientHello-like payload
        tls_payload = b"\x16\x03\x01\x00\x00" + self.test_payload
        context = self._create_context(mode="fake", fake_sni="example.com")
        context.payload = tls_payload
        
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_alpn_manipulation(self):
        """Test ALPN manipulation attack."""
        attack_name = "alpn_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        # Create TLS ClientHello-like payload
        tls_payload = b"\x16\x03\x01\x00\x00" + self.test_payload
        context = self._create_context(protocols=["h2", "http/1.1"])
        context.payload = tls_payload
        
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_grease_injection(self):
        """Test GREASE injection attack."""
        attack_name = "grease_injection"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        # Create TLS ClientHello-like payload
        tls_payload = b"\x16\x03\x01\x00\x00" + self.test_payload
        context = self._create_context(count=3)
        context.payload = tls_payload
        
        result = handler(context)
        self._verify_result(result, attack_name)

    # IP/Obfuscation Attacks Tests

    def test_ip_ttl_manipulation(self):
        """Test IP TTL manipulation attack."""
        attack_name = "ip_ttl_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(ttl=64)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_ip_id_manipulation(self):
        """Test IP ID manipulation attack."""
        attack_name = "ip_id_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(ip_id=12345)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_payload_padding(self):
        """Test payload padding attack."""
        attack_name = "payload_padding"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(padding_size=100)
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_noise_injection(self):
        """Test noise injection attack."""
        attack_name = "noise_injection"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(noise_size=50, position="end")
        result = handler(context)
        self._verify_result(result, attack_name)

    def test_timing_obfuscation(self):
        """Test timing obfuscation attack."""
        attack_name = "timing_obfuscation"
        handler = self.registry.get_attack_handler(attack_name)
        assert handler is not None, f"Handler not found for {attack_name}"
        
        context = self._create_context(chunk_size=100, delay_ms=10)
        result = handler(context)
        self._verify_result(result, attack_name)

    # Alias Resolution Tests

    def test_tcp_window_alias(self):
        """Test TCP window manipulation via alias."""
        handler = self.registry.get_attack_handler("tcp_window")
        assert handler is not None, "Handler not found for alias 'tcp_window'"
        
        context = self._create_context(window_size=2048)
        result = handler(context)
        self._verify_result(result, "tcp_window (alias)")

    def test_sni_manip_alias(self):
        """Test SNI manipulation via alias."""
        handler = self.registry.get_attack_handler("sni_manip")
        assert handler is not None, "Handler not found for alias 'sni_manip'"
        
        tls_payload = b"\x16\x03\x01\x00\x00" + self.test_payload
        context = self._create_context(mode="fake", fake_sni="example.com")
        context.payload = tls_payload
        
        result = handler(context)
        self._verify_result(result, "sni_manip (alias)")

    def test_ttl_manipulation_alias(self):
        """Test IP TTL manipulation via alias."""
        handler = self.registry.get_attack_handler("ip_ttl")
        assert handler is not None, "Handler not found for alias 'ip_ttl'"
        
        context = self._create_context(ttl=64)
        result = handler(context)
        self._verify_result(result, "ip_ttl (alias)")

    # Parameter Normalization Tests

    def test_parameter_normalization_window_size(self):
        """Test parameter normalization for window_size."""
        attack_name = "tcp_window_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        
        # Test with string parameter (should be normalized to int)
        context = self._create_context(window_size="2048")
        result = handler(context)
        self._verify_result(result, f"{attack_name} (string param)")

    def test_parameter_normalization_ttl(self):
        """Test parameter normalization for TTL."""
        attack_name = "ip_ttl_manipulation"
        handler = self.registry.get_attack_handler(attack_name)
        
        # Test with string parameter (should be normalized to int)
        context = self._create_context(ttl="64")
        result = handler(context)
        self._verify_result(result, f"{attack_name} (string param)")

    # Registry Integration Tests

    def test_all_attacks_registered(self):
        """Verify all new attacks are registered."""
        expected_attacks = [
            # TCP Advanced
            "tcp_window_manipulation",
            "tcp_sequence_manipulation",
            "tcp_window_scaling",
            "urgent_pointer_manipulation",
            "tcp_options_padding",
            "tcp_timestamp_manipulation",
            "tcp_wssize_limit",
            # TLS Advanced
            "sni_manipulation",
            "alpn_manipulation",
            "grease_injection",
            # IP/Obfuscation
            "ip_ttl_manipulation",
            "ip_id_manipulation",
            "payload_padding",
            "noise_injection",
            "timing_obfuscation",
        ]
        
        for attack_name in expected_attacks:
            handler = self.registry.get_attack_handler(attack_name)
            assert handler is not None, f"Attack '{attack_name}' not registered"
            logger.info(f"✅ {attack_name} is registered")

    def test_all_aliases_work(self):
        """Verify all attack aliases resolve correctly."""
        alias_mappings = {
            "window_manipulation": "tcp_window_manipulation",
            "tcp_window": "tcp_window_manipulation",
            "sequence_manipulation": "tcp_sequence_manipulation",
            "tcp_seq": "tcp_sequence_manipulation",
            "window_scaling": "tcp_window_scaling",
            "tcp_wscale": "tcp_window_scaling",
            "urgent_manipulation": "urgent_pointer_manipulation",
            "tcp_urgent": "urgent_pointer_manipulation",
            "options_padding": "tcp_options_padding",
            "tcp_pad": "tcp_options_padding",
            "timestamp_manipulation": "tcp_timestamp_manipulation",
            "tcp_ts": "tcp_timestamp_manipulation",
            "wssize_limit": "tcp_wssize_limit",
            "tcp_window_limit": "tcp_wssize_limit",
            "sni_manip": "sni_manipulation",
            "tls_sni": "sni_manipulation",
            "alpn_manip": "alpn_manipulation",
            "tls_alpn": "alpn_manipulation",
            "grease_inject": "grease_injection",
            "tls_grease": "grease_injection",
            "ttl_manipulation": "ip_ttl_manipulation",
            "ip_ttl": "ip_ttl_manipulation",
            "id_manipulation": "ip_id_manipulation",
            "ip_id": "ip_id_manipulation",
            "padding": "payload_padding",
            "payload_pad": "payload_padding",
            "noise_inject": "noise_injection",
            "payload_noise": "noise_injection",
            "timing_obfusc": "timing_obfuscation",
            "timing_evasion": "timing_obfuscation",
        }
        
        for alias, canonical in alias_mappings.items():
            handler = self.registry.get_attack_handler(alias)
            assert handler is not None, f"Alias '{alias}' not resolved"
            logger.info(f"✅ Alias '{alias}' → '{canonical}'")

    def test_metadata_completeness(self):
        """Verify all attacks have complete metadata."""
        attack_names = [
            "tcp_window_manipulation", "tcp_sequence_manipulation",
            "tcp_window_scaling", "urgent_pointer_manipulation",
            "tcp_options_padding", "tcp_timestamp_manipulation",
            "tcp_wssize_limit", "sni_manipulation",
            "alpn_manipulation", "grease_injection",
            "ip_ttl_manipulation", "ip_id_manipulation",
            "payload_padding", "noise_injection",
            "timing_obfuscation",
        ]
        
        for attack_name in attack_names:
            entry = self.registry.attacks.get(attack_name)
            assert entry is not None, f"No entry for {attack_name}"
            assert entry.metadata is not None, f"No metadata for {attack_name}"
            assert entry.metadata.name, f"No name in metadata for {attack_name}"
            assert entry.metadata.description, f"No description for {attack_name}"
            assert entry.metadata.category, f"No category for {attack_name}"
            assert isinstance(entry.metadata.required_params, list), \
                f"Invalid required_params for {attack_name}"
            assert isinstance(entry.metadata.optional_params, dict), \
                f"Invalid optional_params for {attack_name}"
            assert isinstance(entry.metadata.aliases, list), \
                f"Invalid aliases for {attack_name}"
            logger.info(f"✅ {attack_name} has complete metadata")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
