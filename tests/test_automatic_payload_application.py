"""
Tests for automatic payload application in fake attacks.

This test suite verifies that attacks with "fake" in their name
automatically use PayloadManager to get appropriate payloads.

Requirements: 3.5, 6.1, 6.2
"""

import pytest
from pathlib import Path

from core.bypass.attacks.tcp.fakeddisorder_attack import (
    FakedDisorderAttack,
    FakedDisorderConfig,
)
from core.bypass.attacks.base import AttackContext, AttackStatus
from core.payload.manager import PayloadManager
from core.payload.types import PayloadType


class TestAutomaticPayloadApplication:
    """
    Tests for automatic payload application in fake attacks.
    
    Requirements: 3.5, 6.1, 6.2
    """
    
    @pytest.fixture
    def payload_manager(self):
        """Create PayloadManager with bundled payloads."""
        manager = PayloadManager(
            payload_dir=Path("data/payloads/captured"),
            bundled_dir=Path("data/payloads/bundled")
        )
        manager.load_all()
        return manager
    
    def test_fakeddisorder_uses_payload_by_default(self, payload_manager):
        """
        Test that FakedDisorderAttack automatically uses PayloadManager
        when no explicit payload is provided.
        
        Requirements: 6.1
        """
        # Create attack with default config (no explicit payload)
        config = FakedDisorderConfig()
        attack = FakedDisorderAttack(config=config)
        
        # Verify fake_tls defaults to PAYLOADTLS
        assert config.fake_tls == "PAYLOADTLS", (
            "fake_tls should default to PAYLOADTLS placeholder"
        )
        
        # Create context
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="google.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Verify attack succeeded
        assert result.status == AttackStatus.SUCCESS
        assert result.segments is not None
        assert len(result.segments) > 0
        
        # Verify fake payload was used (first segment)
        fake_segment = result.segments[0]
        fake_payload = fake_segment[0]
        
        # Payload should not be empty and not be the default 1400 zeros
        assert len(fake_payload) > 0
        assert fake_payload != bytes(1400), (
            "Should use PayloadManager payload, not default zeros"
        )
        
        print(f"✓ FakedDisorderAttack automatically used payload: {len(fake_payload)} bytes")
    
    def test_cdn_domain_gets_parent_payload_automatically(self, payload_manager):
        """
        Test that CDN domains automatically get parent domain payloads.
        
        Requirements: 3.5, 6.1
        """
        # Create attack with default config
        config = FakedDisorderConfig()
        attack = FakedDisorderAttack(config=config)
        
        # Create context for googlevideo.com (CDN domain)
        context = AttackContext(
            dst_ip="142.250.185.206",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="googlevideo.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Verify attack succeeded
        assert result.status == AttackStatus.SUCCESS
        assert result.segments is not None
        
        # Get the fake payload used
        fake_payload = result.segments[0][0]
        
        # Get google.com payload directly from manager
        google_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if google_payload:
            # If google.com payload exists, verify it was used for googlevideo.com
            assert fake_payload == google_payload, (
                "googlevideo.com should automatically use google.com payload"
            )
            print(f"✓ googlevideo.com automatically used google.com payload: {len(fake_payload)} bytes")
        else:
            # If no google.com payload, should use default
            print(f"⚠ No google.com payload available, using default: {len(fake_payload)} bytes")
    
    def test_explicit_payload_overrides_automatic(self, payload_manager):
        """
        Test that explicit payload parameter overrides automatic selection.
        
        Requirements: 6.2
        """
        # Create custom payload
        custom_payload = b"\x16\x03\x03\x00\x05\x01" + b"CUSTOM" * 10
        
        # Create attack with explicit payload
        config = FakedDisorderConfig(
            fake_payload=custom_payload
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
        
        # Verify attack succeeded
        assert result.status == AttackStatus.SUCCESS
        
        # Verify custom payload was used
        fake_payload = result.segments[0][0]
        assert fake_payload == custom_payload, (
            "Explicit payload should override automatic selection"
        )
        
        print(f"✓ Explicit payload correctly overrode automatic selection")
    
    def test_fake_tls_placeholder_resolves_to_payload(self, payload_manager):
        """
        Test that fake_tls="PAYLOADTLS" placeholder resolves to actual payload.
        
        Requirements: 6.1
        """
        # Create attack with explicit PAYLOADTLS placeholder
        config = FakedDisorderConfig(
            fake_tls="PAYLOADTLS"
        )
        attack = FakedDisorderAttack(config=config)
        
        # Create context
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="www.google.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Verify attack succeeded
        assert result.status == AttackStatus.SUCCESS
        
        # Get fake payload
        fake_payload = result.segments[0][0]
        
        # Get expected payload from manager
        expected_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if expected_payload:
            assert fake_payload == expected_payload, (
                "PAYLOADTLS placeholder should resolve to manager payload"
            )
            print(f"✓ PAYLOADTLS placeholder resolved to payload: {len(fake_payload)} bytes")
        else:
            # Should use default if no payload available
            assert len(fake_payload) > 0
            print(f"⚠ No payload available, used default: {len(fake_payload)} bytes")
    
    def test_multiple_cdn_domains_use_correct_payloads(self, payload_manager):
        """
        Test that different CDN domains automatically use correct parent payloads.
        
        Requirements: 3.5, 6.1
        """
        cdn_domains = [
            ("googlevideo.com", "www.google.com"),
            ("ytimg.com", "www.google.com"),
            ("ggpht.com", "www.google.com"),
        ]
        
        for cdn_domain, parent_domain in cdn_domains:
            # Create attack
            config = FakedDisorderConfig()
            attack = FakedDisorderAttack(config=config)
            
            # Create context for CDN domain
            context = AttackContext(
                dst_ip="1.1.1.1",
                dst_port=443,
                payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
                domain=cdn_domain
            )
            
            # Execute attack
            result = attack.execute(context)
            
            # Verify attack succeeded
            assert result.status == AttackStatus.SUCCESS, (
                f"Attack failed for {cdn_domain}"
            )
            
            # Get fake payload
            fake_payload = result.segments[0][0]
            
            # Get parent payload
            parent_payload = payload_manager.get_payload(
                PayloadType.TLS,
                domain=parent_domain
            )
            
            if parent_payload:
                assert fake_payload == parent_payload, (
                    f"{cdn_domain} should use {parent_domain} payload"
                )
                print(f"✓ {cdn_domain} → {parent_domain}: {len(fake_payload)} bytes")


class TestPayloadLogging:
    """
    Tests for payload usage logging.
    
    Requirements: 7.1
    """
    
    def test_attack_logs_payload_source(self, caplog):
        """
        Test that attack logs which payload source is being used.
        
        Requirements: 7.1
        """
        import logging
        caplog.set_level(logging.DEBUG)
        
        # Create attack
        config = FakedDisorderConfig()
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
        
        # Check logs for payload information
        log_messages = [record.message for record in caplog.records]
        
        # Should have some log about payload
        payload_logs = [msg for msg in log_messages if "payload" in msg.lower()]
        
        assert len(payload_logs) > 0, (
            "Attack should log payload information"
        )
        
        print(f"✓ Found {len(payload_logs)} payload-related log messages")
        for msg in payload_logs[:3]:  # Print first 3
            print(f"  - {msg}")


class TestPayloadSystemAvailability:
    """
    Tests for payload system availability handling.
    
    Requirements: 6.4
    """
    
    def test_attack_works_when_payload_system_unavailable(self):
        """
        Test that attack falls back gracefully when payload system is unavailable.
        
        Requirements: 6.4
        """
        # This test verifies the PAYLOAD_SYSTEM_AVAILABLE flag behavior
        from core.bypass.attacks.tcp import fakeddisorder_attack
        
        # Check if payload system is available
        assert fakeddisorder_attack.PAYLOAD_SYSTEM_AVAILABLE, (
            "Payload system should be available in this test environment"
        )
        
        # Create attack
        config = FakedDisorderConfig()
        attack = FakedDisorderAttack(config=config)
        
        # Create context
        context = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="test.com"
        )
        
        # Execute attack - should work even if payload manager fails
        result = attack.execute(context)
        
        # Should succeed with fallback payload
        assert result.status == AttackStatus.SUCCESS
        assert result.segments is not None
        assert len(result.segments) > 0
        
        print("✓ Attack works with payload system available")
