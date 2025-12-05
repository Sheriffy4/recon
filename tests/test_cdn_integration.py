"""
Integration tests for CDN domain payload handling.

This test suite validates the complete workflow of:
1. Capturing ClientHello from parent domain (google.com)
2. Using captured payload in fake attacks against CDN domains (googlevideo.com)
3. Comparing effectiveness with and without proper fake payloads

Requirements: 3.5, 6.5
"""

import asyncio
import pytest
import time
from pathlib import Path
from typing import Optional

from core.payload.capturer import PayloadCapturer, CaptureResult
from core.payload.manager import PayloadManager
from core.payload.validator import PayloadValidator
from core.payload.types import PayloadType
from core.bypass.attacks.tcp.fakeddisorder_attack import (
    FakedDisorderAttack,
    FakedDisorderConfig,
)
from core.bypass.attacks.base import AttackContext, AttackStatus


class TestCDNPayloadIntegration:
    """
    Integration tests for CDN domain payload handling.
    
    Requirements: 3.5, 6.5
    """
    
    @pytest.fixture
    def temp_payload_dir(self, tmp_path):
        """Create temporary payload directory for testing."""
        payload_dir = tmp_path / "payloads" / "captured"
        payload_dir.mkdir(parents=True, exist_ok=True)
        return payload_dir
    
    @pytest.fixture
    def payload_manager(self, temp_payload_dir):
        """Create PayloadManager with temporary directory."""
        manager = PayloadManager(
            payload_dir=temp_payload_dir,
            bundled_dir=Path("data/payloads/bundled")
        )
        # Load existing bundled payloads
        manager.load_all()
        return manager
    
    @pytest.fixture
    def payload_capturer(self):
        """Create PayloadCapturer for testing."""
        return PayloadCapturer(max_retries=2, backoff_base=0.5)
    
    @pytest.fixture
    def validator(self):
        """Create PayloadValidator for testing."""
        return PayloadValidator()
    
    @pytest.mark.asyncio
    async def test_capture_clienthello_from_google(
        self,
        payload_capturer,
        validator,
        payload_manager
    ):
        """
        Test capturing ClientHello from google.com.
        
        Requirements: 3.5
        
        This test verifies:
        - Successful capture from google.com
        - Captured payload is valid TLS ClientHello
        - Payload can be saved to PayloadManager
        
        Note: This test may fail in restricted network environments.
        The test will skip if capture fails, as the other tests verify
        the system works with existing bundled payloads.
        """
        # Capture ClientHello from google.com
        result = await payload_capturer.capture_clienthello(
            "www.google.com",
            timeout=15.0
        )
        
        # If capture failed (network issues), skip the test
        if not result.success:
            pytest.skip(
                f"Could not capture from google.com (network issue): {result.error}. "
                "This is expected in some environments. Other tests verify the system "
                "works with bundled payloads."
            )
        
        # Verify capture succeeded
        assert result.payload is not None
        assert len(result.payload) > 0
        
        # Verify payload is valid TLS ClientHello
        validation = validator.validate_tls_clienthello(result.payload)
        assert validation.valid, f"Invalid TLS ClientHello: {validation.errors}"
        assert validation.payload_type == PayloadType.TLS
        
        # Verify TLS structure
        assert result.payload[0] == 0x16, "Must start with 0x16 (Handshake)"
        assert result.payload[1] == 0x03, "Must have 0x03 (TLS version)"
        assert result.payload[5] == 0x01, "Must have 0x01 (ClientHello)"
        
        # Save to PayloadManager
        payload_info = payload_manager.add_payload(
            data=result.payload,
            payload_type=PayloadType.TLS,
            domain="www.google.com",
            source="captured"
        )
        
        assert payload_info.domain == "www.google.com"
        assert payload_info.payload_type == PayloadType.TLS
        assert payload_info.size == len(result.payload)
        
        print(f"✓ Successfully captured {len(result.payload)} byte ClientHello from google.com")
    
    @pytest.mark.asyncio
    async def test_cdn_domain_uses_parent_payload(
        self,
        payload_manager,
        payload_capturer
    ):
        """
        Test that CDN domains use parent domain payloads.
        
        Requirements: 3.5
        
        This test verifies:
        - googlevideo.com uses google.com payload
        - CDN mapping works correctly
        - Payload retrieval follows CDN hierarchy
        """
        # First, ensure we have a google.com payload
        # Try to get existing bundled payload first
        google_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if google_payload is None:
            # Capture if not available
            result = await payload_capturer.capture_clienthello(
                "www.google.com",
                timeout=15.0
            )
            
            if result.success:
                payload_manager.add_payload(
                    data=result.payload,
                    payload_type=PayloadType.TLS,
                    domain="www.google.com",
                    source="captured"
                )
                google_payload = result.payload
        
        assert google_payload is not None, "Could not obtain google.com payload"
        
        # Now test CDN domain lookup
        cdn_payload = payload_manager.get_payload_for_cdn("googlevideo.com")
        
        assert cdn_payload is not None, "CDN lookup failed for googlevideo.com"
        assert cdn_payload == google_payload, (
            "CDN domain should use parent domain payload"
        )
        
        print(f"✓ googlevideo.com correctly uses google.com payload ({len(cdn_payload)} bytes)")
    
    @pytest.mark.asyncio
    async def test_attack_with_captured_payload(
        self,
        payload_manager,
        payload_capturer
    ):
        """
        Test using captured payload in fake attack.
        
        Requirements: 6.5
        
        This test verifies:
        - Attack can use captured payload
        - Payload integrity is maintained
        - Attack produces valid segments
        """
        # Get or capture google.com payload
        google_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if google_payload is None:
            result = await payload_capturer.capture_clienthello(
                "www.google.com",
                timeout=15.0
            )
            
            if result.success:
                payload_manager.add_payload(
                    data=result.payload,
                    payload_type=PayloadType.TLS,
                    domain="www.google.com",
                    source="captured"
                )
                google_payload = result.payload
        
        assert google_payload is not None, "Could not obtain google.com payload"
        
        # Create attack with captured payload
        config = FakedDisorderConfig(
            split_pos=3,
            fake_ttl=3,
            fake_payload=google_payload,  # Use captured payload directly
            randomize_fake_content=False
        )
        attack = FakedDisorderAttack(config=config)
        
        # Create attack context for googlevideo.com
        context = AttackContext(
            dst_ip="142.250.185.206",  # Example Google IP
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,  # Minimal TLS payload
            domain="googlevideo.com"
        )
        
        # Execute attack
        result = attack.execute(context)
        
        # Verify attack succeeded
        assert result.status == AttackStatus.SUCCESS, f"Attack failed: {result.error_message}"
        assert result.segments is not None
        assert len(result.segments) > 0
        
        # Verify fake payload in first segment
        fake_segment = result.segments[0]
        fake_payload_used = fake_segment[0]
        
        # Payload should be identical to what we provided
        assert fake_payload_used == google_payload, (
            f"Payload integrity violated: expected {len(google_payload)} bytes, "
            f"got {len(fake_payload_used)} bytes"
        )
        
        print(f"✓ Attack successfully used captured payload ({len(google_payload)} bytes)")
    
    @pytest.mark.asyncio
    async def test_compare_with_and_without_proper_payload(
        self,
        payload_manager,
        payload_capturer
    ):
        """
        Compare attack effectiveness with and without proper fake payload.
        
        Requirements: 6.5
        
        This test documents the difference between:
        1. Using default 1400-byte zero payload
        2. Using captured ClientHello from google.com
        
        The hypothesis is that proper ClientHello should be more effective
        against DPI systems that analyze fake packet content.
        """
        # Get or capture google.com payload
        google_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if google_payload is None:
            result = await payload_capturer.capture_clienthello(
                "www.google.com",
                timeout=15.0
            )
            
            if result.success:
                payload_manager.add_payload(
                    data=result.payload,
                    payload_type=PayloadType.TLS,
                    domain="www.google.com",
                    source="captured"
                )
                google_payload = result.payload
        
        # Test context for googlevideo.com
        context = AttackContext(
            dst_ip="142.250.185.206",
            dst_port=443,
            payload=b"\x16\x03\x01\x00\x10" + b"A" * 16,
            domain="googlevideo.com"
        )
        
        # Test 1: Attack with default payload (1400 bytes of zeros)
        default_payload = bytes(1400)
        config_default = FakedDisorderConfig(
            split_pos=3,
            fake_ttl=3,
            fake_payload=default_payload,
            randomize_fake_content=False
        )
        attack_default = FakedDisorderAttack(config=config_default)
        
        start_time = time.time()
        result_default = attack_default.execute(context)
        time_default = (time.time() - start_time) * 1000
        
        # Test 2: Attack with captured google.com payload
        if google_payload:
            config_captured = FakedDisorderConfig(
                split_pos=3,
                fake_ttl=3,
                fake_payload=google_payload,
                randomize_fake_content=False
            )
            attack_captured = FakedDisorderAttack(config=config_captured)
            
            start_time = time.time()
            result_captured = attack_captured.execute(context)
            time_captured = (time.time() - start_time) * 1000
        else:
            result_captured = None
            time_captured = 0
        
        # Document findings
        findings = {
            "default_payload": {
                "size": len(default_payload),
                "status": result_default.status.value,
                "segments": len(result_default.segments) if result_default.segments else 0,
                "execution_time_ms": time_default,
                "description": "1400 bytes of zeros (current implementation)"
            }
        }
        
        if result_captured:
            findings["captured_payload"] = {
                "size": len(google_payload),
                "status": result_captured.status.value,
                "segments": len(result_captured.segments) if result_captured.segments else 0,
                "execution_time_ms": time_captured,
                "description": "Real ClientHello from google.com"
            }
            
            findings["comparison"] = {
                "size_difference": len(google_payload) - len(default_payload),
                "both_succeeded": (
                    result_default.status == AttackStatus.SUCCESS and
                    result_captured.status == AttackStatus.SUCCESS
                ),
                "hypothesis": (
                    "Proper ClientHello should be more effective against DPI "
                    "systems that analyze fake packet content structure"
                )
            }
        
        # Print findings
        print("\n" + "="*70)
        print("PAYLOAD EFFECTIVENESS COMPARISON")
        print("="*70)
        print(f"\nDefault Payload (zeros):")
        print(f"  Size: {findings['default_payload']['size']} bytes")
        print(f"  Status: {findings['default_payload']['status']}")
        print(f"  Segments: {findings['default_payload']['segments']}")
        print(f"  Time: {findings['default_payload']['execution_time_ms']:.2f}ms")
        
        if "captured_payload" in findings:
            print(f"\nCaptured Payload (google.com ClientHello):")
            print(f"  Size: {findings['captured_payload']['size']} bytes")
            print(f"  Status: {findings['captured_payload']['status']}")
            print(f"  Segments: {findings['captured_payload']['segments']}")
            print(f"  Time: {findings['captured_payload']['execution_time_ms']:.2f}ms")
            
            print(f"\nComparison:")
            print(f"  Size difference: {findings['comparison']['size_difference']} bytes")
            print(f"  Both succeeded: {findings['comparison']['both_succeeded']}")
            print(f"\nHypothesis: {findings['comparison']['hypothesis']}")
        
        print("="*70 + "\n")
        
        # Both attacks should at least execute successfully
        assert result_default.status == AttackStatus.SUCCESS
        if result_captured:
            assert result_captured.status == AttackStatus.SUCCESS
        
        # Store findings for documentation
        return findings
    
    @pytest.mark.asyncio
    async def test_multiple_cdn_domains(
        self,
        payload_manager,
        payload_capturer
    ):
        """
        Test payload resolution for multiple CDN domains.
        
        Requirements: 3.5
        
        Verifies that all Google CDN domains correctly map to google.com payload:
        - googlevideo.com
        - ytimg.com
        - ggpht.com
        - googleusercontent.com
        """
        # Get or capture google.com payload
        google_payload = payload_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        if google_payload is None:
            result = await payload_capturer.capture_clienthello(
                "www.google.com",
                timeout=15.0
            )
            
            if result.success:
                payload_manager.add_payload(
                    data=result.payload,
                    payload_type=PayloadType.TLS,
                    domain="www.google.com",
                    source="captured"
                )
                google_payload = result.payload
        
        assert google_payload is not None, "Could not obtain google.com payload"
        
        # Test all CDN domains
        cdn_domains = [
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "googleusercontent.com",
            "gstatic.com",
            "youtube.com",
            "youtu.be"
        ]
        
        for cdn_domain in cdn_domains:
            cdn_payload = payload_manager.get_payload_for_cdn(cdn_domain)
            
            assert cdn_payload is not None, f"Failed to get payload for {cdn_domain}"
            assert cdn_payload == google_payload, (
                f"{cdn_domain} should use google.com payload"
            )
            
            print(f"✓ {cdn_domain} -> google.com payload")
        
        print(f"\n✓ All {len(cdn_domains)} CDN domains correctly mapped to google.com")
    
    @pytest.mark.asyncio
    async def test_payload_persistence(
        self,
        payload_manager,
        payload_capturer,
        temp_payload_dir
    ):
        """
        Test that captured payloads persist across manager instances.
        
        Requirements: 3.5
        
        Verifies:
        - Captured payload is saved to disk
        - New PayloadManager instance can load saved payload
        - Payload content is identical after reload
        """
        # Capture and save payload
        result = await payload_capturer.capture_clienthello(
            "www.google.com",
            timeout=15.0
        )
        
        if not result.success:
            pytest.skip("Could not capture payload for persistence test")
        
        # Save to manager
        payload_info = payload_manager.add_payload(
            data=result.payload,
            payload_type=PayloadType.TLS,
            domain="www.google.com",
            source="captured"
        )
        
        # Verify file exists
        assert payload_info.file_path.exists(), "Payload file not created"
        
        # Create new manager instance
        new_manager = PayloadManager(
            payload_dir=temp_payload_dir,
            bundled_dir=Path("data/payloads/bundled")
        )
        
        # Load payloads
        count = new_manager.load_all()
        assert count > 0, "No payloads loaded by new manager"
        
        # Retrieve payload
        loaded_payload = new_manager.get_payload(
            PayloadType.TLS,
            domain="www.google.com"
        )
        
        assert loaded_payload is not None, "Payload not found after reload"
        assert loaded_payload == result.payload, "Payload content changed after reload"
        
        print(f"✓ Payload persisted and reloaded successfully ({len(loaded_payload)} bytes)")


class TestCDNPayloadDocumentation:
    """
    Documentation tests that capture findings about payload effectiveness.
    
    These tests serve as executable documentation of the payload system's
    behavior and effectiveness.
    """
    
    @pytest.mark.asyncio
    async def test_document_payload_sizes(self):
        """
        Document typical payload sizes for different sources.
        
        This test captures information about:
        - Default payload size (1400 bytes)
        - Typical ClientHello sizes from real sites
        - Size differences and their implications
        """
        manager = PayloadManager(
            payload_dir=Path("data/payloads/captured"),
            bundled_dir=Path("data/payloads/bundled")
        )
        manager.load_all()
        
        # Get default payload
        default_payload = manager.get_default_payload(PayloadType.TLS)
        
        # Get bundled payloads
        bundled_payloads = [
            info for info in manager.list_payloads(PayloadType.TLS)
            if info.source == "bundled"
        ]
        
        print("\n" + "="*70)
        print("PAYLOAD SIZE ANALYSIS")
        print("="*70)
        print(f"\nDefault payload: {len(default_payload)} bytes (zeros)")
        
        if bundled_payloads:
            print(f"\nBundled payloads:")
            for info in bundled_payloads:
                payload = manager.get_payload(PayloadType.TLS, info.domain)
                if payload:
                    print(f"  {info.domain}: {len(payload)} bytes")
        
        print("\nKey findings:")
        print("  - Default payload is fixed at 1400 bytes")
        print("  - Real ClientHello packets are typically 200-600 bytes")
        print("  - Smaller, realistic payloads may be more effective")
        print("  - DPI systems may detect oversized fake packets")
        print("="*70 + "\n")
    
    @pytest.mark.asyncio
    async def test_document_cdn_mappings(self):
        """
        Document CDN domain mappings.
        
        This test captures the CDN hierarchy and how domains map to parent domains.
        """
        manager = PayloadManager()
        
        from core.payload.manager import CDN_MAPPINGS
        
        print("\n" + "="*70)
        print("CDN DOMAIN MAPPINGS")
        print("="*70)
        print("\nCDN domains that use parent domain payloads:")
        
        for cdn_domain, parent_domain in sorted(CDN_MAPPINGS.items()):
            print(f"  {cdn_domain} -> {parent_domain}")
        
        print(f"\nTotal CDN mappings: {len(CDN_MAPPINGS)}")
        print("\nRationale:")
        print("  - CDN subdomains serve content for parent domain")
        print("  - Using parent domain ClientHello maintains consistency")
        print("  - Reduces need to capture payloads for every subdomain")
        print("="*70 + "\n")
