"""
Test suite for refactored protocol tunneling attacks.

This test suite validates that all refactored attack classes work correctly
and maintain backward compatibility.
"""

import pytest
import asyncio
from core.bypass.attacks.obfuscation.protocol_tunneling import (
    HTTPTunnelingObfuscationAttack,
    DNSOverHTTPSTunnelingAttack,
    WebSocketTunnelingObfuscationAttack,
    SSHTunnelingObfuscationAttack,
    VPNTunnelingObfuscationAttack,
)
from core.bypass.attacks.obfuscation import tunneling_utils
from core.bypass.attacks.base import AttackContext, AttackStatus


class TestHTTPTunnelingObfuscationAttack:
    """Test HTTP tunneling attack."""

    @pytest.mark.asyncio
    async def test_http_post_attack(self):
        """Test HTTP POST attack execution."""
        attack = HTTPTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"test payload",
            params={"method": "POST", "obfuscation_level": "high"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.bytes_sent > 0
        assert result.technique_used == "http_tunneling_obfuscation"

    @pytest.mark.asyncio
    async def test_http_get_attack(self):
        """Test HTTP GET attack execution."""
        attack = HTTPTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"test",
            params={"method": "GET"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS


class TestDNSOverHTTPSTunnelingAttack:
    """Test DNS over HTTPS tunneling attack."""

    @pytest.mark.asyncio
    async def test_dns_attack(self):
        """Test DNS tunneling attack execution."""
        attack = DNSOverHTTPSTunnelingAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            payload=b"test dns payload",
            params={"doh_server": "cloudflare-dns.com"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 1


class TestWebSocketTunnelingObfuscationAttack:
    """Test WebSocket tunneling attack."""

    @pytest.mark.asyncio
    async def test_websocket_fragmentation(self):
        """Test WebSocket with fragmentation."""
        attack = WebSocketTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=443,
            domain="example.com",
            payload=b"test websocket",
            params={"obfuscation_method": "fragmentation"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 2


class TestSSHTunnelingObfuscationAttack:
    """Test SSH tunneling attack."""

    @pytest.mark.asyncio
    async def test_ssh_attack(self):
        """Test SSH tunneling attack execution."""
        attack = SSHTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=22,
            payload=b"test ssh",
            params={"obfuscation_level": "high"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.packets_sent >= 3


class TestVPNTunnelingObfuscationAttack:
    """Test VPN tunneling attack."""

    @pytest.mark.asyncio
    async def test_openvpn_attack(self):
        """Test OpenVPN tunneling."""
        attack = VPNTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=1194,
            payload=b"test vpn",
            params={"vpn_type": "openvpn"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["vpn_type"] == "openvpn"

    @pytest.mark.asyncio
    async def test_wireguard_attack(self):
        """Test WireGuard tunneling."""
        attack = VPNTunnelingObfuscationAttack()
        ctx = AttackContext(
            dst_ip="1.1.1.1",
            dst_port=51820,
            payload=b"test wg",
            params={"vpn_type": "wireguard"},
        )
        result = await attack.execute(ctx)
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["vpn_type"] == "wireguard"


class TestTunnelingUtils:
    """Test tunneling utility functions."""

    def test_url_encode(self):
        """Test URL encoding."""
        result = tunneling_utils.url_encode(b"test data")
        assert "test" in result
        assert "data" in result

    def test_generate_fake_token(self):
        """Test fake token generation."""
        token = tunneling_utils.generate_fake_token()
        assert len(token) > 0
        assert isinstance(token, str)

    def test_create_websocket_frame(self):
        """Test WebSocket frame creation."""
        frame = tunneling_utils.create_websocket_frame(b"test", 2, 1)
        assert len(frame) > len(b"test")
        assert isinstance(frame, bytes)

    def test_create_openvpn_client_hello(self):
        """Test OpenVPN packet creation."""
        packet = tunneling_utils.create_openvpn_client_hello()
        assert len(packet) > 0
        assert isinstance(packet, bytes)

    def test_simulate_compression(self):
        """Test compression simulation."""
        data = b"aaaa" * 10
        compressed = tunneling_utils.simulate_compression(data)
        assert isinstance(compressed, bytes)

    def test_generate_realistic_padding(self):
        """Test padding generation."""
        padding = tunneling_utils.generate_realistic_padding(16, "ssh")
        assert len(padding) == 16
        assert isinstance(padding, bytes)
