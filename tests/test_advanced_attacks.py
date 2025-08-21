import pytest
import asyncio
from unittest.mock import MagicMock

# Import the classes to be tested
from core.bypass.attacks.advanced_base import AdvancedAttackConfig
from core.bypass.attacks.stateful_fragmentation import StatefulFragmentationAttack, AdvancedOverlapAttack
from core.bypass.attacks.tls_record_manipulation import ClientHelloSplitAttack
from core.bypass.attacks.pacing_attack import PacingAttack
from core.bypass.attacks.base import AttackContext, AttackStatus

# Sample Payloads
CLIENT_HELLO_PAYLOAD = (
    b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03' + b'A'*100 + b'\x20' + b'B'*32 +
    b'\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8' +
    b'\xc0\x13\xc0\x14\xc0\x09\xc0\x0a\x00\x9e\x00\x9d\x00\x2f\x00\x35\x00\x0a' +
    b'\x01\x00\x01\x93\x00\x00\x00\x00\x00\x12\x00\x10\x00\x00\x0d' +
    b'example.com' + b'\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a'
)
HTTP_GET_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

# Stateful Fragmentation Attack Test
@pytest.mark.asyncio
async def test_stateful_fragmentation_attack():
    config = AdvancedAttackConfig(
        name="stateful_fragment", priority=1, complexity="High",
        target_protocols=["tcp"], dpi_signatures=["test"]
    )
    attack = StatefulFragmentationAttack(config)
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443, payload=CLIENT_HELLO_PAYLOAD)

    result = await attack.execute(context)

    assert result.status == AttackStatus.SUCCESS
    assert len(result.segments) == 3
    # Check segment 1 (first part of payload)
    assert result.segments[0][0] == CLIENT_HELLO_PAYLOAD[:10]
    assert result.segments[0][1] == 0
    # Check segment 2 (garbage packet)
    assert result.segments[1][2].get("bad_checksum") is True
    assert result.segments[1][1] == 10
    # Check segment 3 (second part of payload)
    assert result.segments[2][0] == CLIENT_HELLO_PAYLOAD[10:]
    assert result.segments[2][1] == 10

# Advanced Overlap Attack Test
@pytest.mark.asyncio
async def test_advanced_overlap_attack():
    config = AdvancedAttackConfig(
        name="advanced_overlap", priority=1, complexity="High",
        target_protocols=["tcp"], dpi_signatures=["test"],
        default_params={"dpi_payload": b"GET /bait HTTP/1.1\r\n"}
    )
    attack = AdvancedOverlapAttack(config)
    context = AttackContext(dst_ip="1.1.1.1", dst_port=80, payload=HTTP_GET_PAYLOAD)

    result = await attack.execute(context)

    assert result.status == AttackStatus.SUCCESS
    assert len(result.segments) == 2
    # Check segment 1 (bait for DPI)
    assert result.segments[0][0] == b"GET /bait HTTP/1.1\r\n"
    assert result.segments[0][1] == 0
    # Check segment 2 (real payload)
    assert result.segments[1][0] == HTTP_GET_PAYLOAD
    assert result.segments[1][1] == 0 # Overlaps segment 1

# Client Hello Split Attack Test
@pytest.mark.asyncio
async def test_client_hello_split_attack():
    config = AdvancedAttackConfig(
        name="client_hello_split", priority=1, complexity="Medium",
        target_protocols=["tls"], dpi_signatures=["test"],
        default_params={"split_pos": 20}
    )
    attack = ClientHelloSplitAttack(config)
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443, payload=CLIENT_HELLO_PAYLOAD)

    result = await attack.execute(context)

    assert result.status == AttackStatus.SUCCESS
    assert len(result.segments) == 1

    modified_payload = result.segments[0][0]
    # Check that the modified payload consists of two valid TLS records
    # Record 1
    assert modified_payload.startswith(b'\x16\x03\x01') # Handshake, TLS 1.2
    record1_len = int.from_bytes(modified_payload[3:5], 'big')
    assert record1_len == 20
    # Record 2
    record2_start = 5 + record1_len
    assert modified_payload[record2_start:].startswith(b'\x16\x03\x01')
    record2_len = int.from_bytes(modified_payload[record2_start+3:record2_start+5], 'big')
    assert record2_len == len(CLIENT_HELLO_PAYLOAD) - 5 - 20
    assert len(modified_payload) == (5 + record1_len) + (5 + record2_len)

# Pacing Attack Test
@pytest.mark.asyncio
async def test_pacing_attack():
    config = AdvancedAttackConfig(
        name="pacing_attack", priority=1, complexity="Medium",
        target_protocols=["tcp"], dpi_signatures=["test"],
        default_params={"chunk_size": 10, "base_delay_ms": 50, "jitter_ms": 0}
    )
    attack = PacingAttack(config)
    context = AttackContext(dst_ip="1.1.1.1", dst_port=80, payload=HTTP_GET_PAYLOAD)

    result = await attack.execute(context)

    assert result.status == AttackStatus.SUCCESS
    assert len(result.segments) == (len(HTTP_GET_PAYLOAD) + 9) // 10 # Ceiling division

    # First segment should have no delay
    assert "delay_ms" not in result.segments[0][2]
    # Subsequent segments should have a delay
    for segment in result.segments[1:]:
        assert "delay_ms" in segment[2]
        assert segment[2]["delay_ms"] == 50
