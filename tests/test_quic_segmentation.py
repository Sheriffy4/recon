import pytest
from core.quic_handler import QuicHandler
from core.bypass.attacks.tunneling.quic_fragmentation import QUICFragmentationAttack
from core.bypass.attacks.base import AttackContext, AttackStatus

def test_quic_handler_scan_frames_on_synthetic():
    qh = QuicHandler(debug=False)
    # synthetic: long header (fake) + CRYPTO(0x06) frame with small payload + padding
    header = b"\xc3\x00\x00\x00\x01" + b"\x08" + b"\x00"*8 + b"\x08" + b"\x00"*8 + b"\x00" + b"\x00"  # token_len=0, length(varint=0)
    # CRYPTO frame: 0x06 + off(0x00) + len(0x05) + data(5 bytes)
    crypto = b"\x06" + b"\x00" + b"\x05" + b"HELLO"
    padding = b"\x00" * 10
    payload = header + crypto + padding
    # приватный метод не доступен, но split_quic_initial вызовет его и должен вернуть сегменты >=2 (hdr + crypto + padding)
    segs = qh.split_quic_initial(payload, positions=[20, 40])
    assert isinstance(segs, list) and len(segs) >= 2
    # первый сегмент — header+часть, offset 0
    first = segs[0][0]
    assert first.startswith(b"\xc3")

def test_quic_fragmentation_frame_split_and_coalesce():
    attack = QUICFragmentationAttack()
    ctx = AttackContext(dst_ip="1.1.1.1", dst_port=443, src_ip="127.0.0.1", src_port=50000,
                        domain="example.com", payload=None, protocol="udp",
                        params={"fragment_size": 100, "split_by_frames": True, "coalesce_count": 2, "padding_ratio": 0.1},
                        timeout=1.0, debug=False, engine_type="test")
    res = attack.execute(ctx)
    assert res.status == AttackStatus.SUCCESS
    segs = (res.metadata or {}).get("segments", [])
    assert isinstance(segs, list)
    # After coalescing 2 fragments of size 100, we should have 11 fragments instead of 12
    # and the first fragment should be 200 bytes long.
    assert len(segs) == 11
    first_len = len(segs[0][0]) if segs and isinstance(segs[0], tuple) else 0
    assert first_len == 200
