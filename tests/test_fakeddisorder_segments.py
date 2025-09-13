import pytest
from core.bypass.techniques.primitives import BypassTechniques

def test_fakeddisorder_offsets():
    payload = b"A"*200
    segs = BypassTechniques.apply_fakeddisorder(payload, 76, 336, 1, [])
    assert len(segs) == 2
    # Correct order: first "right" (real), then "left" (fake)
    real_seg, fake_seg = segs[0], segs[1]
    assert real_seg[0] == payload[76:]
    assert real_seg[1] == 76
    assert fake_seg[0] == payload[:76]
    assert fake_seg[1] == 76-336
    assert fake_seg[2]["is_fake"] is True
    assert real_seg[2]["is_fake"] is False
