import pytest
from core.bypass_engine import BypassTechniques

def test_fakeddisorder_offsets():
    payload = b"A"*200
    segs = BypassTechniques.apply_fakeddisorder(payload, 76, 336)
    assert len(segs) == 2
    assert segs[0][0] == payload[76:]
    assert segs[0][1] == 76
    assert segs[1][0] == payload[:76]
    assert segs[1][1] == 76-336
