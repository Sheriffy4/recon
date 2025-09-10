import pytest
from core.bypass_engine import BypassTechniques

def test_seqovl_split_pos_ge_len():
    payload = b"A"*10
    segs = BypassTechniques.apply_seqovl(payload, split_pos=10, overlap_size=20)
    assert segs == [(payload, 0)]

def test_seqovl_large_overlap():
    payload = b"A"*30
    segs = BypassTechniques.apply_seqovl(payload, split_pos=5, overlap_size=100)
    # part1_with_overlap = 100 zeroes + 5 'A', second segment is part2 from 5:
    assert segs[0][0] == payload[5:]
    assert segs[1][0].startswith(b"\x00"*100)

def test_seqovl_nonpositive_overlap():
    payload = b"A"*30
    segs = BypassTechniques.apply_seqovl(payload, split_pos=5, overlap_size=0)
    # 0 overlap → поведение как простая перестановка с 0 offset
    assert segs[0] == (payload[5:], 5)
    assert segs[1] == (payload[:5], 0)
