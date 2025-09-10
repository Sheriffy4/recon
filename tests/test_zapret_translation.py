import pytest
from core.zapret_parser import ZapretStrategyParser
from core.hybrid_engine import HybridEngine

def test_translation_fake_fakeddisorder_full_params():
    s = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1"
    p = ZapretStrategyParser().parse(s)
    h = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    task = h._translate_zapret_to_engine_task(p)
    assert task['type'] == 'fakeddisorder'
    pr = task['params']
    assert pr['split_pos'] == 76
    assert pr['overlap_size'] == 336
    assert pr['ttl'] == 1
    assert set(pr['fooling']) == {'md5sig','badsum','badseq'}
    assert pr['autottl'] == 2
    assert pr['repeats'] == 1

def test_multisplit_with_splitcount_grid():
    s = "--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-ttl=4"
    p = ZapretStrategyParser().parse(s)
    from core.hybrid_engine import HybridEngine
    h = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    task = h._translate_zapret_to_engine_task(p)
    assert task['type'] == 'multisplit'
    pos = task['params'].get('positions', [])
    assert len(pos) == 4
    assert all(isinstance(x, int) for x in pos)
