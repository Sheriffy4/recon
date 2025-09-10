import pytest
from core.hybrid_engine import HybridEngine

def test_translate_fake_fakeddisorder_params_preserved():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    zapret = "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=10 --dpi-desync-split-pos=76 --dpi-desync-split-seqovl=336"
    task = he._ensure_engine_task(zapret)
    assert task["type"] == "fakeddisorder"
    p = task["params"]
    assert p.get("ttl") == 10
    assert p.get("split_pos") == 76
    assert p.get("overlap_size") == 336
    assert set(p.get("fooling", [])) == {"badsum", "badseq"}

def test_translate_quic_fragment():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    zapret = "--dpi-desync=split --quic-frag=120"
    task = he._ensure_engine_task(zapret)
    # при наличии quic-frag должен вернуться quic_fragmentation
    assert task["type"] == "quic_fragmentation"
    assert task["params"]["fragment_size"] == 120