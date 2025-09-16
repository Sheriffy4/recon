import pytest
from core.hybrid_engine import HybridEngine

ZAPRET_STR = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"

def test_translate_zapret_fake_fakeddisorder_params():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    parsed = he.parser.parse(ZAPRET_STR)
    task = he._translate_zapret_to_engine_task(parsed, strict_cli=True)
    assert task and isinstance(task, dict)
    assert task.get("type") == "fakeddisorder"
    p = task.get("params", {})
    assert p.get("split_pos") == 3
    assert set(p.get("fooling", [])) == {"badsum", "badseq"}
    assert p.get("ttl") == 3
    assert p.get("fake_ttl") == 3
    assert p.get("pre_fake") is True
    assert set(p.get("pre_fake_fooling", [])) == {"badsum", "badseq"}
    assert "overlap_size" not in p
    assert p.get("badseq_delta") == -1

def test_translate_zapret_without_split_pos_is_strict():
    cli_str = "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badsum"
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    task = he._ensure_engine_task(cli_str)
    assert task and isinstance(task, dict)
    assert task.get("type") == "fakeddisorder"
    p = task.get("params", {})
    assert p.get("split_pos") == 3
    assert set(p.get("fooling", [])) == {"badsum"}

def test_translate_zapret_fake_fakeddisorder_with_overlap():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    params = {
        'dpi_desync': ['fake', 'fakeddisorder'],
        'dpi_desync_split_seqovl': 10,
    }
    task = he._translate_zapret_to_engine_task(params)
    assert task['params']['overlap_size'] == 10
