import pytest

from core.hybrid_engine import HybridEngine

ZAPRET_STR = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"

def test_translate_zapret_fake_fakeddisorder_params():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    parsed = he.parser.parse(ZAPRET_STR)
    task = he._translate_zapret_to_engine_task(parsed)
    assert task and isinstance(task, dict)
    assert task.get("type") == "fakeddisorder"
    p = task.get("params", {})
    # Критично: split_pos должен быть именно 3 как в CLI
    assert p.get("split_pos") == 3
    # Fooling перенесён полностью
    assert set(p.get("fooling", [])) == {"badsum", "badseq"}
    # TTL перенесён
    assert p.get("ttl") == 3
    # Семантика fake,fakeddisorder → прединъекция
    assert p.get("pre_fake") is True
    assert p.get("pre_fake_ttl") == 3
    assert set(p.get("pre_fake_fooling", [])) == {"badsum", "badseq"}

def test_ensure_engine_task_from_cli_string():
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    task = he._ensure_engine_task(ZAPRET_STR)
    assert task and isinstance(task, dict)
    assert task.get("type") == "fakeddisorder"
    p = task.get("params", {})
    assert p.get("split_pos") == 3
    assert set(p.get("fooling", [])) == {"badsum", "badseq"}
    assert p.get("ttl") == 3
    assert p.get("pre_fake") is True
    assert p.get("pre_fake_ttl") == 3
    assert set(p.get("pre_fake_fooling", [])) == {"badsum", "badseq"}
