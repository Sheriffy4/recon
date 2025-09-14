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
    # Строгая проверка: split_pos = 3 из CLI
    assert p.get("split_pos") == 3
    # Fooling 1:1
    assert set(p.get("fooling", [])) == {"badsum", "badseq"}
    # TTL 1:1
    assert p.get("ttl") == 3
    # Семантика fake,fakeddisorder → прединъекция
    assert p.get("pre_fake") is True
    assert p.get("pre_fake_ttl") == 3
    assert set(p.get("pre_fake_fooling", [])) == {"badsum", "badseq"}
    # В strict_cli режиме НЕ должно быть неявных дефолтов вроде overlap_size=336
    assert "overlap_size" not in p

def test_ensure_engine_task_cli_uses_strict_mode():
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
    assert "overlap_size" not in p

def test_translate_zapret_without_split_pos_is_strict():
    cli_str = "--dpi-desync=fake,fakeddisorder --dpi-desync-fooling=badsum"
    he = HybridEngine(debug=False, enable_advanced_fingerprinting=False, enable_modern_bypass=False)
    task = he._ensure_engine_task(cli_str)
    assert task and isinstance(task, dict)
    assert task.get("type") == "fakeddisorder"
    p = task.get("params", {})
    # В строгом режиме split_pos не должен выставляться по умолчанию
    assert "split_pos" not in p
    # Но fooling должен быть
    assert set(p.get("fooling", [])) == {"badsum"}
