"""
Tests for strategy comparison with alias handling.

These tests verify that the strategy comparator correctly handles parameter aliases
and doesn't produce noisy diffs when different modes use different names for the same parameter.
"""

from core.strategy_comparator import StrategyCapture, StrategyDiff


def _cap(mode: str, params: dict, strategy_string: str = "--dpi-desync=fake") -> StrategyCapture:
    """Helper to create a StrategyCapture for testing."""
    return StrategyCapture(
        mode=mode,
        domain="example.com",
        timestamp="20260101_000000",
        strategy_string=strategy_string,
        parsed_params=params,
        resolved_ips=[],
        packets_captured=0,
        pcap_file=None,
    )


def test_strategy_diff_alias_attack_type_vs_desync_method_no_diff():
    """
    discovery may provide attack_type, service may provide desync_method (or vice versa).
    Comparator must treat them as aliases and not report a diff if values match.
    """
    disc = _cap("discovery", {"attack_type": "fake", "ttl": 4})
    svc = _cap("service", {"desync_method": "fake", "ttl": 4})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is True
    assert comp.differences == []


def test_strategy_diff_alias_overlap_size_vs_split_seqovl_no_diff():
    """
    overlap_size and split_seqovl are aliases; must not produce noisy diffs.
    """
    disc = _cap("discovery", {"overlap_size": 336, "split_pos": 76})
    svc = _cap("service", {"split_seqovl": 336, "split_pos": 76})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is True
    assert comp.differences == []


def test_strategy_diff_reports_canonical_key_when_values_differ():
    """
    If alias values differ across modes, a single canonical diff must be produced.
    """
    disc = _cap("discovery", {"attack_type": "multidisorder"})
    svc = _cap("service", {"desync_method": "fake"})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is False
    assert len(comp.differences) == 1
    assert comp.differences[0].parameter == "attack_type"
    assert comp.differences[0].discovery_value == "multidisorder"
    assert comp.differences[0].service_value == "fake"


def test_strategy_diff_split_pos_alias():
    """
    split_pos and split_position are aliases.
    """
    disc = _cap("discovery", {"split_pos": 2})
    svc = _cap("service", {"split_position": 2})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is True
    assert comp.differences == []


def test_strategy_diff_fooling_alias():
    """
    fooling and fooling_methods are aliases.
    """
    disc = _cap("discovery", {"fooling": "md5sig"})
    svc = _cap("service", {"fooling_methods": "md5sig"})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is True
    assert comp.differences == []


def test_strategy_diff_multiple_params_with_aliases():
    """
    Test complex scenario with multiple parameters including aliases.
    """
    disc = _cap("discovery", {
        "attack_type": "fake",
        "ttl": 4,
        "split_pos": 2,
        "overlap_size": 336
    })
    svc = _cap("service", {
        "desync_method": "fake",
        "ttl": 4,
        "split_position": 2,
        "split_seqovl": 336
    })

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is True
    assert comp.differences == []


def test_strategy_diff_real_difference_detected():
    """
    Ensure real differences are still detected correctly.
    """
    disc = _cap("discovery", {"attack_type": "fake", "ttl": 4})
    svc = _cap("service", {"attack_type": "fake", "ttl": 8})

    comp = StrategyDiff().compare_strategies(disc, svc)
    assert comp.strategies_match is False
    assert len(comp.differences) == 1
    assert comp.differences[0].parameter == "ttl"
    assert comp.differences[0].discovery_value == 4
    assert comp.differences[0].service_value == 8


if __name__ == "__main__":
    # Run tests
    import sys
    
    tests = [
        test_strategy_diff_alias_attack_type_vs_desync_method_no_diff,
        test_strategy_diff_alias_overlap_size_vs_split_seqovl_no_diff,
        test_strategy_diff_reports_canonical_key_when_values_differ,
        test_strategy_diff_split_pos_alias,
        test_strategy_diff_fooling_alias,
        test_strategy_diff_multiple_params_with_aliases,
        test_strategy_diff_real_difference_detected,
    ]
    
    failed = 0
    for test in tests:
        try:
            test()
            print(f"✓ {test.__name__}")
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: ERROR: {e}")
            failed += 1
    
    if failed:
        print(f"\n{failed} test(s) failed")
        sys.exit(1)
    else:
        print(f"\nAll {len(tests)} tests passed!")
        sys.exit(0)
