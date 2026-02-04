import pytest


def test_closed_loop_manager_imports_even_if_optional_modules_missing():
    """
    Smoke:
    ClosedLoopManager should be importable even when legacy/optional modules are absent.
    (AdvancedStrategyGenerator, LearningAdaptiveAttack are optional now.)
    """
    try:
        import core.integration.closed_loop_manager  # noqa: F401
    except Exception as e:
        pytest.fail(f"closed_loop_manager import must not fail: {e}")
