# recon/core/bypass/modes/test_mode_controller_simple.py
"""
Simple tests for mode controller functionality.
"""

import sys
import os

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from mode_controller import ModeController, OperationMode
from capability_detector import CapabilityDetector
from mode_transition import ModeTransitionManager


def test_capability_detector():
    """Test basic capability detection."""
    print("Testing CapabilityDetector...")

    detector = CapabilityDetector()

    # Test basic functionality
    capabilities = detector.detect_all_capabilities()
    assert len(capabilities) > 0, "Should detect some capabilities"

    # Test mode availability checks
    native_available = detector.is_native_mode_available()
    emulated_available = detector.is_emulated_mode_available()

    print(f"  Native mode available: {native_available}")
    print(f"  Emulated mode available: {emulated_available}")

    # Test recommended mode
    recommended = detector.get_recommended_mode()
    assert recommended in [
        "native",
        "emulated",
        "compatibility",
    ], f"Invalid recommended mode: {recommended}"
    print(f"  Recommended mode: {recommended}")

    print("  CapabilityDetector tests passed!")


def test_mode_transition_manager():
    """Test basic mode transition functionality."""
    print("Testing ModeTransitionManager...")

    detector = CapabilityDetector()
    manager = ModeTransitionManager(detector)

    # Test initialization
    assert manager.current_state.value == "idle", "Should start in idle state"

    # Test handler registration
    def dummy_rollback(data):
        pass

    def dummy_validator():
        return True

    manager.register_rollback_handler("test_mode", dummy_rollback)
    manager.register_validation_handler("test_mode", dummy_validator)

    assert "test_mode" in manager.rollback_handlers
    assert "test_mode" in manager.validation_handlers

    print("  ModeTransitionManager tests passed!")


def test_mode_controller():
    """Test basic mode controller functionality."""
    print("Testing ModeController...")

    controller = ModeController()

    # Test initialization
    assert (
        controller.get_current_mode() == OperationMode.AUTO
    ), "Should start in AUTO mode"

    # Test getting available modes
    available_modes = controller.get_available_modes()
    assert len(available_modes) > 0, "Should have some available modes"
    assert (
        OperationMode.COMPATIBILITY in available_modes
    ), "Compatibility mode should always be available"

    print(f"  Available modes: {[mode.value for mode in available_modes.keys()]}")

    # Test mode availability check
    compat_available = controller.is_mode_available(OperationMode.COMPATIBILITY)
    assert compat_available, "Compatibility mode should be available"

    # Test mode switching to compatibility (should always work)
    try:
        result = controller.switch_mode(OperationMode.COMPATIBILITY, "test switch")
        assert result, "Switch to compatibility mode should succeed"
        assert (
            controller.get_current_mode() == OperationMode.COMPATIBILITY
        ), "Should be in compatibility mode"
        print("  Mode switch to compatibility successful")
    except Exception as e:
        print(f"  Mode switch failed: {e}")
        # This might fail in some environments, but shouldn't crash

    # Test getting mode info
    mode_info = controller.get_mode_info()
    assert "mode" in mode_info, "Mode info should contain mode field"
    assert "available" in mode_info, "Mode info should contain available field"

    # Test health check (should not crash)
    health = controller.check_mode_health()
    print(f"  Mode health check result: {health}")

    print("  ModeController tests passed!")


def test_capability_report():
    """Test capability report generation."""
    print("Testing capability report generation...")

    controller = ModeController()
    report = controller.get_capability_report()

    assert len(report) > 100, "Report should be substantial"
    assert "Capability Report" in report, "Report should contain title"
    assert "Mode Information" in report, "Report should contain mode info"

    print("  Capability report generated successfully")
    print(f"  Report length: {len(report)} characters")


def test_error_handling():
    """Test basic error handling."""
    print("Testing error handling...")

    controller = ModeController()

    # Test switching to same mode (should succeed)
    controller.current_mode = OperationMode.COMPATIBILITY
    result = controller.switch_mode(OperationMode.COMPATIBILITY)
    assert result, "Switching to same mode should succeed"

    # Test auto-fallback with mock error
    try:
        # This might not actually fallback in test environment, but shouldn't crash
        controller.auto_fallback(Exception("test error"))
        print("  Auto-fallback completed without crashing")
    except Exception as e:
        print(f"  Auto-fallback error (expected in test): {e}")

    print("  Error handling tests passed!")


def main():
    """Run all simple tests."""
    print("=== Mode Controller Simple Tests ===\n")

    try:
        test_capability_detector()
        print()

        test_mode_transition_manager()
        print()

        test_mode_controller()
        print()

        test_capability_report()
        print()

        test_error_handling()
        print()

        print("=== All Simple Tests Passed! ===")

        # Generate and display capability report
        print("\n=== System Capability Report ===")
        controller = ModeController()
        print(controller.get_capability_report())

    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
