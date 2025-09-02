# recon/core/fingerprint/test_integration.py
"""
Integration test for advanced fingerprinting models - Task 1 verification
"""

import sys
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)


# Add the parent directory to the path to allow imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def test_advanced_models_import():
    """Test that advanced models can be imported correctly"""
    try:
        from core.fingerprint.advanced_models import (
            DPIFingerprint,
            DPIType,
            ConfidenceLevel,
            FingerprintingError,
            NetworkAnalysisError,
        )

        print("✓ Advanced models imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Failed to import advanced models: {e}")
        return False


def test_basic_functionality():
    """Test basic functionality of the advanced models"""
    try:
        from core.fingerprint.advanced_models import DPIFingerprint, DPIType

        # Create a basic fingerprint
        fp = DPIFingerprint(
            target="test.example.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
        )

        # Test serialization
        fp_dict = fp.to_dict()
        assert fp_dict["target"] == "test.example.com"
        assert fp_dict["dpi_type"] == "roskomnadzor_tspu"

        # Test deserialization
        fp_restored = DPIFingerprint.from_dict(fp_dict)
        assert fp_restored.target == fp.target
        assert fp_restored.dpi_type == fp.dpi_type

        # Test strategy recommendations
        strategies = fp.get_recommended_strategies()
        assert isinstance(strategies, list)
        assert len(strategies) > 0

        print("✓ Basic functionality test passed")
        return True
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False


def test_exception_hierarchy():
    """Test that exception hierarchy works correctly"""
    try:
        from core.fingerprint.advanced_models import (
            FingerprintingError,
            NetworkAnalysisError,
            MLClassificationError,
        )

        # Test that specific exceptions inherit from base
        assert issubclass(NetworkAnalysisError, FingerprintingError)
        assert issubclass(MLClassificationError, FingerprintingError)

        # Test that exceptions can be raised and caught
        try:
            raise NetworkAnalysisError("Test error")
        except FingerprintingError:
            pass  # Should catch the specific error as base type

        print("✓ Exception hierarchy test passed")
        return True
    except Exception as e:
        print(f"✗ Exception hierarchy test failed: {e}")
        return False


def main():
    """Run all integration tests"""
    print("Running Task 1 Integration Tests...")
    print("=" * 50)

    tests = [
        test_advanced_models_import,
        test_basic_functionality,
        test_exception_hierarchy,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 50)
    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All Task 1 integration tests passed!")
        return True
    else:
        print("❌ Some tests failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
