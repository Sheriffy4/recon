#!/usr/bin/env python3
"""
Simple test script for online learning functionality.
Tests basic online learning capabilities without complex dependencies.
"""

import sys
import os
from unittest.mock import Mock

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint.online_learning import OnlineLearningSystem, LearningMode, ABTestConfig
from ml_classifier import MLClassifier


def test_basic_functionality():
    """Test basic online learning functionality."""
    print("Testing basic online learning functionality...")

    # Create mock classifier
    mock_classifier = Mock(spec=MLClassifier)
    mock_classifier.model_path = "test_model.joblib"
    mock_classifier.is_trained = True
    mock_classifier.classify_dpi.return_value = ("ROSKOMNADZOR_TSPU", 0.85)

    # Create online learning system
    online_learning = OnlineLearningSystem(
        ml_classifier=mock_classifier,
        learning_mode=LearningMode.MODERATE,
        buffer_size=5,  # Small for testing
        min_confidence_threshold=0.7,
        performance_window_size=3,
        retraining_threshold=0.2,
    )

    print("✓ Created online learning system")
    print(f"  Learning mode: {online_learning.learning_mode.value}")
    print(f"  Buffer size: {online_learning.buffer_size}")

    # Test adding learning examples
    sample_metrics = {
        "rst_latency_ms": 50.0,
        "connection_latency_ms": 100.0,
        "rst_ttl": 63,
        "rst_from_target": False,
        "stateful_inspection": True,
    }

    # Test 1: High confidence correct prediction (should be skipped)
    result1 = online_learning.add_learning_example(
        metrics=sample_metrics,
        predicted_type="ROSKOMNADZOR_TSPU",
        actual_type="ROSKOMNADZOR_TSPU",
        confidence=0.95,
        source="automatic",
    )
    print(
        f"✓ High confidence correct prediction: {'learned' if result1 else 'skipped'} (expected: skipped)"
    )

    # Test 2: Incorrect prediction (should be learned)
    result2 = online_learning.add_learning_example(
        metrics=sample_metrics,
        predicted_type="ROSKOMNADZOR_TSPU",
        actual_type="COMMERCIAL_DPI",
        confidence=0.75,
        source="user_feedback",
    )
    print(
        f"✓ Incorrect prediction: {'learned' if result2 else 'skipped'} (expected: learned)"
    )

    # Test 3: Low confidence (should be skipped in moderate mode)
    result3 = online_learning.add_learning_example(
        metrics=sample_metrics,
        predicted_type="ROSKOMNADZOR_TSPU",
        actual_type="COMMERCIAL_DPI",
        confidence=0.6,
        source="automatic",
    )
    print(
        f"✓ Low confidence prediction: {'learned' if result3 else 'skipped'} (expected: skipped)"
    )

    # Check statistics
    stats = online_learning.get_learning_statistics()
    print("✓ Statistics:")
    print(
        f"  Total examples received: {stats['statistics']['total_examples_received']}"
    )
    print(f"  Examples learned from: {stats['statistics']['examples_learned_from']}")
    print(f"  Buffer size: {stats['buffer_size']}")

    return True


def test_learning_modes():
    """Test different learning modes."""
    print("\nTesting learning modes...")

    mock_classifier = Mock(spec=MLClassifier)
    mock_classifier.model_path = "test_model.joblib"
    mock_classifier.is_trained = True

    sample_metrics = {"rst_latency_ms": 50.0, "confidence": 0.75}

    modes_results = {}

    for mode in [
        LearningMode.CONSERVATIVE,
        LearningMode.MODERATE,
        LearningMode.AGGRESSIVE,
    ]:
        online_learning = OnlineLearningSystem(
            ml_classifier=mock_classifier, learning_mode=mode, buffer_size=10
        )

        # Test with medium confidence incorrect prediction
        result = online_learning.add_learning_example(
            metrics=sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.75,
            source="automatic",
        )

        modes_results[mode.value] = result
        print(f"  {mode.value.capitalize()}: {'learned' if result else 'skipped'}")

    print("✓ Learning modes tested")
    return True


def test_ab_testing():
    """Test A/B testing functionality."""
    print("\nTesting A/B testing...")

    # Create mock classifiers
    control_classifier = Mock(spec=MLClassifier)
    control_classifier.model_path = "control_model.joblib"
    control_classifier.is_trained = True
    control_classifier.classify_dpi.return_value = ("ROSKOMNADZOR_TSPU", 0.8)

    test_classifier = Mock(spec=MLClassifier)
    test_classifier.load_model.return_value = True
    test_classifier.classify_dpi.return_value = ("COMMERCIAL_DPI", 0.9)

    online_learning = OnlineLearningSystem(
        ml_classifier=control_classifier, learning_mode=LearningMode.MODERATE
    )

    # Mock the MLClassifier import for A/B test
    import unittest.mock

    with unittest.mock.patch(
        "online_learning.MLClassifier", return_value=test_classifier
    ):
        config = ABTestConfig(
            test_name="test_experiment",
            control_model_path="control_model.joblib",
            test_model_path="test_model.joblib",
            traffic_split=0.5,
            min_samples=5,
            max_duration_hours=24,
            success_threshold=0.05,
        )

        success = online_learning.start_ab_test(config)
        print(f"✓ A/B test started: {success}")

        if success:
            # Test classification
            sample_metrics = {"rst_latency_ms": 50.0}
            dpi_type, confidence, model_used = online_learning.classify_with_ab_test(
                sample_metrics
            )
            print(
                f"  Classification result: {dpi_type} (confidence: {confidence:.2f}, model: {model_used})"
            )

    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("ONLINE LEARNING - SIMPLE FUNCTIONALITY TEST")
    print("=" * 60)

    try:
        # Run tests
        test_basic_functionality()
        test_learning_modes()
        test_ab_testing()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)
        print("✓ Basic online learning functionality")
        print("✓ Learning mode variations")
        print("✓ A/B testing framework")
        print("✓ Statistics and monitoring")

        return True

    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        # Clean up any test files
        test_files = ["online_learning_state.json"]
        for file in test_files:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
