# tests/test_online_learning_integration.py
"""
Integration tests for the OnlineLearningIntegrator.
"""
import unittest
from unittest.mock import Mock, patch

# Add project root to path
import sys
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)


project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.fingerprint.online_learning import OnlineLearningSystem, LearningMode
from core.fingerprint.online_learning_integration import (
    OnlineLearningIntegrator,
    FeedbackData,
)
from core.fingerprint.ml_classifier import MLClassifier
from core.fingerprint.advanced_models import DPIFingerprint, DPIType


class TestOnlineLearningIntegrator(unittest.TestCase):
    """Test suite for the OnlineLearningIntegrator."""

    def setUp(self):
        """Set up test fixtures."""
        # Mock the MLClassifier
        self.mock_classifier = Mock(spec=MLClassifier)
        self.mock_classifier.get_prediction_with_alternatives.return_value = (
            "ROSKOMNADZOR_TSPU",
            0.85,
            [("COMMERCIAL_DPI", 0.1)],
        )

        # Mock the OnlineLearningSystem
        self.mock_online_learning_system = Mock(spec=OnlineLearningSystem)
        self.mock_online_learning_system.add_learning_example.return_value = True
        self.mock_online_learning_system.active_ab_test = None

        # Create the integrator
        self.integrator = OnlineLearningIntegrator(
            ml_classifier=self.mock_classifier,
            learning_mode=LearningMode.MODERATE,
            enable_online_learning=True,
        )
        # Replace the real OnlineLearningSystem with our mock for controlled tests
        self.integrator.online_learning = self.mock_online_learning_system

    def test_initialization(self):
        """Test that the integrator initializes correctly."""
        self.assertIsNotNone(self.integrator.online_learning)
        self.assertTrue(self.integrator.enable_online_learning)
        self.assertEqual(self.integrator.ml_classifier, self.mock_classifier)

    def test_classify_with_learning_no_ab_test(self):
        """Test classification when no A/B test is active."""
        metrics = {"rst_ttl": 63}
        dpi_type, confidence, alternatives = self.integrator.classify_with_learning(
            metrics
        )

        self.mock_classifier.get_prediction_with_alternatives.assert_called_once_with(
            metrics
        )
        self.assertEqual(dpi_type, "ROSKOMNADZOR_TSPU")
        self.assertEqual(confidence, 0.85)
        self.assertEqual(len(alternatives), 1)
        self.assertEqual(self.integrator.stats["fingerprints_processed"], 1)

    def test_classify_with_learning_with_ab_test(self):
        """Test classification when an A/B test is active."""
        # Set up the mock to simulate an active A/B test
        self.mock_online_learning_system.active_ab_test = True
        self.mock_online_learning_system.classify_with_ab_test.return_value = (
            "COMMERCIAL_DPI",
            0.9,
            "test",
        )

        metrics = {"rst_ttl": 255}
        dpi_type, confidence, alternatives = self.integrator.classify_with_learning(
            metrics
        )

        self.mock_online_learning_system.classify_with_ab_test.assert_called_once_with(
            metrics
        )
        self.mock_classifier.get_prediction_with_alternatives.assert_not_called()
        self.assertEqual(dpi_type, "COMMERCIAL_DPI")
        self.assertEqual(confidence, 0.9)
        self.assertEqual(self.integrator.stats["fingerprints_processed"], 1)

    def test_add_user_feedback(self):
        """Test processing of user feedback."""
        fingerprint = DPIFingerprint(
            target="test.com",
            dpi_type=DPIType.ROSKOMNADZOR_TSPU,
            confidence=0.85,
            rst_injection_detected=True,
        )

        feedback = FeedbackData(
            target="test.com",
            fingerprint=fingerprint,
            user_reported_type="COMMERCIAL_DPI",
            confidence_in_feedback=0.9,
            feedback_source="user_manual",
            timestamp=1234567890.0,
        )

        # Mock the metric extraction
        with patch.object(
            self.integrator,
            "_extract_metrics_from_fingerprint",
            return_value={"rst_ttl": 63},
        ):
            processed = self.integrator.add_user_feedback(feedback)

            self.assertTrue(processed)
            self.assertEqual(self.integrator.stats["feedback_received"], 1)
            self.assertEqual(self.integrator.stats["learning_examples_added"], 1)

            # Verify that the learning system was called with the correct data
            self.mock_online_learning_system.add_learning_example.assert_called_once()
            call_args, _ = (
                self.mock_online_learning_system.add_learning_example.call_args
            )
            self.assertEqual(call_args[0]["actual_type"], "COMMERCIAL_DPI")
            self.assertEqual(call_args[0]["source"], "user_manual")

    def test_add_validation_result(self):
        """Test processing of an automated validation result."""
        metrics = {"rst_ttl": 63}
        processed = self.integrator.add_validation_result(
            target="test.com",
            metrics=metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            validated_type="ROSKOMNADZOR_TSPU",
            confidence=0.9,
            validation_method="automated_test",
        )

        self.assertTrue(processed)
        self.assertEqual(self.integrator.stats["learning_examples_added"], 1)
        self.mock_online_learning_system.add_learning_example.assert_called_once()
        call_args, _ = self.mock_online_learning_system.add_learning_example.call_args
        self.assertEqual(call_args[0]["source"], "validation_automated_test")

    def test_enable_disable_online_learning(self):
        """Test enabling and disabling the online learning system."""
        # Initially enabled
        self.assertTrue(self.integrator.enable_online_learning)
        self.assertIsNotNone(self.integrator.online_learning)

        # Disable
        self.integrator.disable_online_learning()
        self.assertFalse(self.integrator.enable_online_learning)
        self.assertIsNone(self.integrator.online_learning)

        # Re-enable
        self.integrator.enable_online_learning()
        self.assertTrue(self.integrator.enable_online_learning)
        self.assertIsNotNone(self.integrator.online_learning)

    def test_get_learning_insights(self):
        """Test retrieval of learning insights."""
        # Mock the learning system's stats
        self.mock_online_learning_system.get_learning_statistics.return_value = {
            "learning_mode": "moderate",
            "statistics": {
                "total_examples_received": 100,
                "examples_learned_from": 40,
                "retraining_events": 1,
            },
            "baseline_performance": {"accuracy": 0.8},
            "active_ab_test": None,
            "buffer_size": 10,
            "buffer_capacity": 500,
        }

        insights = self.integrator.get_learning_insights()

        self.assertTrue(insights["online_learning_enabled"])
        self.assertEqual(insights["learning_mode"], "moderate")
        self.assertAlmostEqual(insights["learning_efficiency"], 0.4)
        self.assertEqual(insights["retraining_events"], 1)
        self.assertIn("recommendations", insights)


if __name__ == "__main__":
    unittest.main()
