# recon/core/fingerprint/test_online_learning.py
"""
Comprehensive tests for online learning capabilities.
Tests incremental learning, confidence-based updates, performance monitoring,
and A/B testing framework.
"""

import unittest
import tempfile
import os
import time
from unittest.mock import Mock, patch

from .online_learning import (
    OnlineLearningSystem,
    LearningMode,
    LearningExample,
    PerformanceMetrics,
    ABTestConfig,
)
from .ml_classifier import MLClassifier


class TestOnlineLearningSystem(unittest.TestCase):
    """Test suite for OnlineLearningSystem."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, "test_model.joblib")

        # Create mock ML classifier
        self.mock_classifier = Mock(spec=MLClassifier)
        self.mock_classifier.model_path = self.model_path
        self.mock_classifier.is_trained = True
        self.mock_classifier.classify_dpi.return_value = ("ROSKOMNADZOR_TSPU", 0.85)

        # Create online learning system
        self.online_learning = OnlineLearningSystem(
            ml_classifier=self.mock_classifier,
            learning_mode=LearningMode.MODERATE,
            buffer_size=10,  # Small buffer for testing
            min_confidence_threshold=0.7,
            performance_window_size=5,
            retraining_threshold=0.1,
        )

        # Sample metrics for testing
        self.sample_metrics = {
            "rst_latency_ms": 50.0,
            "connection_latency_ms": 100.0,
            "rst_ttl": 63,
            "rst_from_target": False,
            "stateful_inspection": True,
            "tcp_option_len_limit": 40,
        }

    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temporary files
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Clean up state file
        if os.path.exists("online_learning_state.json"):
            os.remove("online_learning_state.json")

    def test_initialization(self):
        """Test online learning system initialization."""
        self.assertEqual(self.online_learning.learning_mode, LearningMode.MODERATE)
        self.assertEqual(self.online_learning.buffer_size, 10)
        self.assertEqual(self.online_learning.min_confidence_threshold, 0.7)
        self.assertEqual(len(self.online_learning.learning_buffer), 0)
        self.assertEqual(len(self.online_learning.performance_history), 0)
        self.assertIsNone(self.online_learning.baseline_performance)

    def test_add_learning_example_high_confidence_correct(self):
        """Test adding high confidence correct prediction (should be skipped)."""
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="ROSKOMNADZOR_TSPU",
            confidence=0.95,
            source="automatic",
        )

        # Should not learn from high confidence correct predictions
        self.assertFalse(result)
        self.assertEqual(len(self.online_learning.learning_buffer), 0)
        self.assertEqual(self.online_learning.stats["examples_learned_from"], 0)

    def test_add_learning_example_incorrect_prediction(self):
        """Test adding incorrect prediction (should be learned from)."""
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.75,
            source="user_feedback",
        )

        self.assertTrue(result)
        self.assertEqual(len(self.online_learning.learning_buffer), 1)
        self.assertEqual(self.online_learning.stats["examples_learned_from"], 1)

        # Check example details
        example = self.online_learning.learning_buffer[0]
        self.assertEqual(example.predicted_type, "ROSKOMNADZOR_TSPU")
        self.assertEqual(example.actual_type, "COMMERCIAL_DPI")
        self.assertEqual(example.confidence, 0.75)
        self.assertEqual(example.source, "user_feedback")

    def test_add_learning_example_low_confidence(self):
        """Test adding low confidence prediction."""
        # In moderate mode, should not learn from confidence < 0.7
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.6,
            source="automatic",
        )

        self.assertFalse(result)
        self.assertEqual(len(self.online_learning.learning_buffer), 0)

    def test_learning_mode_conservative(self):
        """Test conservative learning mode."""
        self.online_learning.set_learning_mode(LearningMode.CONSERVATIVE)

        # Should not learn from medium confidence
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.75,
            source="automatic",
        )
        self.assertFalse(result)

        # Should learn from high confidence incorrect prediction
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.85,
            source="automatic",
        )
        self.assertTrue(result)

    def test_learning_mode_aggressive(self):
        """Test aggressive learning mode."""
        self.online_learning.set_learning_mode(LearningMode.AGGRESSIVE)

        # Should learn from lower confidence
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.55,
            source="automatic",
        )
        self.assertTrue(result)

    def test_learning_mode_disabled(self):
        """Test disabled learning mode."""
        self.online_learning.set_learning_mode(LearningMode.DISABLED)

        # Should not learn from any example
        result = self.online_learning.add_learning_example(
            metrics=self.sample_metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.95,
            source="user_feedback",
        )
        self.assertFalse(result)

    def test_performance_monitoring(self):
        """Test performance monitoring and baseline establishment."""
        # Add examples to fill performance window
        for i in range(6):  # More than window size (5)
            correct = i < 3  # First 3 correct, last 3 incorrect
            actual_type = "ROSKOMNADZOR_TSPU" if correct else "COMMERCIAL_DPI"

            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type=actual_type,
                confidence=0.8,
                source="automatic",
            )

        # Should have established baseline
        self.assertIsNotNone(self.online_learning.baseline_performance)

        # Performance history should be at window size
        self.assertEqual(len(self.online_learning.performance_history), 5)

        # Check baseline accuracy (should be based on first 5 examples: 3 correct, 2 incorrect)
        expected_accuracy = 3 / 5  # 0.6
        self.assertAlmostEqual(
            self.online_learning.baseline_performance.accuracy,
            expected_accuracy,
            places=2,
        )

    @patch("recon.core.fingerprint.online_learning.ModelTrainer")
    def test_incremental_update_trigger(self, mock_trainer_class):
        """Test incremental update triggering."""
        # Set aggressive mode for faster triggering (20 examples)
        self.online_learning.set_learning_mode(LearningMode.AGGRESSIVE)

        # Mock trainer
        mock_trainer = Mock()
        mock_trainer.prepare_training_data.return_value = []
        mock_trainer.train_model_with_evaluation.return_value = Mock(accuracy=0.85)
        mock_trainer.ml_classifier = self.mock_classifier
        mock_trainer_class.return_value = mock_trainer

        # Add examples to trigger update
        for i in range(20):
            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type="COMMERCIAL_DPI",
                confidence=0.75,
                source="automatic",
            )

        # Should have triggered incremental update
        mock_trainer.train_model_with_evaluation.assert_called_once()

        # Buffer should be cleared after update
        self.assertEqual(len(self.online_learning.learning_buffer), 0)

    @patch("recon.core.fingerprint.online_learning.ModelTrainer")
    def test_retraining_trigger(self, mock_trainer_class):
        """Test automatic retraining trigger due to performance degradation."""
        # Mock trainer
        mock_trainer = Mock()
        mock_trainer.prepare_training_data.return_value = []
        mock_trainer.train_model_with_evaluation.return_value = Mock(
            accuracy=0.9, f1_macro=0.85
        )
        mock_trainer.ml_classifier = self.mock_classifier
        mock_trainer_class.return_value = mock_trainer

        # Establish good baseline
        for i in range(5):
            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type="ROSKOMNADZOR_TSPU",  # All correct
                confidence=0.8,
                source="automatic",
            )

        # Now add poor performance examples to trigger retraining
        for i in range(5):
            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type="COMMERCIAL_DPI",  # All incorrect
                confidence=0.8,
                source="automatic",
            )

        # Should have triggered retraining
        mock_trainer.train_model_with_evaluation.assert_called()
        self.assertEqual(self.online_learning.stats["retraining_events"], 1)
        self.assertIsNotNone(self.online_learning.stats["last_retraining_time"])

    def test_ab_test_start(self):
        """Test starting A/B test."""
        # Create test model file
        test_model_path = os.path.join(self.temp_dir, "test_model.joblib")

        # Mock test model
        with patch(
            "recon.core.fingerprint.online_learning.MLClassifier"
        ) as mock_ml_class:
            mock_test_model = Mock()
            mock_test_model.load_model.return_value = True
            mock_ml_class.return_value = mock_test_model

            config = ABTestConfig(
                test_name="test_experiment",
                control_model_path=self.model_path,
                test_model_path=test_model_path,
                traffic_split=0.5,
                min_samples=10,
                max_duration_hours=24,
                success_threshold=0.05,
            )

            result = self.online_learning.start_ab_test(config)

            self.assertTrue(result)
            self.assertIsNotNone(self.online_learning.active_ab_test)
            self.assertEqual(
                self.online_learning.active_ab_test.test_name, "test_experiment"
            )
            self.assertIsNotNone(self.online_learning.test_model)

    def test_ab_test_classification(self):
        """Test classification during A/B test."""
        # Start A/B test
        with patch(
            "recon.core.fingerprint.online_learning.MLClassifier"
        ) as mock_ml_class:
            mock_test_model = Mock()
            mock_test_model.load_model.return_value = True
            mock_test_model.classify_dpi.return_value = ("COMMERCIAL_DPI", 0.9)
            mock_ml_class.return_value = mock_test_model

            config = ABTestConfig(
                test_name="test_experiment",
                control_model_path=self.model_path,
                test_model_path="test_model.joblib",
                traffic_split=0.5,
                min_samples=10,
                max_duration_hours=24,
                success_threshold=0.05,
            )

            self.online_learning.start_ab_test(config)

            # Test classification (with fixed random seed for predictable results)
            with patch("numpy.random.random", return_value=0.3):  # Use control model
                dpi_type, confidence, model_used = (
                    self.online_learning.classify_with_ab_test(self.sample_metrics)
                )
                self.assertEqual(model_used, "control")
                self.assertEqual(dpi_type, "ROSKOMNADZOR_TSPU")  # From mock_classifier

            with patch("numpy.random.random", return_value=0.7):  # Use test model
                dpi_type, confidence, model_used = (
                    self.online_learning.classify_with_ab_test(self.sample_metrics)
                )
                self.assertEqual(model_used, "test")
                self.assertEqual(dpi_type, "COMMERCIAL_DPI")  # From mock_test_model

    def test_ab_test_conclusion(self):
        """Test A/B test conclusion and results."""
        # Start A/B test
        with patch(
            "recon.core.fingerprint.online_learning.MLClassifier"
        ) as mock_ml_class:
            mock_test_model = Mock()
            mock_test_model.load_model.return_value = True
            mock_ml_class.return_value = mock_test_model

            config = ABTestConfig(
                test_name="test_experiment",
                control_model_path=self.model_path,
                test_model_path="test_model.joblib",
                traffic_split=0.5,
                min_samples=5,  # Small for testing
                max_duration_hours=24,
                success_threshold=0.1,
            )

            self.online_learning.start_ab_test(config)

            # Add results for both models
            # Control model: 4/5 correct (80%)
            for i in range(5):
                correct = i < 4
                actual_type = "ROSKOMNADZOR_TSPU" if correct else "COMMERCIAL_DPI"
                self.online_learning.record_ab_test_result(
                    metrics=self.sample_metrics,
                    predicted_type="ROSKOMNADZOR_TSPU",
                    actual_type=actual_type,
                    confidence=0.8,
                    model_used="control",
                )

            # Test model: 5/5 correct (100%)
            for i in range(5):
                self.online_learning.record_ab_test_result(
                    metrics=self.sample_metrics,
                    predicted_type="ROSKOMNADZOR_TSPU",
                    actual_type="ROSKOMNADZOR_TSPU",
                    confidence=0.9,
                    model_used="test",
                )

            # Test should be concluded automatically
            self.assertIsNone(self.online_learning.active_ab_test)
            self.assertEqual(self.online_learning.stats["ab_tests_completed"], 1)

    def test_learning_statistics(self):
        """Test learning statistics collection."""
        # Add some examples
        for i in range(3):
            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type="COMMERCIAL_DPI",
                confidence=0.8,
                source="automatic",
            )

        stats = self.online_learning.get_learning_statistics()

        self.assertEqual(stats["learning_mode"], "moderate")
        self.assertEqual(stats["buffer_size"], 3)
        self.assertEqual(stats["buffer_capacity"], 10)
        self.assertEqual(stats["statistics"]["examples_learned_from"], 3)
        self.assertEqual(stats["statistics"]["total_examples_received"], 3)

    def test_state_persistence(self):
        """Test saving and loading of online learning state."""
        # Add some examples
        for i in range(3):
            self.online_learning.add_learning_example(
                metrics=self.sample_metrics,
                predicted_type="ROSKOMNADZOR_TSPU",
                actual_type="COMMERCIAL_DPI",
                confidence=0.8,
                source="automatic",
            )

        # Save state
        self.online_learning._save_state()

        # Verify state file exists
        self.assertTrue(os.path.exists("online_learning_state.json"))

        # Create new instance and load state
        new_online_learning = OnlineLearningSystem(
            ml_classifier=self.mock_classifier,
            learning_mode=LearningMode.CONSERVATIVE,  # Different from saved
            buffer_size=20,  # Different from saved
        )

        # Should have loaded the saved examples
        self.assertEqual(len(new_online_learning.learning_buffer), 3)
        self.assertEqual(new_online_learning.stats["examples_learned_from"], 3)


class TestLearningExample(unittest.TestCase):
    """Test suite for LearningExample dataclass."""

    def test_learning_example_creation(self):
        """Test creating learning example."""
        metrics = {"rst_latency_ms": 50.0, "confidence": 0.8}
        example = LearningExample(
            metrics=metrics,
            predicted_type="ROSKOMNADZOR_TSPU",
            actual_type="COMMERCIAL_DPI",
            confidence=0.75,
            timestamp=time.time(),
            source="user_feedback",
        )

        self.assertEqual(example.metrics, metrics)
        self.assertEqual(example.predicted_type, "ROSKOMNADZOR_TSPU")
        self.assertEqual(example.actual_type, "COMMERCIAL_DPI")
        self.assertEqual(example.confidence, 0.75)
        self.assertEqual(example.source, "user_feedback")

    def test_learning_example_serialization(self):
        """Test learning example serialization."""
        example = LearningExample(
            metrics={"test": 1.0},
            predicted_type="TYPE_A",
            actual_type="TYPE_B",
            confidence=0.8,
            timestamp=1234567890.0,
            source="test",
        )

        # Test to_dict
        data = example.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["predicted_type"], "TYPE_A")

        # Test from_dict
        restored = LearningExample.from_dict(data)
        self.assertEqual(restored.predicted_type, example.predicted_type)
        self.assertEqual(restored.actual_type, example.actual_type)
        self.assertEqual(restored.confidence, example.confidence)


class TestPerformanceMetrics(unittest.TestCase):
    """Test suite for PerformanceMetrics dataclass."""

    def test_performance_metrics_creation(self):
        """Test creating performance metrics."""
        metrics = PerformanceMetrics(
            accuracy=0.85,
            f1_score=0.82,
            confidence_distribution={"80-90%": 5, "90-100%": 3},
            prediction_counts={"TYPE_A": 4, "TYPE_B": 4},
            timestamp=time.time(),
            sample_size=8,
        )

        self.assertEqual(metrics.accuracy, 0.85)
        self.assertEqual(metrics.f1_score, 0.82)
        self.assertEqual(metrics.sample_size, 8)

    def test_performance_metrics_serialization(self):
        """Test performance metrics serialization."""
        metrics = PerformanceMetrics(
            accuracy=0.9,
            f1_score=0.88,
            confidence_distribution={},
            prediction_counts={},
            timestamp=1234567890.0,
            sample_size=10,
        )

        # Test serialization round-trip
        data = metrics.to_dict()
        restored = PerformanceMetrics.from_dict(data)

        self.assertEqual(restored.accuracy, metrics.accuracy)
        self.assertEqual(restored.f1_score, metrics.f1_score)
        self.assertEqual(restored.sample_size, metrics.sample_size)


class TestABTestConfig(unittest.TestCase):
    """Test suite for ABTestConfig dataclass."""

    def test_ab_test_config_creation(self):
        """Test creating A/B test configuration."""
        config = ABTestConfig(
            test_name="experiment_1",
            control_model_path="control.joblib",
            test_model_path="test.joblib",
            traffic_split=0.3,
            min_samples=100,
            max_duration_hours=48,
            success_threshold=0.05,
        )

        self.assertEqual(config.test_name, "experiment_1")
        self.assertEqual(config.traffic_split, 0.3)
        self.assertEqual(config.min_samples, 100)
        self.assertEqual(config.success_threshold, 0.05)

    def test_ab_test_config_serialization(self):
        """Test A/B test config serialization."""
        config = ABTestConfig(
            test_name="test",
            control_model_path="control.joblib",
            test_model_path="test.joblib",
            traffic_split=0.5,
            min_samples=50,
            max_duration_hours=24,
            success_threshold=0.1,
        )

        # Test serialization round-trip
        data = config.to_dict()
        restored = ABTestConfig.from_dict(data)

        self.assertEqual(restored.test_name, config.test_name)
        self.assertEqual(restored.traffic_split, config.traffic_split)
        self.assertEqual(restored.min_samples, config.min_samples)


if __name__ == "__main__":
    unittest.main()
