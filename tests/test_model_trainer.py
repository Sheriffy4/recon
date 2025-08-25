# tests/test_model_trainer.py
"""
Comprehensive tests for the model training pipeline.
"""
import unittest
import tempfile
import os
from unittest.mock import patch
import numpy as np

# Add project root to path to allow imports
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.fingerprint.model_trainer import ModelTrainer, ModelEvaluationMetrics

# Check if sklearn is available, skip tests if not
try:
    from sklearn.ensemble import RandomForestClassifier

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@unittest.skipUnless(
    SKLEARN_AVAILABLE, "scikit-learn is not installed, skipping model trainer tests."
)
class TestModelTrainer(unittest.TestCase):
    """Test suite for the ModelTrainer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, "test_model.joblib")
        self.trainer = ModelTrainer(self.model_path)

        # Use a small, controlled training dataset for tests
        self.test_training_data = [
            {
                "metrics": {
                    "rst_ttl": 63,
                    "stateful_inspection": True,
                    "rst_latency_ms": 50,
                },
                "dpi_type": "ROSKOMNADZOR_TSPU",
                "confidence": 0.9,
            },
            {
                "metrics": {
                    "rst_ttl": 62,
                    "stateful_inspection": True,
                    "rst_latency_ms": 45,
                },
                "dpi_type": "ROSKOMNADZOR_TSPU",
                "confidence": 0.9,
            },
            {
                "metrics": {
                    "rst_ttl": 255,
                    "ml_detection_blocked": True,
                    "rst_latency_ms": 30,
                },
                "dpi_type": "COMMERCIAL_DPI",
                "confidence": 0.9,
            },
            {
                "metrics": {
                    "rst_ttl": 254,
                    "ml_detection_blocked": True,
                    "rst_latency_ms": 25,
                },
                "dpi_type": "COMMERCIAL_DPI",
                "confidence": 0.9,
            },
        ]

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_prepare_training_data(self):
        """Test that training data preparation works."""
        with patch.object(
            self.trainer.training_data_generator,
            "get_training_data",
            return_value=self.test_training_data,
        ):
            data = self.trainer.prepare_training_data(include_synthetic=False)
            self.assertEqual(len(data), 4)
            self.assertIn("metrics", data[0])
            self.assertIn("dpi_type", data[0])

    def test_prepare_features_and_labels(self):
        """Test the conversion of training data to feature arrays and labels."""
        X, y, feature_names = self.trainer._prepare_features_and_labels(
            self.test_training_data
        )

        self.assertIsInstance(X, np.ndarray)
        self.assertIsInstance(y, np.ndarray)
        self.assertIsInstance(feature_names, list)

        self.assertEqual(X.shape[0], 4)  # 4 samples
        self.assertEqual(y.shape[0], 4)
        self.assertGreater(X.shape[1], 0)  # Should have features
        self.assertEqual(X.shape[1], len(feature_names))

    def test_train_model_with_evaluation(self):
        """Test the main training and evaluation workflow."""
        metrics = self.trainer.train_model_with_evaluation(
            training_data=self.test_training_data,
            test_size=0.5,  # 2 for train, 2 for test
            cv_folds=2,
        )

        self.assertIsInstance(metrics, ModelEvaluationMetrics)
        self.assertGreaterEqual(metrics.accuracy, 0.0)
        self.assertLessEqual(metrics.accuracy, 1.0)
        self.assertIsNotNone(metrics.classification_report)
        self.assertIsNotNone(metrics.confusion_matrix)
        self.assertIn("rst_ttl_normalized", metrics.feature_importance)

        # Check that the model was saved
        self.assertTrue(os.path.exists(self.model_path))

        # Check that the classifier in the trainer is now trained
        self.assertTrue(self.trainer.ml_classifier.is_trained)

    def test_generate_training_report(self):
        """Test the generation of a human-readable training report."""
        # First, train the model to populate evaluation_metrics
        self.trainer.train_model_with_evaluation(self.test_training_data)

        report = self.trainer.generate_training_report()

        self.assertIsInstance(report, str)
        self.assertIn("DPI ML CLASSIFIER TRAINING REPORT", report)
        self.assertIn("OVERALL PERFORMANCE", report)
        self.assertIn("Accuracy:", report)
        self.assertIn("CROSS-VALIDATION RESULTS", report)
        self.assertIn("TOP 10 MOST IMPORTANT FEATURES", report)

    def test_save_and_load_evaluation_results(self):
        """Test saving and loading of evaluation metrics."""
        # Train to get metrics
        metrics = self.trainer.train_model_with_evaluation(self.test_training_data)

        results_path = os.path.join(self.temp_dir, "eval_results.json")
        self.trainer.save_evaluation_results(results_path)

        self.assertTrue(os.path.exists(results_path))

        # Create a new trainer and load the results
        new_trainer = ModelTrainer()
        loaded_metrics = new_trainer.load_evaluation_results(results_path)

        self.assertIsInstance(loaded_metrics, ModelEvaluationMetrics)
        self.assertAlmostEqual(metrics.accuracy, loaded_metrics.accuracy)
        self.assertEqual(metrics.class_distribution, loaded_metrics.class_distribution)

    def test_quick_train_and_evaluate(self):
        """Test the convenience function for quick training."""
        with patch.object(
            self.trainer, "prepare_training_data", return_value=self.test_training_data
        ):
            metrics = self.trainer.quick_train_and_evaluate(save_results=False)

            self.assertIsInstance(metrics, ModelEvaluationMetrics)
            self.assertTrue(self.trainer.ml_classifier.is_trained)


if __name__ == "__main__":
    unittest.main()
