"""
Comprehensive tests for the training pipeline and model evaluation.
Tests training data generation, feature engineering, and model training.
"""

import unittest
import tempfile
import os
from unittest.mock import patch
from recon.тесты.training_data import (
    TrainingDataGenerator,
    FeatureEngineer,
    TrainingExample,
)
from recon.тесты.model_trainer import ModelTrainer, ModelEvaluationMetrics

try:
    import sklearn

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class TestTrainingDataGenerator(unittest.TestCase):
    """Test training data generation and management."""

    def setUp(self):
        self.generator = TrainingDataGenerator()

    def test_initialization(self):
        """Test that generator initializes with base examples."""
        self.assertGreater(len(self.generator.training_examples), 0)
        dpi_types = {example.dpi_type for example in self.generator.training_examples}
        expected_types = {
            "ROSKOMNADZOR_TSPU",
            "ROSKOMNADZOR_DPI",
            "COMMERCIAL_DPI",
            "FIREWALL_BASED",
            "ISP_TRANSPARENT_PROXY",
            "CLOUDFLARE_PROTECTION",
            "GOVERNMENT_CENSORSHIP",
            "UNKNOWN",
        }
        self.assertTrue(expected_types.issubset(dpi_types))

    def test_training_example_structure(self):
        """Test that training examples have correct structure."""
        example = self.generator.training_examples[0]
        self.assertIsInstance(example, TrainingExample)
        self.assertIsInstance(example.dpi_type, str)
        self.assertIsInstance(example.confidence, float)
        self.assertIsInstance(example.metrics, dict)
        self.assertIsInstance(example.source, str)
        self.assertIsInstance(example.description, str)
        self.assertGreaterEqual(example.confidence, 0.0)
        self.assertLessEqual(example.confidence, 1.0)

    def test_metrics_completeness(self):
        """Test that examples have required metrics."""
        required_metrics = [
            "rst_ttl",
            "rst_latency_ms",
            "connection_latency_ms",
            "dns_resolution_time_ms",
            "handshake_time_ms",
        ]
        for example in self.generator.training_examples:
            for metric in required_metrics:
                self.assertIn(
                    metric,
                    example.metrics,
                    f"Missing {metric} in {example.dpi_type} example",
                )

    def test_synthetic_variation_generation(self):
        """Test synthetic variation generation."""
        original_count = len(self.generator.training_examples)
        synthetic = self.generator.generate_synthetic_variations(base_examples=3)
        self.assertGreater(len(synthetic), 0)
        for syn_example in synthetic:
            self.assertEqual(syn_example.source, "synthetic_variation")
            self.assertIn("Synthetic variation", syn_example.description)

    def test_get_training_data(self):
        """Test training data retrieval."""
        data_no_syn = self.generator.get_training_data(include_synthetic=False)
        self.assertEqual(len(data_no_syn), len(self.generator.training_examples))
        data_with_syn = self.generator.get_training_data(include_synthetic=True)
        self.assertGreater(len(data_with_syn), len(data_no_syn))
        for item in data_with_syn:
            self.assertIn("metrics", item)
            self.assertIn("dpi_type", item)
            self.assertIn("confidence", item)

    def test_class_distribution(self):
        """Test class distribution calculation."""
        distribution = self.generator.get_class_distribution()
        self.assertIsInstance(distribution, dict)
        self.assertGreater(len(distribution), 0)
        for count in distribution.values():
            self.assertGreater(count, 0)

    def test_validation(self):
        """Test training data validation."""
        validation = self.generator.validate_training_data()
        self.assertIn("total_examples", validation)
        self.assertIn("class_distribution", validation)
        self.assertIn("missing_features", validation)
        self.assertIn("feature_coverage", validation)
        self.assertGreater(validation["total_examples"], 0)

    def test_save_load_training_data(self):
        """Test saving and loading training data."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name
        try:
            self.generator.save_training_data(temp_file, include_synthetic=False)
            self.assertTrue(os.path.exists(temp_file))
            loaded_data = self.generator.load_training_data(temp_file)
            original_data = self.generator.get_training_data(include_synthetic=False)
            self.assertEqual(len(loaded_data), len(original_data))
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


class TestFeatureEngineer(unittest.TestCase):
    """Test feature engineering pipeline."""

    def setUp(self):
        self.engineer = FeatureEngineer()
        self.generator = TrainingDataGenerator()
        self.sample_training_data = self.generator.get_training_data(
            include_synthetic=False
        )[:5]

    def test_fit_transform_pipeline(self):
        """Test fitting and transforming features."""
        self.engineer.fit(self.sample_training_data)
        self.assertTrue(self.engineer.is_fitted)
        self.assertGreater(len(self.engineer.feature_stats), 0)
        sample_metrics = self.sample_training_data[0]["metrics"]
        features = self.engineer.transform(sample_metrics)
        self.assertIsInstance(features, dict)
        self.assertGreater(len(features), 0)
        for value in features.values():
            self.assertIsInstance(value, (int, float))

    def test_feature_normalization(self):
        """Test that features are properly normalized."""
        self.engineer.fit(self.sample_training_data)
        sample_metrics = self.sample_training_data[0]["metrics"]
        features = self.engineer.transform(sample_metrics)
        normalized_features = [k for k in features.keys() if "_normalized" in k]
        minmax_features = [k for k in features.keys() if "_minmax" in k]
        self.assertGreater(len(normalized_features), 0)
        self.assertGreater(len(minmax_features), 0)

    def test_derived_features(self):
        """Test creation of derived features."""
        self.engineer.fit(self.sample_training_data)
        sample_metrics = self.sample_training_data[0]["metrics"]
        features = self.engineer.transform(sample_metrics)
        derived_features = ["blocking_intensity", "technology_support", "ttl_is_common"]
        for derived_feature in derived_features:
            if derived_feature in features:
                value = features[derived_feature]
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 1.0)

    def test_unfitted_transform(self):
        """Test transform without fitting (should use raw features)."""
        sample_metrics = self.sample_training_data[0]["metrics"]
        features = self.engineer.transform(sample_metrics)
        self.assertIsInstance(features, dict)
        self.assertGreater(len(features), 0)


@unittest.skipUnless(SKLEARN_AVAILABLE, "sklearn not available")
class TestModelTrainer(unittest.TestCase):
    """Test model training and evaluation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.model_path = os.path.join(self.temp_dir, "test_model.joblib")
        self.trainer = ModelTrainer(self.model_path)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_prepare_training_data(self):
        """Test training data preparation."""
        training_data = self.trainer.prepare_training_data(include_synthetic=True)
        self.assertIsInstance(training_data, list)
        self.assertGreater(len(training_data), 0)
        for item in training_data:
            self.assertIn("metrics", item)
            self.assertIn("dpi_type", item)
            self.assertIn("confidence", item)

    def test_train_model_with_evaluation(self):
        """Test complete model training with evaluation."""
        training_data = self.trainer.prepare_training_data(include_synthetic=False)
        metrics = self.trainer.train_model_with_evaluation(
            training_data=training_data, test_size=0.3, cv_folds=3
        )
        self.assertIsInstance(metrics, ModelEvaluationMetrics)
        self.assertGreaterEqual(metrics.accuracy, 0.0)
        self.assertLessEqual(metrics.accuracy, 1.0)
        self.assertGreater(len(metrics.cross_val_scores), 0)
        self.assertIsInstance(metrics.confusion_matrix, list)
        self.assertIsInstance(metrics.feature_importance, dict)

    def test_evaluation_metrics_serialization(self):
        """Test evaluation metrics serialization."""
        metrics = ModelEvaluationMetrics(
            accuracy=0.85,
            precision_macro=0.83,
            precision_micro=0.85,
            recall_macro=0.82,
            recall_micro=0.85,
            f1_macro=0.82,
            f1_micro=0.85,
            f1_weighted=0.84,
            cross_val_scores=[0.8, 0.85, 0.9],
            cross_val_mean=0.85,
            cross_val_std=0.04,
            confusion_matrix=[[10, 2], [1, 12]],
            classification_report="test report",
            feature_importance={"feature1": 0.5, "feature2": 0.3},
            class_distribution={"class1": 15, "class2": 10},
        )
        metrics_dict = metrics.to_dict()
        self.assertIsInstance(metrics_dict, dict)
        restored_metrics = ModelEvaluationMetrics.from_dict(metrics_dict)
        self.assertEqual(restored_metrics.accuracy, metrics.accuracy)
        self.assertEqual(restored_metrics.cross_val_scores, metrics.cross_val_scores)

    def test_feature_importance_report(self):
        """Test feature importance analysis."""
        self.trainer.evaluation_metrics = ModelEvaluationMetrics(
            accuracy=0.85,
            precision_macro=0.83,
            precision_micro=0.85,
            recall_macro=0.82,
            recall_micro=0.85,
            f1_macro=0.82,
            f1_micro=0.85,
            f1_weighted=0.84,
            cross_val_scores=[0.8, 0.85, 0.9],
            cross_val_mean=0.85,
            cross_val_std=0.04,
            confusion_matrix=[[10, 2], [1, 12]],
            classification_report="test report",
            feature_importance={
                "feature1": 0.5,
                "feature2": 0.3,
                "feature3": 0.2,
                "feature4": 0.1,
                "feature5": 0.05,
            },
            class_distribution={"class1": 15, "class2": 10},
        )
        report = self.trainer.get_feature_importance_report(top_n=3)
        self.assertIn("top_features", report)
        self.assertIn("total_features", report)
        self.assertEqual(len(report["top_features"]), 3)
        self.assertEqual(report["total_features"], 5)

    def test_training_report_generation(self):
        """Test training report generation."""
        self.trainer.evaluation_metrics = ModelEvaluationMetrics(
            accuracy=0.85,
            precision_macro=0.83,
            precision_micro=0.85,
            recall_macro=0.82,
            recall_micro=0.85,
            f1_macro=0.82,
            f1_micro=0.85,
            f1_weighted=0.84,
            cross_val_scores=[0.8, 0.85, 0.9],
            cross_val_mean=0.85,
            cross_val_std=0.04,
            confusion_matrix=[[10, 2], [1, 12]],
            classification_report="Precision    Recall  F1-Score   Support\nClass1         0.83      0.85      0.84        15",
            feature_importance={"feature1": 0.5, "feature2": 0.3},
            class_distribution={"ROSKOMNADZOR_TSPU": 15, "COMMERCIAL_DPI": 10},
        )
        report = self.trainer.generate_training_report()
        self.assertIsInstance(report, str)
        self.assertIn("TRAINING REPORT", report)
        self.assertIn("Accuracy:", report)
        self.assertIn("CROSS-VALIDATION", report)
        self.assertIn("FEATURE", report)

    def test_save_load_evaluation_results(self):
        """Test saving and loading evaluation results."""
        metrics = ModelEvaluationMetrics(
            accuracy=0.85,
            precision_macro=0.83,
            precision_micro=0.85,
            recall_macro=0.82,
            recall_micro=0.85,
            f1_macro=0.82,
            f1_micro=0.85,
            f1_weighted=0.84,
            cross_val_scores=[0.8, 0.85, 0.9],
            cross_val_mean=0.85,
            cross_val_std=0.04,
            confusion_matrix=[[10, 2], [1, 12]],
            classification_report="test report",
            feature_importance={"feature1": 0.5, "feature2": 0.3},
            class_distribution={"class1": 15, "class2": 10},
        )
        self.trainer.evaluation_metrics = metrics
        results_file = os.path.join(self.temp_dir, "results.json")
        self.trainer.save_evaluation_results(results_file)
        self.assertTrue(os.path.exists(results_file))
        loaded_metrics = self.trainer.load_evaluation_results(results_file)
        self.assertEqual(loaded_metrics.accuracy, metrics.accuracy)
        self.assertEqual(loaded_metrics.cross_val_scores, metrics.cross_val_scores)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete training pipeline."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.skipUnless(SKLEARN_AVAILABLE, "sklearn not available")
    def test_end_to_end_training_pipeline(self):
        """Test complete end-to-end training pipeline."""
        model_path = os.path.join(self.temp_dir, "test_model.joblib")
        trainer = ModelTrainer(model_path)
        with patch.object(
            trainer.training_data_generator, "generate_synthetic_variations"
        ) as mock_synthetic:
            mock_synthetic.return_value = (
                trainer.training_data_generator.training_examples[:3]
            )
            metrics = trainer.train_model_with_evaluation(test_size=0.3, cv_folds=2)
        self.assertIsInstance(metrics, ModelEvaluationMetrics)
        self.assertGreaterEqual(metrics.accuracy, 0.0)
        self.assertTrue(trainer.ml_classifier.is_trained)
        sample_metrics = trainer.training_data_generator.training_examples[0].metrics
        dpi_type, confidence = trainer.ml_classifier.classify_dpi(sample_metrics)
        self.assertIsInstance(dpi_type, str)
        self.assertIsInstance(confidence, float)
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)

    def test_training_data_quality_validation(self):
        """Test training data quality and completeness."""
        generator = TrainingDataGenerator()
        for example in generator.training_examples:
            self.assertIsInstance(example.dpi_type, str)
            self.assertIn(
                example.dpi_type,
                [
                    "UNKNOWN",
                    "ROSKOMNADZOR_TSPU",
                    "ROSKOMNADZOR_DPI",
                    "COMMERCIAL_DPI",
                    "FIREWALL_BASED",
                    "ISP_TRANSPARENT_PROXY",
                    "CLOUDFLARE_PROTECTION",
                    "GOVERNMENT_CENSORSHIP",
                ],
            )
            required_metrics = [
                "rst_ttl",
                "rst_latency_ms",
                "connection_latency_ms",
                "dns_resolution_time_ms",
                "handshake_time_ms",
            ]
            for metric in required_metrics:
                self.assertIn(metric, example.metrics)
                self.assertIsNotNone(example.metrics[metric])

    def test_feature_engineering_consistency(self):
        """Test feature engineering produces consistent results."""
        generator = TrainingDataGenerator()
        engineer = FeatureEngineer()
        training_data = generator.get_training_data(include_synthetic=False)
        engineer.fit(training_data)
        sample_metrics = training_data[0]["metrics"]
        features1 = engineer.transform(sample_metrics)
        features2 = engineer.transform(sample_metrics)
        self.assertEqual(features1, features2)
        for key, value in features1.items():
            self.assertIsInstance(
                value, (int, float), f"Feature {key} is not numeric: {type(value)}"
            )


if __name__ == "__main__":
    unittest.main()
