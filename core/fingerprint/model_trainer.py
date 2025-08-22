"""
Model training and evaluation for DPI ML classifier.
Implements comprehensive training pipeline with cross-validation and metrics.
"""
from __future__ import annotations
import logging
import os
import json
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
from dataclasses import dataclass, asdict
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix, roc_auc_score
    from sklearn.preprocessing import LabelEncoder
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
from recon.core.fingerprint.training_data import TrainingDataGenerator, FeatureEngineer
from recon.core.fingerprint.ml_classifier import MLClassifier
LOG = logging.getLogger('model_trainer')

@dataclass
class ModelEvaluationMetrics:
    """Comprehensive evaluation metrics for the trained model."""
    accuracy: float
    precision_macro: float
    precision_micro: float
    recall_macro: float
    recall_micro: float
    f1_macro: float
    f1_micro: float
    f1_weighted: float
    cross_val_scores: List[float]
    cross_val_mean: float
    cross_val_std: float
    confusion_matrix: List[List[int]]
    classification_report: str
    feature_importance: Dict[str, float]
    class_distribution: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelEvaluationMetrics':
        """Create from dictionary."""
        return cls(**data)

class ModelTrainer:
    """
    Comprehensive model trainer with evaluation and cross-validation.
    Handles the complete training pipeline from data preparation to model evaluation.
    """

    def __init__(self, model_path: str='dpi_classifier.joblib'):
        self.model_path = model_path
        self.training_data_generator = TrainingDataGenerator()
        self.feature_engineer = FeatureEngineer()
        self.ml_classifier = MLClassifier(model_path)
        self.evaluation_metrics: Optional[ModelEvaluationMetrics] = None
        if not SKLEARN_AVAILABLE:
            LOG.error('sklearn not available, model training will not work')

    def prepare_training_data(self, include_synthetic: bool=True, save_to_file: Optional[str]=None) -> List[Dict[str, Any]]:
        """
        Prepare comprehensive training dataset.

        Args:
            include_synthetic: Whether to include synthetic variations
            save_to_file: Optional path to save training data

        Returns:
            List of training examples
        """
        LOG.info('Preparing training data...')
        training_data = self.training_data_generator.get_training_data(include_synthetic)
        validation_results = self.training_data_generator.validate_training_data()
        LOG.info(f'Training data validation: {validation_results}')
        if save_to_file:
            self.training_data_generator.save_training_data(save_to_file, include_synthetic)
        LOG.info(f'Prepared {len(training_data)} training examples')
        return training_data

    def train_model_with_evaluation(self, training_data: Optional[List[Dict[str, Any]]]=None, test_size: float=0.2, cv_folds: int=5, random_state: int=42) -> ModelEvaluationMetrics:
        """
        Train model with comprehensive evaluation.

        Args:
            training_data: Training data (if None, will be generated)
            test_size: Fraction of data to use for testing
            cv_folds: Number of cross-validation folds
            random_state: Random state for reproducibility

        Returns:
            ModelEvaluationMetrics with comprehensive evaluation results
        """
        if not SKLEARN_AVAILABLE:
            raise RuntimeError('sklearn not available for model training')
        if training_data is None:
            training_data = self.prepare_training_data(include_synthetic=True)
        LOG.info(f'Training model with {len(training_data)} examples...')
        X, y, feature_names = self._prepare_features_and_labels(training_data)
        unique_classes, class_counts = np.unique(y, return_counts=True)
        min_class_count = np.min(class_counts)
        if min_class_count < 2:
            LOG.warning('Some classes have only 1 example, disabling stratification')
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
        else:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)
        LOG.info(f'Training set: {len(X_train)} examples, Test set: {len(X_test)} examples')
        model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=random_state, class_weight='balanced', n_jobs=-1)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)
        evaluation_metrics = self._calculate_evaluation_metrics(model, X, y, X_test, y_test, y_pred, y_pred_proba, feature_names, cv_folds, random_state, min_class_count)
        self.ml_classifier.model = model
        self.ml_classifier.feature_names = feature_names
        self.ml_classifier.is_trained = True
        self.ml_classifier.save_model()
        self.evaluation_metrics = evaluation_metrics
        LOG.info(f'Model training completed with accuracy: {evaluation_metrics.accuracy:.3f}')
        return evaluation_metrics

    def _prepare_features_and_labels(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare features and labels for training.

        Args:
            training_data: List of training examples

        Returns:
            Tuple of (features, labels, feature_names)
        """
        self.feature_engineer.fit(training_data)
        X = []
        y = []
        for example in training_data:
            features = self.feature_engineer.transform(example['metrics'])
            if not hasattr(self, '_feature_order'):
                self._feature_order = sorted(features.keys())
            feature_vector = [features.get(key, 0.0) for key in self._feature_order]
            X.append(feature_vector)
            y.append(example['dpi_type'])
        return (np.array(X), np.array(y), self._feature_order)

    def _calculate_evaluation_metrics(self, model, X, y, X_test, y_test, y_pred, y_pred_proba, feature_names: List[str], cv_folds: int, random_state: int, min_class_count: int) -> ModelEvaluationMetrics:
        """Calculate comprehensive evaluation metrics."""
        accuracy = accuracy_score(y_test, y_pred)
        precision_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
        precision_micro = precision_score(y_test, y_pred, average='micro', zero_division=0)
        recall_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
        recall_micro = recall_score(y_test, y_pred, average='micro', zero_division=0)
        f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
        f1_micro = f1_score(y_test, y_pred, average='micro', zero_division=0)
        f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        n_samples = len(X)
        actual_cv_folds = min(cv_folds, n_samples, min_class_count)
        if actual_cv_folds < 2:
            LOG.warning('Not enough samples for cross-validation, using simple validation')
            cv_scores = np.array([accuracy])
        else:
            try:
                cv = StratifiedKFold(n_splits=actual_cv_folds, shuffle=True, random_state=random_state)
                cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
            except ValueError as e:
                LOG.warning(f'Stratified CV failed: {e}, using simple CV')
                from sklearn.model_selection import KFold
                cv = KFold(n_splits=actual_cv_folds, shuffle=True, random_state=random_state)
                cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred, zero_division=0)
        feature_importance = dict(zip(feature_names, model.feature_importances_))
        unique, counts = np.unique(y, return_counts=True)
        class_distribution = dict(zip(unique, counts.tolist()))
        return ModelEvaluationMetrics(accuracy=float(accuracy), precision_macro=float(precision_macro), precision_micro=float(precision_micro), recall_macro=float(recall_macro), recall_micro=float(recall_micro), f1_macro=float(f1_macro), f1_micro=float(f1_micro), f1_weighted=float(f1_weighted), cross_val_scores=cv_scores.tolist(), cross_val_mean=float(cv_scores.mean()), cross_val_std=float(cv_scores.std()), confusion_matrix=cm.tolist(), classification_report=report, feature_importance=feature_importance, class_distribution=class_distribution)

    def evaluate_model_performance(self, test_data: Optional[List[Dict[str, Any]]]=None) -> Dict[str, Any]:
        """
        Evaluate model performance on test data.

        Args:
            test_data: Test data (if None, will use held-out test set)

        Returns:
            Dictionary with performance metrics
        """
        if not self.ml_classifier.is_trained:
            raise RuntimeError('Model not trained yet')
        if test_data is None:
            if self.evaluation_metrics is None:
                raise RuntimeError('No evaluation metrics available and no test data provided')
            return self.evaluation_metrics.to_dict()
        correct_predictions = 0
        total_predictions = 0
        predictions_by_class = {}
        for example in test_data:
            predicted_type, confidence = self.ml_classifier.classify_dpi(example['metrics'])
            actual_type = example['dpi_type']
            total_predictions += 1
            if predicted_type == actual_type:
                correct_predictions += 1
            if actual_type not in predictions_by_class:
                predictions_by_class[actual_type] = {'correct': 0, 'total': 0}
            predictions_by_class[actual_type]['total'] += 1
            if predicted_type == actual_type:
                predictions_by_class[actual_type]['correct'] += 1
        per_class_accuracy = {}
        for class_name, stats in predictions_by_class.items():
            per_class_accuracy[class_name] = stats['correct'] / stats['total'] if stats['total'] > 0 else 0.0
        return {'overall_accuracy': correct_predictions / total_predictions if total_predictions > 0 else 0.0, 'total_predictions': total_predictions, 'correct_predictions': correct_predictions, 'per_class_accuracy': per_class_accuracy, 'predictions_by_class': predictions_by_class}

    def save_evaluation_results(self, filepath: str):
        """Save evaluation results to JSON file."""
        if self.evaluation_metrics is None:
            raise RuntimeError('No evaluation metrics to save')
        results = self.evaluation_metrics.to_dict()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        LOG.info(f'Evaluation results saved to {filepath}')

    def load_evaluation_results(self, filepath: str) -> ModelEvaluationMetrics:
        """Load evaluation results from JSON file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f'Evaluation results file {filepath} not found')
        with open(filepath, 'r', encoding='utf-8') as f:
            results = json.load(f)
        self.evaluation_metrics = ModelEvaluationMetrics.from_dict(results)
        LOG.info(f'Evaluation results loaded from {filepath}')
        return self.evaluation_metrics

    def get_feature_importance_report(self, top_n: int=10) -> Dict[str, Any]:
        """
        Get feature importance analysis.

        Args:
            top_n: Number of top features to include

        Returns:
            Dictionary with feature importance analysis
        """
        if self.evaluation_metrics is None:
            raise RuntimeError('No evaluation metrics available')
        sorted_features = sorted(self.evaluation_metrics.feature_importance.items(), key=lambda x: x[1], reverse=True)
        top_features = sorted_features[:top_n]
        return {'top_features': top_features, 'total_features': len(self.evaluation_metrics.feature_importance), 'top_features_importance_sum': sum((importance for _, importance in top_features)), 'feature_importance_distribution': {'mean': np.mean(list(self.evaluation_metrics.feature_importance.values())), 'std': np.std(list(self.evaluation_metrics.feature_importance.values())), 'min': min(self.evaluation_metrics.feature_importance.values()), 'max': max(self.evaluation_metrics.feature_importance.values())}}

    def generate_training_report(self) -> str:
        """Generate comprehensive training report."""
        if self.evaluation_metrics is None:
            return 'No evaluation metrics available'
        metrics = self.evaluation_metrics
        report = []
        report.append('=' * 60)
        report.append('DPI ML CLASSIFIER TRAINING REPORT')
        report.append('=' * 60)
        report.append('')
        report.append('OVERALL PERFORMANCE:')
        report.append(f'  Accuracy: {metrics.accuracy:.3f}')
        report.append(f'  F1-Score (Macro): {metrics.f1_macro:.3f}')
        report.append(f'  F1-Score (Weighted): {metrics.f1_weighted:.3f}')
        report.append('')
        report.append('CROSS-VALIDATION RESULTS:')
        report.append(f'  Mean CV Score: {metrics.cross_val_mean:.3f} ± {metrics.cross_val_std:.3f}')
        report.append(f"  CV Scores: {[f'{score:.3f}' for score in metrics.cross_val_scores]}")
        report.append('')
        report.append('PRECISION AND RECALL:')
        report.append(f'  Precision (Macro): {metrics.precision_macro:.3f}')
        report.append(f'  Precision (Micro): {metrics.precision_micro:.3f}')
        report.append(f'  Recall (Macro): {metrics.recall_macro:.3f}')
        report.append(f'  Recall (Micro): {metrics.recall_micro:.3f}')
        report.append('')
        report.append('CLASS DISTRIBUTION:')
        for class_name, count in metrics.class_distribution.items():
            percentage = count / sum(metrics.class_distribution.values()) * 100
            report.append(f'  {class_name}: {count} ({percentage:.1f}%)')
        report.append('')
        feature_report = self.get_feature_importance_report(top_n=10)
        report.append('TOP 10 MOST IMPORTANT FEATURES:')
        for i, (feature, importance) in enumerate(feature_report['top_features'], 1):
            report.append(f'  {i:2d}. {feature}: {importance:.4f}')
        report.append('')
        report.append('DETAILED CLASSIFICATION REPORT:')
        report.append(metrics.classification_report)
        return '\n'.join(report)

    def quick_train_and_evaluate(self, save_results: bool=True) -> ModelEvaluationMetrics:
        """
        Quick training and evaluation with default parameters.

        Args:
            save_results: Whether to save results to files

        Returns:
            ModelEvaluationMetrics
        """
        LOG.info('Starting quick training and evaluation...')
        training_data = self.prepare_training_data(include_synthetic=True, save_to_file='training_data.json' if save_results else None)
        metrics = self.train_model_with_evaluation(training_data)
        if save_results:
            self.save_evaluation_results('evaluation_results.json')
            report = self.generate_training_report()
            with open('training_report.txt', 'w', encoding='utf-8') as f:
                f.write(report)
            LOG.info('Results saved to training_data.json, evaluation_results.json, and training_report.txt')
        print(self.generate_training_report())
        return metrics