"""
Online learning capabilities for DPI ML classifier.
Implements incremental learning, confidence-based updates, performance monitoring,
and A/B testing framework for continuous model improvement.
"""
from __future__ import annotations
import logging
import os
import json
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
import numpy as np
from enum import Enum
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
from recon.core.fingerprint.ml_classifier import MLClassifier
LOG = logging.getLogger('online_learning')

class LearningMode(Enum):
    """Learning modes for online learning system."""
    CONSERVATIVE = 'conservative'
    MODERATE = 'moderate'
    AGGRESSIVE = 'aggressive'
    DISABLED = 'disabled'

@dataclass
class LearningExample:
    """A single learning example with metadata."""
    metrics: Dict[str, Any]
    predicted_type: str
    actual_type: str
    confidence: float
    timestamp: float
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LearningExample':
        return cls(**data)

@dataclass
class PerformanceMetrics:
    """Performance metrics for monitoring model degradation."""
    accuracy: float
    f1_score: float
    confidence_distribution: Dict[str, int]
    prediction_counts: Dict[str, int]
    timestamp: float
    sample_size: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PerformanceMetrics':
        return cls(**data)

@dataclass
class ABTestConfig:
    """Configuration for A/B testing."""
    test_name: str
    control_model_path: str
    test_model_path: str
    traffic_split: float
    min_samples: int
    max_duration_hours: int
    success_threshold: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ABTestConfig':
        return cls(**data)

@dataclass
class ABTestResults:
    """Results from A/B testing."""
    test_name: str
    control_accuracy: float
    test_accuracy: float
    control_f1: float
    test_f1: float
    control_samples: int
    test_samples: int
    improvement: float
    statistical_significance: float
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ABTestResults':
        return cls(**data)

class OnlineLearningSystem:
    """
    Comprehensive online learning system for DPI ML classifier.

    Features:
    - Incremental model updates with confidence-based learning
    - Performance monitoring and automatic retraining triggers
    - A/B testing framework for model improvements
    - Learning example buffer with intelligent sampling
    """

    def __init__(self, ml_classifier: MLClassifier, learning_mode: LearningMode=LearningMode.MODERATE, buffer_size: int=1000, min_confidence_threshold: float=0.7, performance_window_size: int=100, retraining_threshold: float=0.05):
        """
        Initialize online learning system.

        Args:
            ml_classifier: The ML classifier to enhance with online learning
            learning_mode: Learning mode (conservative, moderate, aggressive)
            buffer_size: Maximum size of learning example buffer
            min_confidence_threshold: Minimum confidence for learning
            performance_window_size: Size of sliding window for performance monitoring
            retraining_threshold: Performance drop threshold for triggering retraining
        """
        self.ml_classifier = ml_classifier
        self.learning_mode = learning_mode
        self.buffer_size = buffer_size
        self.min_confidence_threshold = min_confidence_threshold
        self.performance_window_size = performance_window_size
        self.retraining_threshold = retraining_threshold
        self.learning_buffer: deque = deque(maxlen=buffer_size)
        self.performance_history: deque = deque(maxlen=performance_window_size)
        self.baseline_performance: Optional[PerformanceMetrics] = None
        self.active_ab_test: Optional[ABTestConfig] = None
        self.ab_test_results: Dict[str, List[Dict[str, Any]]] = {'control': [], 'test': []}
        self.test_model: Optional[MLClassifier] = None
        self._lock = threading.Lock()
        self.stats = {'total_examples_received': 0, 'examples_learned_from': 0, 'retraining_events': 0, 'ab_tests_completed': 0, 'last_retraining_time': None, 'learning_mode_changes': 0}
        self._load_state()
        LOG.info(f'Online learning system initialized with mode: {learning_mode.value}')

    def add_learning_example(self, metrics: Dict[str, Any], predicted_type: str, actual_type: str, confidence: float, source: str='automatic') -> bool:
        """
        Add a new learning example to the system.

        Args:
            metrics: DPI metrics that were used for prediction
            predicted_type: What the model predicted
            actual_type: The actual/correct DPI type
            confidence: Confidence score of the prediction
            source: Source of the example ('user_feedback', 'validation', 'automatic')

        Returns:
            bool: True if example was accepted for learning, False otherwise
        """
        with self._lock:
            self.stats['total_examples_received'] += 1
            if not self._should_learn_from_example(confidence, predicted_type, actual_type):
                LOG.debug(f'Skipping learning example: confidence={confidence:.3f}, predicted={predicted_type}, actual={actual_type}')
                return False
            example = LearningExample(metrics=metrics, predicted_type=predicted_type, actual_type=actual_type, confidence=confidence, timestamp=time.time(), source=source)
            self.learning_buffer.append(example)
            self.stats['examples_learned_from'] += 1
            LOG.info(f'Added learning example: {predicted_type} -> {actual_type} (confidence: {confidence:.3f}, source: {source})')
            if self._should_trigger_incremental_update():
                self._perform_incremental_update()
            self._update_performance_monitoring(example)
            if self._should_trigger_retraining():
                self._trigger_retraining()
            return True

    def _should_learn_from_example(self, confidence: float, predicted: str, actual: str) -> bool:
        """Determine if we should learn from this example based on learning mode and confidence."""
        if self.learning_mode == LearningMode.DISABLED:
            return False
        if predicted == actual and confidence > 0.9:
            return False
        if self.learning_mode == LearningMode.CONSERVATIVE:
            return confidence >= 0.8 or (predicted != actual and confidence >= 0.6)
        elif self.learning_mode == LearningMode.MODERATE:
            if predicted == actual:
                return confidence >= 0.8
            else:
                return confidence >= self.min_confidence_threshold
        elif self.learning_mode == LearningMode.AGGRESSIVE:
            return confidence >= 0.5
        return False

    def _should_trigger_incremental_update(self) -> bool:
        """Check if we should perform an incremental model update."""
        if self.learning_mode == LearningMode.AGGRESSIVE:
            threshold = 20
        elif self.learning_mode == LearningMode.MODERATE:
            threshold = 50
        else:
            threshold = 100
        return len(self.learning_buffer) >= threshold

    def _perform_incremental_update(self):
        """Perform incremental model update with buffered examples."""
        if not SKLEARN_AVAILABLE or not self.ml_classifier.is_trained:
            LOG.warning('Cannot perform incremental update: sklearn unavailable or model not trained')
            return
        try:
            LOG.info(f'Performing incremental update with {len(self.learning_buffer)} examples')
            training_data = []
            for example in self.learning_buffer:
                training_data.append({'metrics': example.metrics, 'dpi_type': example.actual_type})
            if not training_data:
                LOG.debug('No training data for incremental update')
                return
            pre_update_performance = self._evaluate_current_performance()
            from recon.core.fingerprint.model_trainer import ModelTrainer
            trainer = ModelTrainer(self.ml_classifier.model_path)
            try:
                existing_data = trainer.prepare_training_data(include_synthetic=False)
                combined_data = existing_data + training_data
            except:
                combined_data = training_data
            if len(combined_data) < 5:
                LOG.debug('Not enough data for incremental update')
                return
            metrics = trainer.train_model_with_evaluation(combined_data)
            self.ml_classifier = trainer.ml_classifier
            post_update_performance = self._evaluate_current_performance()
            LOG.info(f'Incremental update completed. Performance change: {post_update_performance.accuracy - pre_update_performance.accuracy:.3f}')
            self.learning_buffer.clear()
        except Exception as e:
            LOG.error(f'Incremental update failed: {e}')

    def _update_performance_monitoring(self, example: LearningExample):
        """Update performance monitoring with new example."""
        is_correct = example.predicted_type == example.actual_type
        if len(self.performance_history) >= self.performance_window_size:
            correct_predictions = sum((1 for ex in self.performance_history if ex.predicted_type == ex.actual_type))
            accuracy = correct_predictions / len(self.performance_history)
            confidence_dist = defaultdict(int)
            prediction_counts = defaultdict(int)
            for ex in self.performance_history:
                conf_bucket = f'{int(ex.confidence * 10) * 10}-{int(ex.confidence * 10) * 10 + 10}%'
                confidence_dist[conf_bucket] += 1
                prediction_counts[ex.predicted_type] += 1
            current_metrics = PerformanceMetrics(accuracy=accuracy, f1_score=0.0, confidence_distribution=dict(confidence_dist), prediction_counts=dict(prediction_counts), timestamp=time.time(), sample_size=len(self.performance_history))
            if self.baseline_performance is None:
                self.baseline_performance = current_metrics
                LOG.info(f'Set baseline performance: accuracy={accuracy:.3f}')
        self.performance_history.append(example)

    def _should_trigger_retraining(self) -> bool:
        """Check if performance has degraded enough to trigger retraining."""
        if self.baseline_performance is None or len(self.performance_history) < self.performance_window_size:
            return False
        correct_predictions = sum((1 for ex in self.performance_history if ex.predicted_type == ex.actual_type))
        current_accuracy = correct_predictions / len(self.performance_history)
        performance_drop = self.baseline_performance.accuracy - current_accuracy
        if performance_drop > self.retraining_threshold:
            LOG.warning(f'Performance degradation detected: {performance_drop:.3f} (threshold: {self.retraining_threshold})')
            return True
        return False

    def _trigger_retraining(self):
        """Trigger full model retraining due to performance degradation."""
        LOG.info('Triggering full model retraining due to performance degradation')
        try:
            from recon.core.fingerprint.model_trainer import ModelTrainer
            trainer = ModelTrainer(self.ml_classifier.model_path)
            recent_examples = []
            for example in self.learning_buffer:
                recent_examples.append({'metrics': example.metrics, 'dpi_type': example.actual_type})
            try:
                base_data = trainer.prepare_training_data(include_synthetic=True)
                combined_data = base_data + recent_examples
            except:
                combined_data = recent_examples
            if len(combined_data) < 10:
                LOG.warning('Not enough data for retraining, skipping')
                return
            metrics = trainer.train_model_with_evaluation(combined_data)
            self.ml_classifier = trainer.ml_classifier
            self.baseline_performance = PerformanceMetrics(accuracy=metrics.accuracy, f1_score=metrics.f1_macro, confidence_distribution={}, prediction_counts={}, timestamp=time.time(), sample_size=len(combined_data))
            self.performance_history.clear()
            self.stats['retraining_events'] += 1
            self.stats['last_retraining_time'] = time.time()
            LOG.info(f'Model retraining completed. New accuracy: {metrics.accuracy:.3f}')
        except Exception as e:
            LOG.error(f'Model retraining failed: {e}')

    def _evaluate_current_performance(self) -> PerformanceMetrics:
        """Evaluate current model performance."""
        if len(self.performance_history) == 0:
            return PerformanceMetrics(accuracy=0.0, f1_score=0.0, confidence_distribution={}, prediction_counts={}, timestamp=time.time(), sample_size=0)
        correct_predictions = sum((1 for ex in self.performance_history if ex.predicted_type == ex.actual_type))
        accuracy = correct_predictions / len(self.performance_history)
        return PerformanceMetrics(accuracy=accuracy, f1_score=0.0, confidence_distribution={}, prediction_counts={}, timestamp=time.time(), sample_size=len(self.performance_history))

    def start_ab_test(self, config: ABTestConfig) -> bool:
        """
        Start an A/B test comparing current model with a test model.

        Args:
            config: A/B test configuration

        Returns:
            bool: True if test started successfully, False otherwise
        """
        if self.active_ab_test is not None:
            LOG.warning('A/B test already active, cannot start new test')
            return False
        try:
            self.test_model = MLClassifier(config.test_model_path)
            if not self.test_model.load_model():
                LOG.error(f'Failed to load test model from {config.test_model_path}')
                return False
            self.active_ab_test = config
            self.ab_test_results = {'control': [], 'test': []}
            LOG.info(f"Started A/B test '{config.test_name}' with {config.traffic_split:.1%} traffic to test model")
            return True
        except Exception as e:
            LOG.error(f'Failed to start A/B test: {e}')
            return False

    def classify_with_ab_test(self, metrics: Dict[str, Any]) -> Tuple[str, float, str]:
        """
        Classify using A/B test if active, otherwise use main model.

        Args:
            metrics: DPI metrics for classification

        Returns:
            Tuple[str, float, str]: (dpi_type, confidence, model_used)
        """
        if self.active_ab_test is None or self.test_model is None:
            result = self.ml_classifier.classify_dpi(metrics)
            return (result[0], result[1], 'control')
        use_test_model = np.random.random() < self.active_ab_test.traffic_split
        if use_test_model:
            result = self.test_model.classify_dpi(metrics)
            model_used = 'test'
        else:
            result = self.ml_classifier.classify_dpi(metrics)
            model_used = 'control'
        return (result[0], result[1], model_used)

    def record_ab_test_result(self, metrics: Dict[str, Any], predicted_type: str, actual_type: str, confidence: float, model_used: str):
        """Record result for A/B test analysis."""
        if self.active_ab_test is None:
            return
        result = {'predicted_type': predicted_type, 'actual_type': actual_type, 'confidence': confidence, 'timestamp': time.time(), 'correct': predicted_type == actual_type}
        self.ab_test_results[model_used].append(result)
        if self._should_conclude_ab_test():
            self._conclude_ab_test()

    def _should_conclude_ab_test(self) -> bool:
        """Check if A/B test should be concluded."""
        if self.active_ab_test is None:
            return False
        config = self.active_ab_test
        control_samples = len(self.ab_test_results['control'])
        test_samples = len(self.ab_test_results['test'])
        if control_samples < config.min_samples or test_samples < config.min_samples:
            return False
        total_samples = control_samples + test_samples
        return total_samples >= config.min_samples * 2

    def _conclude_ab_test(self) -> ABTestResults:
        """Conclude A/B test and return results."""
        if self.active_ab_test is None:
            raise RuntimeError('No active A/B test to conclude')
        config = self.active_ab_test
        control_results = self.ab_test_results['control']
        test_results = self.ab_test_results['test']
        control_accuracy = sum((r['correct'] for r in control_results)) / len(control_results)
        test_accuracy = sum((r['correct'] for r in test_results)) / len(test_results)
        improvement = test_accuracy - control_accuracy
        statistical_significance = abs(improvement) / max(0.01, np.sqrt(control_accuracy * (1 - control_accuracy) / len(control_results) + test_accuracy * (1 - test_accuracy) / len(test_results)))
        if improvement > config.success_threshold and statistical_significance > 1.96:
            recommendation = 'deploy'
        elif improvement < -config.success_threshold:
            recommendation = 'reject'
        else:
            recommendation = 'continue'
        results = ABTestResults(test_name=config.test_name, control_accuracy=control_accuracy, test_accuracy=test_accuracy, control_f1=0.0, test_f1=0.0, control_samples=len(control_results), test_samples=len(test_results), improvement=improvement, statistical_significance=statistical_significance, recommendation=recommendation)
        self.active_ab_test = None
        self.test_model = None
        self.stats['ab_tests_completed'] += 1
        LOG.info(f'A/B test concluded: {results.recommendation} (improvement: {improvement:.3f}, significance: {statistical_significance:.2f})')
        return results

    def set_learning_mode(self, mode: LearningMode):
        """Change the learning mode."""
        old_mode = self.learning_mode
        self.learning_mode = mode
        self.stats['learning_mode_changes'] += 1
        LOG.info(f'Learning mode changed from {old_mode.value} to {mode.value}')

    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics."""
        return {'learning_mode': self.learning_mode.value, 'buffer_size': len(self.learning_buffer), 'buffer_capacity': self.buffer_size, 'performance_history_size': len(self.performance_history), 'baseline_performance': self.baseline_performance.to_dict() if self.baseline_performance else None, 'active_ab_test': self.active_ab_test.test_name if self.active_ab_test else None, 'statistics': self.stats.copy()}

    def _save_state(self):
        """Save online learning state to disk."""
        try:
            state = {'learning_mode': self.learning_mode.value, 'buffer_size': self.buffer_size, 'min_confidence_threshold': self.min_confidence_threshold, 'performance_window_size': self.performance_window_size, 'retraining_threshold': self.retraining_threshold, 'learning_buffer': [ex.to_dict() for ex in self.learning_buffer], 'performance_history': [ex.to_dict() for ex in self.performance_history], 'baseline_performance': self.baseline_performance.to_dict() if self.baseline_performance else None, 'stats': self.stats}
            with open('online_learning_state.json', 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            LOG.error(f'Failed to save online learning state: {e}')

    def _load_state(self):
        """Load online learning state from disk."""
        try:
            if not os.path.exists('online_learning_state.json'):
                return
            with open('online_learning_state.json', 'r') as f:
                state = json.load(f)
            self.learning_buffer = deque(maxlen=self.buffer_size)
            for ex_data in state.get('learning_buffer', []):
                self.learning_buffer.append(LearningExample.from_dict(ex_data))
            self.performance_history = deque(maxlen=self.performance_window_size)
            for ex_data in state.get('performance_history', []):
                self.performance_history.append(LearningExample.from_dict(ex_data))
            if state.get('baseline_performance'):
                self.baseline_performance = PerformanceMetrics.from_dict(state['baseline_performance'])
            self.stats.update(state.get('stats', {}))
            LOG.info('Online learning state loaded from disk')
        except Exception as e:
            LOG.error(f'Failed to load online learning state: {e}')

    def __del__(self):
        """Save state when object is destroyed."""
        self._save_state()