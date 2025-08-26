"""
Unit tests for MLClassifier.
Tests ML operations and model lifecycle according to task requirements.
"""
import pytest
import os
import tempfile
import shutil
from unittest.mock import patch
from tests.ml_classifier import MLClassifier, MLClassificationError

class TestMLClassifier:
    """Test suite for MLClassifier."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_model_path = os.path.join(self.temp_dir, 'test_model.joblib')
        self.sample_training_data = [{'metrics': {'rst_ttl': 63, 'rst_latency_ms': 50, 'stateful_inspection': True, 'ip_level_blocked': False, 'ml_detection_blocked': False, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls13', 'ipv6_handling': 'allowed', 'tcp_keepalive_handling': 'forward'}, 'dpi_type': 'ROSKOMNADZOR_TSPU'}, {'metrics': {'rst_ttl': 128, 'rst_latency_ms': 120, 'stateful_inspection': False, 'ip_level_blocked': True, 'ml_detection_blocked': False, 'rate_limiting_detected': False, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_all_tls', 'ipv6_handling': 'blocked', 'tcp_keepalive_handling': 'reset'}, 'dpi_type': 'GOVERNMENT_CENSORSHIP'}, {'metrics': {'rst_ttl': 255, 'rst_latency_ms': 30, 'stateful_inspection': True, 'ip_level_blocked': False, 'ml_detection_blocked': True, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls12', 'ipv6_handling': 'throttled', 'tcp_keepalive_handling': 'strip'}, 'dpi_type': 'COMMERCIAL_DPI'}, {'metrics': {'rst_ttl': 200, 'rst_latency_ms': 150, 'stateful_inspection': False, 'ip_level_blocked': False, 'ml_detection_blocked': False, 'rate_limiting_detected': False, 'rst_from_target': True, 'tls_version_sensitivity': 'no_version_preference', 'ipv6_handling': 'allowed', 'tcp_keepalive_handling': 'forward'}, 'dpi_type': 'CLOUDFLARE_PROTECTION'}]
        self.sample_metrics = {'rst_ttl': 63, 'rst_latency_ms': 45, 'stateful_inspection': True, 'ip_level_blocked': False, 'ml_detection_blocked': False, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls13', 'ipv6_handling': 'allowed', 'tcp_keepalive_handling': 'forward'}

    def teardown_method(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_init_with_sklearn_available(self):
        """Test MLClassifier initialization when sklearn is available."""
        with patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True):
            classifier = MLClassifier(model_path=self.test_model_path)
            assert classifier.sklearn_available is True
            assert classifier.model is not None
            assert classifier.is_trained is False
            assert len(classifier.dpi_types) == 8
            assert 'ROSKOMNADZOR_TSPU' in classifier.dpi_types

    def test_init_without_sklearn(self):
        """Test MLClassifier initialization when sklearn is not available."""
        with patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False):
            classifier = MLClassifier(model_path=self.test_model_path)
            assert classifier.sklearn_available is False
            assert classifier.model is None
            assert classifier.is_trained is False

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_train_model_success(self):
        """Test successful model training."""
        classifier = MLClassifier(model_path=self.test_model_path)
        accuracy = classifier.train_model(self.sample_training_data)
        assert isinstance(accuracy, float)
        assert 0.0 <= accuracy <= 1.0
        assert classifier.is_trained is True
        assert len(classifier.feature_names) > 0

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False)
    def test_train_model_without_sklearn(self):
        """Test model training when sklearn is not available."""
        classifier = MLClassifier(model_path=self.test_model_path)
        with pytest.raises(MLClassificationError, match='sklearn not available'):
            classifier.train_model(self.sample_training_data)

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_train_model_empty_data(self):
        """Test model training with empty data."""
        classifier = MLClassifier(model_path=self.test_model_path)
        with pytest.raises(MLClassificationError, match='No training data provided'):
            classifier.train_model([])

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_train_model_invalid_data(self):
        """Test model training with invalid data."""
        classifier = MLClassifier(model_path=self.test_model_path)
        invalid_data = [{'metrics': {}, 'invalid_key': 'test'}, {'dpi_type': 'TEST', 'invalid_key': 'test'}]
        with pytest.raises(MLClassificationError, match='No valid training examples'):
            classifier.train_model(invalid_data)

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_classify_dpi_trained_model(self):
        """Test DPI classification with trained model."""
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier.train_model(self.sample_training_data)
        dpi_type, confidence = classifier.classify_dpi(self.sample_metrics)
        assert isinstance(dpi_type, str)
        assert dpi_type in classifier.dpi_types
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_classify_dpi_untrained_model(self):
        """Test DPI classification with untrained model (should use fallback)."""
        classifier = MLClassifier(model_path=self.test_model_path)
        dpi_type, confidence = classifier.classify_dpi(self.sample_metrics)
        assert isinstance(dpi_type, str)
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False)
    def test_classify_dpi_without_sklearn(self):
        """Test DPI classification when sklearn is not available (should use fallback)."""
        classifier = MLClassifier(model_path=self.test_model_path)
        dpi_type, confidence = classifier.classify_dpi(self.sample_metrics)
        assert isinstance(dpi_type, str)
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0

    def test_fallback_classification_government_censorship(self):
        """Test fallback classification for government censorship."""
        classifier = MLClassifier(model_path=self.test_model_path)
        metrics = {'ip_level_blocked': True}
        dpi_type, confidence = classifier._fallback_classification(metrics)
        assert dpi_type == 'GOVERNMENT_CENSORSHIP'
        assert confidence == 0.7

    def test_fallback_classification_roskomnadzor_tspu(self):
        """Test fallback classification for Roskomnadzor TSPU."""
        classifier = MLClassifier(model_path=self.test_model_path)
        metrics = {'rst_ttl': 63, 'stateful_inspection': True}
        dpi_type, confidence = classifier._fallback_classification(metrics)
        assert dpi_type == 'ROSKOMNADZOR_TSPU'
        assert confidence == 0.6

    def test_fallback_classification_commercial_dpi(self):
        """Test fallback classification for commercial DPI."""
        classifier = MLClassifier(model_path=self.test_model_path)
        metrics = {'ml_detection_blocked': True}
        dpi_type, confidence = classifier._fallback_classification(metrics)
        assert dpi_type == 'COMMERCIAL_DPI'
        assert confidence == 0.6

    def test_fallback_classification_unknown(self):
        """Test fallback classification for unknown DPI."""
        classifier = MLClassifier(model_path=self.test_model_path)
        metrics = {}
        dpi_type, confidence = classifier._fallback_classification(metrics)
        assert dpi_type == 'UNKNOWN'
        assert confidence == 0.3

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_save_and_load_model(self):
        """Test model persistence (save and load)."""
        classifier1 = MLClassifier(model_path=self.test_model_path)
        classifier1.train_model(self.sample_training_data)
        classifier1.save_model()
        assert os.path.exists(self.test_model_path)
        classifier2 = MLClassifier(model_path=self.test_model_path)
        loaded = classifier2.load_model()
        assert loaded is True
        assert classifier2.is_trained is True
        assert len(classifier2.feature_names) > 0
        assert classifier2.dpi_types == classifier1.dpi_types

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False)
    def test_save_model_without_sklearn(self):
        """Test model saving when sklearn is not available."""
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier.save_model()
        assert not os.path.exists(self.test_model_path)

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False)
    def test_load_model_without_sklearn(self):
        """Test model loading when sklearn is not available."""
        classifier = MLClassifier(model_path=self.test_model_path)
        loaded = classifier.load_model()
        assert loaded is False

    def test_load_model_nonexistent_file(self):
        """Test loading model when file doesn't exist."""
        nonexistent_path = os.path.join(self.temp_dir, 'nonexistent.joblib')
        classifier = MLClassifier(model_path=nonexistent_path)
        loaded = classifier.load_model()
        assert loaded is False

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_update_model(self):
        """Test model update with new data."""
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier.train_model(self.sample_training_data)
        new_data = {'metrics': {'rst_ttl': 100, 'stateful_inspection': False, 'ml_detection_blocked': True}}
        classifier.update_model(new_data, 'FIREWALL_BASED')

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', False)
    def test_update_model_without_sklearn(self):
        """Test model update when sklearn is not available."""
        classifier = MLClassifier(model_path=self.test_model_path)
        new_data = {'metrics': {}}
        classifier.update_model(new_data, 'TEST_TYPE')

    def test_extract_features_from_metrics(self):
        """Test feature extraction from metrics."""
        classifier = MLClassifier(model_path=self.test_model_path)
        features = classifier._extract_features_from_metrics(self.sample_metrics)
        assert isinstance(features, list)
        assert len(features) > 0
        assert all((isinstance(f, float) for f in features))
        assert len(classifier.feature_names) > 0

    def test_extract_features_missing_metrics(self):
        """Test feature extraction with missing metrics."""
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier._extract_features_from_metrics(self.sample_metrics)
        incomplete_metrics = {'rst_ttl': 50}
        features = classifier._extract_features_from_metrics(incomplete_metrics)
        assert isinstance(features, list)
        assert len(features) == len(classifier.feature_names)
        assert features.count(-1.0) > 0

    def test_encode_tls_sensitivity(self):
        """Test TLS sensitivity encoding."""
        classifier = MLClassifier(model_path=self.test_model_path)
        assert classifier._encode_tls_sensitivity('blocks_tls13') == 3.0
        assert classifier._encode_tls_sensitivity('blocks_tls12') == 2.0
        assert classifier._encode_tls_sensitivity('no_version_preference') == 0.0
        assert classifier._encode_tls_sensitivity('unknown_value') == -1.0
        assert classifier._encode_tls_sensitivity(None) == -1.0

    def test_encode_ipv6_handling(self):
        """Test IPv6 handling encoding."""
        classifier = MLClassifier(model_path=self.test_model_path)
        assert classifier._encode_ipv6_handling('blocked') == 2.0
        assert classifier._encode_ipv6_handling('throttled') == 1.0
        assert classifier._encode_ipv6_handling('allowed') == 0.0
        assert classifier._encode_ipv6_handling('unknown_value') == -1.0
        assert classifier._encode_ipv6_handling(None) == -1.0

    def test_encode_tcp_keepalive(self):
        """Test TCP keepalive encoding."""
        classifier = MLClassifier(model_path=self.test_model_path)
        assert classifier._encode_tcp_keepalive('reset') == 2.0
        assert classifier._encode_tcp_keepalive('strip') == 1.0
        assert classifier._encode_tcp_keepalive('forward') == 0.0
        assert classifier._encode_tcp_keepalive('unknown_value') == -1.0
        assert classifier._encode_tcp_keepalive(None) == -1.0

    def test_get_model_info(self):
        """Test getting model information."""
        classifier = MLClassifier(model_path=self.test_model_path)
        info = classifier.get_model_info()
        assert isinstance(info, dict)
        assert 'sklearn_available' in info
        assert 'is_trained' in info
        assert 'model_path' in info
        assert 'feature_count' in info
        assert 'dpi_types' in info
        assert 'model_exists' in info
        assert info['model_path'] == self.test_model_path
        assert isinstance(info['dpi_types'], list)
        assert len(info['dpi_types']) == 8

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_get_model_info_trained(self):
        """Test getting model information for trained model."""
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier.train_model(self.sample_training_data)
        info = classifier.get_model_info()
        assert info['is_trained'] is True
        assert info['feature_count'] > 0
        assert info['model_exists'] is True

    @patch('recon.core.fingerprint.ml_classifier.joblib.load')
    def test_load_model_corrupted_file(self, mock_load):
        """Test loading corrupted model file."""
        mock_load.side_effect = Exception('Corrupted file')
        with open(self.test_model_path, 'w') as f:
            f.write('corrupted')
        classifier = MLClassifier(model_path=self.test_model_path)
        loaded = classifier.load_model()
        assert loaded is False
        assert classifier.is_trained is False

    @patch('recon.core.fingerprint.ml_classifier.joblib.dump')
    def test_save_model_write_error(self, mock_dump):
        """Test model saving with write error."""
        mock_dump.side_effect = Exception('Write error')
        classifier = MLClassifier(model_path=self.test_model_path)
        classifier.is_trained = True
        classifier.sklearn_available = True
        classifier.save_model()

class TestMLClassifierIntegration:
    """Integration tests for MLClassifier."""

    def setup_method(self):
        """Set up integration test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_model_path = os.path.join(self.temp_dir, 'integration_test_model.joblib')

    def teardown_method(self):
        """Clean up integration test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch('recon.core.fingerprint.ml_classifier.SKLEARN_AVAILABLE', True)
    def test_full_ml_lifecycle(self):
        """Test complete ML lifecycle: train, save, load, classify."""
        training_data = []
        for i in range(5):
            training_data.append({'metrics': {'rst_ttl': 60 + i, 'rst_latency_ms': 40 + i * 5, 'stateful_inspection': True, 'ip_level_blocked': False, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls13', 'ipv6_handling': 'allowed'}, 'dpi_type': 'ROSKOMNADZOR_TSPU'})
        for i in range(5):
            training_data.append({'metrics': {'rst_ttl': 250 + i, 'rst_latency_ms': 25 + i * 3, 'stateful_inspection': True, 'ml_detection_blocked': True, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls12', 'ipv6_handling': 'throttled'}, 'dpi_type': 'COMMERCIAL_DPI'})
        for i in range(5):
            training_data.append({'metrics': {'rst_ttl': 120 + i, 'rst_latency_ms': 100 + i * 10, 'ip_level_blocked': True, 'stateful_inspection': False, 'rate_limiting_detected': False, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_all_tls', 'ipv6_handling': 'blocked'}, 'dpi_type': 'GOVERNMENT_CENSORSHIP'})
        classifier1 = MLClassifier(model_path=self.test_model_path)
        accuracy = classifier1.train_model(training_data)
        assert accuracy > 0.5
        assert classifier1.is_trained
        classifier1.save_model()
        assert os.path.exists(self.test_model_path)
        classifier2 = MLClassifier(model_path=self.test_model_path)
        loaded = classifier2.load_model()
        assert loaded
        assert classifier2.is_trained
        test_metrics = {'rst_ttl': 62, 'rst_latency_ms': 45, 'stateful_inspection': True, 'rate_limiting_detected': True, 'rst_from_target': False, 'tls_version_sensitivity': 'blocks_tls13', 'ipv6_handling': 'allowed'}
        dpi_type, confidence = classifier2.classify_dpi(test_metrics)
        assert isinstance(dpi_type, str)
        assert dpi_type in classifier2.dpi_types
        assert 0.0 <= confidence <= 1.0
        new_data = {'metrics': test_metrics}
        classifier2.update_model(new_data, 'ROSKOMNADZOR_TSPU')
        info = classifier2.get_model_info()
        assert info['is_trained']
        assert info['sklearn_available']
        assert info['model_exists']
if __name__ == '__main__':
    pytest.main([__file__])