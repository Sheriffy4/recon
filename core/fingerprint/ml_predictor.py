"""
ML Prediction Module for Fingerprint Engine

This module handles all machine learning and prediction logic for the fingerprint engine,
including model initialization, feature extraction, and effectiveness predictions.

Extracted from advanced_fingerprint_engine.py as part of Step 6 refactoring.
"""

import logging
import os
from typing import Dict, List, Optional, Tuple, Any

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.utils.validation import check_is_fitted
    import joblib
    import numpy as np

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    check_is_fitted = None
    np = None

from core.fingerprint.models import EnhancedFingerprint

LOG = logging.getLogger("fingerprint_ml_predictor")


class FingerprintMLPredictor:
    """
    Handles ML-based predictions for fingerprint analysis.

    This class encapsulates all machine learning functionality including:
    - Model initialization and loading
    - Feature extraction from fingerprints
    - Weakness prediction
    - Attack effectiveness prediction
    - Technique effectiveness prediction
    """

    def __init__(self, ml_enabled: bool = True, attack_adapter=None, debug: bool = True):
        """
        Initialize ML predictor.

        Args:
            ml_enabled: Enable ML features (requires sklearn)
            attack_adapter: Attack adapter for getting available attacks
            debug: Enable debug logging
        """
        self.ml_enabled = ml_enabled and SKLEARN_AVAILABLE
        self.attack_adapter = attack_adapter
        self.debug = debug

        self.effectiveness_model = None
        self.strategy_predictor = None
        self.is_effectiveness_model_fitted = False

        if self.ml_enabled:
            self._initialize_ml_models()

        LOG.info(
            f"FingerprintMLPredictor initialized (ML enabled: {self.ml_enabled}, "
            f"sklearn available: {SKLEARN_AVAILABLE})"
        )

    def _is_model_fitted(self, model) -> bool:
        """
        Check if sklearn model is fitted.

        Args:
            model: sklearn model to check

        Returns:
            True if model is fitted, False otherwise
        """
        if not SKLEARN_AVAILABLE or model is None:
            return False
        try:
            if hasattr(model, "n_features_in_"):
                return hasattr(model, "n_features_in_") and model.n_features_in_ > 0
            else:
                check_is_fitted(model)
                return True
        except (AttributeError, ValueError, TypeError) as e:
            LOG.debug(f"Model not fitted: {e}")
            return False

    def _initialize_ml_models(self):
        """Initialize ML models for predictions"""
        try:
            model_path = "data/ml_models/effectiveness_predictor.pkl"
            if os.path.exists(model_path):
                try:
                    self.effectiveness_model = joblib.load(model_path)
                    self.is_effectiveness_model_fitted = self._is_model_fitted(
                        self.effectiveness_model
                    )
                except Exception as e:
                    LOG.warning(f"Failed to load effectiveness model: {e}")
                    self.effectiveness_model = None
                    self.is_effectiveness_model_fitted = False
            else:
                LOG.info("No pre-trained effectiveness model found")
                self.effectiveness_model = None
                self.is_effectiveness_model_fitted = False

            try:
                from core.ml.strategy_predictor import StrategyPredictor

                self.strategy_predictor = StrategyPredictor(train_on_init=False)
            except ImportError:
                LOG.warning("Strategy predictor not available")
                self.strategy_predictor = None
        except Exception as e:
            LOG.error(f"Failed to initialize ML models: {e}")
            self.effectiveness_model = None
            self.is_effectiveness_model_fitted = False

    def extract_ml_features(self, fp: EnhancedFingerprint) -> Dict[str, float]:
        """
        Extract comprehensive ML features from fingerprint.

        Args:
            fp: EnhancedFingerprint object

        Returns:
            Dictionary of ML features
        """
        features = {}

        # Basic numeric features
        features["rst_ttl"] = fp.rst_ttl or -1
        features["rst_latency_ms"] = fp.rst_latency_ms or -1
        features["connection_latency"] = fp.connection_latency
        features["packet_loss_rate"] = fp.packet_loss_rate

        # Boolean features
        bool_attrs = [
            "supports_ip_frag",
            "checksum_validation",
            "stateful_inspection",
            "ml_detection_blocked",
            "rate_limiting_detected",
            "large_payload_bypass",
        ]
        for attr in bool_attrs:
            value = getattr(fp, attr, None)
            features[f"has_{attr}"] = 1.0 if value else 0.0

        # Technique success rate statistics
        if fp.technique_success_rates:
            rates = list(fp.technique_success_rates.values())
            if SKLEARN_AVAILABLE and rates:
                features["avg_technique_success"] = np.mean(rates)
                features["std_technique_success"] = np.std(rates) if len(rates) > 1 else 0
                features["max_technique_success"] = max(rates)
                features["min_technique_success"] = min(rates)
            else:
                features["avg_technique_success"] = sum(rates) / len(rates) if rates else 0
                features["max_technique_success"] = max(rates) if rates else 0
                features["min_technique_success"] = min(rates) if rates else 0
                features["std_technique_success"] = 0

        # Evasion difficulty
        features["evasion_difficulty"] = fp.calculate_evasion_difficulty()

        return features

    def predict_weaknesses(self, fp: EnhancedFingerprint) -> List[str]:
        """
        Predict DPI weaknesses using ML and rule-based analysis.

        Args:
            fp: EnhancedFingerprint object

        Returns:
            List of predicted weakness descriptions
        """
        weaknesses = []

        # Rule-based weakness detection
        if fp.supports_ip_frag:
            weaknesses.append("Vulnerable to IP fragmentation attacks")
        if not fp.checksum_validation:
            weaknesses.append("No checksum validation - checksum attacks possible")
        if fp.large_payload_bypass:
            weaknesses.append("Large payloads can bypass inspection")
        if not fp.ml_detection_blocked:
            weaknesses.append("No ML-based anomaly detection")

        # ML-based weakness prediction
        if (
            self.ml_enabled
            and self.strategy_predictor
            and hasattr(self.strategy_predictor, "predict_weaknesses")
        ):
            try:
                ml_weaknesses = self.strategy_predictor.predict_weaknesses(fp.to_dict())
                weaknesses.extend(ml_weaknesses)
            except Exception as e:
                LOG.debug(f"ML weakness prediction failed: {e}")

        return list(set(weaknesses))

    def predict_best_attacks(self, fp: EnhancedFingerprint) -> List[Tuple[str, float]]:
        """
        Predict most effective attacks using ML.

        Args:
            fp: EnhancedFingerprint object

        Returns:
            List of (attack_name, effectiveness_score) tuples, sorted by score
        """
        predictions = []

        if self.ml_enabled and self._is_model_fitted(self.effectiveness_model):
            try:
                if not self.attack_adapter:
                    LOG.warning("No attack adapter available for predictions")
                    return predictions

                all_attacks = self.attack_adapter.get_available_attacks()
                for attack in all_attacks[:20]:
                    score = self.predict_technique_effectiveness(attack, fp.domain, fp)
                    if score is not None:
                        predictions.append((attack, score))

                predictions.sort(key=lambda x: x[1], reverse=True)
            except Exception as e:
                LOG.error(f"Attack prediction failed: {e}")

        return predictions[:10]

    def predict_technique_effectiveness(
        self, technique: str, domain: str, fp: Optional[EnhancedFingerprint] = None
    ) -> Optional[float]:
        """
        Predict technique effectiveness using ML model.

        Args:
            technique: Attack technique name
            domain: Target domain
            fp: EnhancedFingerprint object (optional)

        Returns:
            Predicted effectiveness score (0.0-1.0) or None if prediction fails
        """
        if not self._is_model_fitted(self.effectiveness_model):
            return None

        try:
            # Placeholder for actual ML prediction
            # In production, this would use the fitted model with extracted features
            return 0.5
        except Exception as e:
            LOG.debug(f"Effectiveness prediction failed: {e}")
            return None

    def is_ml_available(self) -> bool:
        """
        Check if ML functionality is available.

        Returns:
            True if ML is enabled and sklearn is available
        """
        return self.ml_enabled and SKLEARN_AVAILABLE

    def is_model_ready(self) -> bool:
        """
        Check if effectiveness model is fitted and ready.

        Returns:
            True if model is fitted and ready for predictions
        """
        return self.is_effectiveness_model_fitted and self._is_model_fitted(
            self.effectiveness_model
        )
