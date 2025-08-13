# recon/ml/strategy_predictor.py
"""
Specialized Strategy Predictor for recommending attack categories based on DPI behavioral profile
"""
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict

# Scikit-learn is an optional dependency
try:
    from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
    from sklearn.multioutput import MultiOutputRegressor
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import mean_squared_error, r2_score
    import joblib

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile

LOG = logging.getLogger("strategy_predictor")


@dataclass
class StrategyPrediction:
    """Result of strategy prediction"""

    recommended_categories: List[str]
    category_scores: Dict[str, float]
    predicted_success_rates: Dict[str, float]
    reasoning: List[str]
    confidence: float
    feature_contributions: Dict[str, float]


class StrategyPredictor:
    """
    Specialized ML predictor for recommending attack strategy categories based on DPI behavioral profiles
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or "data/strategy_predictor_model.joblib"
        self.success_rate_model = None
        self.category_ranking_model = None
        self.feature_scaler = StandardScaler() if SKLEARN_AVAILABLE else None

        # Attack strategy categories
        self.strategy_categories = [
            "tcp_segmentation",  # TCP-level segmentation attacks
            "ip_fragmentation",  # IP-level fragmentation attacks
            "timing_manipulation",  # Timing-based attacks
            "payload_obfuscation",  # Payload encoding/encryption
            "protocol_tunneling",  # Protocol tunneling attacks
            "header_manipulation",  # Header field manipulation
            "modern_protocols",  # HTTP/2, QUIC, ECH attacks
            "traffic_mimicry",  # Traffic pattern mimicry
            "multi_layer_combo",  # Multi-layer combination attacks
            "steganography",  # Steganographic techniques
        ]

        # Feature extraction configuration
        self.behavioral_features = [
            "supports_ip_frag",
            "checksum_validation",
            "rst_latency_ms",
            "timing_sensitivity_avg",
            "burst_tolerance",
            "tcp_state_depth",
            "tls_inspection_level_score",
            "http_parsing_strictness_score",
            "anti_evasion_count",
            "detection_sophistication_score",
            "connection_limit_log",
            "dpi_depth_log",
            "protocol_support_score",
        ]

        self.is_trained = False

        if SKLEARN_AVAILABLE:
            self._initialize_models()
            self._try_load_model()
        else:
            LOG.warning(
                "Scikit-learn not available, strategy predictor will use rule-based fallback"
            )

    def _initialize_models(self):
        """Initialize ML models"""
        if not SKLEARN_AVAILABLE:
            return

        # Success rate prediction model - predicts success rate for each category
        self.success_rate_model = MultiOutputRegressor(
            RandomForestRegressor(
                n_estimators=100, max_depth=12, random_state=42, n_jobs=-1
            )
        )

        # Category ranking model - predicts relative ranking of categories
        self.category_ranking_model = GradientBoostingRegressor(
            n_estimators=100, max_depth=8, learning_rate=0.1, random_state=42
        )

    def _try_load_model(self):
        """Try to load pre-trained model"""
        try:
            if SKLEARN_AVAILABLE:
                model_data = joblib.load(self.model_path)
                self.success_rate_model = model_data["success_rate_model"]
                self.category_ranking_model = model_data["category_ranking_model"]
                self.feature_scaler = model_data["feature_scaler"]
                self.is_trained = True
                LOG.info("Pre-trained strategy predictor model loaded successfully")
        except Exception as e:
            LOG.debug(f"Could not load pre-trained model: {e}")
            self.is_trained = False

    def extract_behavioral_features(self, profile: DPIBehaviorProfile) -> np.ndarray:
        """Extract numerical features from behavioral profile for strategy prediction"""
        if not SKLEARN_AVAILABLE:
            return np.array([])

        features = []

        # Core DPI capabilities
        features.append(1.0 if profile.supports_ip_frag else 0.0)
        features.append(1.0 if profile.checksum_validation else 0.0)
        features.append(
            float(profile.rst_latency_ms or 0.0) / 1000.0
        )  # Normalize to seconds

        # Timing sensitivity (average across all delay types)
        timing_scores = (
            list(profile.timing_sensitivity_profile.values())
            if profile.timing_sensitivity_profile
            else [0.0]
        )
        features.append(np.mean(timing_scores))

        # Burst tolerance
        features.append(float(profile.burst_tolerance or 0.0))

        # TCP state tracking depth
        features.append(float(profile.tcp_state_tracking_depth or 0))

        # TLS inspection level (numerical encoding)
        tls_level_score = 0.0
        if profile.tls_inspection_level == "full":
            tls_level_score = 4.0
        elif profile.tls_inspection_level == "deep":
            tls_level_score = 3.0
        elif profile.tls_inspection_level == "basic":
            tls_level_score = 2.0
        elif profile.tls_inspection_level == "none":
            tls_level_score = 1.0
        features.append(tls_level_score)

        # HTTP parsing strictness (numerical encoding)
        http_strictness_score = 0.0
        if profile.http_parsing_strictness == "strict":
            http_strictness_score = 3.0
        elif profile.http_parsing_strictness == "standard":
            http_strictness_score = 2.0
        elif profile.http_parsing_strictness == "loose":
            http_strictness_score = 1.0
        features.append(http_strictness_score)

        # Anti-evasion technique count
        features.append(float(len(profile.anti_evasion_techniques)))

        # Detection sophistication score
        detection_score = 0.0
        if profile.ml_detection:
            detection_score += 4.0
        if profile.behavioral_analysis:
            detection_score += 3.0
        if profile.statistical_analysis:
            detection_score += 2.0
        if profile.signature_based_detection:
            detection_score += 1.0
        features.append(detection_score)

        # Connection limit (log scale)
        conn_limit = profile.stateful_connection_limit or 1000
        features.append(np.log10(conn_limit))

        # DPI inspection depth (log scale)
        dpi_depth = profile.deep_packet_inspection_depth or 100
        features.append(np.log10(dpi_depth))

        # Protocol support score
        protocol_score = 0.0
        if profile.ech_support:
            protocol_score += 3.0
        if hasattr(profile, "http2_support") and profile.http2_support:
            protocol_score += 2.0
        if hasattr(profile, "quic_support") and profile.quic_support:
            protocol_score += 2.0
        features.append(protocol_score)

        return np.array(features)

    def predict_strategy_categories(
        self, profile: DPIBehaviorProfile
    ) -> StrategyPrediction:
        """Predict optimal attack strategy categories for given DPI behavioral profile"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return self._rule_based_strategy_prediction(profile)

        try:
            # Extract features
            features = self.extract_behavioral_features(profile)
            features_scaled = self.feature_scaler.transform(features.reshape(1, -1))

            # Predict success rates for each category
            success_rates = self.success_rate_model.predict(features_scaled)[0]

            # Create category scores dictionary
            category_scores = {}
            predicted_success_rates = {}

            for i, category in enumerate(self.strategy_categories):
                if i < len(success_rates):
                    success_rate = max(
                        0.0, min(1.0, success_rates[i])
                    )  # Clamp to [0,1]
                    category_scores[category] = success_rate
                    predicted_success_rates[category] = success_rate
                else:
                    category_scores[category] = 0.5
                    predicted_success_rates[category] = 0.5

            # Sort categories by predicted success rate
            sorted_categories = sorted(
                category_scores.items(), key=lambda x: x[1], reverse=True
            )

            # Select top categories (those with success rate > 0.6)
            recommended_categories = [
                cat for cat, score in sorted_categories if score > 0.6
            ]

            # If no categories meet threshold, take top 3
            if not recommended_categories:
                recommended_categories = [cat for cat, _ in sorted_categories[:3]]

            # Calculate overall confidence
            top_scores = [score for _, score in sorted_categories[:3]]
            confidence = np.mean(top_scores) if top_scores else 0.5

            # Get feature contributions (simplified)
            feature_contributions = {}
            if hasattr(self.success_rate_model.estimators_[0], "feature_importances_"):
                for i, importance in enumerate(
                    self.success_rate_model.estimators_[0].feature_importances_
                ):
                    if i < len(self.behavioral_features):
                        feature_contributions[self.behavioral_features[i]] = float(
                            importance
                        )

            # Generate reasoning
            reasoning = self._generate_ml_reasoning(
                profile, category_scores, feature_contributions
            )

            return StrategyPrediction(
                recommended_categories=recommended_categories,
                category_scores=category_scores,
                predicted_success_rates=predicted_success_rates,
                reasoning=reasoning,
                confidence=confidence,
                feature_contributions=feature_contributions,
            )

        except Exception as e:
            LOG.error(f"ML strategy prediction failed: {e}")
            return self._rule_based_strategy_prediction(profile)

    def _rule_based_strategy_prediction(
        self, profile: DPIBehaviorProfile
    ) -> StrategyPrediction:
        """Fallback rule-based strategy prediction when ML is not available"""
        LOG.debug("Using rule-based strategy prediction")

        category_scores = {}
        reasoning = []

        # Initialize all categories with base score
        for category in self.strategy_categories:
            category_scores[category] = 0.3  # Base score

        # Rule-based scoring

        # IP fragmentation effectiveness
        if profile.supports_ip_frag:
            category_scores["ip_fragmentation"] += 0.4
            reasoning.append(
                "IP fragmentation supported - fragmentation attacks likely effective"
            )
        else:
            category_scores["ip_fragmentation"] -= 0.2
            reasoning.append(
                "IP fragmentation blocked - fragmentation attacks less effective"
            )

        # TCP segmentation based on checksum validation
        if not profile.checksum_validation:
            category_scores["tcp_segmentation"] += 0.3
            reasoning.append(
                "Weak checksum validation - TCP segmentation attacks effective"
            )

        # Timing attacks based on RST latency
        if profile.rst_latency_ms and profile.rst_latency_ms > 100:
            category_scores["timing_manipulation"] += 0.3
            reasoning.append("Slow RST response - timing attacks may be effective")

        # Modern protocol attacks
        if profile.ech_support is False:
            category_scores["modern_protocols"] += 0.2
            reasoning.append("ECH not supported - modern protocol attacks may work")

        # Traffic mimicry for sophisticated DPI
        if profile.ml_detection or profile.behavioral_analysis:
            category_scores["traffic_mimicry"] += 0.4
            reasoning.append("Advanced detection methods - traffic mimicry recommended")

        # Payload obfuscation for deep inspection
        if (
            profile.deep_packet_inspection_depth
            and profile.deep_packet_inspection_depth > 1000
        ):
            category_scores["payload_obfuscation"] += 0.3
            reasoning.append("Deep packet inspection - payload obfuscation recommended")

        # Protocol tunneling for restrictive DPI
        if len(profile.anti_evasion_techniques) >= 3:
            category_scores["protocol_tunneling"] += 0.4
            reasoning.append(
                "Multiple anti-evasion techniques - protocol tunneling recommended"
            )

        # Header manipulation for stateful inspection
        if profile.tcp_state_tracking_depth and profile.tcp_state_tracking_depth >= 2:
            category_scores["header_manipulation"] += 0.3
            reasoning.append(
                "Stateful inspection detected - header manipulation may work"
            )

        # Multi-layer combo for sophisticated DPI
        sophistication_score = 0
        if profile.ml_detection:
            sophistication_score += 1
        if profile.behavioral_analysis:
            sophistication_score += 1
        if profile.statistical_analysis:
            sophistication_score += 1
        if len(profile.anti_evasion_techniques) >= 2:
            sophistication_score += 1

        if sophistication_score >= 3:
            category_scores["multi_layer_combo"] += 0.5
            reasoning.append(
                "Highly sophisticated DPI - multi-layer combination attacks recommended"
            )

        # Steganography for advanced DPI
        if profile.learning_adaptation_detected or profile.honeypot_detection:
            category_scores["steganography"] += 0.4
            reasoning.append(
                "Adaptive DPI detected - steganographic techniques recommended"
            )

        # Normalize scores to [0,1] range
        for category in category_scores:
            category_scores[category] = max(0.0, min(1.0, category_scores[category]))

        # Sort and select top categories
        sorted_categories = sorted(
            category_scores.items(), key=lambda x: x[1], reverse=True
        )
        recommended_categories = [
            cat for cat, score in sorted_categories if score > 0.6
        ]

        if not recommended_categories:
            recommended_categories = [cat for cat, _ in sorted_categories[:3]]

        # Calculate confidence
        top_scores = [score for _, score in sorted_categories[:3]]
        confidence = np.mean(top_scores) if top_scores else 0.5

        return StrategyPrediction(
            recommended_categories=recommended_categories,
            category_scores=category_scores,
            predicted_success_rates=category_scores.copy(),
            reasoning=reasoning,
            confidence=confidence,
            feature_contributions={},
        )

    def _generate_ml_reasoning(
        self,
        profile: DPIBehaviorProfile,
        category_scores: Dict[str, float],
        feature_contributions: Dict[str, float],
    ) -> List[str]:
        """Generate human-readable reasoning for ML predictions"""
        reasoning = []

        # Get top 3 categories
        top_categories = sorted(
            category_scores.items(), key=lambda x: x[1], reverse=True
        )[:3]

        for category, score in top_categories:
            if score > 0.6:
                reasoning.append(
                    f"{category.replace('_', ' ').title()} predicted with {score:.1%} success rate"
                )

        # Explain top contributing features
        if feature_contributions:
            sorted_features = sorted(
                feature_contributions.items(), key=lambda x: x[1], reverse=True
            )

            for feature, contribution in sorted_features[:2]:
                if contribution > 0.1:
                    reasoning.append(
                        f"Key factor: {feature.replace('_', ' ')} (contribution: {contribution:.2f})"
                    )

        return reasoning

    def train_model(
        self, training_data: List[Tuple[DPIBehaviorProfile, Dict[str, float]]]
    ):
        """Train the strategy predictor with labeled data"""
        if not SKLEARN_AVAILABLE:
            LOG.warning("Cannot train model: scikit-learn not available")
            return

        if len(training_data) < 20:
            LOG.warning("Insufficient training data for reliable model training")
            return

        LOG.info(f"Training strategy predictor with {len(training_data)} samples")

        # Extract features and labels
        X = []
        y = []

        for profile, success_rates in training_data:
            features = self.extract_behavioral_features(profile)
            X.append(features)

            # Create target vector for all categories
            target_vector = []
            for category in self.strategy_categories:
                target_vector.append(success_rates.get(category, 0.5))
            y.append(target_vector)

        X = np.array(X)
        y = np.array(y)

        # Scale features
        X_scaled = self.feature_scaler.fit_transform(X)

        # Train success rate model
        self.success_rate_model.fit(X_scaled, y)

        # Evaluate model
        y_pred = self.success_rate_model.predict(X_scaled)
        mse = mean_squared_error(y, y_pred)
        r2 = r2_score(y, y_pred)

        self.is_trained = True

        LOG.info(f"Model training completed - MSE: {mse:.4f}, R²: {r2:.4f}")

        # Save model
        self.save_model()

    def save_model(self):
        """Save trained model to disk"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return

        try:
            model_data = {
                "success_rate_model": self.success_rate_model,
                "category_ranking_model": self.category_ranking_model,
                "feature_scaler": self.feature_scaler,
                "strategy_categories": self.strategy_categories,
                "behavioral_features": self.behavioral_features,
                "training_timestamp": datetime.now().isoformat(),
            }

            joblib.dump(model_data, self.model_path)
            LOG.info(f"Strategy predictor model saved to {self.model_path}")

        except Exception as e:
            LOG.error(f"Failed to save model: {e}")

    def update_model_with_feedback(
        self, profile: DPIBehaviorProfile, actual_success_rates: Dict[str, float]
    ):
        """Update model with feedback from actual attack results"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return

        try:
            # This would implement online learning or model updating
            # For now, we'll store the feedback for future retraining
            LOG.info(f"Received feedback for model improvement: {actual_success_rates}")

            # In a full implementation, this would:
            # 1. Store the feedback data
            # 2. Periodically retrain the model with accumulated feedback
            # 3. Use techniques like incremental learning

        except Exception as e:
            LOG.error(f"Failed to update model with feedback: {e}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        info = {
            "is_trained": self.is_trained,
            "sklearn_available": SKLEARN_AVAILABLE,
            "strategy_categories": self.strategy_categories,
            "behavioral_features": self.behavioral_features,
        }

        if SKLEARN_AVAILABLE and self.is_trained:
            # Get feature importances if available
            if hasattr(self.success_rate_model.estimators_[0], "feature_importances_"):
                info["feature_importances"] = {
                    feature: float(importance)
                    for feature, importance in zip(
                        self.behavioral_features,
                        self.success_rate_model.estimators_[0].feature_importances_,
                    )
                }

        return info
