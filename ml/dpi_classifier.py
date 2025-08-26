"""
Specialized DPI Classifier for predicting DPI vendor and type based on behavioral profile
"""
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
from core.fingerprint.models import DPIBehaviorProfile
LOG = logging.getLogger('dpi_classifier')

@dataclass
class DPIClassificationResult:
    """Result of DPI classification"""
    predicted_vendor: str
    predicted_type: str
    confidence: float
    vendor_probabilities: Dict[str, float]
    type_probabilities: Dict[str, float]
    feature_importance: Dict[str, float]
    classification_reasoning: List[str]

class DPIClassifier:
    """
    Specialized ML classifier for DPI vendor and type prediction based on behavioral profiles
    """

    def __init__(self, model_path: Optional[str]=None):
        self.model_path = model_path or 'data/dpi_classifier_model.joblib'
        self.vendor_model = None
        self.type_model = None
        self.feature_scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.vendor_encoder = LabelEncoder() if SKLEARN_AVAILABLE else None
        self.type_encoder = LabelEncoder() if SKLEARN_AVAILABLE else None
        self.known_vendors = ['Cisco', 'Fortinet', 'Palo Alto', 'Check Point', 'SonicWall', 'Juniper', 'F5', 'Barracuda', 'WatchGuard', 'pfSense', 'Sophos', 'Forcepoint', 'Zscaler', 'Cloudflare', 'Akamai', 'Generic', 'Unknown']
        self.known_types = ['Enterprise_Firewall', 'NGFW', 'UTM', 'Cloud_Security', 'ISP_DPI', 'Government_DPI', 'CDN_Protection', 'WAF', 'Inline_IPS', 'Transparent_Proxy', 'Unknown']
        self.behavioral_features = ['supports_ip_frag', 'checksum_validation', 'rst_latency_ms', 'ech_support', 'timing_sensitivity_score', 'burst_tolerance', 'tcp_state_tracking_depth', 'stateful_connection_limit', 'deep_packet_inspection_depth', 'anti_evasion_count']
        self.is_trained = False
        if SKLEARN_AVAILABLE:
            self._initialize_models()
            self._try_load_model()
        else:
            LOG.warning('Scikit-learn not available, DPI classifier will use rule-based fallback')

    def _initialize_models(self):
        """Initialize ML models"""
        if not SKLEARN_AVAILABLE:
            return
        self.vendor_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
        self.type_model = GradientBoostingClassifier(n_estimators=100, max_depth=8, learning_rate=0.1, random_state=42)

    def _try_load_model(self):
        """Try to load pre-trained model"""
        try:
            if SKLEARN_AVAILABLE:
                model_data = joblib.load(self.model_path)
                self.vendor_model = model_data['vendor_model']
                self.type_model = model_data['type_model']
                self.feature_scaler = model_data['feature_scaler']
                self.vendor_encoder = model_data['vendor_encoder']
                self.type_encoder = model_data['type_encoder']
                self.is_trained = True
                LOG.info('Pre-trained DPI classifier model loaded successfully')
        except Exception as e:
            LOG.debug(f'Could not load pre-trained model: {e}')
            self.is_trained = False

    def extract_behavioral_features(self, profile: DPIBehaviorProfile) -> np.ndarray:
        """Extract numerical features from behavioral profile"""
        if not SKLEARN_AVAILABLE:
            return np.array([])
        features = []
        features.append(1.0 if profile.supports_ip_frag else 0.0)
        features.append(1.0 if profile.checksum_validation else 0.0)
        features.append(float(profile.rst_latency_ms or 0.0) / 1000.0)
        features.append(1.0 if profile.ech_support else 0.0)
        timing_scores = list(profile.timing_sensitivity_profile.values()) if profile.timing_sensitivity_profile else [0.0]
        features.append(np.mean(timing_scores))
        features.append(float(profile.burst_tolerance or 0.0))
        features.append(float(profile.tcp_state_tracking_depth or 0))
        conn_limit = profile.stateful_connection_limit or 1000
        features.append(np.log10(conn_limit))
        dpi_depth = profile.deep_packet_inspection_depth or 100
        features.append(np.log10(dpi_depth))
        features.append(float(len(profile.anti_evasion_techniques)))
        protocol_sophistication = 0.0
        if profile.tls_inspection_level == 'full':
            protocol_sophistication += 3.0
        elif profile.tls_inspection_level == 'deep':
            protocol_sophistication += 2.0
        elif profile.tls_inspection_level == 'basic':
            protocol_sophistication += 1.0
        if profile.http_parsing_strictness == 'strict':
            protocol_sophistication += 2.0
        elif profile.http_parsing_strictness == 'standard':
            protocol_sophistication += 1.0
        features.append(protocol_sophistication)
        detection_sophistication = 0.0
        if profile.ml_detection:
            detection_sophistication += 3.0
        if profile.behavioral_analysis:
            detection_sophistication += 2.0
        if profile.statistical_analysis:
            detection_sophistication += 1.0
        if profile.signature_based_detection:
            detection_sophistication += 1.0
        features.append(detection_sophistication)
        adaptation_score = 0.0
        if profile.learning_adaptation_detected:
            adaptation_score += 2.0
        if profile.honeypot_detection:
            adaptation_score += 1.0
        features.append(adaptation_score)
        return np.array(features)

    def predict_dpi_vendor_and_type(self, profile: DPIBehaviorProfile) -> DPIClassificationResult:
        """Predict DPI vendor and type from behavioral profile"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return self._rule_based_classification(profile)
        try:
            features = self.extract_behavioral_features(profile)
            features_scaled = self.feature_scaler.transform(features.reshape(1, -1))
            vendor_probs = self.vendor_model.predict_proba(features_scaled)[0]
            vendor_classes = self.vendor_model.classes_
            vendor_idx = np.argmax(vendor_probs)
            predicted_vendor = self.vendor_encoder.inverse_transform([vendor_classes[vendor_idx]])[0]
            vendor_confidence = vendor_probs[vendor_idx]
            type_probs = self.type_model.predict_proba(features_scaled)[0]
            type_classes = self.type_model.classes_
            type_idx = np.argmax(type_probs)
            predicted_type = self.type_encoder.inverse_transform([type_classes[type_idx]])[0]
            type_confidence = type_probs[type_idx]
            overall_confidence = np.sqrt(vendor_confidence * type_confidence)
            feature_importance = {}
            if hasattr(self.vendor_model, 'feature_importances_'):
                for i, importance in enumerate(self.vendor_model.feature_importances_):
                    if i < len(self.behavioral_features):
                        feature_importance[self.behavioral_features[i]] = float(importance)
            vendor_probabilities = {self.vendor_encoder.inverse_transform([cls])[0]: float(prob) for cls, prob in zip(vendor_classes, vendor_probs)}
            type_probabilities = {self.type_encoder.inverse_transform([cls])[0]: float(prob) for cls, prob in zip(type_classes, type_probs)}
            reasoning = self._generate_ml_reasoning(profile, feature_importance, predicted_vendor, predicted_type)
            return DPIClassificationResult(predicted_vendor=predicted_vendor, predicted_type=predicted_type, confidence=overall_confidence, vendor_probabilities=vendor_probabilities, type_probabilities=type_probabilities, feature_importance=feature_importance, classification_reasoning=reasoning)
        except Exception as e:
            LOG.error(f'ML classification failed: {e}')
            return self._rule_based_classification(profile)

    def _rule_based_classification(self, profile: DPIBehaviorProfile) -> DPIClassificationResult:
        """Fallback rule-based classification when ML is not available"""
        LOG.debug('Using rule-based DPI classification')
        vendor = 'Unknown'
        dpi_type = 'Unknown'
        confidence = 0.5
        reasoning = []
        if profile.ml_detection and profile.deep_packet_inspection_depth and (profile.deep_packet_inspection_depth > 1000):
            vendor = 'Palo Alto'
            reasoning.append('Advanced ML detection suggests Palo Alto Networks')
            confidence += 0.2
        elif profile.checksum_validation and profile.tcp_state_tracking_depth and (profile.tcp_state_tracking_depth >= 3):
            vendor = 'Cisco'
            reasoning.append('Deep TCP state tracking suggests Cisco ASA/Firepower')
            confidence += 0.15
        elif profile.ech_support is False and profile.tls_inspection_level == 'full':
            vendor = 'Fortinet'
            reasoning.append('Full TLS inspection with ECH blocking suggests Fortinet')
            confidence += 0.15
        elif profile.burst_tolerance and profile.burst_tolerance < 0.3:
            vendor = 'SonicWall'
            reasoning.append('Low burst tolerance suggests SonicWall')
            confidence += 0.1
        if profile.stateful_connection_limit and profile.stateful_connection_limit > 500000:
            dpi_type = 'ISP_DPI'
            reasoning.append('High connection limit suggests ISP-level DPI')
            confidence += 0.2
        elif profile.anti_evasion_techniques and len(profile.anti_evasion_techniques) >= 4:
            dpi_type = 'Government_DPI'
            reasoning.append('Multiple anti-evasion techniques suggest government DPI')
            confidence += 0.2
        elif profile.ml_detection and profile.behavioral_analysis:
            dpi_type = 'NGFW'
            reasoning.append('ML and behavioral analysis suggest Next-Gen Firewall')
            confidence += 0.15
        elif profile.signature_based_detection and (not profile.ml_detection):
            dpi_type = 'Enterprise_Firewall'
            reasoning.append('Signature-based detection suggests traditional enterprise firewall')
            confidence += 0.1
        confidence = min(confidence, 1.0)
        return DPIClassificationResult(predicted_vendor=vendor, predicted_type=dpi_type, confidence=confidence, vendor_probabilities={vendor: confidence}, type_probabilities={dpi_type: confidence}, feature_importance={}, classification_reasoning=reasoning)

    def _generate_ml_reasoning(self, profile: DPIBehaviorProfile, feature_importance: Dict[str, float], vendor: str, dpi_type: str) -> List[str]:
        """Generate human-readable reasoning for ML classification"""
        reasoning = []
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        for feature, importance in sorted_features[:3]:
            if importance > 0.1:
                if feature == 'supports_ip_frag':
                    if profile.supports_ip_frag:
                        reasoning.append(f'IP fragmentation support (importance: {importance:.2f}) indicates {vendor}')
                    else:
                        reasoning.append(f'IP fragmentation blocking (importance: {importance:.2f}) suggests {dpi_type}')
                elif feature == 'rst_latency_ms':
                    if profile.rst_latency_ms and profile.rst_latency_ms < 100:
                        reasoning.append(f'Fast RST response (importance: {importance:.2f}) characteristic of {vendor}')
                elif feature == 'anti_evasion_count':
                    count = len(profile.anti_evasion_techniques)
                    reasoning.append(f'Anti-evasion technique count ({count}, importance: {importance:.2f}) suggests {dpi_type}')
        if not reasoning:
            reasoning.append('Classification based on overall behavioral pattern analysis')
        return reasoning

    def train_model(self, training_data: List[Tuple[DPIBehaviorProfile, str, str]]):
        """Train the DPI classifier with labeled data"""
        if not SKLEARN_AVAILABLE:
            LOG.warning('Cannot train model: scikit-learn not available')
            return
        if len(training_data) < 10:
            LOG.warning('Insufficient training data for reliable model training')
            return
        LOG.info(f'Training DPI classifier with {len(training_data)} samples')
        X = []
        vendor_labels = []
        type_labels = []
        for profile, vendor, dpi_type in training_data:
            features = self.extract_behavioral_features(profile)
            X.append(features)
            vendor_labels.append(vendor)
            type_labels.append(dpi_type)
        X = np.array(X)
        vendor_encoded = self.vendor_encoder.fit_transform(vendor_labels)
        type_encoded = self.type_encoder.fit_transform(type_labels)
        X_scaled = self.feature_scaler.fit_transform(X)
        self.vendor_model.fit(X_scaled, vendor_encoded)
        vendor_score = cross_val_score(self.vendor_model, X_scaled, vendor_encoded, cv=5).mean()
        self.type_model.fit(X_scaled, type_encoded)
        type_score = cross_val_score(self.type_model, X_scaled, type_encoded, cv=5).mean()
        self.is_trained = True
        LOG.info(f'Model training completed - Vendor accuracy: {vendor_score:.3f}, Type accuracy: {type_score:.3f}')
        self.save_model()

    def save_model(self):
        """Save trained model to disk"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return
        try:
            model_data = {'vendor_model': self.vendor_model, 'type_model': self.type_model, 'feature_scaler': self.feature_scaler, 'vendor_encoder': self.vendor_encoder, 'type_encoder': self.type_encoder, 'training_timestamp': datetime.now().isoformat(), 'behavioral_features': self.behavioral_features}
            joblib.dump(model_data, self.model_path)
            LOG.info(f'DPI classifier model saved to {self.model_path}')
        except Exception as e:
            LOG.error(f'Failed to save model: {e}')

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        info = {'is_trained': self.is_trained, 'sklearn_available': SKLEARN_AVAILABLE, 'known_vendors': self.known_vendors, 'known_types': self.known_types, 'behavioral_features': self.behavioral_features}
        if SKLEARN_AVAILABLE and self.is_trained:
            info['vendor_classes'] = self.vendor_encoder.classes_.tolist()
            info['type_classes'] = self.type_encoder.classes_.tolist()
            if hasattr(self.vendor_model, 'feature_importances_'):
                info['feature_importances'] = {feature: float(importance) for feature, importance in zip(self.behavioral_features, self.vendor_model.feature_importances_)}
        return info