"""
Integration module for ML-based strategy prediction in DPI bypass engines.
"""
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
try:
    from ml.strategy_predictor import StrategyPredictor, StrategyPrediction
    from core.fingerprint.models import DPIBehaviorProfile, EnhancedFingerprint
    ML_PREDICTION_AVAILABLE = True
except ImportError as e:
    ML_PREDICTION_AVAILABLE = False
    logging.warning(f'ML prediction not available: {e}')
try:
    from recon.core.integration.fingerprint_integration import get_fingerprint_integrator
    FINGERPRINT_INTEGRATION_AVAILABLE = True
except ImportError as e:
    FINGERPRINT_INTEGRATION_AVAILABLE = False
    logging.warning(f'Fingerprint integration not available: {e}')
try:
    from recon.core.integration.evolutionary_optimization_integration import get_evolutionary_integrator
    EVOLUTIONARY_OPTIMIZATION_AVAILABLE = True
except ImportError as e:
    EVOLUTIONARY_OPTIMIZATION_AVAILABLE = False
    logging.warning(f'Evolutionary optimization not available: {e}')
LOG = logging.getLogger('strategy_prediction_integration')

@dataclass
class StrategyRecommendation:
    """Simplified strategy recommendation for engine integration."""
    primary_strategy: str
    fallback_strategies: List[str]
    confidence: float
    reasoning: str
    predicted_success_rate: float

class StrategyPredictionIntegrator:
    """
    Integrates ML-based strategy prediction into bypass engines.
    Provides intelligent strategy selection based on DPI fingerprinting.
    """

    def __init__(self, enable_ml: bool=True, enable_fingerprinting: bool=True, enable_evolutionary: bool=True):
        self.enable_ml = enable_ml and ML_PREDICTION_AVAILABLE
        self.enable_fingerprinting = enable_fingerprinting and FINGERPRINT_INTEGRATION_AVAILABLE
        self.enable_evolutionary = enable_evolutionary and EVOLUTIONARY_OPTIMIZATION_AVAILABLE
        self.predictor = None
        self.fingerprint_integrator = None
        self.evolutionary_integrator = None
        self.cache = {}
        self.cache_ttl = 300
        if self.enable_ml:
            try:
                self.predictor = StrategyPredictor()
                LOG.info('ML strategy predictor initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize ML predictor: {e}')
                self.enable_ml = False
        if self.enable_fingerprinting:
            try:
                self.fingerprint_integrator = get_fingerprint_integrator()
                LOG.info('Fingerprint integrator initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize fingerprint integrator: {e}')
                self.enable_fingerprinting = False
        if self.enable_evolutionary:
            try:
                self.evolutionary_integrator = get_evolutionary_integrator()
                LOG.info('Evolutionary optimization integrator initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize evolutionary integrator: {e}')
                self.enable_evolutionary = False
        if not self.enable_ml:
            LOG.info('Using rule-based strategy selection fallback')

    def predict_best_strategy(self, target_ip: str, domain: Optional[str]=None, fingerprint: Optional[Dict]=None, dpi_profile: Optional[DPIBehaviorProfile]=None) -> StrategyRecommendation:
        """
        Predict the best strategy for a target IP based on DPI fingerprint.

        Args:
            target_ip: Target IP address
            domain: Domain name (optional, for fingerprinting)
            fingerprint: DPI fingerprint data (optional)
            dpi_profile: DPI behavior profile (optional)

        Returns:
            StrategyRecommendation with best strategy and alternatives
        """
        if self.enable_evolutionary and self.evolutionary_integrator and domain:
            try:
                optimized_strategy = self.evolutionary_integrator.get_optimized_strategy(domain)
                if optimized_strategy:
                    LOG.info(f'Using evolutionarily optimized strategy for {domain}')
                    return self._convert_optimized_strategy(optimized_strategy, domain)
                elif self.evolutionary_integrator.suggest_optimization_for_domains([domain]):
                    self.evolutionary_integrator.start_background_optimization(domains=[domain], target_ips={target_ip})
                    LOG.debug(f'Started background evolutionary optimization for {domain}')
            except Exception as e:
                LOG.debug(f'Evolutionary optimization check failed for {domain}: {e}')
        cache_key = f'{target_ip}_{hash(str(fingerprint))}'
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                LOG.debug(f'Using cached strategy prediction for {target_ip}')
                return cached_result
        enhanced_dpi_profile = dpi_profile
        enhanced_fingerprint = fingerprint
        if self.enable_fingerprinting and self.fingerprint_integrator and domain:
            try:
                cached_fp = self.fingerprint_integrator.get_cached_fingerprint(domain, target_ip)
                if cached_fp:
                    LOG.debug(f'Using cached fingerprint for {domain} ({target_ip})')
                    enhanced_fingerprint = cached_fp.fingerprint_data
                    enhanced_dpi_profile = cached_fp.behavior_profile
                else:
                    self.fingerprint_integrator.start_background_fingerprinting(domain, target_ip)
                    LOG.debug(f'Started background fingerprinting for {domain} ({target_ip})')
            except Exception as e:
                LOG.debug(f'Fingerprinting failed for {domain}: {e}')
        if self.enable_ml and self.predictor and enhanced_dpi_profile:
            try:
                try:
                    from recon.core.integration.performance_integration import get_performance_integrator
                    perf_integrator = get_performance_integrator()
                    perf_integrator.record_ml_prediction()
                except Exception:
                    pass
                prediction = self.predictor.predict_strategy_categories(enhanced_dpi_profile)
                recommendation = self._convert_ml_prediction(prediction)
                if enhanced_fingerprint != fingerprint:
                    recommendation.reasoning += ' (Enhanced with advanced fingerprinting)'
                self.cache[cache_key] = (recommendation, time.time())
                LOG.info(f'ML strategy prediction for {target_ip}: {recommendation.primary_strategy} (confidence: {recommendation.confidence:.2f})')
                return recommendation
            except Exception as e:
                LOG.error(f'ML prediction failed for {target_ip}: {e}')
        recommendation = self._rule_based_prediction(target_ip, enhanced_fingerprint or fingerprint)
        self.cache[cache_key] = (recommendation, time.time())
        LOG.info(f'Rule-based strategy prediction for {target_ip}: {recommendation.primary_strategy}')
        return recommendation

    def _convert_ml_prediction(self, prediction: StrategyPrediction) -> StrategyRecommendation:
        """Convert ML prediction to engine-compatible recommendation."""
        category_to_method = {'tcp_segmentation': 'tcp_window_scaling', 'ip_fragmentation': 'ip_fragmentation', 'timing_manipulation': 'tcp_timestamp_manipulation', 'payload_obfuscation': 'payload_obfuscation', 'protocol_tunneling': 'dns_tunneling', 'header_manipulation': 'tcp_options_padding', 'modern_protocols': 'http2_attacks', 'traffic_mimicry': 'traffic_mimicry', 'multi_layer_combo': 'dynamic_combo', 'steganography': 'steganography'}
        primary_category = prediction.recommended_categories[0] if prediction.recommended_categories else 'tcp_segmentation'
        primary_strategy = category_to_method.get(primary_category, 'tcp_window_scaling')
        fallback_strategies = []
        for category in prediction.recommended_categories[1:4]:
            method = category_to_method.get(category)
            if method and method != primary_strategy:
                fallback_strategies.append(method)
        default_fallbacks = ['tcp_multisplit', 'badsum_race', 'low_ttl_poisoning']
        for fallback in default_fallbacks:
            if fallback not in fallback_strategies and fallback != primary_strategy:
                fallback_strategies.append(fallback)
                if len(fallback_strategies) >= 3:
                    break
        success_rate = prediction.predicted_success_rates.get(primary_category, 0.5)
        reasoning = f"ML prediction based on DPI profile analysis. Top categories: {', '.join(prediction.recommended_categories[:3])}"
        if prediction.reasoning:
            reasoning += f'. {prediction.reasoning[0]}'
        return StrategyRecommendation(primary_strategy=primary_strategy, fallback_strategies=fallback_strategies, confidence=prediction.confidence, reasoning=reasoning, predicted_success_rate=success_rate)

    def _rule_based_prediction(self, target_ip: str, fingerprint: Optional[Dict]) -> StrategyRecommendation:
        """Fallback rule-based strategy prediction."""
        primary_strategy = 'tcp_window_scaling'
        fallback_strategies = ['tcp_multisplit', 'badsum_race', 'low_ttl_poisoning']
        if fingerprint:
            if fingerprint.get('supports_ip_frag', False):
                primary_strategy = 'ip_fragmentation'
            elif fingerprint.get('timing_sensitive', False):
                primary_strategy = 'tcp_timestamp_manipulation'
            elif fingerprint.get('deep_inspection', False):
                primary_strategy = 'payload_obfuscation'
        if target_ip.startswith('104.'):
            primary_strategy = 'tcp_window_scaling'
        elif target_ip.startswith('185.'):
            primary_strategy = 'tcp_multisplit'
        return StrategyRecommendation(primary_strategy=primary_strategy, fallback_strategies=fallback_strategies, confidence=0.6, reasoning='Rule-based prediction using basic heuristics', predicted_success_rate=0.7)

    def _convert_optimized_strategy(self, optimized_strategy: Dict[str, Any], domain: str) -> StrategyRecommendation:
        """Convert evolutionarily optimized strategy to recommendation."""
        strategy_type = optimized_strategy.get('type', 'dynamic_combo')
        stages = optimized_strategy.get('stages', [])
        primary_strategy = 'tcp_window_scaling'
        if stages:
            first_stage = stages[0]
            primary_strategy = first_stage.get('name', primary_strategy)
        fallback_strategies = []
        for stage in stages[1:4]:
            stage_name = stage.get('name')
            if stage_name and stage_name != primary_strategy:
                fallback_strategies.append(stage_name)
        default_fallbacks = ['tcp_multisplit', 'badsum_race', 'low_ttl_poisoning']
        for fallback in default_fallbacks:
            if fallback not in fallback_strategies and fallback != primary_strategy:
                fallback_strategies.append(fallback)
                if len(fallback_strategies) >= 3:
                    break
        return StrategyRecommendation(primary_strategy=primary_strategy, fallback_strategies=fallback_strategies, confidence=0.9, reasoning=f'Evolutionarily optimized strategy for {domain} with {len(stages)} stages', predicted_success_rate=0.85)

    def get_strategy_for_domain(self, domain: str, target_ip: str) -> StrategyRecommendation:
        """Get strategy recommendation for a specific domain."""
        domain_strategies = {'rutracker.org': 'tcp_window_scaling', 'instagram.com': 'http2_attacks', 'x.com': 'traffic_mimicry', 'mail.ru': 'tcp_multisplit'}
        if domain in domain_strategies:
            strategy = domain_strategies[domain]
            return StrategyRecommendation(primary_strategy=strategy, fallback_strategies=['tcp_window_scaling', 'badsum_race'], confidence=0.8, reasoning=f'Domain-specific strategy for {domain}', predicted_success_rate=0.8)
        return self.predict_best_strategy(target_ip)

    def update_strategy_effectiveness(self, target_ip: str, strategy: str, success: bool, latency_ms: float=0):
        """Update strategy effectiveness data for learning."""
        LOG.info(f"Strategy feedback for {target_ip}: {strategy} -> {('success' if success else 'failure')} (latency: {latency_ms}ms)")

    def clear_cache(self):
        """Clear the prediction cache."""
        self.cache.clear()
        LOG.info('Strategy prediction cache cleared')
_global_integrator = None

def get_strategy_integrator() -> StrategyPredictionIntegrator:
    """Get global strategy prediction integrator instance."""
    global _global_integrator
    if _global_integrator is None:
        _global_integrator = StrategyPredictionIntegrator()
    return _global_integrator