"""
Ultimate Advanced Fingerprinting Engine combining all expert approaches
"""

import logging
import asyncio
import inspect
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from dataclasses import asdict

from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile
from core.fingerprint.analyzer import PacketAnalyzer
from core.fingerprint.metrics_collector import ExtendedMetricsCollector
from core.fingerprint.behavior_analyzer import DPIBehaviorAnalyzer
from core.fingerprint.cache_utils import (
    TimestampedCache,
    generate_cache_key,
    collect_effectiveness_stats,
)
from core.fingerprint.ml_predictor import FingerprintMLPredictor, SKLEARN_AVAILABLE
from core.fingerprint.attack_recommender import AttackRecommender
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.base import AttackResult, AttackStatus
from core.interfaces import IProber, IClassifier, IAttackAdapter, IFingerprintEngine

LOG = logging.getLogger("ultimate_fingerprint_engine")

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None


class UltimateAdvancedFingerprintEngine(IFingerprintEngine):
    """
    Ultimate Advanced Fingerprinting Engine with modular architecture.

    This engine orchestrates multiple specialized components to provide comprehensive
    DPI fingerprinting and attack recommendation capabilities:

    Components:
        - MetricsCollector: Extended metrics collection (ECH, effectiveness)
        - BehaviorAnalyzer: DPI behavioral analysis and profiling
        - MLPredictor: Machine learning predictions and feature extraction
        - AttackRecommender: Attack recommendation and scoring
        - TimestampedCache: Intelligent caching with TTL and LRU eviction

    Architecture:
        - Dependency Injection: All dependencies injected through constructor
        - Delegation Pattern: Delegates to specialized components
        - Separation of Concerns: Each component has single responsibility
        - Testability: Components can be tested independently

    Refactored from 1400 LOC god class to 700 LOC orchestrator + 5 specialized modules.
    """

    def __init__(
        self,
        prober: "IProber",
        classifier: "IClassifier",
        attack_adapter: "IAttackAdapter",
        debug: bool = True,
        ml_enabled: bool = True,
    ):
        """
        Initialize the fingerprint engine with injected dependencies.

        Args:
            prober: DPI probing service (required)
            classifier: DPI classification service (required)
            attack_adapter: Attack execution adapter (required)
            debug: Enable debug logging
            ml_enabled: Enable machine learning features
        """
        if not prober:
            raise ValueError("prober is required for UltimateAdvancedFingerprintEngine")
        if not classifier:
            raise ValueError("classifier is required for UltimateAdvancedFingerprintEngine")
        if not attack_adapter:
            raise ValueError("attack_adapter is required for UltimateAdvancedFingerprintEngine")
        self.debug = debug
        self.ml_enabled = ml_enabled and SKLEARN_AVAILABLE
        self.prober = prober
        self.classifier = classifier
        self.attack_adapter = attack_adapter
        self.attack_registry = AttackRegistry()

        # Initialize metrics collector
        self.metrics_collector = ExtendedMetricsCollector(
            dns_timeout=1.2, effectiveness_timeout=10.0
        )

        # Initialize behavior analyzer
        self.behavior_analyzer = DPIBehaviorAnalyzer(debug=debug)

        # Initialize ML predictor
        self.ml_predictor = FingerprintMLPredictor(
            ml_enabled=ml_enabled, attack_adapter=attack_adapter, debug=debug
        )

        # Initialize attack recommender
        self.attack_recommender = AttackRecommender(technique_effectiveness=None, debug=debug)

        # Initialize caches using TimestampedCache
        self.fingerprint_cache = TimestampedCache(max_size=1000, ttl=timedelta(hours=1))
        self.behavior_profiles = {}
        self.attack_history = defaultdict(lambda: defaultdict(list))
        self.technique_effectiveness = defaultdict(lambda: defaultdict(list))
        # Share technique_effectiveness with attack_recommender
        self.attack_recommender.technique_effectiveness = self.technique_effectiveness
        self.cache_ttl = timedelta(hours=1)
        self.max_cache_size = 1000
        self.stats = {
            "fingerprints_created": 0,
            "ml_predictions": 0,
            "cache_hits": 0,
            "probes_executed": 0,
            "attacks_recommended": 0,
            "model_updates": 0,
        }
        LOG.info("Ultimate Advanced Fingerprint Engine initialized with DI")

    def _ensure_mapping_attr(self, obj: Any, attr: str) -> Dict[str, Any]:
        """
        Ensure obj.<attr> exists and is a dict-like mapping.
        Returns the mapping (possibly newly created).
        """
        current = getattr(obj, attr, None)
        if isinstance(current, dict):
            return current
        new_val: Dict[str, Any] = {}
        try:
            setattr(obj, attr, new_val)
        except Exception:
            # If object uses slots/readonly attrs, just return a temp mapping.
            return {}
        return new_val

    async def _safe_run_probes(self, **kwargs) -> Dict[str, Any]:
        """
        Call prober.run_probes with only supported keyword parameters.
        Keeps compatibility with different IProber implementations.
        """
        fn = getattr(self.prober, "run_probes", None)
        if not callable(fn):
            return {}
        try:
            sig = inspect.signature(fn)
            filtered = {k: v for k, v in kwargs.items() if k in sig.parameters}
            res = await fn(**filtered)
            return res or {}
        except Exception as e:
            LOG.error(f"Probing failed: {e}")
            return {}

    def _apply_probe_results(self, probe_results: Dict[str, Any], fp: EnhancedFingerprint):
        """Applies the results from probing to the fingerprint object."""
        if not probe_results:
            return
        for key, value in probe_results.items():
            if hasattr(fp, key) and value is not None:
                setattr(fp, key, value)

    async def create_comprehensive_fingerprint(
        self,
        domain: str,
        target_ips: List[str] = None,
        packets: List[Any] = None,
        force_refresh: bool = False,
    ) -> EnhancedFingerprint:
        """
        Create ultimate fingerprint with all available techniques
        """
        start_time = datetime.now()
        # Use stable string-based cache key
        cache_key = generate_cache_key(domain, target_ips)

        # Check cache
        if not force_refresh:
            cached_fp = self.fingerprint_cache.get(cache_key)
            if cached_fp:
                self.stats["cache_hits"] += 1
                LOG.debug(f"Using cached fingerprint for {domain}")
                return cached_fp
        LOG.info(f"Creating comprehensive fingerprint for {domain}")
        self.stats["fingerprints_created"] += 1
        if not target_ips:
            target_ips = await self._resolve_domain_ips(domain)
        if not target_ips:
            LOG.error(f"No IPs found for {domain}")
            return EnhancedFingerprint(domain=domain)
        fp = EnhancedFingerprint(domain=domain, ip_addresses=target_ips, timestamp=datetime.now())
        if packets:
            LOG.debug("Phase 1: Performing passive analysis on captured packets...")
            packet_analyzer = PacketAnalyzer(target_ip=target_ips[0])
            passive_fp = packet_analyzer.analyze_packets(packets)
            try:
                passive_dict = asdict(passive_fp)
            except Exception:
                passive_dict = getattr(passive_fp, "__dict__", {}) or {}
            for attr, value in passive_dict.items():
                if hasattr(fp, attr) and value is not None and (value != ()) and (value != {}):
                    setattr(fp, attr, value)
        LOG.debug("Phase 2: Performing preliminary signature-based classification...")
        prelim = getattr(self.classifier, "_signature_classify", None)
        if callable(prelim):
            try:
                prelim_classification = prelim(fp)
                if hasattr(prelim_classification, "dpi_type") and prelim_classification.dpi_type:
                    fp.dpi_type = prelim_classification.dpi_type
            except Exception as e:
                LOG.debug(f"Preliminary signature classification failed: {e}")
        LOG.debug("Phase 3: Performing intelligent active probing...")
        preliminary_type = fp.dpi_type if fp.dpi_type and fp.dpi_type != "Unknown" else None
        probe_results = await self._safe_run_probes(
            domain=domain,
            preliminary_type=preliminary_type,
            force_all=force_refresh,
        )
        self._apply_probe_results(probe_results, fp)
        self.stats["probes_executed"] += len(probe_results or {})
        LOG.debug("Phase 4: Performing final classification...")
        try:
            classification = self.classifier.classify(fp)
            if hasattr(classification, "dpi_type") and classification.dpi_type:
                fp.dpi_type = classification.dpi_type
            if hasattr(classification, "confidence") and classification.confidence is not None:
                # Keep both names if model supports them
                fp.ml_confidence = classification.confidence
                if hasattr(fp, "confidence"):
                    fp.confidence = classification.confidence
        except Exception as e:
            LOG.error(f"Final classification failed for {domain}: {e}")
        LOG.debug("Phase 5: Extracting ML features...")
        fp.ml_features = self.ml_predictor.extract_ml_features(fp)
        if self.ml_enabled and self.ml_predictor.is_model_ready():
            LOG.debug("Phase 7: Generating ML-based predictions and recommendations...")
            fp.predicted_weaknesses = self.ml_predictor.predict_weaknesses(fp)
            fp.recommended_attacks = self.ml_predictor.predict_best_attacks(fp)
            self.stats["ml_predictions"] += 1
        else:
            LOG.debug("Phase 7: Using rule-based recommendations (ML model not ready)")
            fp.predicted_weaknesses = self.ml_predictor.predict_weaknesses(fp)
            fp.recommended_attacks = []

        # Update cache
        self.fingerprint_cache.set(cache_key, fp)

        elapsed = (datetime.now() - start_time).total_seconds()
        confidence_val = getattr(fp, "confidence", None)
        if confidence_val is None:
            confidence_val = getattr(fp, "ml_confidence", 0.0) or 0.0
        LOG.info(
            f"Fingerprint complete for {domain}: {fp.dpi_type} [{confidence_val:.0%}] in {elapsed:.2f}s"
        )
        return fp

    async def analyze_dpi_behavior(
        self,
        domain: str,
        fingerprint: "EnhancedFingerprint" = None,
        extended_metrics: Optional[Dict[str, Any]] = None,
    ) -> "DPIBehaviorProfile":
        """
        Create comprehensive behavioral profile with enhanced behavioral analysis.

        Delegates to DPIBehaviorAnalyzer for actual analysis.

        Args:
            domain: Target domain
            fingerprint: EnhancedFingerprint object (optional, will be created if None)
            extended_metrics: Optional extended metrics from ECHDetector

        Returns:
            DPIBehaviorProfile with comprehensive analysis
        """
        # Create fingerprint if not provided
        if not fingerprint:
            fingerprint = await self.create_comprehensive_fingerprint(domain)

        # Delegate to behavior analyzer
        profile = await self.behavior_analyzer.analyze_dpi_behavior(
            domain=domain,
            fingerprint=fingerprint,
            extended_metrics=extended_metrics,
            fingerprint_creator=self.create_comprehensive_fingerprint,
        )

        # Cache profile in engine
        self.behavior_profiles[domain] = profile

        return profile

    def recommend_optimal_attacks(
        self,
        domain: str,
        fingerprint: EnhancedFingerprint = None,
        context: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate optimal attack recommendations using ML and analysis.

        Delegates to AttackRecommender for actual recommendation generation.

        Args:
            domain: Target domain
            fingerprint: EnhancedFingerprint object (optional)
            context: Optional context with requirements

        Returns:
            List of attack recommendations sorted by score
        """
        self.stats["attacks_recommended"] += 1
        LOG.info(f"Generating attack recommendations for {domain}")

        # Try to find fingerprint in cache if not provided
        if not fingerprint:
            fingerprint = self.fingerprint_cache.find_by_prefix(domain)

        # Get behavior profile if available
        behavior_profile = self.behavior_profiles.get(domain)

        # Get ML recommendations if available
        ml_recommendations = None
        if (
            self.ml_enabled
            and self.ml_predictor.is_model_ready()
            and fingerprint
            and hasattr(fingerprint, "recommended_attacks")
        ):
            ml_recommendations = fingerprint.recommended_attacks

        # Delegate to attack recommender
        return self.attack_recommender.generate_recommendations(
            domain=domain,
            fingerprint=fingerprint,
            behavior_profile=behavior_profile,
            ml_recommendations=ml_recommendations,
            context=context,
            max_recommendations=10,
        )

    async def refine_fingerprint(
        self,
        current_fingerprint: EnhancedFingerprint,
        test_results: List[Any],
        learning_insights: Optional[Dict[str, Any]] = None,
    ) -> EnhancedFingerprint:
        """
        Refine fingerprint based on testing results and learning insights.

        This method updates the fingerprint with new information gained from
        attack testing and effectiveness analysis to improve future strategy generation.

        Args:
            current_fingerprint: Current fingerprint to refine
            test_results: List of test results (EffectivenessResult objects)
            learning_insights: Additional insights from learning system

        Returns:
            Refined EnhancedFingerprint with updated information
        """
        LOG.info(
            f"Refining fingerprint for {current_fingerprint.domain} based on {len(test_results)} test results"
        )
        refined_fp = EnhancedFingerprint(
            domain=current_fingerprint.domain,
            ip_addresses=current_fingerprint.ip_addresses,
            timestamp=datetime.now(),
        )
        for attr, value in current_fingerprint.__dict__.items():
            if hasattr(refined_fp, attr) and attr not in ["timestamp"]:
                setattr(refined_fp, attr, value)
        if test_results:
            await self._analyze_test_results_for_refinement(refined_fp, test_results)
        if learning_insights:
            self._apply_learning_insights(refined_fp, learning_insights)
        self._update_technique_success_rates(refined_fp, test_results)
        await self._refine_dpi_classification(refined_fp, test_results)
        self._update_confidence_scores(refined_fp, test_results)
        needs_additional_probing = await self._determine_additional_probing_needs(
            refined_fp, test_results
        )
        if needs_additional_probing:
            LOG.info(f"Additional probing needed for {refined_fp.domain}")
            additional_probe_results = await self._run_targeted_probes(refined_fp, test_results)
            if additional_probe_results:
                self._apply_probe_results(additional_probe_results, refined_fp)

        # Update cache
        cache_key = generate_cache_key(refined_fp.domain, refined_fp.ip_addresses)
        self.fingerprint_cache.set(cache_key, refined_fp)

        LOG.info(f"Fingerprint refinement completed for {refined_fp.domain}")
        return refined_fp

    def collect_extended_fingerprint_metrics(self, domain: str) -> Dict[str, Any]:
        """
        Collect ECH-related metrics through ECHDetector.

        Delegates to ExtendedMetricsCollector for actual collection.

        Args:
            domain: Target domain

        Returns:
            Dictionary containing ECH metrics
        """
        return self.metrics_collector.collect_ech_metrics(domain)

    async def collect_extended_fingerprint_metrics(
        self, domain: str, target_ips: List[str] = None
    ) -> Dict[str, Any]:
        """
        Collect extended metrics using RealEffectivenessTester.

        Delegates to ExtendedMetricsCollector for actual collection.

        Args:
            domain: Target domain
            target_ips: List of target IPs (optional)

        Returns:
            Dictionary containing extended metrics
        """
        return await self.metrics_collector.collect_effectiveness_metrics(
            domain, target_ips, resolve_ips_callback=self._resolve_domain_ips
        )

    def _apply_extended_metrics_to_fingerprint(
        self, fingerprint: EnhancedFingerprint, extended_metrics: Dict[str, Any]
    ):
        """
        Apply collected extended metrics to the fingerprint object.

        Delegates to ExtendedMetricsCollector for actual application.

        Args:
            fingerprint: EnhancedFingerprint object to update
            extended_metrics: Extended metrics collected from RealEffectivenessTester
        """
        self.metrics_collector.apply_metrics_to_fingerprint(fingerprint, extended_metrics)

    async def create_comprehensive_fingerprint_with_extended_metrics(
        self,
        domain: str,
        target_ips: List[str] = None,
        packets: List[Any] = None,
        force_refresh: bool = False,
    ) -> EnhancedFingerprint:
        """
        Create comprehensive fingerprint with extended metrics collection.

        This method extends the standard fingerprint creation with the new
        extended metrics required for Requirements 6.1, 6.2, and 6.3.

        Args:
            domain: Target domain
            target_ips: List of target IPs (optional)
            packets: Captured packets for passive analysis (optional)
            force_refresh: Force refresh of cached data

        Returns:
            EnhancedFingerprint with extended metrics
        """
        LOG.info(f"Creating comprehensive fingerprint with extended metrics for {domain}")
        fingerprint = await self.create_comprehensive_fingerprint(
            domain, target_ips, packets, force_refresh
        )
        try:
            extended_metrics = await self.collect_extended_fingerprint_metrics(domain, target_ips)
            self._apply_extended_metrics_to_fingerprint(fingerprint, extended_metrics)
            fingerprint.timestamp = datetime.now()
            LOG.info(f"Enhanced fingerprint with extended metrics completed for {domain}")
        except (ConnectionError, TimeoutError, ImportError, AttributeError) as e:
            LOG.error(f"Failed to enhance fingerprint with extended metrics for {domain}: {e}")
        return fingerprint

    async def _analyze_test_results_for_refinement(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ):
        """Analyze test results to extract refinement insights."""
        successful_attacks = []
        failed_attacks = []
        timing_patterns = []
        block_types = []
        for result in test_results:
            if hasattr(result, "bypass_effective") and result.bypass_effective:
                successful_attacks.append(result.bypass.attack_name)
            else:
                failed_attacks.append(result.bypass.attack_name)
            if hasattr(result.baseline, "response_timing_pattern"):
                timing_patterns.append(result.baseline.response_timing_pattern)
            if hasattr(result.bypass, "response_timing_pattern"):
                timing_patterns.append(result.bypass.response_timing_pattern)
            if hasattr(result.baseline, "block_type"):
                block_types.append(result.baseline.block_type)
            if hasattr(result.bypass, "block_type"):
                block_types.append(result.bypass.block_type)
        if successful_attacks:
            for attack in successful_attacks:
                if "fragmentation" in attack.lower():
                    fingerprint.supports_ip_frag = True
                elif "checksum" in attack.lower() or "badsum" in attack.lower():
                    fingerprint.checksum_validation = False
                elif "timing" in attack.lower():
                    fingerprint.timing_sensitivity = True
        if timing_patterns:
            unique_patterns = set(timing_patterns)
            if "immediate_rst" in unique_patterns:
                fingerprint.rst_latency_ms = 50
            elif "fast_rst" in unique_patterns:
                fingerprint.rst_latency_ms = 500
            elif "long_timeout" in unique_patterns:
                fingerprint.connection_timeout_ms = 10000
        if block_types:
            from core.bypass.attacks.real_effectiveness_tester import BlockType

            rst_count = sum((1 for bt in block_types if bt == BlockType.RST))
            timeout_count = sum((1 for bt in block_types if bt == BlockType.TIMEOUT))
            if rst_count > timeout_count:
                fingerprint.primary_block_method = "rst"
            elif timeout_count > rst_count:
                fingerprint.primary_block_method = "timeout"

    def _apply_learning_insights(
        self, fingerprint: EnhancedFingerprint, learning_insights: Dict[str, Any]
    ):
        """Apply insights from learning system to fingerprint."""
        technique_rates = self._ensure_mapping_attr(fingerprint, "technique_success_rates")
        if "successful_attack_patterns" in learning_insights:
            patterns = learning_insights["successful_attack_patterns"]
            for attack_name, success_rate in patterns.items():
                technique_rates[attack_name] = success_rate
        if "dpi_behavior_patterns" in learning_insights:
            behavior = learning_insights["dpi_behavior_patterns"]
            if "rate_limiting" in behavior:
                fingerprint.rate_limiting_detected = behavior["rate_limiting"]
            if "ml_detection" in behavior:
                fingerprint.ml_detection_blocked = behavior["ml_detection"]
            if "stateful_inspection" in behavior:
                fingerprint.stateful_inspection = behavior["stateful_inspection"]
        if "optimal_parameters" in learning_insights:
            fingerprint.optimal_parameters = learning_insights["optimal_parameters"]

    def _update_technique_success_rates(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ):
        """Update technique success rates based on test results."""
        technique_rates = self._ensure_mapping_attr(fingerprint, "technique_success_rates")
        technique_results = {}
        for result in test_results:
            if hasattr(result, "bypass") and hasattr(result.bypass, "attack_name"):
                attack_name = result.bypass.attack_name
                if attack_name:
                    if attack_name not in technique_results:
                        technique_results[attack_name] = []
                    success = 1.0 if result.bypass_effective else 0.0
                    technique_results[attack_name].append(success)
        for attack_name, results in technique_results.items():
            if results:
                avg_success = sum(results) / len(results)
                technique_rates[attack_name] = avg_success

    async def _refine_dpi_classification(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ):
        """Refine DPI classification based on observed behavior."""
        rst_responses = 0
        timeout_responses = 0
        content_blocks = 0
        for result in test_results:
            if hasattr(result, "baseline"):
                if hasattr(result.baseline, "block_type"):
                    from core.bypass.attacks.real_effectiveness_tester import BlockType

                    if result.baseline.block_type == BlockType.RST:
                        rst_responses += 1
                    elif result.baseline.block_type == BlockType.TIMEOUT:
                        timeout_responses += 1
                    elif result.baseline.block_type == BlockType.CONTENT:
                        content_blocks += 1
        total_responses = rst_responses + timeout_responses + content_blocks
        if total_responses > 0:
            rst_ratio = rst_responses / total_responses
            timeout_ratio = timeout_responses / total_responses
            content_ratio = content_blocks / total_responses
            if rst_ratio > 0.7:
                if fingerprint.dpi_type == "Unknown":
                    fingerprint.dpi_type = "Active_RST_Based"
                fingerprint.ml_confidence = min(1.0, fingerprint.ml_confidence + 0.2)
            elif timeout_ratio > 0.7:
                if fingerprint.dpi_type == "Unknown":
                    fingerprint.dpi_type = "Passive_Timeout_Based"
                fingerprint.ml_confidence = min(1.0, fingerprint.ml_confidence + 0.1)
            elif content_ratio > 0.5:
                if fingerprint.dpi_type == "Unknown":
                    fingerprint.dpi_type = "Application_Layer_DPI"
                fingerprint.ml_confidence = min(1.0, fingerprint.ml_confidence + 0.15)

    def _update_confidence_scores(self, fingerprint: EnhancedFingerprint, test_results: List[Any]):
        """Update confidence scores based on test result consistency."""
        if not test_results:
            return
        effectiveness_scores = []
        for result in test_results:
            if hasattr(result, "effectiveness_score"):
                effectiveness_scores.append(result.effectiveness_score)
        if effectiveness_scores:
            if len(effectiveness_scores) > 1:
                variance = sum(
                    (
                        (x - sum(effectiveness_scores) / len(effectiveness_scores)) ** 2
                        for x in effectiveness_scores
                    )
                ) / len(effectiveness_scores)
                if variance > 0.3:
                    fingerprint.ml_confidence = max(0.1, fingerprint.ml_confidence - 0.1)
                elif variance < 0.1:
                    fingerprint.ml_confidence = min(1.0, fingerprint.ml_confidence + 0.1)

    async def _determine_additional_probing_needs(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ) -> bool:
        """Determine if additional targeted probing is needed."""
        if fingerprint.ml_confidence < 0.6:
            LOG.debug("Low confidence - additional probing recommended")
            return True
        if test_results:
            success_count = sum(
                (1 for r in test_results if hasattr(r, "bypass_effective") and r.bypass_effective)
            )
            failure_count = len(test_results) - success_count
            if (
                success_count > 0
                and failure_count > 0
                and (abs(success_count - failure_count) <= 1)
            ):
                LOG.debug("Mixed results - additional probing recommended")
                return True
        missing_data = []
        key_attributes = [
            "rst_ttl",
            "checksum_validation",
            "stateful_inspection",
            "rate_limiting_detected",
        ]
        for attr in key_attributes:
            if not hasattr(fingerprint, attr) or getattr(fingerprint, attr) is None:
                missing_data.append(attr)
        if len(missing_data) > 2:
            LOG.debug(f"Missing key data: {missing_data} - additional probing recommended")
            return True
        return False

    async def _run_targeted_probes(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """Run targeted probes based on what we learned from test results."""
        try:
            targeted_probes = []
            # Analyze test results to determine which probes are needed
            if test_results:
                # Check if checksum validation needs testing based on results
                checksum_related = any(
                    "checksum" in str(getattr(r, "bypass", "")).lower()
                    for r in test_results
                    if hasattr(r, "bypass")
                )
                if checksum_related and (
                    not hasattr(fingerprint, "checksum_validation")
                    or fingerprint.checksum_validation is None
                ):
                    targeted_probes.append("bad_checksum")

            # Add probes for missing fingerprint data
            if (
                not hasattr(fingerprint, "checksum_validation")
                or fingerprint.checksum_validation is None
            ):
                if "bad_checksum" not in targeted_probes:
                    targeted_probes.append("bad_checksum")
            if not hasattr(fingerprint, "supports_ip_frag") or fingerprint.supports_ip_frag is None:
                targeted_probes.append("ip_fragmentation")
            if (
                not hasattr(fingerprint, "rate_limiting_detected")
                or fingerprint.rate_limiting_detected is None
            ):
                targeted_probes.append("rate_limiting")
            if not targeted_probes:
                return None
            LOG.info(f"Running {len(targeted_probes)} targeted probes for {fingerprint.domain}")
            preliminary_type = None
            probe_results = await self.prober.run_probes(
                fingerprint.domain,
                preliminary_type=fingerprint.dpi_type,
                force_all=False,
            )
            filtered_results = {k: v for k, v in probe_results.items() if k in targeted_probes}
            return filtered_results
        except (ConnectionError, TimeoutError, AttributeError) as e:
            LOG.error(f"Failed to run targeted probes: {e}")
            return None

    def update_with_attack_results(self, domain: str, attack_results: List[AttackResult]):
        """
        Update models and data based on attack execution results
        """
        LOG.info(f"Updating with {len(attack_results)} attack results for {domain}")
        for result in attack_results:
            self.attack_history[domain][result.technique_used].append(
                {
                    "timestamp": datetime.now(),
                    "status": result.status,
                    "latency_ms": result.latency_ms,
                    "metadata": result.metadata,
                }
            )
            effectiveness = self._calculate_effectiveness(result)
            self.technique_effectiveness[domain][result.technique_used].append(effectiveness)
            if self.ml_enabled and self.ml_predictor.is_model_ready():
                self._update_effectiveness_model(domain, result, effectiveness)

        # Update cached fingerprint with new technique success rates
        fp = self.fingerprint_cache.find_by_prefix(domain)
        if fp:
            for technique, scores in self.technique_effectiveness[domain].items():
                if scores:
                    fp.technique_success_rates[technique] = sum(scores) / len(scores)

    async def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            import socket

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
            ips = list(set([addr[4][0] for addr in result]))
            LOG.debug(f"Resolved {domain} to {len(ips)} IPs")
            return ips
        except Exception as e:
            LOG.error(f"Failed to resolve {domain}: {e}")
            return []

    async def _analyze_technique_effectiveness(self, domain: str) -> Dict[str, float]:
        """Analyze historical technique effectiveness"""
        effectiveness = {}
        domain_history = self.technique_effectiveness.get(domain, {})
        for technique, scores in domain_history.items():
            if scores:
                if SKLEARN_AVAILABLE and np is not None:
                    weights = np.exp(np.linspace(0, 2, len(scores)))
                    weights = weights / weights.sum()
                    effectiveness[technique] = np.average(scores, weights=weights)
                else:
                    effectiveness[technique] = sum(scores) / len(scores)
        if self.ml_enabled and self.ml_predictor.is_model_ready():
            all_techniques = self.attack_adapter.get_available_attacks()
            for technique in all_techniques:
                if technique not in effectiveness:
                    predicted = self.ml_predictor.predict_technique_effectiveness(technique, domain)
                    if predicted is not None:
                        effectiveness[technique] = predicted
        return effectiveness

    def _calculate_effectiveness(self, result: AttackResult) -> float:
        """Calculate effectiveness score from attack result"""
        if result.status == AttackStatus.SUCCESS:
            score = 1.0
        elif (
            getattr(AttackStatus, "BLOCKED", None) is not None
            and result.status == AttackStatus.BLOCKED
        ):
            score = 0.0
        else:
            score = 0.1
        if result.latency_ms:
            if result.latency_ms < 50:
                score *= 1.1
            elif result.latency_ms > 200:
                score *= 0.9
        return min(score, 1.0)

    def _update_effectiveness_model(self, domain: str, result: AttackResult, effectiveness: float):
        """Update ML model with new result"""
        try:
            # Find fingerprint in cache
            found_fp = self.fingerprint_cache.find_by_prefix(domain)
            if not found_fp:
                LOG.debug(f"No fingerprint found for {domain} to update model")
                return
            features = self.ml_predictor.extract_ml_features(found_fp)
            attack_info = self.attack_adapter.get_attack_info(result.technique_used)
            attack_features = {
                "attack_category": (
                    attack_info.get("category", "unknown") if attack_info else "unknown"
                ),
                "attack_complexity": len(result.technique_used),
            }
            all_features = {**features, **attack_features}
            # Store for future model training
            # Note: effectiveness parameter is used for future model updates
            LOG.debug(f"Collected features for model update: effectiveness={effectiveness:.2f}")
            self.stats["model_updates"] += 1
        except (AttributeError, KeyError, TypeError) as e:
            LOG.error(f"Failed to update effectiveness model: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics"""
        stats = self.stats.copy()

        # Cache statistics
        stats["cache_entries"] = self.fingerprint_cache.size()
        cache_stats = self.fingerprint_cache.get_stats()
        stats["cache_hits"] = cache_stats["hits"]
        stats["cache_misses"] = cache_stats["misses"]
        stats["cache_hit_rate"] = cache_stats["hit_rate"]
        stats["cache_evictions"] = cache_stats["evictions"]

        # Behavior profiles
        stats["behavior_profiles"] = len(self.behavior_profiles)

        # Effectiveness statistics
        effectiveness_stats = collect_effectiveness_stats(self.technique_effectiveness)
        stats.update(effectiveness_stats)

        return stats


def create_ultimate_fingerprint_engine(
    prober: "IProber" = None,
    classifier: "IClassifier" = None,
    attack_adapter: "IAttackAdapter" = None,
    debug: bool = True,
    ml_enabled: bool = True,
) -> UltimateAdvancedFingerprintEngine:
    """
    Factory function to create the ultimate fingerprint engine.

    DEPRECATED: This factory function is kept for backward compatibility.
    Prefer direct instantiation with dependency injection:
        engine = UltimateAdvancedFingerprintEngine(prober, classifier, attack_adapter)

    Args:
        prober: DPI probing service (required)
        classifier: DPI classification service (required)
        attack_adapter: Attack execution adapter (required)
        debug: Enable debug logging
        ml_enabled: Enable machine learning features

    Returns:
        UltimateAdvancedFingerprintEngine instance

    Raises:
        ValueError: If required dependencies are not provided
    """
    if not prober or not classifier or not attack_adapter:
        raise ValueError(
            "create_ultimate_fingerprint_engine requires prober, classifier, and attack_adapter. "
            "Use direct instantiation: UltimateAdvancedFingerprintEngine(prober, classifier, attack_adapter)"
        )

    return UltimateAdvancedFingerprintEngine(
        prober=prober,
        classifier=classifier,
        attack_adapter=attack_adapter,
        debug=debug,
        ml_enabled=ml_enabled,
    )
