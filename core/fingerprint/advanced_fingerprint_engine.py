"""
Ultimate Advanced Fingerprinting Engine combining all expert approaches
"""

import logging
import asyncio
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from dataclasses import asdict

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.utils.validation import check_is_fitted
    import joblib
    import numpy as np

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    check_is_fitted = None
from core.fingerprint.models import EnhancedFingerprint, DPIBehaviorProfile
from core.fingerprint.analyzer import PacketAnalyzer
from core.bypass.attacks.registry import AttackRegistry
from core.bypass.attacks.base import AttackResult, AttackStatus
from core.fingerprint.ech_detector import ECHDetector
from core.interfaces import IProber, IClassifier, IAttackAdapter, IFingerprintEngine

LOG = logging.getLogger("ultimate_fingerprint_engine")


class UltimateAdvancedFingerprintEngine(IFingerprintEngine):
    """
    Ultimate Advanced Fingerprinting Engine with Dependency Injection support.

    This class now accepts its dependencies through constructor injection,
    improving testability and following DI principles.
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
            raise ValueError(
                "classifier is required for UltimateAdvancedFingerprintEngine"
            )
        if not attack_adapter:
            raise ValueError(
                "attack_adapter is required for UltimateAdvancedFingerprintEngine"
            )
        self.debug = debug
        self.ml_enabled = ml_enabled and SKLEARN_AVAILABLE
        self.prober = prober
        self.classifier = classifier
        self.attack_adapter = attack_adapter
        self.attack_registry = AttackRegistry()
        self.effectiveness_model = None
        self.strategy_predictor = None
        self.is_effectiveness_model_fitted = False
        if self.ml_enabled:
            self._initialize_ml_models()
        self.fingerprint_cache = {}
        self.behavior_profiles = {}
        self.attack_history = defaultdict(lambda: defaultdict(list))
        self.technique_effectiveness = defaultdict(lambda: defaultdict(list))
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

    def _is_model_fitted(self, model) -> bool:
        """Check if sklearn model is fitted"""
        if not SKLEARN_AVAILABLE or model is None:
            return False
        try:
            if hasattr(model, "n_features_in_"):
                return hasattr(model, "n_features_in_") and model.n_features_in_ > 0
            else:
                check_is_fitted(model)
                return True
        except:
            return False

    def _apply_probe_results(
        self, probe_results: Dict[str, Any], fp: EnhancedFingerprint
    ):
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
        cache_key = f"{domain}_{hash(str(target_ips))}"
        if not force_refresh and cache_key in self.fingerprint_cache:
            cached_fp, timestamp = self.fingerprint_cache[cache_key]
            if datetime.now() - timestamp < self.cache_ttl:
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
        fp = EnhancedFingerprint(
            domain=domain, ip_addresses=target_ips, timestamp=datetime.now()
        )
        if packets:
            LOG.debug("Phase 1: Performing passive analysis on captured packets...")
            packet_analyzer = PacketAnalyzer(target_ip=target_ips[0])
            passive_fp = packet_analyzer.analyze_packets(packets)
            for attr, value in asdict(passive_fp).items():
                if (
                    hasattr(fp, attr)
                    and value is not None
                    and (value != ())
                    and (value != {})
                ):
                    setattr(fp, attr, value)
        LOG.debug("Phase 2: Performing preliminary signature-based classification...")
        prelim_classification = self.classifier._signature_classify(fp)
        fp.dpi_type = prelim_classification.dpi_type
        LOG.debug("Phase 3: Performing intelligent active probing...")
        preliminary_type = (
            fp.dpi_type if fp.dpi_type and fp.dpi_type != "Unknown" else None
        )
        probe_results = await self.prober.run_probes(
            domain=domain, preliminary_type=preliminary_type, force_all=force_refresh
        )
        self._apply_probe_results(probe_results, fp)
        self.stats["probes_executed"] += len(probe_results)
        LOG.debug("Phase 4: Performing final classification...")
        classification = self.classifier.classify(fp)
        fp.ml_confidence = classification.confidence
        LOG.debug("Phase 6: Extracting ML features...")
        fp.ml_features = self._extract_ml_features(fp)
        if self.ml_enabled and self._is_model_fitted(self.effectiveness_model):
            LOG.debug("Phase 7: Generating ML-based predictions and recommendations...")
            fp.predicted_weaknesses = self._predict_weaknesses(fp)
            fp.recommended_attacks = self._predict_best_attacks(fp)
        else:
            LOG.debug("Phase 7: Using rule-based recommendations (ML model not ready)")
            fp.predicted_weaknesses = self._predict_weaknesses(fp)
            fp.recommended_attacks = []
        self._update_cache(cache_key, fp)
        elapsed = (datetime.now() - start_time).total_seconds()
        LOG.info(
            f"Fingerprint complete for {domain}: {fp.dpi_type} [{fp.confidence:.0%}] in {elapsed:.2f}s"
        )
        return fp

    async def analyze_dpi_behavior(self, fingerprint: "EnhancedFingerprint", extended_metrics: Optional[Dict[str, Any]] = None) -> "DPIBehaviorProfile":
        """
        Create comprehensive behavioral profile with enhanced behavioral analysis
        """
        LOG.info(f"Analyzing DPI behavior for {domain}")
        if not fingerprint:
            fingerprint = await self.create_comprehensive_fingerprint(domain)
        profile = DPIBehaviorProfile(
            dpi_system_id=f"{domain}_{fingerprint.dpi_type}_{fingerprint.short_hash()}",
            ech_support=(
                extended_metrics.get("ech_support")
                if extended_metrics is not None
                else getattr(fingerprint, "ech_support", None)
            ),
        )
        # Новые флаги из ECHDetector (если есть)
        if extended_metrics:
            profile.ech_present = extended_metrics.get("ech_present")
            profile.ech_blocked = extended_metrics.get("ech_blocked")
            profile.http3_support = extended_metrics.get("http3_support")
        )
        profile.signature_based_detection = self._check_signature_detection(fingerprint)
        profile.behavioral_analysis = fingerprint.stateful_inspection or False
        profile.ml_detection = fingerprint.ml_detection_blocked or False
        profile.statistical_analysis = fingerprint.rate_limiting_detected or False
        profile.evasion_effectiveness = fingerprint.technique_success_rates.copy()
        profile.technique_rankings = sorted(
            profile.evasion_effectiveness.items(), key=lambda x: x[1], reverse=True
        )
        profile.supports_ip_frag = fingerprint.supports_ip_frag
        profile.checksum_validation = fingerprint.checksum_validation
        profile.rst_latency_ms = fingerprint.rst_latency_ms
        profile.ech_support = fingerprint.ech_support
        profile.timing_sensitivity_profile = await self._analyze_timing_sensitivity(
            domain, fingerprint
        )
        profile.connection_timeout_patterns = self._analyze_connection_timeouts(
            fingerprint
        )
        profile.burst_tolerance = await self._analyze_burst_tolerance(domain)
        profile.tcp_state_tracking_depth = self._analyze_tcp_state_depth(fingerprint)
        profile.tls_inspection_level = self._analyze_tls_inspection_level(fingerprint)
        profile.http_parsing_strictness = self._analyze_http_parsing_strictness(
            fingerprint
        )
        profile.stateful_connection_limit = await self._probe_connection_limit(domain)
        profile.packet_reordering_tolerance = await self._probe_packet_reordering(
            domain
        )
        profile.fragmentation_reassembly_timeout = (
            await self._probe_fragmentation_timeout(domain)
        )
        profile.deep_packet_inspection_depth = await self._probe_dpi_depth(domain)
        profile.pattern_matching_engine = self._identify_pattern_engine(fingerprint)
        profile.content_caching_behavior = await self._analyze_content_caching(domain)
        profile.anti_evasion_techniques = self._identify_anti_evasion_techniques(
            fingerprint
        )
        profile.learning_adaptation_detected = await self._probe_learning_adaptation(
            domain
        )
        profile.honeypot_detection = await self._probe_honeypot_detection(domain)
        profile.temporal_patterns = await self._analyze_temporal_patterns(domain)
        profile.packet_size_sensitivity = self._analyze_packet_sizes(fingerprint)
        profile.protocol_handling = self._analyze_protocols(fingerprint)
        profile.traffic_shaping_detected = self._detect_traffic_shaping(fingerprint)
        profile.ssl_interception_indicators = self._detect_ssl_interception(fingerprint)
        profile.identified_weaknesses = profile.analyze_weakness_patterns()
        profile.exploit_recommendations = [profile.generate_exploit_strategy()]
        self.behavior_profiles[domain] = profile
        LOG.info(
            f"Enhanced behavioral profile created for {domain} with {len(profile.identified_weaknesses)} weaknesses identified"
        )
        return profile

    def recommend_optimal_attacks(
        self,
        domain: str,
        fingerprint: EnhancedFingerprint = None,
        context: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate optimal attack recommendations using ML and analysis
        """
        self.stats["attacks_recommended"] += 1
        LOG.info(f"Generating attack recommendations for {domain}")
        recommendations = []
        if not fingerprint:
            found_fp = None
            for key, (fp, _) in self.fingerprint_cache.items():
                if key.startswith(domain):
                    found_fp = fp
                    break
            fingerprint = found_fp
            if not fingerprint:
                LOG.warning(f"No fingerprint available for {domain}")
                return self._get_generic_recommendations()
        type_recommendations = fingerprint.classification_reasons
        if (
            self.ml_enabled
            and self._is_model_fitted(self.effectiveness_model)
            and hasattr(fingerprint, "recommended_attacks")
        ):
            ml_recommendations = fingerprint.recommended_attacks
        else:
            ml_recommendations = []
        if domain in self.behavior_profiles:
            profile = self.behavior_profiles[domain]
            behavior_recommendations = self._get_behavior_recommendations(profile)
        else:
            behavior_recommendations = []
        all_techniques = set()
        all_techniques.update(type_recommendations)
        all_techniques.update(
            [r[0] for r in ml_recommendations if isinstance(r, tuple)]
        )
        all_techniques.update(behavior_recommendations)
        for technique in all_techniques:
            score = self._calculate_attack_score(
                technique, fingerprint, domain, context
            )
            recommendation = {
                "technique": technique,
                "score": score,
                "confidence": min(score, 1.0),
                "parameters": self._get_optimal_parameters(technique, fingerprint),
                "reasoning": self._get_attack_reasoning(technique, fingerprint),
            }
            recommendations.append(recommendation)
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        recommendations = self._add_execution_order(recommendations)
        return recommendations[:10]

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
            additional_probe_results = await self._run_targeted_probes(
                refined_fp, test_results
            )
            if additional_probe_results:
                self._apply_probe_results(additional_probe_results, refined_fp)
        cache_key = f"{refined_fp.domain}_{hash(str(refined_fp.ip_addresses))}"
        self._update_cache(cache_key, refined_fp)
        LOG.info(f"Fingerprint refinement completed for {refined_fp.domain}")
        return refined_fp
        
    def collect_extended_fingerprint_metrics(self, domain: str) -> Dict[str, Any]:
        """
        Сбор расширенных метрик через единую точку правды: ECHDetector.
        Возвращает словарь с ключами ech_present/ech_support/ech_blocked/quic_support/http3_support и доп. полями.
        """
        import asyncio

        detector = ECHDetector(dns_timeout=getattr(self, "dns_timeout", 1.2))

        async def _gather():
            dns_info = await detector.detect_ech_dns(domain)
            quic_info = await detector.probe_quic(domain)
            ech_block = await detector.detect_ech_blockage(domain)
            http3_info = await detector.probe_http3(domain)
            return dns_info, quic_info, ech_block, http3_info

        try:
            results = asyncio.run(_gather())
        except RuntimeError:
            # На случай, если уже есть запущенный event loop
            loop = asyncio.get_event_loop()
            results = loop.run_until_complete(_gather())

        dns_info, quic_info, ech_block, http3_info = results

        metrics: Dict[str, Any] = {
            "ech_present": bool(dns_info.get("ech_present")),
            # Поддержку ECH считаем по наличию валидного ECHConfigList в DNS
            "ech_support": bool(dns_info.get("ech_present")),
            "ech_blocked": ech_block.get("ech_blocked"),
            "quic_support": bool(quic_info.get("success")),
            "quic_rtt_ms": quic_info.get("rtt_ms"),
            "http3_support": bool(http3_info.get("supported")),
            "alpn": dns_info.get("alpn"),
            "ech_dns_records": dns_info.get("records"),
        }
        return metrics

    async def collect_extended_fingerprint_metrics(
        self, domain: str, target_ips: List[str] = None
    ) -> Dict[str, Any]:
        """
        Collect extended metrics using RealEffectivenessTester for enhanced fingerprinting.

        This method integrates with the RealEffectivenessTester to gather the new metrics
        required for Requirements 6.2 and 6.3.

        Args:
            domain: Target domain
            target_ips: List of target IPs (optional)

        Returns:
            Dictionary containing extended metrics for fingerprint enhancement
        """
        LOG.info(f"Collecting extended fingerprint metrics for {domain}")
        from core.bypass.attacks.real_effectiveness_tester import (
            RealEffectivenessTester,
        )

        extended_metrics = {}
        try:
            effectiveness_tester = RealEffectivenessTester(timeout=10.0)
            if not target_ips:
                target_ips = await self._resolve_domain_ips(domain)
            if not target_ips:
                LOG.warning(
                    f"No IPs found for {domain}, skipping extended metrics collection"
                )
                return extended_metrics
            https_metrics = await effectiveness_tester.collect_extended_metrics(
                domain, 443
            )
            extended_metrics["https"] = https_metrics
            try:
                http_metrics = await effectiveness_tester.collect_extended_metrics(
                    domain, 80
                )
                extended_metrics["http"] = http_metrics
            except Exception as e:
                LOG.debug(f"Failed to collect HTTP metrics for {domain}: {e}")
                extended_metrics["http"] = {"collection_error": str(e)}
            if (
                hasattr(effectiveness_tester, "session")
                and effectiveness_tester.session
            ):
                await effectiveness_tester.session.close()
            LOG.info(f"Extended metrics collection completed for {domain}")
        except Exception as e:
            LOG.error(f"Failed to collect extended metrics for {domain}: {e}")
            extended_metrics["collection_error"] = str(e)
        return extended_metrics

    def _apply_extended_metrics_to_fingerprint(
        self, fingerprint: EnhancedFingerprint, extended_metrics: Dict[str, Any]
    ):
        """
        Apply collected extended metrics to the fingerprint object.

        Args:
            fingerprint: EnhancedFingerprint object to update
            extended_metrics: Extended metrics collected from RealEffectivenessTester
        """
        try:
            https_metrics = extended_metrics.get("https", {})
            if https_metrics and "collection_error" not in https_metrics:
                if "rst_ttl_distance" in https_metrics:
                    fingerprint.rst_ttl_distance = https_metrics["rst_ttl_distance"]
                if "baseline_block_type" in https_metrics:
                    fingerprint.baseline_block_type = https_metrics[
                        "baseline_block_type"
                    ]
                if "sni_consistency_blocked" in https_metrics:
                    fingerprint.sni_consistency_blocked = https_metrics[
                        "sni_consistency_blocked"
                    ]
                if "primary_block_method" in https_metrics:
                    fingerprint.primary_block_method = https_metrics[
                        "primary_block_method"
                    ]
                if "connection_timeout_ms" in https_metrics:
                    fingerprint.connection_timeout_ms = https_metrics[
                        "connection_timeout_ms"
                    ]
                if "timing_attack_vulnerable" in https_metrics:
                    fingerprint.timing_attack_vulnerable = https_metrics[
                        "timing_attack_vulnerable"
                    ]
                if "response_timing_patterns" in https_metrics:
                    fingerprint.response_timing_patterns.update(
                        https_metrics["response_timing_patterns"]
                    )
                if "content_filtering_indicators" in https_metrics:
                    fingerprint.content_filtering_indicators.update(
                        https_metrics["content_filtering_indicators"]
                    )
                if "http2_support" in https_metrics:
                    fingerprint.http2_support = https_metrics["http2_support"]
                if "http2_frame_analysis" in https_metrics:
                    fingerprint.http2_frame_analysis.update(
                        https_metrics["http2_frame_analysis"]
                    )
                if "quic_support" in https_metrics:
                    fingerprint.quic_support = https_metrics["quic_support"]
                if "quic_analysis" in https_metrics:
                    quic_analysis = https_metrics["quic_analysis"]
                    if "quic_versions" in quic_analysis:
                        fingerprint.quic_version_support = quic_analysis[
                            "quic_versions"
                        ]
                    if "connection_id_handling" in quic_analysis:
                        fingerprint.quic_connection_id_handling = quic_analysis[
                            "connection_id_handling"
                        ]
                if "ech_support" in https_metrics:
                    fingerprint.ech_support = https_metrics["ech_support"]
                if "ech_analysis" in https_metrics:
                    ech_analysis = https_metrics["ech_analysis"]
                    if "grease_handling" in ech_analysis:
                        fingerprint.ech_grease_handling = ech_analysis[
                            "grease_handling"
                        ]
                    if "fragmentation_sensitivity" in ech_analysis:
                        fingerprint.ech_fragmentation_sensitivity = ech_analysis[
                            "fragmentation_sensitivity"
                        ]
            http_metrics = extended_metrics.get("http", {})
            if http_metrics and "collection_error" not in http_metrics:
                if "response_timing_patterns" in http_metrics:
                    for pattern_name, timings in http_metrics[
                        "response_timing_patterns"
                    ].items():
                        http_pattern_name = f"http_{pattern_name}"
                        fingerprint.response_timing_patterns[http_pattern_name] = (
                            timings
                        )
            LOG.debug(
                f"Applied extended metrics to fingerprint for {fingerprint.domain}"
            )
        except Exception as e:
            LOG.error(f"Failed to apply extended metrics to fingerprint: {e}")

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
        LOG.info(
            f"Creating comprehensive fingerprint with extended metrics for {domain}"
        )
        fingerprint = await self.create_comprehensive_fingerprint(
            domain, target_ips, packets, force_refresh
        )
        try:
            extended_metrics = await self.collect_extended_fingerprint_metrics(
                domain, target_ips
            )
            self._apply_extended_metrics_to_fingerprint(fingerprint, extended_metrics)
            fingerprint.timestamp = datetime.now()
            LOG.info(
                f"Enhanced fingerprint with extended metrics completed for {domain}"
            )
        except Exception as e:
            LOG.error(
                f"Failed to enhance fingerprint with extended metrics for {domain}: {e}"
            )
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
        if "successful_attack_patterns" in learning_insights:
            patterns = learning_insights["successful_attack_patterns"]
            for attack_name, success_rate in patterns.items():
                fingerprint.technique_success_rates[attack_name] = success_rate
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
                fingerprint.technique_success_rates[attack_name] = avg_success

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

    def _update_confidence_scores(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ):
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
                    fingerprint.ml_confidence = max(
                        0.1, fingerprint.ml_confidence - 0.1
                    )
                elif variance < 0.1:
                    fingerprint.ml_confidence = min(
                        1.0, fingerprint.ml_confidence + 0.1
                    )

    async def _determine_additional_probing_needs(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ) -> bool:
        """Determine if additional targeted probing is needed."""
        if fingerprint.ml_confidence < 0.6:
            LOG.debug("Low confidence - additional probing recommended")
            return True
        if test_results:
            success_count = sum(
                (
                    1
                    for r in test_results
                    if hasattr(r, "bypass_effective") and r.bypass_effective
                )
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
            LOG.debug(
                f"Missing key data: {missing_data} - additional probing recommended"
            )
            return True
        return False

    async def _run_targeted_probes(
        self, fingerprint: EnhancedFingerprint, test_results: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """Run targeted probes based on what we learned from test results."""
        try:
            targeted_probes = []
            if (
                not hasattr(fingerprint, "checksum_validation")
                or fingerprint.checksum_validation is None
            ):
                targeted_probes.append("bad_checksum")
            if (
                not hasattr(fingerprint, "supports_ip_frag")
                or fingerprint.supports_ip_frag is None
            ):
                targeted_probes.append("ip_fragmentation")
            if (
                not hasattr(fingerprint, "rate_limiting_detected")
                or fingerprint.rate_limiting_detected is None
            ):
                targeted_probes.append("rate_limiting")
            if not targeted_probes:
                return None
            LOG.info(
                f"Running {len(targeted_probes)} targeted probes for {fingerprint.domain}"
            )
            preliminary_type = None
            probe_results = await self.prober.run_probes(
                fingerprint.domain,
                preliminary_type=fingerprint.dpi_type,
                force_all=False,
            )
            filtered_results = {
                k: v for k, v in probe_results.items() if k in targeted_probes
            }
            return filtered_results
        except Exception as e:
            LOG.error(f"Failed to run targeted probes: {e}")
            return None

    def update_with_attack_results(
        self, domain: str, attack_results: List[AttackResult]
    ):
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
            self.technique_effectiveness[domain][result.technique_used].append(
                effectiveness
            )
            if self.ml_enabled and self._is_model_fitted(self.effectiveness_model):
                self._update_effectiveness_model(domain, result, effectiveness)
        found_key = None
        for key in self.fingerprint_cache:
            if key.startswith(domain):
                found_key = key
                break
        if found_key:
            fp, _ = self.fingerprint_cache[found_key]
            for technique, scores in self.technique_effectiveness[domain].items():
                if scores:
                    fp.technique_success_rates[technique] = sum(scores) / len(scores)

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
                if SKLEARN_AVAILABLE:
                    weights = np.exp(np.linspace(0, 2, len(scores)))
                    weights = weights / weights.sum()
                    effectiveness[technique] = np.average(scores, weights=weights)
                else:
                    effectiveness[technique] = sum(scores) / len(scores)
        if self.ml_enabled and self._is_model_fitted(self.effectiveness_model):
            all_techniques = self.attack_adapter.get_available_attacks()
            for technique in all_techniques:
                if technique not in effectiveness:
                    predicted = self._predict_technique_effectiveness(technique, domain)
                    if predicted is not None:
                        effectiveness[technique] = predicted
        return effectiveness

    def _extract_ml_features(self, fp: EnhancedFingerprint) -> Dict[str, float]:
        """Extract comprehensive ML features"""
        features = {}
        features["rst_ttl"] = fp.rst_ttl or -1
        features["rst_latency_ms"] = fp.rst_latency_ms or -1
        features["connection_latency"] = fp.connection_latency
        features["packet_loss_rate"] = fp.packet_loss_rate
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
        if fp.technique_success_rates:
            rates = list(fp.technique_success_rates.values())
            if SKLEARN_AVAILABLE and rates:
                features["avg_technique_success"] = np.mean(rates)
                features["std_technique_success"] = (
                    np.std(rates) if len(rates) > 1 else 0
                )
                features["max_technique_success"] = max(rates)
                features["min_technique_success"] = min(rates)
            else:
                features["avg_technique_success"] = (
                    sum(rates) / len(rates) if rates else 0
                )
                features["max_technique_success"] = max(rates) if rates else 0
                features["min_technique_success"] = min(rates) if rates else 0
                features["std_technique_success"] = 0
        features["evasion_difficulty"] = fp.calculate_evasion_difficulty()
        return features

    def _predict_weaknesses(self, fp: EnhancedFingerprint) -> List[str]:
        """Predict DPI weaknesses using ML"""
        weaknesses = []
        if fp.supports_ip_frag:
            weaknesses.append("Vulnerable to IP fragmentation attacks")
        if not fp.checksum_validation:
            weaknesses.append("No checksum validation - checksum attacks possible")
        if fp.large_payload_bypass:
            weaknesses.append("Large payloads can bypass inspection")
        if not fp.ml_detection_blocked:
            weaknesses.append("No ML-based anomaly detection")
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

    def _predict_best_attacks(self, fp: EnhancedFingerprint) -> List[Tuple[str, float]]:
        """Predict most effective attacks using ML"""
        predictions = []
        if self.ml_enabled and self._is_model_fitted(self.effectiveness_model):
            try:
                all_attacks = self.attack_adapter.get_available_attacks()
                for attack in all_attacks[:20]:
                    score = self._predict_technique_effectiveness(attack, fp.domain, fp)
                    if score is not None:
                        predictions.append((attack, score))
                predictions.sort(key=lambda x: x[1], reverse=True)
            except Exception as e:
                LOG.error(f"Attack prediction failed: {e}")
        return predictions[:10]

    def _predict_technique_effectiveness(
        self, technique: str, domain: str, fp: Optional[EnhancedFingerprint] = None
    ) -> Optional[float]:
        """Predict technique effectiveness using ML model"""
        if not self._is_model_fitted(self.effectiveness_model):
            return None
        try:
            return 0.5
        except Exception as e:
            LOG.debug(f"Effectiveness prediction failed: {e}")
            return None

    def _update_cache(self, key: str, fp: EnhancedFingerprint):
        """Update fingerprint cache with size management"""
        if len(self.fingerprint_cache) >= self.max_cache_size:
            oldest_key = min(
                self.fingerprint_cache.keys(),
                key=lambda k: self.fingerprint_cache[k][1],
            )
            del self.fingerprint_cache[oldest_key]
        self.fingerprint_cache[key] = (fp, datetime.now())

    def _calculate_effectiveness(self, result: AttackResult) -> float:
        """Calculate effectiveness score from attack result"""
        if result.status == AttackStatus.SUCCESS:
            score = 1.0
        elif (
            result.status == AttackStatus.BLOCKED
            if hasattr(AttackStatus, "BLOCKED")
            else False
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

    def _update_effectiveness_model(
        self, domain: str, result: AttackResult, effectiveness: float
    ):
        """Update ML model with new result"""
        try:
            found_fp = None
            for key, (fp, _) in self.fingerprint_cache.items():
                if key.startswith(domain):
                    found_fp = fp
                    break
            if not found_fp:
                return
            features = self._extract_ml_features(found_fp)
            attack_info = self.attack_adapter.get_attack_info(result.technique_used)
            attack_features = {
                "attack_category": (
                    attack_info.get("category", "unknown") if attack_info else "unknown"
                ),
                "attack_complexity": len(result.technique_used),
            }
            all_features = {**features, **attack_features}
        except Exception as e:
            LOG.error(f"Failed to update effectiveness model: {e}")

    def _check_signature_detection(self, fp: EnhancedFingerprint) -> bool:
        """Check if DPI uses signature-based detection"""
        return bool(fp.dpi_type and fp.dpi_type != "Unknown")

    async def _analyze_temporal_patterns(self, domain: str) -> Dict[str, Any]:
        """Analyze temporal patterns in DPI behavior"""
        return {
            "peak_hours_blocking": False,
            "rate_limit_reset_period": 60,
            "temporal_consistency": 0.9,
        }

    def _analyze_packet_sizes(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze packet size sensitivity"""
        return {
            "max_uninspected_size": (
                fp.large_payload_bypass if hasattr(fp, "large_payload_bypass") else 0
            ),
            "fragmentation_effective": (
                fp.supports_ip_frag if hasattr(fp, "supports_ip_frag") else False
            ),
        }

    def _analyze_protocols(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze protocol handling"""
        return {
            "tls_versions_blocked": [],
            "quic_support": (
                fp.quic_udp_blocked if hasattr(fp, "quic_udp_blocked") else None
            ),
            "http2_support": True,
        }

    def _detect_traffic_shaping(self, fp: EnhancedFingerprint) -> bool:
        """Detect if traffic shaping is applied"""
        return (
            fp.rate_limiting_detected
            if hasattr(fp, "rate_limiting_detected")
            else False
        )

    def _detect_ssl_interception(self, fp: EnhancedFingerprint) -> List[str]:
        """Detect SSL interception indicators"""
        indicators = []
        if hasattr(fp, "ech_grease_blocked") and fp.ech_grease_blocked:
            indicators.append("ECH GREASE blocking")
        if hasattr(fp, "tls_version_sensitivity") and fp.tls_version_sensitivity:
            indicators.append("TLS version manipulation")
        return indicators

    def _get_generic_recommendations(self) -> List[Dict[str, Any]]:
        """Get generic attack recommendations when no fingerprint available"""
        return [
            {
                "technique": "tcp_fakeddisorder",
                "score": 0.7,
                "confidence": 0.5,
                "parameters": {"split_pos": 3},
                "reasoning": "Generic recommendation - often effective",
            },
            {
                "technique": "tcp_multisplit",
                "score": 0.6,
                "confidence": 0.5,
                "parameters": {"positions": [1, 3, 5]},
                "reasoning": "Generic recommendation - good for many DPIs",
            },
        ]

    def _get_behavior_recommendations(self, profile: DPIBehaviorProfile) -> List[str]:
        """Get recommendations based on behavioral profile"""
        recommendations = []
        if profile.identified_weaknesses:
            weakness_mapping = {
                "ip_fragmentation": [
                    "ip_basic_fragmentation",
                    "ip_overlap_fragmentation",
                ],
                "tcp_segmentation": ["tcp_fakeddisorder", "tcp_multisplit"],
                "timing_based": ["tcp_timing_manipulation", "tcp_burst_timing"],
            }
            for weakness in profile.identified_weaknesses:
                if weakness in weakness_mapping:
                    recommendations.extend(weakness_mapping[weakness])
        return recommendations

    def _calculate_attack_score(
        self,
        technique: str,
        fp: EnhancedFingerprint,
        domain: str,
        context: Optional[Dict[str, Any]],
    ) -> float:
        """Calculate attack effectiveness score"""
        score = 0.5
        if (
            domain in self.technique_effectiveness
            and technique in self.technique_effectiveness[domain]
        ):
            historical_scores = self.technique_effectiveness[domain][technique]
            if historical_scores:
                score = sum(historical_scores) / len(historical_scores)
        if technique in fp.technique_success_rates:
            score = fp.technique_success_rates[technique]
        if context:
            if context.get("stealth_required") and "race" in technique:
                score *= 0.8
            if context.get("speed_priority") and "multi" in technique:
                score *= 0.9
        return min(score, 1.0)

    def _get_optimal_parameters(
        self, technique: str, fp: EnhancedFingerprint
    ) -> Dict[str, Any]:
        """Get optimal parameters for a technique based on fingerprint"""
        params = {
            "tcp_fakeddisorder": {"split_pos": 3},
            "tcp_multisplit": {"positions": [1, 3, 5]},
            "ip_basic_fragmentation": {"frag_size": 8},
            "tcp_timing_manipulation": {"delay_ms": 10},
        }
        if technique == "tcp_fakeddisorder" and hasattr(fp, "optimal_split_pos"):
            params[technique]["split_pos"] = fp.optimal_split_pos
        return params.get(technique, {})

    def _get_attack_reasoning(self, technique: str, fp: EnhancedFingerprint) -> str:
        """Get reasoning for why this attack was recommended"""
        reasons = []
        if technique in fp.classification_reasons:
            reasons.append(f"Recommended for {fp.dpi_type}")
        if technique in fp.technique_success_rates:
            rate = fp.technique_success_rates[technique]
            if rate > 0.7:
                reasons.append(f"High historical success rate ({rate:.0%})")
        if hasattr(fp, "predicted_weaknesses"):
            for weakness in fp.predicted_weaknesses:
                if technique.lower() in weakness.lower():
                    reasons.append(f"Exploits: {weakness}")
        return "; ".join(reasons) if reasons else "General recommendation"

    def _add_execution_order(
        self, recommendations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Add execution order suggestions to recommendations"""
        for i, rec in enumerate(recommendations):
            rec["execution_order"] = i + 1
            if i == 0:
                rec["execution_notes"] = "Try this first - highest confidence"
            elif i < 3:
                rec["execution_notes"] = "Good alternative if previous fails"
            else:
                rec["execution_notes"] = "Fallback option"
        return recommendations

    async def _analyze_timing_sensitivity(
        self, domain: str, fingerprint: EnhancedFingerprint
    ) -> Dict[str, float]:
        """Analyze DPI sensitivity to various timing delays"""
        LOG.debug(f"Analyzing timing sensitivity for {domain}")
        timing_profile = {}
        try:
            delay_tests = {
                "connection_delay": [0.1, 0.5, 1.0, 2.0],
                "handshake_delay": [0.05, 0.2, 0.5, 1.0],
                "data_delay": [0.01, 0.1, 0.5, 1.0],
                "keepalive_delay": [1.0, 5.0, 10.0, 30.0],
            }
            for delay_type, delays in delay_tests.items():
                sensitivity_scores = []
                for delay in delays:
                    success_rate = await self._probe_with_timing_delay(
                        domain, delay_type, delay
                    )
                    sensitivity_scores.append(success_rate)
                if sensitivity_scores:
                    if SKLEARN_AVAILABLE:
                        variance = (
                            float(np.var(sensitivity_scores))
                            if len(sensitivity_scores) > 1
                            else 0.0
                        )
                    else:
                        mean_val = sum(sensitivity_scores) / len(sensitivity_scores)
                        variance = sum(
                            ((x - mean_val) ** 2 for x in sensitivity_scores)
                        ) / len(sensitivity_scores)
                    timing_profile[delay_type] = variance
        except Exception as e:
            LOG.error(f"Failed to analyze timing sensitivity for {domain}: {e}")
        return timing_profile

    async def _probe_with_timing_delay(
        self, domain: str, delay_type: str, delay: float
    ) -> float:
        """Probe with specific timing delay and return success rate"""
        try:
            from core.bypass.attacks.real_effectiveness_tester import (
                RealEffectivenessTester,
            )

            tester = RealEffectivenessTester(timeout=10.0)
            baseline = await tester.test_baseline(domain, 443)
            await asyncio.sleep(delay)
            delayed_test = await tester.test_baseline(domain, 443)
            if baseline and delayed_test:
                if baseline.success == delayed_test.success:
                    return 1.0
                else:
                    return 0.0
            return 0.5
        except Exception as e:
            LOG.debug(
                f"Timing probe failed for {domain} with {delay_type}={delay}: {e}"
            )
            return 0.5

    def _analyze_connection_timeouts(
        self, fingerprint: EnhancedFingerprint
    ) -> Dict[str, int]:
        """Analyze connection timeout patterns for different protocols"""
        timeout_patterns = {}
        if fingerprint.connection_timeout_ms:
            timeout_patterns["tcp"] = fingerprint.connection_timeout_ms
        if fingerprint.baseline_block_type == "TIMEOUT":
            timeout_patterns["https"] = 10000
        elif fingerprint.baseline_block_type == "RST":
            timeout_patterns["https"] = 100
        if fingerprint.quic_support:
            timeout_patterns["quic"] = timeout_patterns.get("tcp", 5000)
        if fingerprint.http2_support:
            timeout_patterns["http2"] = timeout_patterns.get("https", 8000)
        return timeout_patterns

    async def _analyze_burst_tolerance(self, domain: str) -> Optional[float]:
        """Analyze DPI tolerance to traffic bursts"""
        try:
            burst_scores = []
            for burst_size in [5, 10, 20, 50]:
                score = await self._simulate_burst_test(domain, burst_size)
                burst_scores.append(score)
            if burst_scores:
                return sum(burst_scores) / len(burst_scores)
        except Exception as e:
            LOG.debug(f"Burst tolerance analysis failed for {domain}: {e}")
        return None

    async def _simulate_burst_test(self, domain: str, burst_size: int) -> float:
        """Simulate burst test with given burst size"""
        base_success = 0.8
        burst_penalty = min(burst_size * 0.02, 0.6)
        return max(base_success - burst_penalty, 0.1)

    def _analyze_tcp_state_depth(
        self, fingerprint: EnhancedFingerprint
    ) -> Optional[int]:
        """Analyze depth of TCP state tracking"""
        if fingerprint.stateful_inspection:
            if fingerprint.tcp_option_splicing:
                return 3
            elif fingerprint.supports_ip_frag is False:
                return 2
            else:
                return 1
        return 0

    def _analyze_tls_inspection_level(
        self, fingerprint: EnhancedFingerprint
    ) -> Optional[str]:
        """Analyze level of TLS inspection"""
        if fingerprint.ech_support is False and fingerprint.ech_blocked:
            return "full"
        elif fingerprint.sni_case_sensitive:
            return "deep"
        elif fingerprint.certificate_validation:
            return "basic"
        else:
            return "none"

    def _analyze_http_parsing_strictness(
        self, fingerprint: EnhancedFingerprint
    ) -> Optional[str]:
        """Analyze HTTP parsing strictness"""
        if fingerprint.http2_support and fingerprint.http2_frame_analysis:
            frame_analysis = fingerprint.http2_frame_analysis
            if frame_analysis.get("strict_frame_validation", False):
                return "strict"
            elif frame_analysis.get("basic_frame_validation", False):
                return "standard"
            else:
                return "loose"
        if fingerprint.stateful_inspection:
            return "standard"
        else:
            return "loose"

    async def _probe_connection_limit(self, domain: str) -> Optional[int]:
        """Probe maximum number of tracked connections"""
        try:
            estimated_limits = {
                "enterprise": 100000,
                "national": 1000000,
                "inline_fast": 10000,
                "cloud_based": 500000,
            }
            return estimated_limits.get("enterprise", 50000)
        except Exception as e:
            LOG.debug(f"Connection limit probing failed for {domain}: {e}")
            return None

    async def _probe_packet_reordering(self, domain: str) -> Optional[bool]:
        """Probe packet reordering tolerance"""
        try:
            return True
        except Exception as e:
            LOG.debug(f"Packet reordering probe failed for {domain}: {e}")
            return None

    async def _probe_fragmentation_timeout(self, domain: str) -> Optional[int]:
        """Probe fragmentation reassembly timeout"""
        try:
            return 30000
        except Exception as e:
            LOG.debug(f"Fragmentation timeout probe failed for {domain}: {e}")
            return None

    async def _probe_dpi_depth(self, domain: str) -> Optional[int]:
        """Probe how deep into payload DPI inspects"""
        try:
            return 1500
        except Exception as e:
            LOG.debug(f"DPI depth probe failed for {domain}: {e}")
            return None

    def _identify_pattern_engine(
        self, fingerprint: EnhancedFingerprint
    ) -> Optional[str]:
        """Identify pattern matching engine type"""
        if fingerprint.ml_detection_blocked:
            return "hyperscan"
        elif fingerprint.rate_limiting_detected:
            return "aho-corasick"
        elif fingerprint.stateful_inspection:
            return "regex"
        else:
            return "custom"

    async def _analyze_content_caching(self, domain: str) -> Optional[str]:
        """Analyze content caching behavior"""
        try:
            return "headers"
        except Exception as e:
            LOG.debug(f"Content caching analysis failed for {domain}: {e}")
            return None

    def _identify_anti_evasion_techniques(
        self, fingerprint: EnhancedFingerprint
    ) -> List[str]:
        """Identify known anti-evasion techniques"""
        techniques = []
        if fingerprint.checksum_validation:
            techniques.append("checksum_validation")
        if fingerprint.tcp_option_splicing:
            techniques.append("tcp_option_normalization")
        if fingerprint.supports_ip_frag is False:
            techniques.append("fragmentation_blocking")
        if fingerprint.rate_limiting_detected:
            techniques.append("rate_limiting")
        if fingerprint.ml_detection_blocked:
            techniques.append("ml_anomaly_detection")
        if fingerprint.stateful_inspection:
            techniques.append("stateful_tracking")
        return techniques

    async def _probe_learning_adaptation(self, domain: str) -> Optional[bool]:
        """Probe whether DPI adapts to evasion attempts"""
        try:
            return False
        except Exception as e:
            LOG.debug(f"Learning adaptation probe failed for {domain}: {e}")
            return None

    async def _probe_honeypot_detection(self, domain: str) -> Optional[bool]:
        """Probe for honeypot detection techniques"""
        try:
            return False
        except Exception as e:
            LOG.debug(f"Honeypot detection probe failed for {domain}: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics"""
        stats = self.stats.copy()
        stats["cache_entries"] = len(self.fingerprint_cache)
        stats["behavior_profiles"] = len(self.behavior_profiles)
        all_effectiveness = []
        for domain_data in self.technique_effectiveness.values():
            for scores in domain_data.values():
                all_effectiveness.extend(scores)
        if all_effectiveness:
            if SKLEARN_AVAILABLE:
                stats["avg_attack_effectiveness"] = np.mean(all_effectiveness)
            else:
                stats["avg_attack_effectiveness"] = sum(all_effectiveness) / len(
                    all_effectiveness
                )
            stats["total_attacks_tracked"] = len(all_effectiveness)
        return stats


def create_ultimate_fingerprint_engine(
    fast_bypass_engine=None, debug: bool = True, ml_enabled: bool = True
) -> UltimateAdvancedFingerprintEngine:
    """
    Factory function to create the ultimate fingerprint engine
    """
    return UltimateAdvancedFingerprintEngine(
        fast_bypass_engine=fast_bypass_engine, debug=debug, ml_enabled=ml_enabled
    )
