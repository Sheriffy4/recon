# recon/ml/strategy_generator.py
import random
import logging
import asyncio
import time
from typing import Dict, List, Optional, Any

# FIX: Change imports to reflect the new architecture
from core.fingerprint.models import Fingerprint
from core.fingerprint.classifier import UltimateDPIClassifier
from core.storage import Storage
from core.zapret import synth
from .strategy_predictor import StrategyPredictor, SKLEARN_AVAILABLE
from core.domain_specific_strategies import DomainSpecificStrategies
from core.bypass.attacks.registry import AttackRegistry
from core.optimization.dynamic_parameter_optimizer import (
    DynamicParameterOptimizer, # <-- Импортируем класс, даже если он может быть None
    OptimizationStrategy,
)
from core.bypass.attacks.base import AttackContext
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.bypass.attacks.registry import AttackRegistry
    from core.domain_specific_strategies import DomainSpecificStrategies
    from .strategy_predictor import StrategyPredictor

LOG = logging.getLogger("AdvancedStrategyGenerator")


class AdvancedStrategyGenerator:
    """
    Generates effective and diverse strategies using ML predictions,
    fingerprints, history, and mutations.
    This is an advanced version that replaces the older ZapretStrategyGenerator.

    Now supports Dependency Injection for improved testability.
    """

    PROVEN_WORKING = [
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
        "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
        "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=3,10 --dpi-desync-fooling=badseq",
    ]

    def __init__(
        self,
        attack_registry: AttackRegistry,
        domain_strategies: DomainSpecificStrategies,
        strategy_predictor: Optional[StrategyPredictor],
        # >>>>> ИЗМЕНЕНИЕ 1: Указываем, что зависимость может быть None <<<<<
        parameter_optimizer: Optional[DynamicParameterOptimizer],
        fingerprint_dict: Dict,
        history: List,
        doh_success: bool = False,
        max_strategies: int = 50,
        enable_ml_prediction: bool = True,
    ):
        self.fingerprint_dict = fingerprint_dict
        self.history = history
        self.doh_success = doh_success
        self.max_strategies = max_strategies  # <-- ДОБАВЛЕНО
        self.enable_ml_prediction = enable_ml_prediction  # <-- ДОБАВЛЕНО
        self.fp_object = None

        # Initialize dependencies with fallbacks
        
        self.attack_registry = attack_registry
        self.domain_strategies = domain_strategies
        self.strategy_predictor = strategy_predictor
        self.parameter_optimizer = parameter_optimizer
        self.parser = UnifiedStrategyParser()

        if self.fingerprint_dict:
            try:
                # First try EnhancedFingerprint if it has enhanced fields
                if any(
                    key in fingerprint_dict
                    for key in [
                        "connection_latency",
                        "technique_success_rates",
                        "optimal_parameters",
                    ]
                ):
                    from core.fingerprint.models import EnhancedFingerprint

                    # Create a minimal EnhancedFingerprint with required fields
                    domain = fingerprint_dict.get("domain", "unknown")
                    self.fp_object = EnhancedFingerprint(domain=domain)
                    # Copy over available fields
                    for key, value in fingerprint_dict.items():
                        if hasattr(self.fp_object, key):
                            setattr(self.fp_object, key, value)
                else:
                    # Use regular Fingerprint
                    self.fp_object = Fingerprint(**fingerprint_dict)
            except (TypeError, ImportError) as e:
                LOG.warning(f"Could not create Fingerprint object from dict: {e}")

    def _get_seeded_strategies(self) -> List[Dict]:
        """
        Возвращает набор проверенных временем, полных стратегий для "посева".
        Это комбинация лучших практик из старой и новой версий.
        """
        # Список полных, рабочих zapret-строк из старой версии
        proven_zapret_strings = [
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
            "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-fooling=badsum",
            "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badseq",
            "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-repeats=2 --dpi-desync-fake-tls=0x160303",
            "--quic-frag=100",
            "--dpi-desync=disorder --dpi-desync-split-pos=3 --hostcase" # tcp_http_combo
        ]
        
        seeds = []
        for strategy_str in proven_zapret_strings:
            # Парсим строку в нашу новую структуру задачи
            parsed = self.parser.parse(strategy_str)
            task = self.parser.translate_to_engine_task(parsed)
            if task:
                seeds.append(task)
        
        # Добавляем несколько простых, но важных техник
        seeds.append({"type": "tcp_fakeddisorder", "params": {"split_pos": 1}})
        seeds.append({"type": "tlsrec_split", "params": {"split_pos": 5}})

        return seeds
    
    def generate_strategies(self, count: int = 20, use_parameter_ranges: bool = True) -> List[Dict]:
        """
        Generates a list of unique attack tasks (dictionaries) using all available intelligence.
        Now supports parameter range generation for optimization.

        Args:
            count: Number of strategies to generate
            use_parameter_ranges: Whether to use parameter ranges instead of fixed values
        """
        attack_tasks = []
        seen_tasks = set()

        def make_hashable(obj):
            """Convert nested structures to hashable tuples"""
            if isinstance(obj, dict):
                return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
            elif isinstance(obj, list):
                return tuple(make_hashable(e) for e in obj)
            else:
                return obj

        def add_task(task: Dict):
            # Create a hashable representation
            task_repr = make_hashable(task)
            if task_repr not in seen_tasks:
                attack_tasks.append(task)
                seen_tasks.add(task_repr)

        # 1. Add domain-specific strategies first if a domain is known
        if (
            self.fp_object
            and hasattr(self.fp_object, "domain")
            and self.fp_object.domain
        ):
            domain_strategies = DomainSpecificStrategies.get_strategies_for_domain(
                self.fp_object.domain
            )
            if domain_strategies:
                LOG.info(
                    f"Adding {len(domain_strategies)} domain-specific strategies for {self.fp_object.domain}."
                )
                # This part needs a reverse parser from zapret string to task dict,
                # which is complex. For now, we'll skip adding them directly as tasks.
                # In a future version, a parser would be used here.

        # 2. QUIC priority if not blocked
        if (
            self.fp_object
            and hasattr(self.fp_object, "quic_udp_blocked")
            and not self.fp_object.quic_udp_blocked
        ):
            LOG.info("QUIC is not blocked. Prioritizing QUIC-based attacks.")
            quic_params = self._generate_task_parameters(
                "quic_fragmentation", use_parameter_ranges
            )
            add_task({"name": "quic_fragmentation", "params": quic_params})

        # 3. ML Predictions using specialized models
        if self.fp_object and SKLEARN_AVAILABLE and self.strategy_predictor and self.enable_ml_prediction:
            try:
                # First, create behavioral profile if we have enhanced fingerprint
                if hasattr(self.fp_object, "technique_success_rates"):
                    from core.fingerprint.models import DPIBehaviorProfile

                    # Create behavioral profile from fingerprint
                    behavior_profile = DPIBehaviorProfile(
                        dpi_system_id=f"{self.fp_object.domain}_{getattr(self.fp_object, 'dpi_type', 'unknown')}"
                    )

                    # Copy behavioral indicators from fingerprint
                    behavior_profile.supports_ip_frag = getattr(
                        self.fp_object, "supports_ip_frag", None
                    )
                    behavior_profile.checksum_validation = getattr(
                        self.fp_object, "checksum_validation", None
                    )
                    behavior_profile.rst_latency_ms = getattr(
                        self.fp_object, "rst_latency_ms", None
                    )
                    behavior_profile.ech_support = getattr(
                        self.fp_object, "ech_support", None
                    )
                    behavior_profile.ml_detection = getattr(
                        self.fp_object, "ml_detection_blocked", False
                    )
                    behavior_profile.behavioral_analysis = getattr(
                        self.fp_object, "stateful_inspection", False
                    )
                    behavior_profile.statistical_analysis = getattr(
                        self.fp_object, "rate_limiting_detected", False
                    )
                    behavior_profile.signature_based_detection = (
                        True  # Assume signature-based detection
                    )

                    # Get strategy predictions
                    strategy_prediction = (
                        self.strategy_predictor.predict_strategy_categories(
                            behavior_profile
                        )
                    )

                    if strategy_prediction.recommended_categories:
                        LOG.info(
                            f"Adding {len(strategy_prediction.recommended_categories)} ML-predicted strategy categories"
                        )

                        for category in strategy_prediction.recommended_categories:
                            success_rate = strategy_prediction.category_scores.get(
                                category, 0.5
                            )
                            if success_rate > 0.5:
                                # Map strategy categories to specific attack techniques
                                techniques = self._map_category_to_techniques(category)

                                for technique in techniques:
                                    params = self._generate_task_parameters(
                                        technique, use_parameter_ranges
                                    )
                                    # Add ML confidence and reasoning to params
                                    params["ml_confidence"] = success_rate
                                    params["ml_reasoning"] = (
                                        strategy_prediction.reasoning
                                    )
                                    add_task({"name": technique, "params": params})

                    LOG.debug(
                        f"ML strategy prediction reasoning: {strategy_prediction.reasoning}"
                    )

                else:
                    # Fallback to old prediction method for basic fingerprints
                    predictor = StrategyPredictor()
                    ml_predictions = predictor.predict(self.fingerprint_dict)
                    if ml_predictions:
                        LOG.info("Adding top strategies from ML predictions.")
                        for tech_type, prob in ml_predictions[:3]:
                            if prob > 0.1:
                                # Generate parameters for ML-predicted technique
                                params = self._generate_task_parameters(
                                    tech_type, use_parameter_ranges
                                )
                                add_task({"name": tech_type, "params": params})
            except Exception as e:
                LOG.warning(f"Could not get ML predictions: {e}")

        # 4. Fingerprint-based recommendations (Rule-based)
        if self.fp_object:
            try:
                # FIX: Instantiate the classifier and use it to get recommendations
                classifier = UltimateDPIClassifier(
                    ml_enabled=False
                )  # ML is not needed for signature-based recs
                classification_result = classifier.classify(self.fp_object)
                recommended_tech_names = classification_result.recommended_techniques

                if recommended_tech_names:
                    LOG.info(
                        f"Adding {len(recommended_tech_names)} recommended strategies based on fingerprint."
                    )
                    for tech_name in recommended_tech_names:
                        params = self._generate_task_parameters(
                            tech_name, use_parameter_ranges
                        )
                        add_task({"name": tech_name, "params": params})
            except Exception as e:
                LOG.warning(f"Could not get fingerprint-based recommendations: {e}")

        # 5. Add proven working strategies for variety
        proven_attacks = [
            "tcp_fakeddisorder",
            "tcp_multisplit",
            "tcp_multidisorder",
            "tcp_seqovl",
            "tcp_window_scaling",
            "urgent_pointer_manipulation",
        ]

        for attack_name in proven_attacks:
            if len(attack_tasks) >= count:
                break
            params = self._generate_task_parameters(attack_name, use_parameter_ranges)
            add_task({"name": attack_name, "params": params})

        # 6. Generate variations and new combos until count is met
        initial_tasks = list(attack_tasks)
        while len(attack_tasks) < count:
            if not initial_tasks:
                break  # Avoid infinite loop if no base tasks
            base_task = random.choice(initial_tasks)

            # Generate variations (mutations)
            variation = self._mutate_task_with_ranges(base_task, use_parameter_ranges)
            add_task(variation)

            # Generate new combos
            if len(attack_tasks) < count:
                combo = self._generate_combo_task_with_ranges(
                    initial_tasks, use_parameter_ranges
                )
                add_task(combo)

        final_count = min(count, self.max_strategies)
        return attack_tasks[:final_count]

    def generate_strategies_with_failure_analysis(
        self,
        count: int = 20,
        failure_analysis: Optional[Any] = None,
        use_parameter_ranges: bool = True,
    ) -> List[Dict]:
        """
        Generate strategies informed by failure analysis results.

        Args:
            count: Number of strategies to generate
            failure_analysis: FailureAnalysisResult from previous iterations
            use_parameter_ranges: Whether to use parameter ranges for optimization

        Returns:
            List of strategy dictionaries prioritized based on failure patterns
        """
        attack_tasks = []
        seen_tasks = set()

        def make_hashable(obj):
            """Convert nested structures to hashable tuples"""
            if isinstance(obj, dict):
                return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
            elif isinstance(obj, list):
                return tuple(make_hashable(e) for e in obj)
            else:
                return obj

        def add_task(task: Dict):
            # Create a hashable representation
            task_repr = make_hashable(task)
            if task_repr not in seen_tasks:
                attack_tasks.append(task)
                seen_tasks.add(task_repr)

        # 1. Prioritize techniques based on failure analysis
        if failure_analysis and hasattr(failure_analysis, "next_iteration_focus"):
            LOG.info(
                f"Prioritizing {len(failure_analysis.next_iteration_focus)} techniques from failure analysis"
            )
            for technique in failure_analysis.next_iteration_focus[
                :5
            ]:  # Top 5 recommendations
                params = self._generate_task_parameters(technique, use_parameter_ranges)
                add_task({"name": technique, "params": params, "priority": "high"})

        # 2. Avoid techniques that consistently fail
        avoided_techniques = set()
        if failure_analysis and hasattr(failure_analysis, "detected_patterns"):
            for pattern in failure_analysis.detected_patterns:
                if pattern.confidence > 0.8 and pattern.affected_techniques:
                    # Avoid techniques that failed with high confidence
                    avoided_techniques.update(pattern.affected_techniques)
                    LOG.debug(
                        f"Avoiding techniques due to pattern {pattern.pattern_type}: {pattern.affected_techniques}"
                    )

        # 3. Generate strategies using base method, filtering out avoided techniques
        base_strategies = self.generate_strategies(
            count * 2, use_parameter_ranges
        )  # Generate more to filter

        for strategy in base_strategies:
            if len(attack_tasks) >= count:
                break

            # Skip avoided techniques unless we have very few alternatives
            if (
                strategy["name"] in avoided_techniques
                and len(attack_tasks) < count // 2
            ):
                continue

            add_task(strategy)

        # 4. Fill remaining slots with diverse techniques if needed
        if len(attack_tasks) < count:
            diverse_techniques = [
                "traffic_mimicry",
                "multi_flow_correlation",
                "full_session_simulation",
                "ech_fragmentation",
                "quic_packet_coalescing",
                "http2_frame_splitting",
            ]

            for technique in diverse_techniques:
                if len(attack_tasks) >= count:
                    break
                if technique not in avoided_techniques:
                    params = self._generate_task_parameters(
                        technique, use_parameter_ranges
                    )
                    add_task(
                        {
                            "name": technique,
                            "params": params,
                            "priority": "experimental",
                        }
                    )

        # Sort by priority (high priority first)
        prioritized_tasks = []
        normal_tasks = []

        for task in attack_tasks:
            if task.get("priority") == "high":
                prioritized_tasks.append(task)
            else:
                normal_tasks.append(task)

        # Return prioritized tasks first, then normal tasks
        final_tasks = prioritized_tasks + normal_tasks
        return final_tasks[:count]

    def generate_strategies_with_block_type_prioritization(
        self,
        count: int = 20,
        block_type: Optional[str] = None,
        use_parameter_ranges: bool = True,
    ) -> List[Dict]:
        """
        Generate strategies prioritized based on detected block type.

        This method implements Task 17.1: Prioritize strategies based on block type
        (timeout, RST, content) and prioritize specific attacks for stateful DPI.

        Args:
            count: Number of strategies to generate
            block_type: Detected block type ('timeout', 'rst', 'content', 'none')
            use_parameter_ranges: Whether to use parameter ranges for optimization

        Returns:
            List of strategy dictionaries prioritized based on block type
        """
        attack_tasks = []
        seen_tasks = set()

        def make_hashable(obj):
            """Convert nested structures to hashable tuples"""
            if isinstance(obj, dict):
                return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
            elif isinstance(obj, list):
                return tuple(make_hashable(e) for e in obj)
            else:
                return obj

        def add_task(task: Dict):
            # Create a hashable representation
            task_repr = make_hashable(task)
            if task_repr not in seen_tasks:
                attack_tasks.append(task)
                seen_tasks.add(task_repr)

        LOG.info(f"Generating strategies prioritized for block_type: {block_type}")

        # 1. Block type specific prioritization
        if block_type == "timeout":
            # For timeout blocks, prioritize stateful DPI attacks
            LOG.info("Prioritizing stateful DPI attacks for timeout blocks")

            timeout_priority_attacks = [
                "tcp_fakeddisorder",  # Fake + disorder to confuse state tracking
                "tcp_multidisorder",  # Multiple disorder packets
                "tcp_seqovl",  # Sequence overlap for state confusion
                "tcp_multisplit",  # Multiple splits to overwhelm state tracking
                "tcp_timing_manipulation",  # Timing attacks for stateful DPI
                "tcp_window_scaling",  # Window manipulation
                "urgent_pointer_manipulation",  # Urgent pointer attacks
            ]

            for attack_name in timeout_priority_attacks:
                if len(attack_tasks) >= count // 2:  # Fill half with priority attacks
                    break
                params = self._generate_task_parameters(
                    attack_name, use_parameter_ranges
                )
                # Add specific parameters for timeout scenarios
                if attack_name in ["tcp_fakeddisorder", "tcp_multidisorder"]:
                    params["disorder_level"] = "high"
                    params["state_confusion"] = True
                elif attack_name == "tcp_seqovl":
                    params["overlap_size"] = 20  # Larger overlap for state confusion
                    params["sequence_manipulation"] = "aggressive"
                elif attack_name == "tcp_timing_manipulation":
                    params["delay_pattern"] = "variable"
                    params["timing_jitter"] = True

                add_task(
                    {
                        "name": attack_name,
                        "params": params,
                        "priority": "timeout_optimized",
                        "block_type_reason": "stateful_dpi_confusion",
                    }
                )

        elif block_type == "rst":
            # For RST blocks, prioritize techniques that avoid triggering immediate RST
            LOG.info("Prioritizing RST avoidance attacks for RST blocks")

            rst_avoidance_attacks = [
                "tcp_fragmentation",  # Fragment to avoid signature detection
                "tcp_multisplit",  # Split payloads to avoid pattern matching
                "ip_fragmentation",  # IP-level fragmentation
                "tcp_options_padding",  # TCP options manipulation
                "tcp_timestamp_manipulation",  # Timestamp attacks
                "payload_obfuscation",  # Payload encoding/encryption
                "tls_record_manipulation",  # TLS record splitting
            ]

            for attack_name in rst_avoidance_attacks:
                if len(attack_tasks) >= count // 2:
                    break
                params = self._generate_task_parameters(
                    attack_name, use_parameter_ranges
                )
                # Add specific parameters for RST avoidance
                if attack_name in ["tcp_fragmentation", "tcp_multisplit"]:
                    params["fragment_size"] = (
                        "small"  # Smaller fragments to avoid detection
                    )
                    params["randomize_order"] = True
                elif attack_name == "payload_obfuscation":
                    params["obfuscation_level"] = "high"
                    params["encoding_method"] = "base64"

                add_task(
                    {
                        "name": attack_name,
                        "params": params,
                        "priority": "rst_avoidance",
                        "block_type_reason": "signature_evasion",
                    }
                )

        elif block_type == "content":
            # For content blocks, prioritize payload manipulation and encryption
            LOG.info("Prioritizing payload manipulation attacks for content blocks")

            content_evasion_attacks = [
                "payload_encryption",  # Encrypt payload to hide content
                "payload_obfuscation",  # Obfuscate payload patterns
                "steganography",  # Hide data in legitimate-looking traffic
                "traffic_mimicry",  # Mimic legitimate application traffic
                "tls_extension_attacks",  # TLS extension manipulation
                "http_header_attacks",  # HTTP header manipulation
                "tunneling_attacks",  # Protocol tunneling
            ]

            for attack_name in content_evasion_attacks:
                if len(attack_tasks) >= count // 2:
                    break
                params = self._generate_task_parameters(
                    attack_name, use_parameter_ranges
                )
                # Add specific parameters for content evasion
                if attack_name == "payload_encryption":
                    params["encryption_method"] = "aes"
                    params["key_rotation"] = True
                elif attack_name == "traffic_mimicry":
                    params["mimic_application"] = "zoom"  # Popular application
                    params["behavioral_patterns"] = True
                elif attack_name == "steganography":
                    params["steganography_method"] = "tcp_timestamp"
                    params["data_encoding"] = "distributed"

                add_task(
                    {
                        "name": attack_name,
                        "params": params,
                        "priority": "content_evasion",
                        "block_type_reason": "content_hiding",
                    }
                )

        # 2. Add general effective techniques to fill remaining slots
        general_techniques = [
            "adaptive_multi_layer",
            "multi_flow_correlation",
            "full_session_simulation",
            "http2_frame_splitting",
            "quic_packet_coalescing",
            "ech_fragmentation",
        ]

        for technique in general_techniques:
            if len(attack_tasks) >= count:
                break
            params = self._generate_task_parameters(technique, use_parameter_ranges)
            add_task(
                {
                    "name": technique,
                    "params": params,
                    "priority": "general",
                    "block_type_reason": "general_effectiveness",
                }
            )

        # 3. Fill remaining slots with base strategies if needed
        if len(attack_tasks) < count:
            base_strategies = self.generate_strategies(
                count - len(attack_tasks), use_parameter_ranges
            )
            for strategy in base_strategies:
                add_task(strategy)

        # 4. Sort by priority (block-type optimized first)
        priority_order = {
            "timeout_optimized": 0,
            "rst_avoidance": 1,
            "content_evasion": 2,
            "general": 3,
            None: 4,  # Default priority for base strategies
        }

        attack_tasks.sort(key=lambda x: priority_order.get(x.get("priority"), 4))

        LOG.info(
            f"Generated {len(attack_tasks)} strategies prioritized for {block_type} blocks"
        )
        return attack_tasks[:count]

    async def generate_optimized_strategies(
        self,
        count: int = 10,
        context: Optional[AttackContext] = None,
        optimization_strategy: OptimizationStrategy = OptimizationStrategy.RANDOM_SEARCH,
        max_optimization_iterations: int = 10,
    ) -> List[Dict]:
        """
        Generate strategies with optimized parameters through real testing.

        Args:
            count: Number of strategies to generate
            context: Attack context for optimization testing
            optimization_strategy: Parameter optimization strategy
            max_optimization_iterations: Maximum iterations per attack optimization

        Returns:
            List of strategies with optimized parameters
        """
        LOG.info(
            f"Generating {count} optimized strategies using {optimization_strategy.value}"
        )

        # Generate base strategies with parameter ranges
        base_strategies = self.generate_strategies(count, use_parameter_ranges=True)

        if not context:
            LOG.warning(
                "No context provided for optimization, returning base strategies"
            )
            return base_strategies

        optimized_strategies = []

        for strategy in base_strategies:
            try:
                attack_name = strategy["name"]

                # Skip optimization for attacks not in registry
                if not AttackRegistry.get(attack_name):
                    LOG.warning(
                        f"Attack {attack_name} not found in registry, skipping optimization"
                    )
                    optimized_strategies.append(strategy)
                    continue

                LOG.info(f"Optimizing parameters for {attack_name}")

                # Optimize parameters
                optimization_result = (
                    await self.parameter_optimizer.optimize_parameters(
                        attack_name=attack_name,
                        context=context,
                        strategy=optimization_strategy,
                        max_iterations=max_optimization_iterations,
                        convergence_threshold=0.8,
                        timeout_seconds=60,
                    )
                )

                # Update strategy with optimized parameters
                if optimization_result.optimal_parameters:
                    strategy["params"] = optimization_result.optimal_parameters
                    strategy["optimization_metadata"] = {
                        "best_effectiveness": optimization_result.best_effectiveness,
                        "total_tests": optimization_result.total_tests,
                        "optimization_time_ms": optimization_result.optimization_time_ms,
                        "convergence_iteration": optimization_result.convergence_iteration,
                    }
                    LOG.info(
                        f"Optimized {attack_name}: effectiveness={optimization_result.best_effectiveness:.3f}"
                    )
                else:
                    LOG.warning(
                        f"No optimal parameters found for {attack_name}, using defaults"
                    )

                optimized_strategies.append(strategy)

            except Exception as e:
                LOG.error(
                    f"Error optimizing strategy {strategy.get('name', 'unknown')}: {e}"
                )
                optimized_strategies.append(
                    strategy
                )  # Add original strategy as fallback

        LOG.info(f"Generated {len(optimized_strategies)} optimized strategies")
        return optimized_strategies

    def _generate_task_parameters(self, attack_name: str, use_parameter_ranges: bool = True) -> Dict[str, Any]:
        if not use_parameter_ranges:
            return self._generate_fixed_parameters(attack_name)

        # >>>>> КЛЮЧЕВАЯ ПРОВЕРКА <<<<<
        if not self.parameter_optimizer or self.parameter_optimizer is None:
            LOG.debug(f"Parameter optimizer not available. Using fixed parameters for {attack_name}.")
            return self._generate_fixed_parameters(attack_name)
        
        # Additional safety check for the method
        if not hasattr(self.parameter_optimizer, 'generate_parameter_ranges'):
            LOG.warning(f"Parameter optimizer does not have generate_parameter_ranges method. Using fixed parameters for {attack_name}.")
            return self._generate_fixed_parameters(attack_name)
        
        param_ranges = self.parameter_optimizer.generate_parameter_ranges(attack_name)

        if not param_ranges:
            return {}

        # Generate sample parameters from ranges
        params = {}
        for param_name, param_range in param_ranges.items():
            params[param_name] = self.parameter_optimizer._sample_parameter_value(
                param_range
            )

        return params

    def _generate_fixed_parameters(self, attack_name: str) -> Dict[str, Any]:
        """Generate fixed parameters for backward compatibility."""
        # Default parameters for common attacks
        defaults = {
            "tcp_fakeddisorder": {"split_pos": 3},
            "tcp_multisplit": {"positions": [1, 3, 10]},
            "tcp_multidisorder": {"positions": [1, 3, 10]},
            "tcp_seqovl": {"split_pos": 3, "overlap_size": 10},
            "tcp_window_scaling": {"window_scale": 2, "split_pos": 3},
            "urgent_pointer_manipulation": {"split_pos": 5, "urgent_data_size": 2},
            "tcp_options_padding": {"padding_size": 8, "split_pos": 4},
            "tcp_timestamp_manipulation": {"split_pos": 6},
            "quic_fragmentation": {"fragment_size": 100},
            "http2_frame_splitting": {"frame_size": 1024},
            "ech_fragmentation": {"fragment_size": 64},
        }

        return defaults.get(attack_name, {})

    def _mutate_task(self, task: Dict) -> Dict:
        """Creates a small mutation of an existing attack task."""
        return self._mutate_task_with_ranges(task, use_parameter_ranges=False)

    def _mutate_task_with_ranges(
        self, task: Dict, use_parameter_ranges: bool = True
    ) -> Dict:
        """Creates a small mutation of an existing attack task with parameter range support."""
        mutated_task = task.copy()
        mutated_task["params"] = task.get("params", {}).copy()

        attack_name = task.get("name", "")

        if use_parameter_ranges and self.parameter_optimizer and hasattr(self.parameter_optimizer, 'generate_parameter_ranges'):
            # Use parameter ranges for mutation
            param_ranges = self.parameter_optimizer.generate_parameter_ranges(
                attack_name
            )

            # Mutate 1-2 parameters using ranges
            params_to_mutate = (
                random.sample(list(param_ranges.keys()), min(2, len(param_ranges)))
                if param_ranges
                else []
            )

            for param_name in params_to_mutate:
                if param_name in param_ranges:
                    param_range = param_ranges[param_name]
                    mutated_task["params"][param_name] = (
                        self.parameter_optimizer._sample_parameter_value(param_range)
                    )
        else:
            # Legacy mutation logic
            if "ttl" in mutated_task["params"]:
                mutated_task["params"]["ttl"] = random.choice([2, 3, 5, 10])
            if "segment_size" in mutated_task["params"]:
                mutated_task["params"]["segment_size"] = random.choice([1, 3, 5, 8])
            if "split_pos" in mutated_task["params"]:
                mutated_task["params"]["split_pos"] = random.choice([1, 3, 5, "midsld"])

        return mutated_task

    def _generate_combo_task(self, existing_tasks: List[Dict]) -> Dict:
        """Generates a new, more logical combo attack task."""
        return self._generate_combo_task_with_ranges(
            existing_tasks, use_parameter_ranges=False
        )

    def _generate_combo_task_with_ranges(
        self, existing_tasks: List[Dict], use_parameter_ranges: bool = True
    ) -> Dict:
        """Generates a new, more logical combo attack task with parameter range support."""
        if len(existing_tasks) < 2:
            if existing_tasks:
                return random.choice(existing_tasks)
            else:
                # Generate default combo task
                params = self._generate_task_parameters(
                    "adaptive_multi_layer", use_parameter_ranges
                )
                return {"name": "adaptive_multi_layer", "params": params}

        task1, task2 = random.sample(existing_tasks, 2)

        # --- НАЧАЛО ИЗМЕНЕНИЙ: Логическая проверка совместимости ---
        attack_info1 = AttackRegistry().get(task1["name"])
        attack_info2 = AttackRegistry().get(task2["name"])

        # Не комбинируем атаки, работающие по разным протоколам (например, TCP и UDP/QUIC)
        if attack_info1 and attack_info2:
            try:
                protocols1 = set(attack_info1().supported_protocols)
                protocols2 = set(attack_info2().supported_protocols)
                if not protocols1.intersection(protocols2):
                    # Атаки несовместимы, возвращаем одну из них
                    return task1
            except Exception as e:
                LOG.warning(f"Error checking protocol compatibility: {e}")
        # --- КОНЕЦ ИЗМЕНЕНИЙ ---

        # Generate combo parameters
        if use_parameter_ranges:
            combo_params = self._generate_task_parameters(
                "adaptive_multi_layer", use_parameter_ranges
            )
            combo_params.update({"layer1": task1["name"], "layer2": task2["name"]})
        else:
            combo_params = {
                "layer1": task1["name"],
                "layer2": task2["name"],
                "adaptation_level": random.choice(["light", "medium", "high"]),
            }

        combo_task = {"name": "adaptive_multi_layer", "params": combo_params}
        return combo_task

    def save_optimized_parameters(
        self, attack_name: str, parameters: Dict[str, Any], effectiveness: float
    ):
        """
        Save optimized parameters to StrategySaver.

        Args:
            attack_name: Name of the attack
            parameters: Optimized parameters
            effectiveness: Effectiveness score
        """
        try:
            from core.integration.strategy_saver import StrategySaver

            # Create strategy dictionary for saving
            strategy = {
                "attack_name": attack_name,
                "task": {"name": attack_name, "params": parameters},
                "success_rate": effectiveness,
                "avg_latency_ms": 1000.0,  # Placeholder - would be from real testing
                "domains": [self.fingerprint_dict.get("domain", "unknown")],
                "fingerprint_summary": self.fingerprint_dict,
                "strategy": f"# Optimized parameters for {attack_name}: {parameters}",
                "optimization_metadata": {
                    "optimized": True,
                    "effectiveness": effectiveness,
                    "timestamp": time.time(),
                },
            }

            # Save using StrategySaver
            saver = StrategySaver()
            success = saver.save_effective_strategies([strategy])

            if success:
                LOG.info(f"Successfully saved optimized parameters for {attack_name}")
            else:
                LOG.warning(f"Failed to save optimized parameters for {attack_name}")

        except Exception as e:
            LOG.error(f"Error saving optimized parameters for {attack_name}: {e}")

    def get_parameter_ranges_for_attack(self, attack_name: str) -> Dict[str, Any]:
        """
        Get parameter ranges for a specific attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Dictionary of parameter ranges
        """
        if not self.parameter_optimizer or not hasattr(self.parameter_optimizer, 'generate_parameter_ranges'):
            return {}
        return self.parameter_optimizer.generate_parameter_ranges(attack_name)

    def _map_category_to_techniques(self, category: str) -> List[str]:
        """
        Map strategy categories from ML predictor to specific attack techniques.

        Args:
            category: Strategy category from ML predictor

        Returns:
            List of specific attack technique names
        """
        category_mapping = {
            "tcp_segmentation": [
                "tcp_fakeddisorder",
                "tcp_multisplit",
                "tcp_multidisorder",
                "tcp_seqovl",
            ],
            "ip_fragmentation": [
                "ip_basic_fragmentation",
                "ip_advanced_fragmentation",
                "ip_fragmentation_overlap",
            ],
            "timing_manipulation": [
                "tcp_timing_manipulation",
                "tcp_drip_feed",
                "tcp_burst_timing",
            ],
            "payload_obfuscation": [
                "payload_encryption",
                "payload_obfuscation",
                "payload_noise_injection",
            ],
            "protocol_tunneling": [
                "dns_tunneling",
                "icmp_tunneling",
                "protocol_tunneling",
            ],
            "header_manipulation": [
                "tcp_header_manipulation",
                "ip_header_manipulation",
                "tcp_urgent_pointer_manipulation",
            ],
            "modern_protocols": [
                "http2_frame_splitting",
                "quic_cid_manipulation",
                "quic_packet_coalescing",
                "ech_fragmentation",
                "ech_grease",
            ],
            "traffic_mimicry": [
                "traffic_mimicry",
                "multi_flow_correlation",
                "full_session_simulation",
            ],
            "multi_layer_combo": [
                "adaptive_multi_layer",
                "multi_layer_attack",
                "combo_attack",
            ],
            "steganography": ["steganography", "covert_channel", "data_hiding"],
        }

        # Return techniques for the category, or fallback to generic techniques
        techniques = category_mapping.get(category, [])

        if not techniques:
            # Fallback to some generic techniques if category not found
            LOG.warning(
                f"Unknown strategy category: {category}, using fallback techniques"
            )
            techniques = [
                "tcp_fakeddisorder",
                "ip_basic_fragmentation",
                "payload_obfuscation",
            ]

        # Filter techniques to only include those available in the attack registry
        available_techniques = []
        for technique in techniques:
            if self.attack_registry.get(technique):
                available_techniques.append(technique)
            else:
                LOG.debug(f"Technique {technique} not available in attack registry")

        # If no techniques are available, return the original list (they might be added later)
        return available_techniques if available_techniques else techniques
# Export StrategyGenerator for backward compatibility
StrategyGenerator = AdvancedStrategyGenerator