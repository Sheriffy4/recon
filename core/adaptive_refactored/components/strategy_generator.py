"""
Strategy Generator implementation for the refactored Adaptive Engine.

This component is responsible for generating new bypass strategies.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import time
from ..interfaces import IStrategyGenerator, IFailureAnalyzer
from ..models import Strategy, DPIFingerprint, FailureReport, StrategyType
from ..config import StrategyConfig


logger = logging.getLogger(__name__)


class StrategyGenerator(IStrategyGenerator):
    """
    Implementation of strategy generation based on DPI fingerprints and failure analysis.

    Generates bypass strategies using various techniques including:
    - TCP fragmentation
    - TLS fragmentation
    - HTTP fragmentation
    - Fake packets
    - Domain fronting
    - SNI modification
    - Mixed case techniques
    - Combination strategies
    """

    def __init__(self, config: StrategyConfig, failure_analyzer: Optional[IFailureAnalyzer] = None):
        self.config = config
        self.failure_analyzer = failure_analyzer
        self._generation_timeout = config.generation_timeout

        # Statistics tracking
        self._stats = {
            "total_generated": 0,
            "generation_time": 0.0,
            "success_rate": 0.0,
            "last_generation_time": 0.0,
            "strategies_by_type": {},
            "failures": 0,
        }

        logger.info(f"Strategy generator initialized with timeout {self._generation_timeout}s")

    async def generate_strategies(
        self, fingerprint: DPIFingerprint, max_count: int = 10
    ) -> List[Strategy]:
        """Generate strategies based on DPI fingerprint."""
        start_time = time.monotonic()
        try:
            # Use configured max count if not specified
            if not isinstance(max_count, int) or max_count <= 0:
                max_count = self.config.max_strategies_per_domain

            logger.info(f"Generating up to {max_count} strategies for domain: {fingerprint.domain}")

            # Generate strategies with timeout (treat non-positive timeout as "no timeout")
            if self._generation_timeout and self._generation_timeout > 0:
                strategies = await asyncio.wait_for(
                    self._generate_strategies_internal(fingerprint, max_count),
                    timeout=self._generation_timeout,
                )
            else:
                strategies = await self._generate_strategies_internal(fingerprint, max_count)

            # Update statistics
            generation_time = time.monotonic() - start_time
            self._stats["total_generated"] += len(strategies)
            self._stats["generation_time"] += generation_time
            self._stats["last_generation_time"] = generation_time

            # Update success rate (assuming successful generation)
            total_attempts = self._stats["total_generated"] + self._stats["failures"]
            if total_attempts > 0:
                self._stats["success_rate"] = self._stats["total_generated"] / total_attempts

            # Update strategies by type
            for strategy in strategies:
                strategy_type = strategy.strategy_type.value
                self._stats["strategies_by_type"][strategy_type] = (
                    self._stats["strategies_by_type"].get(strategy_type, 0) + 1
                )

            logger.info(f"Generated {len(strategies)} strategies for {fingerprint.domain}")
            return strategies

        except asyncio.TimeoutError:
            self._stats["failures"] += 1
            logger.warning(
                f"Strategy generation timed out after {self._generation_timeout}s for {fingerprint.domain}"
            )
            return []
        except Exception as e:
            self._stats["failures"] += 1
            logger.exception(f"Failed to generate strategies for {fingerprint.domain}: {e}")
            return []

    async def _generate_strategies_internal(
        self, fingerprint: DPIFingerprint, max_count: int
    ) -> List[Strategy]:
        """Internal strategy generation logic."""
        strategies = []

        # Generate basic single-technique strategies
        strategies.extend(await self._generate_fragmentation_strategies(fingerprint))
        strategies.extend(await self._generate_fake_packet_strategies(fingerprint))
        strategies.extend(await self._generate_sni_strategies(fingerprint))
        strategies.extend(await self._generate_domain_fronting_strategies(fingerprint))

        # Generate combination strategies if enabled
        if self.config.enable_fingerprinting:
            strategies.extend(await self._generate_combination_strategies(fingerprint, strategies))

        # CRITICAL FIX: Diversify strategies instead of just sorting by confidence
        # This ensures we test different attack types, not just the highest confidence ones
        diversified_strategies = self._diversify_strategies(strategies, max_count)
        return diversified_strategies

    def _diversify_strategies(self, strategies: List[Strategy], max_count: int) -> List[Strategy]:
        """
        Diversify strategies to ensure variety of attack types.

        Instead of just taking top N by confidence, we:
        1. Group strategies by type
        2. Take best from each type in round-robin fashion
        3. Fill remaining slots with highest confidence strategies

        This ensures we test different attack approaches, not just variations of one type.
        """
        if not strategies:
            return []

        if len(strategies) <= max_count:
            # If we have fewer strategies than max_count, return all sorted by confidence
            return sorted(strategies, key=lambda s: s.confidence_score, reverse=True)

        # Group strategies by type
        by_type: Dict[StrategyType, List[Strategy]] = {}
        for strategy in strategies:
            strategy_type = strategy.strategy_type
            if strategy_type not in by_type:
                by_type[strategy_type] = []
            by_type[strategy_type].append(strategy)

        # Sort each group by confidence
        for strategy_type in by_type:
            by_type[strategy_type].sort(key=lambda s: s.confidence_score, reverse=True)

        # Round-robin selection from each type
        selected = []
        type_list = list(by_type.keys())
        type_index = 0

        while len(selected) < max_count and any(by_type.values()):
            # Get next type in round-robin
            current_type = type_list[type_index % len(type_list)]

            # Take best strategy from this type if available
            if by_type[current_type]:
                selected.append(by_type[current_type].pop(0))

            type_index += 1

            # If we've gone through all types and still have empty ones, remove them
            if type_index % len(type_list) == 0:
                type_list = [t for t in type_list if by_type[t]]
                if not type_list:
                    break
                type_index = 0

        logger.debug(f"Diversified {len(strategies)} strategies to {len(selected)} with variety:")
        type_counts = {}
        for s in selected:
            type_name = s.strategy_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        for type_name, count in type_counts.items():
            logger.debug(f"  - {type_name}: {count} strategies")

        return selected

    async def _generate_fragmentation_strategies(
        self, fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Generate fragmentation-based strategies."""
        strategies = []
        domain = fingerprint.domain

        # TCP fragmentation strategies using 'split' attack
        for frag_size in [40, 80, 120, 200]:
            strategy = Strategy(
                name=f"tcp_frag_{frag_size}",
                attack_combination=["split"],  # Use registered attack name
                parameters={"domain": domain, "fragment_size": frag_size, "split_pos": frag_size},
                strategy_type=StrategyType.TCP_FRAGMENTATION,
                confidence_score=0.7,
            )
            strategies.append(strategy)

        # TLS fragmentation strategies using 'multisplit' attack
        for frag_size in [1, 2, 4, 8]:
            strategy = Strategy(
                name=f"tls_fragmentation_{frag_size}",
                attack_combination=["multisplit"],  # Use registered attack name
                parameters={
                    "domain": domain,
                    "fragment_size": frag_size,
                    "split_count": frag_size,
                },
                strategy_type=StrategyType.TLS_FRAGMENTATION,
                confidence_score=0.8,
            )
            strategies.append(strategy)

        # HTTP fragmentation strategies using 'disorder' attack
        # CRITICAL: fragmentation_method specifies target (header/body/both)
        # disorder_method specifies how to reorder (reverse/random/swap)
        disorder_mapping = {
            "header": "reverse",  # Header fragmentation uses reverse order
            "body": "random",  # Body fragmentation uses random order
            "both": "swap",  # Both uses swap order
        }

        for method in ["header", "body", "both"]:
            strategy = Strategy(
                name=f"http_fragmentation_{method}",
                attack_combination=["disorder"],  # Use registered attack name
                parameters={
                    "domain": domain,
                    "fragmentation_method": method,
                    "disorder_method": disorder_mapping[method],
                    "split_pos": 2,  # HTTP fragmentation uses split_pos=2
                },
                strategy_type=StrategyType.HTTP_FRAGMENTATION,
                confidence_score=0.6,
            )
            strategies.append(strategy)

        return strategies

    async def _generate_fake_packet_strategies(self, fingerprint: DPIFingerprint) -> List[Strategy]:
        """Generate fake packet strategies."""
        strategies = []
        domain = fingerprint.domain

        # Fake SYN strategies using 'fake' attack
        strategy = Strategy(
            name="fake_syn",
            attack_combination=["fake"],  # Use registered attack name
            parameters={"domain": domain, "fake_count": 3, "ttl": 8},
            strategy_type=StrategyType.FAKE_PACKETS,
            confidence_score=0.75,
        )
        strategies.append(strategy)

        # Fake data strategies using 'fakeddisorder' attack
        for ttl in [1, 2, 4, 8]:
            strategy = Strategy(
                name=f"fake_data_ttl_{ttl}",
                attack_combination=["fakeddisorder"],  # Use registered attack name
                parameters={
                    "domain": domain,
                    "fake_ttl": ttl,
                    "fake_payload": "GET / HTTP/1.1\r\n\r\n",
                },
                strategy_type=StrategyType.FAKE_PACKETS,
                confidence_score=0.65,
            )
            strategies.append(strategy)

        return strategies

    async def _generate_sni_strategies(self, fingerprint: DPIFingerprint) -> List[Strategy]:
        """Generate SNI modification strategies."""
        strategies = []
        domain = fingerprint.domain

        # Mixed case SNI using 'disorder' attack
        strategy = Strategy(
            name="sni_mixed_case",
            attack_combination=["disorder"],  # Use registered attack name
            parameters={
                "domain": domain,
                "case_pattern": "alternating",
                "disorder_method": "reverse",
            },
            strategy_type=StrategyType.MIXED_CASE,
            confidence_score=0.5,
        )
        strategies.append(strategy)

        # SNI fragmentation using 'split' attack
        for frag_pos in [1, 2, 4]:
            strategy = Strategy(
                name=f"sni_frag_{frag_pos}",
                attack_combination=["split"],  # Use registered attack name
                parameters={
                    "domain": domain,
                    "fragment_position": frag_pos,
                    "split_pos": frag_pos,
                },
                strategy_type=StrategyType.SNI_MODIFICATION,
                confidence_score=0.7,
            )
            strategies.append(strategy)

        return strategies

    async def _generate_domain_fronting_strategies(
        self, fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Generate domain fronting strategies."""
        strategies = []
        domain = fingerprint.domain

        # Basic domain fronting using 'passthrough' attack (as it's the safest fallback)
        common_fronts = ["cloudflare.com", "amazonaws.com", "googleusercontent.com"]

        for front_domain in common_fronts:
            strategy = Strategy(
                name=f"domain_front_{front_domain.split('.')[0]}",
                attack_combination=["passthrough"],  # Use registered attack name
                parameters={
                    "domain": domain,
                    "front_domain": front_domain,
                    "real_domain": domain,
                },
                strategy_type=StrategyType.DOMAIN_FRONTING,
                confidence_score=0.4,  # Lower confidence as it's more complex
            )
            strategies.append(strategy)

        return strategies

    async def _generate_combination_strategies(
        self, fingerprint: DPIFingerprint, base_strategies: List[Strategy]
    ) -> List[Strategy]:
        """Generate combination strategies from base strategies."""
        strategies = []
        domain = fingerprint.domain

        # Only generate combinations if we have enough base strategies
        if len(base_strategies) < 2:
            return strategies

        # Generate 2-technique combinations
        for i, strategy1 in enumerate(base_strategies[:5]):  # Limit to avoid explosion
            for strategy2 in base_strategies[i + 1 : 5]:
                if strategy1.strategy_type != strategy2.strategy_type:
                    combo_strategy = Strategy(
                        name=f"combo_{strategy1.name}_{strategy2.name}",
                        attack_combination=strategy1.attack_combination
                        + strategy2.attack_combination,
                        parameters={
                            # keep domain explicit for downstream validators/dispatchers
                            "domain": domain,
                            **strategy1.parameters,
                            **strategy2.parameters,
                        },
                        strategy_type=StrategyType.COMBINATION,
                        confidence_score=(strategy1.confidence_score + strategy2.confidence_score)
                        / 2
                        * 0.9,  # Slightly lower confidence
                    )
                    strategies.append(combo_strategy)

        return strategies[:10]  # Limit combination strategies

    async def generate_from_failure(self, failure_report: FailureReport) -> List[Strategy]:
        """Generate strategies based on failure analysis."""
        try:
            logger.info(f"Generating strategies from failure analysis for {failure_report.domain}")

            strategies = []
            error_message = str(getattr(failure_report, "error_message", "") or "")

            # Analyze failure patterns and generate targeted strategies
            if "timeout" in error_message.lower():
                strategies.extend(await self._generate_timeout_recovery_strategies(failure_report))
            elif "connection" in error_message.lower():
                strategies.extend(
                    await self._generate_connection_recovery_strategies(failure_report)
                )
            elif "ssl" in error_message.lower() or "tls" in error_message.lower():
                strategies.extend(await self._generate_tls_recovery_strategies(failure_report))
            else:
                # Generate general recovery strategies
                strategies.extend(await self._generate_general_recovery_strategies(failure_report))

            # Apply failure analyzer insights if available
            if self.failure_analyzer:
                try:
                    enhanced_strategies = await self._enhance_with_failure_analysis(
                        strategies, failure_report
                    )
                    strategies.extend(enhanced_strategies)
                except Exception as e:
                    logger.warning(f"Failed to enhance strategies with failure analysis: {e}")

            logger.info(f"Generated {len(strategies)} recovery strategies")
            return strategies

        except Exception as e:
            logger.error(f"Failed to generate strategies from failure: {e}")
            return []

    async def _generate_timeout_recovery_strategies(
        self, failure_report: FailureReport
    ) -> List[Strategy]:
        """Generate strategies to recover from timeout failures."""
        strategies = []
        domain = failure_report.domain

        # Faster techniques for timeout recovery using registered attacks
        strategy = Strategy(
            name="timeout_recovery_fast_frag",
            attack_combination=["split"],  # Use registered attack name
            parameters={
                "domain": domain,
                "fragment_size": 40,
                "fast_mode": True,
                "split_pos": 40,
            },
            strategy_type=StrategyType.TCP_FRAGMENTATION,
            confidence_score=0.8,
        )
        strategies.append(strategy)

        return strategies

    async def _generate_connection_recovery_strategies(
        self, failure_report: FailureReport
    ) -> List[Strategy]:
        """Generate strategies to recover from connection failures."""
        strategies = []
        domain = failure_report.domain

        # Connection-focused techniques using registered attacks
        strategy = Strategy(
            name="connection_recovery_fake_syn",
            attack_combination=["fake"],  # Use registered attack name
            parameters={"domain": domain, "fake_count": 1, "ttl": 4},
            strategy_type=StrategyType.FAKE_PACKETS,
            confidence_score=0.75,
        )
        strategies.append(strategy)

        return strategies

    async def _generate_tls_recovery_strategies(
        self, failure_report: FailureReport
    ) -> List[Strategy]:
        """Generate strategies to recover from TLS/SSL failures."""
        strategies = []
        domain = failure_report.domain

        # TLS-focused techniques using registered attacks
        strategy = Strategy(
            name="tls_recovery_sni_frag",
            attack_combination=["split"],  # Use registered attack name
            parameters={"domain": domain, "fragment_position": 1, "split_pos": 1},
            strategy_type=StrategyType.SNI_MODIFICATION,
            confidence_score=0.7,
        )
        strategies.append(strategy)

        return strategies

    async def _generate_general_recovery_strategies(
        self, failure_report: FailureReport
    ) -> List[Strategy]:
        """Generate general recovery strategies."""
        strategies = []
        domain = failure_report.domain

        # General purpose recovery strategy using registered attacks
        strategy = Strategy(
            name="general_recovery_combo",
            attack_combination=["split", "fake"],  # Use registered attack names
            parameters={
                "domain": domain,
                "fragment_size": 80,
                "fake_count": 2,
                "ttl": 8,
                "split_pos": 80,
            },
            strategy_type=StrategyType.COMBINATION,
            confidence_score=0.6,
        )
        strategies.append(strategy)

        return strategies

    async def _enhance_with_failure_analysis(
        self, strategies: List[Strategy], failure_report: FailureReport
    ) -> List[Strategy]:
        """Enhance strategies using failure analyzer insights."""
        # This would integrate with the failure analyzer to get more sophisticated insights
        # For now, return empty list as placeholder
        return []

    def set_generation_timeout(self, timeout: float) -> None:
        """Set timeout for strategy generation."""
        self._generation_timeout = timeout
        logger.info(f"Strategy generation timeout set to {timeout}s")

    def get_generation_stats(self) -> Dict[str, Any]:
        """Get generation statistics."""
        return self._stats.copy()

    def _create_attack_combinations(self, fingerprint: DPIFingerprint) -> List[List[str]]:
        """Create attack combinations based on DPI fingerprint characteristics."""
        combinations = []

        # Get characteristics from fingerprint
        characteristics = fingerprint.characteristics

        # Basic single-attack combinations using registered attacks
        basic_attacks = ["fake", "badseq", "split", "multisplit"]
        for attack in basic_attacks:
            combinations.append([attack])

        # Combinations based on detected characteristics
        if characteristics.get("rst_on_fake_sni"):
            combinations.extend([["fake", "badseq"], ["fake", "split"], ["badseq", "split"]])

        if characteristics.get("blocks_http"):
            combinations.extend([["disorder"], ["fake", "disorder"], ["badseq", "disorder"]])

        return combinations

    def _generate_parameters(self, attack_combination: List[str], domain: str) -> Dict[str, Any]:
        """Generate parameters for an attack combination."""
        parameters = {"domain": domain}

        for attack in attack_combination:
            if attack == "fake":
                parameters.update({"fake_count": 3, "ttl": 8})
            elif attack == "badseq":
                parameters.update({"badseq_increment": 10000, "badseq_ack_increment": 10000})
            elif attack == "split":
                parameters.update({"split_pos": 40, "fragment_delay": 0})
            elif attack == "multisplit":
                parameters.update({"split_count": 2, "fragment_delay": 0})
            elif attack == "disorder":
                parameters.update({"disorder_method": "reverse", "fragment_size": 80})

        return parameters

    def _calculate_strategy_priority(
        self, fingerprint: DPIFingerprint, attack_combination: List[str]
    ) -> float:
        """Calculate priority score for a strategy based on fingerprint and attacks."""
        base_priority = 1.0

        # Get characteristics from fingerprint
        characteristics = fingerprint.characteristics

        # Boost priority based on detected characteristics
        if "fake" in attack_combination and characteristics.get("rst_on_fake_sni"):
            base_priority += 0.5

        if "disorder" in attack_combination and characteristics.get("blocks_http"):
            base_priority += 0.3

        # Combination strategies get slightly lower priority
        if len(attack_combination) > 1:
            base_priority *= 0.9

        return base_priority

    def _validate_strategy(self, strategy: Strategy) -> bool:
        """Validate that a strategy is properly formed."""
        if not strategy.name or not strategy.name.strip():
            return False

        if not strategy.attack_combination or len(strategy.attack_combination) == 0:
            return False

        if not isinstance(strategy.parameters, dict):
            return False

        # Check that domain is specified in parameters
        if "domain" not in strategy.parameters:
            return False

        return True
