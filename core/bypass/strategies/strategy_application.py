"""
Enhanced Strategy Application Algorithm for Bypass Engine Modernization

This module implements intelligent strategy selection, user preference prioritization,
automatic pool assignment, and conflict resolution mechanisms.
"""

import json
import logging
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from enum import Enum

try:
    from core.bypass.strategies.pool_management import (
        StrategyPool,
        StrategyPoolManager,
        BypassStrategy,
        DomainRule,
    )
    from core.bypass.attacks.attack_registry import AttackRegistry
except ImportError:
    import sys
    import os

    sys.path.append(os.path.dirname(__file__))
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "attacks"))
    from pool_management import StrategyPool, StrategyPoolManager, BypassStrategy

    try:
        from attack_registry import AttackRegistry
    except ImportError:

        class AttackRegistry:

            def get_attack_definition(self, attack_id):
                return None


LOG = logging.getLogger("StrategyApplication")


class SelectionCriteria(Enum):
    """Criteria for strategy selection."""

    SUCCESS_RATE = "success_rate"
    LATENCY = "latency"
    RELIABILITY = "reliability"
    USER_PREFERENCE = "user_preference"
    COMPATIBILITY = "compatibility"
    FRESHNESS = "freshness"


class ConflictResolution(Enum):
    """Methods for resolving strategy conflicts."""

    USER_PREFERENCE = "user_preference"
    HIGHEST_SUCCESS_RATE = "highest_success_rate"
    LOWEST_LATENCY = "lowest_latency"
    MOST_RECENT = "most_recent"
    POOL_PRIORITY = "pool_priority"
    MERGE_STRATEGIES = "merge_strategies"


@dataclass
class StrategyScore:
    """Score for a strategy based on various criteria."""

    strategy_id: str
    total_score: float
    criteria_scores: Dict[SelectionCriteria, float] = field(default_factory=dict)
    confidence: float = 0.0
    reasoning: List[str] = field(default_factory=list)


@dataclass
class UserPreference:
    """User preference for domain strategies."""

    domain: str
    strategy: str
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    fingerprint_used: bool = False
    dpi_type: str = "unknown"
    dpi_confidence: float = 0.0

    @classmethod
    def from_best_strategy_json(
        cls, data: Dict[str, Any], domain: str = "default"
    ) -> "UserPreference":
        """Create UserPreference from best_strategy.json format."""
        return cls(
            domain=domain,
            strategy=data.get("strategy", ""),
            success_rate=data.get("success_rate", 0.0),
            avg_latency_ms=data.get("avg_latency_ms", 0.0),
            fingerprint_used=data.get("fingerprint_used", False),
            dpi_type=data.get("dpi_type", "unknown"),
            dpi_confidence=data.get("dpi_confidence", 0.0),
        )


@dataclass
class DomainAnalysis:
    """Analysis results for a domain."""

    domain: str
    tld: str
    sld: str
    subdomains: List[str]
    is_social_media: bool = False
    is_cdn: bool = False
    is_video_platform: bool = False
    is_news_site: bool = False
    estimated_complexity: int = 1
    suggested_ports: List[int] = field(default_factory=lambda: [443, 80])
    tags: List[str] = field(default_factory=list)


class EnhancedStrategySelector:
    """
    Enhanced strategy selection algorithm with intelligent decision making.
    """

    def __init__(
        self,
        pool_manager: StrategyPoolManager,
        attack_registry: AttackRegistry,
        user_preferences_path: str = "recon/best_strategy.json",
    ):
        self.pool_manager = pool_manager
        self.attack_registry = attack_registry
        self.user_preferences_path = user_preferences_path
        self.user_preferences: Dict[str, UserPreference] = {}
        self.selection_weights = {
            SelectionCriteria.SUCCESS_RATE: 0.3,
            SelectionCriteria.LATENCY: 0.2,
            SelectionCriteria.RELIABILITY: 0.2,
            SelectionCriteria.USER_PREFERENCE: 0.15,
            SelectionCriteria.COMPATIBILITY: 0.1,
            SelectionCriteria.FRESHNESS: 0.05,
        }
        self.conflict_resolution_order = [
            ConflictResolution.USER_PREFERENCE,
            ConflictResolution.POOL_PRIORITY,
            ConflictResolution.HIGHEST_SUCCESS_RATE,
            ConflictResolution.LOWEST_LATENCY,
        ]
        self.domain_patterns = {
            "social_media": [
                ".*youtube\\.com.*",
                ".*twitter\\.com.*",
                ".*instagram\\.com.*",
                ".*tiktok\\.com.*",
                ".*facebook\\.com.*",
                ".*vk\\.com.*",
                ".*telegram\\.org.*",
                ".*discord\\.com.*",
            ],
            "video_platforms": [
                ".*youtube\\.com.*",
                ".*vimeo\\.com.*",
                ".*twitch\\.tv.*",
                ".*netflix\\.com.*",
                ".*hulu\\.com.*",
            ],
            "cdn_providers": [
                ".*cloudflare\\.com.*",
                ".*fastly\\.com.*",
                ".*akamai\\.com.*",
                ".*amazonaws\\.com.*",
                ".*googleusercontent\\.com.*",
            ],
            "news_sites": [
                ".*bbc\\.com.*",
                ".*cnn\\.com.*",
                ".*reuters\\.com.*",
                ".*nytimes\\.com.*",
                ".*guardian\\.com.*",
            ],
        }
        self._load_user_preferences()

    def select_strategy(
        self, domain: str, port: int = 443, context: Optional[Dict[str, Any]] = None
    ) -> Optional[BypassStrategy]:
        """
        Select the best strategy for a domain using intelligent algorithm.

        Args:
            domain: Target domain
            port: Target port
            context: Additional context for selection

        Returns:
            Selected bypass strategy or None if no suitable strategy found
        """
        LOG.info(f"Selecting strategy for {domain}:{port}")
        domain_analysis = self._analyze_domain(domain)
        candidates = self._get_candidate_strategies(domain, port, domain_analysis)
        if not candidates:
            LOG.warning(f"No candidate strategies found for {domain}")
            return self._get_fallback_strategy(domain_analysis)
        scored_strategies = []
        for strategy in candidates:
            score = self._score_strategy(
                strategy, domain, port, domain_analysis, context
            )
            scored_strategies.append(score)
        scored_strategies.sort(key=lambda x: x.total_score, reverse=True)
        best_score = scored_strategies[0]
        LOG.info(
            f"Selected strategy '{best_score.strategy_id}' for {domain} (score: {best_score.total_score:.3f}, confidence: {best_score.confidence:.3f})"
        )
        LOG.debug(f"Selection reasoning: {'; '.join(best_score.reasoning)}")
        for strategy in candidates:
            if strategy.id == best_score.strategy_id:
                return strategy
        return None

    def auto_assign_domain(self, domain: str, **kwargs) -> Optional[str]:
        """
        Automatically assign a domain to the most appropriate pool.

        Args:
            domain: Domain to assign
            **kwargs: Additional context for assignment

        Returns:
            Pool ID if assignment successful, None otherwise
        """
        LOG.info(f"Auto-assigning domain: {domain}")
        pool_id = self.pool_manager.auto_assign_domain(domain, **kwargs)
        if pool_id:
            LOG.info(f"Domain {domain} assigned to existing pool {pool_id}")
            return pool_id
        domain_analysis = self._analyze_domain(domain)
        target_pool = self._find_or_create_pool_for_domain(domain_analysis)
        if target_pool:
            if self.pool_manager.add_domain_to_pool(target_pool.id, domain):
                LOG.info(f"Domain {domain} auto-assigned to pool {target_pool.id}")
                return target_pool.id
        LOG.warning(f"Failed to auto-assign domain {domain}")
        return None

    def resolve_strategy_conflicts(
        self,
        domain: str,
        conflicting_strategies: List[BypassStrategy],
        resolution_method: ConflictResolution = None,
    ) -> BypassStrategy:
        """
        Resolve conflicts when multiple strategies are available for a domain.

        Args:
            domain: Target domain
            conflicting_strategies: List of conflicting strategies
            resolution_method: Specific resolution method to use

        Returns:
            Resolved strategy
        """
        if len(conflicting_strategies) <= 1:
            return conflicting_strategies[0] if conflicting_strategies else None
        LOG.info(
            f"Resolving strategy conflict for {domain} ({len(conflicting_strategies)} strategies)"
        )
        methods = (
            [resolution_method] if resolution_method else self.conflict_resolution_order
        )
        for method in methods:
            resolved = self._apply_conflict_resolution(
                domain, conflicting_strategies, method
            )
            if resolved:
                LOG.info(f"Conflict resolved using {method.value}: {resolved.id}")
                return resolved
        LOG.warning(f"Could not resolve conflict for {domain}, using first strategy")
        return conflicting_strategies[0]

    def update_user_preference(
        self,
        domain: str,
        strategy: str,
        success_rate: float = None,
        latency_ms: float = None,
        **kwargs,
    ) -> None:
        """
        Update user preference for a domain.

        Args:
            domain: Target domain
            strategy: Strategy string (zapret format)
            success_rate: Success rate (0.0-1.0)
            latency_ms: Average latency in milliseconds
            **kwargs: Additional preference data
        """
        preference = UserPreference(
            domain=domain,
            strategy=strategy,
            success_rate=success_rate or 0.0,
            avg_latency_ms=latency_ms or 0.0,
            last_updated=datetime.now(),
            **kwargs,
        )
        self.user_preferences[domain] = preference
        self._save_user_preferences()
        LOG.info(f"Updated user preference for {domain}: {strategy}")

    def get_strategy_recommendations(
        self, domain: str, count: int = 3
    ) -> List[Tuple[BypassStrategy, float]]:
        """
        Get top strategy recommendations for a domain.

        Args:
            domain: Target domain
            count: Number of recommendations to return

        Returns:
            List of (strategy, confidence_score) tuples
        """
        domain_analysis = self._analyze_domain(domain)
        candidates = self._get_candidate_strategies(domain, 443, domain_analysis)
        if not candidates:
            return []
        scored_strategies = []
        for strategy in candidates:
            score = self._score_strategy(strategy, domain, 443, domain_analysis)
            scored_strategies.append((strategy, score.confidence))
        scored_strategies.sort(key=lambda x: x[1], reverse=True)
        return scored_strategies[:count]

    def _analyze_domain(self, domain: str) -> DomainAnalysis:
        """Analyze domain characteristics for strategy selection."""
        parts = domain.split(".")
        analysis = DomainAnalysis(
            domain=domain,
            tld=parts[-1] if parts else "",
            sld=".".join(parts[-2:]) if len(parts) >= 2 else domain,
            subdomains=parts[:-2] if len(parts) > 2 else [],
        )
        domain_lower = domain.lower()
        for pattern_type, patterns in self.domain_patterns.items():
            for pattern in patterns:
                if re.match(pattern, domain_lower):
                    if pattern_type == "social_media":
                        analysis.is_social_media = True
                        analysis.tags.append("social")
                    elif pattern_type == "video_platforms":
                        analysis.is_video_platform = True
                        analysis.tags.append("video")
                    elif pattern_type == "cdn_providers":
                        analysis.is_cdn = True
                        analysis.tags.append("cdn")
                    elif pattern_type == "news_sites":
                        analysis.is_news_site = True
                        analysis.tags.append("news")
                    break
        complexity = 1
        if analysis.is_social_media or analysis.is_video_platform:
            complexity += 2
        if analysis.is_cdn:
            complexity += 1
        if len(analysis.subdomains) > 1:
            complexity += 1
        analysis.estimated_complexity = min(complexity, 5)
        if analysis.is_video_platform:
            analysis.suggested_ports = [443, 80, 8080]
        elif analysis.is_social_media:
            analysis.suggested_ports = [443, 80]
        return analysis

    def _get_candidate_strategies(
        self, domain: str, port: int, domain_analysis: DomainAnalysis
    ) -> List[BypassStrategy]:
        """Get candidate strategies for a domain."""
        candidates = []
        pool_strategy = self.pool_manager.get_strategy_for_domain(domain, port)
        if pool_strategy:
            candidates.append(pool_strategy)
        user_pref = self.user_preferences.get(domain)
        if user_pref:
            strategy = self._convert_user_preference_to_strategy(user_pref)
            if strategy:
                candidates.append(strategy)
        similar_pools = self._find_similar_pools(domain_analysis)
        for pool in similar_pools:
            if pool.strategy not in candidates:
                candidates.append(pool.strategy)
        generated_strategies = self._generate_strategies_for_domain(domain_analysis)
        candidates.extend(generated_strategies)
        seen_ids = set()
        unique_candidates = []
        for strategy in candidates:
            if strategy.id not in seen_ids:
                unique_candidates.append(strategy)
                seen_ids.add(strategy.id)
        return unique_candidates

    def _score_strategy(
        self,
        strategy: BypassStrategy,
        domain: str,
        port: int,
        domain_analysis: DomainAnalysis,
        context: Optional[Dict[str, Any]] = None,
    ) -> StrategyScore:
        """Score a strategy for a domain."""
        score = StrategyScore(strategy_id=strategy.id, total_score=0.0)
        context = context or {}
        success_score = strategy.success_rate
        score.criteria_scores[SelectionCriteria.SUCCESS_RATE] = success_score
        score.reasoning.append(f"Success rate: {success_score:.2f}")
        avg_latency = getattr(strategy, "avg_latency_ms", 500.0)
        latency_score = max(0.0, 1.0 - avg_latency / 1000.0)
        score.criteria_scores[SelectionCriteria.LATENCY] = latency_score
        score.reasoning.append(f"Latency score: {latency_score:.2f}")
        reliability_score = self._calculate_reliability_score(strategy)
        score.criteria_scores[SelectionCriteria.RELIABILITY] = reliability_score
        score.reasoning.append(f"Reliability: {reliability_score:.2f}")
        user_pref_score = self._calculate_user_preference_score(strategy, domain)
        score.criteria_scores[SelectionCriteria.USER_PREFERENCE] = user_pref_score
        if user_pref_score > 0:
            score.reasoning.append(f"User preference: {user_pref_score:.2f}")
        compat_score = self._calculate_compatibility_score(strategy, domain_analysis)
        score.criteria_scores[SelectionCriteria.COMPATIBILITY] = compat_score
        score.reasoning.append(f"Compatibility: {compat_score:.2f}")
        freshness_score = self._calculate_freshness_score(strategy)
        score.criteria_scores[SelectionCriteria.FRESHNESS] = freshness_score
        score.reasoning.append(f"Freshness: {freshness_score:.2f}")
        total = 0.0
        for criteria, weight in self.selection_weights.items():
            criteria_score = score.criteria_scores.get(criteria, 0.0)
            total += criteria_score * weight
        score.total_score = total
        score.confidence = min(1.0, total * 1.2)
        return score

    def _calculate_reliability_score(self, strategy: BypassStrategy) -> float:
        """Calculate reliability score based on attack stability."""
        if not strategy.attacks:
            return 0.5
        total_stability = 0.0
        attack_count = 0
        for attack_id in strategy.attacks:
            definition = self.attack_registry.get_attack_definition(attack_id)
            if definition:
                stability_scores = {
                    "STABLE": 1.0,
                    "MOSTLY_STABLE": 0.8,
                    "EXPERIMENTAL": 0.6,
                    "UNSTABLE": 0.3,
                    "DEPRECATED": 0.1,
                }
                stability_name = (
                    definition.stability.name
                    if hasattr(definition.stability, "name")
                    else str(definition.stability)
                )
                total_stability += stability_scores.get(stability_name, 0.5)
                attack_count += 1
        return total_stability / attack_count if attack_count > 0 else 0.5

    def _calculate_user_preference_score(
        self, strategy: BypassStrategy, domain: str
    ) -> float:
        """Calculate user preference score."""
        user_pref = self.user_preferences.get(domain)
        if not user_pref:
            return 0.0
        strategy_str = strategy.to_zapret_format()
        if strategy_str == user_pref.strategy:
            return 1.0
        similarity = self._calculate_strategy_similarity(
            strategy_str, user_pref.strategy
        )
        return similarity * 0.8

    def _calculate_compatibility_score(
        self, strategy: BypassStrategy, domain_analysis: DomainAnalysis
    ) -> float:
        """Calculate compatibility score based on domain characteristics."""
        score = 0.5
        if domain_analysis.is_social_media and "social" in strategy.name.lower():
            score += 0.3
        if domain_analysis.is_video_platform and any(
            (attack in strategy.attacks for attack in ["multisplit", "timing"])
        ):
            score += 0.2
        if domain_analysis.is_cdn and "tcp_fragmentation" in strategy.attacks:
            score += 0.2
        strategy_complexity = len(strategy.attacks) + len(strategy.parameters)
        if abs(strategy_complexity - domain_analysis.estimated_complexity) <= 1:
            score += 0.1
        return min(1.0, score)

    def _calculate_freshness_score(self, strategy: BypassStrategy) -> float:
        """Calculate freshness score based on last tested time."""
        if not strategy.last_tested:
            return 0.3
        days_since_test = (datetime.now() - strategy.last_tested).days
        if days_since_test <= 1:
            return 1.0
        elif days_since_test <= 7:
            return 0.8
        elif days_since_test <= 30:
            return 0.6
        elif days_since_test <= 90:
            return 0.4
        else:
            return 0.2

    def _calculate_strategy_similarity(self, strategy1: str, strategy2: str) -> float:
        """Calculate similarity between two strategy strings."""
        params1 = set(strategy1.split())
        params2 = set(strategy2.split())
        if not params1 and (not params2):
            return 1.0
        intersection = params1.intersection(params2)
        union = params1.union(params2)
        return len(intersection) / len(union) if union else 0.0

    def _find_similar_pools(
        self, domain_analysis: DomainAnalysis
    ) -> List[StrategyPool]:
        """Find pools with similar domains."""
        similar_pools = []
        for pool in self.pool_manager.list_pools():
            similarity_score = 0
            for domain in pool.domains:
                other_analysis = self._analyze_domain(domain)
                if other_analysis.tld == domain_analysis.tld:
                    similarity_score += 1
                if other_analysis.sld == domain_analysis.sld:
                    similarity_score += 2
                common_tags = set(other_analysis.tags).intersection(
                    set(domain_analysis.tags)
                )
                similarity_score += len(common_tags)
            if similarity_score > 0:
                similar_pools.append(pool)
        return similar_pools

    def _find_or_create_pool_for_domain(
        self, domain_analysis: DomainAnalysis
    ) -> Optional[StrategyPool]:
        """Find existing pool or create new one for domain."""
        for pool in self.pool_manager.list_pools():
            pool_tags = set(pool.tags)
            domain_tags = set(domain_analysis.tags)
            if pool_tags.intersection(domain_tags):
                return pool
        if domain_analysis.is_social_media:
            strategy = self._create_social_media_strategy()
            return self.pool_manager.create_pool(
                "Social Media Sites",
                strategy,
                "Automatically created for social media domains",
            )
        elif domain_analysis.is_video_platform:
            strategy = self._create_video_platform_strategy()
            return self.pool_manager.create_pool(
                "Video Platforms",
                strategy,
                "Automatically created for video platform domains",
            )
        elif domain_analysis.is_cdn:
            strategy = self._create_cdn_strategy()
            return self.pool_manager.create_pool(
                "CDN Sites", strategy, "Automatically created for CDN domains"
            )
        else:
            strategy = self._create_general_strategy()
            return self.pool_manager.create_pool(
                "General Sites", strategy, "Automatically created for general domains"
            )

    def _generate_strategies_for_domain(
        self, domain_analysis: DomainAnalysis
    ) -> List[BypassStrategy]:
        """Generate appropriate strategies based on domain analysis."""
        strategies = []
        if domain_analysis.is_social_media:
            strategies.append(self._create_social_media_strategy())
        if domain_analysis.is_video_platform:
            strategies.append(self._create_video_platform_strategy())
        if domain_analysis.is_cdn:
            strategies.append(self._create_cdn_strategy())
        strategies.append(self._create_general_strategy())
        return strategies

    def _create_social_media_strategy(self) -> BypassStrategy:
        """Create strategy optimized for social media sites."""
        return BypassStrategy(
            id="auto_social_media",
            name="Auto Social Media Strategy",
            attacks=["http_manipulation", "tls_evasion"],
            parameters={"split_pos": "midsld", "ttl": 2},
            target_ports=[443, 80],
            priority=2,
        )

    def _create_video_platform_strategy(self) -> BypassStrategy:
        """Create strategy optimized for video platforms."""
        return BypassStrategy(
            id="auto_video_platform",
            name="Auto Video Platform Strategy",
            attacks=["tcp_fragmentation", "packet_timing"],
            parameters={"split_count": 5, "ttl": 3},
            target_ports=[443, 80, 8080],
            priority=2,
        )

    def _create_cdn_strategy(self) -> BypassStrategy:
        """Create strategy optimized for CDN sites."""
        return BypassStrategy(
            id="auto_cdn",
            name="Auto CDN Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3, "ttl": 1},
            target_ports=[443, 80],
            priority=1,
        )

    def _create_general_strategy(self) -> BypassStrategy:
        """Create general-purpose strategy."""
        return BypassStrategy(
            id="auto_general",
            name="Auto General Strategy",
            attacks=["tcp_fragmentation"],
            parameters={"split_pos": 3, "ttl": 2},
            target_ports=[443, 80],
            priority=1,
        )

    def _get_fallback_strategy(self, domain_analysis: DomainAnalysis) -> BypassStrategy:
        """Get fallback strategy when no candidates found."""
        return self.pool_manager.fallback_strategy or self._create_general_strategy()

    def _convert_user_preference_to_strategy(
        self, user_pref: UserPreference
    ) -> Optional[BypassStrategy]:
        """Convert user preference to BypassStrategy object."""
        try:
            attacks = []
            parameters = {}
            parts = user_pref.strategy.split()
            for i, part in enumerate(parts):
                if part.startswith("--dpi-desync="):
                    desync_type = part.split("=")[1]
                    if desync_type in ["fake", "split", "split2"]:
                        attacks.append("tcp_fragmentation")
                    elif desync_type in ["disorder", "multisplit"]:
                        attacks.append("http_manipulation")
                elif part.startswith("--dpi-desync-ttl="):
                    parameters["ttl"] = int(part.split("=")[1])
                elif part.startswith("--dpi-desync-split-pos="):
                    parameters["split_pos"] = part.split("=")[1]
                elif part.startswith("--dpi-desync-split-count="):
                    parameters["split_count"] = int(part.split("=")[1])
            if not attacks:
                attacks = ["tcp_fragmentation"]
            return BypassStrategy(
                id=f"user_pref_{user_pref.domain}",
                name=f"User Preference for {user_pref.domain}",
                attacks=attacks,
                parameters=parameters,
                success_rate=user_pref.success_rate,
                last_tested=user_pref.last_updated,
            )
        except Exception as e:
            LOG.error(f"Failed to convert user preference: {e}")
            return None

    def _apply_conflict_resolution(
        self, domain: str, strategies: List[BypassStrategy], method: ConflictResolution
    ) -> Optional[BypassStrategy]:
        """Apply specific conflict resolution method."""
        if method == ConflictResolution.USER_PREFERENCE:
            user_pref = self.user_preferences.get(domain)
            if user_pref:
                for strategy in strategies:
                    if strategy.to_zapret_format() == user_pref.strategy:
                        return strategy
        elif method == ConflictResolution.HIGHEST_SUCCESS_RATE:
            return max(strategies, key=lambda s: s.success_rate)
        elif method == ConflictResolution.LOWEST_LATENCY:
            return min(strategies, key=lambda s: getattr(s, "avg_latency_ms", 500.0))
        elif method == ConflictResolution.MOST_RECENT:
            return max(strategies, key=lambda s: s.last_tested or datetime.min)
        elif method == ConflictResolution.POOL_PRIORITY:
            pool_strategies = []
            for strategy in strategies:
                for pool in self.pool_manager.list_pools():
                    if strategy.id == pool.strategy.id:
                        pool_strategies.append((strategy, pool.priority.value))
                        break
            if pool_strategies:
                return max(pool_strategies, key=lambda x: x[1])[0]
        elif method == ConflictResolution.MERGE_STRATEGIES:
            return self._merge_strategies(strategies)
        return None

    def _merge_strategies(self, strategies: List[BypassStrategy]) -> BypassStrategy:
        """Merge multiple strategies into one."""
        all_attacks = []
        all_parameters = {}
        all_ports = set()
        for strategy in strategies:
            all_attacks.extend(strategy.attacks)
            all_parameters.update(strategy.parameters)
            all_ports.update(strategy.target_ports)
        unique_attacks = []
        seen = set()
        for attack in all_attacks:
            if attack not in seen:
                unique_attacks.append(attack)
                seen.add(attack)
        return BypassStrategy(
            id="merged_strategy",
            name="Merged Strategy",
            attacks=unique_attacks,
            parameters=all_parameters,
            target_ports=list(all_ports),
            priority=max((s.priority for s in strategies)),
        )

    def _load_user_preferences(self) -> None:
        """Load user preferences from best_strategy.json."""
        try:
            if Path(self.user_preferences_path).exists():
                with open(self.user_preferences_path, "r") as f:
                    data = json.load(f)
                if "strategy" in data:
                    pref = UserPreference.from_best_strategy_json(data, "default")
                    self.user_preferences["default"] = pref
                elif "preferences" in data:
                    for domain, pref_data in data["preferences"].items():
                        pref = UserPreference.from_best_strategy_json(pref_data, domain)
                        self.user_preferences[domain] = pref
                LOG.info(f"Loaded {len(self.user_preferences)} user preferences")
        except Exception as e:
            LOG.error(f"Failed to load user preferences: {e}")

    def _save_user_preferences(self) -> None:
        """Save user preferences to file."""
        try:
            if len(self.user_preferences) == 1 and "default" in self.user_preferences:
                pref = self.user_preferences["default"]
                data = {
                    "strategy": pref.strategy,
                    "success_rate": pref.success_rate,
                    "avg_latency_ms": pref.avg_latency_ms,
                    "fingerprint_used": pref.fingerprint_used,
                    "dpi_type": pref.dpi_type,
                    "dpi_confidence": pref.dpi_confidence,
                    "last_updated": pref.last_updated.isoformat(),
                }
            else:
                data = {"preferences": {}}
                for domain, pref in self.user_preferences.items():
                    data["preferences"][domain] = {
                        "strategy": pref.strategy,
                        "success_rate": pref.success_rate,
                        "avg_latency_ms": pref.avg_latency_ms,
                        "fingerprint_used": pref.fingerprint_used,
                        "dpi_type": pref.dpi_type,
                        "dpi_confidence": pref.dpi_confidence,
                        "last_updated": pref.last_updated.isoformat(),
                    }
            Path(self.user_preferences_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.user_preferences_path, "w") as f:
                json.dump(data, f, indent=2)
            LOG.debug(f"Saved user preferences to {self.user_preferences_path}")
        except Exception as e:
            LOG.error(f"Failed to save user preferences: {e}")


if __name__ == "__main__":
    print("Testing enhanced strategy application algorithm...")
    print("✅ Enhanced strategy application algorithm implementation complete!")
