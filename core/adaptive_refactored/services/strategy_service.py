"""
Strategy Service implementation for the refactored Adaptive Engine.

This service handles all strategy-related operations including generation, caching, and management.
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from ..interfaces import IStrategyService, IStrategyGenerator, ICacheManager
from ..models import Strategy, DPIFingerprint, CacheType
from ..config import StrategyConfig


logger = logging.getLogger(__name__)


class StrategyService(IStrategyService):
    """
    Implementation of strategy service operations.

    Coordinates strategy generation, caching, and management
    by orchestrating the strategy generator and cache manager.
    """

    def __init__(
        self, generator: IStrategyGenerator, cache_manager: ICacheManager, config: StrategyConfig
    ):
        self.generator = generator
        self.cache_manager = cache_manager
        self.config = config
        self._total_generated = 0  # Track total strategies generated

        logger.info("Strategy service initialized")

    async def generate_strategies(self, fingerprint: DPIFingerprint) -> List[Strategy]:
        """Generate strategies based on DPI fingerprint."""
        try:
            logger.info(f"Generating strategies for domain: {fingerprint.domain}")

            # Check cache first
            cached_strategies = await self.get_cached_strategy(fingerprint.domain)
            if cached_strategies and self.config.enable_learning:
                logger.info(f"Found cached strategies for {fingerprint.domain}")
                return [cached_strategies]  # Return as list for consistency

            # Generate new strategies
            strategies = await self.generator.generate_strategies(
                fingerprint, self.config.max_strategies_per_domain
            )

            # Track total generated strategies
            self._total_generated += len(strategies)

            # Cache the best strategy if we have any
            if strategies:
                best_strategy = max(strategies, key=lambda s: s.confidence_score)
                await self.save_strategy(fingerprint.domain, best_strategy)

            logger.info(f"Generated {len(strategies)} strategies for {fingerprint.domain}")
            return strategies

        except Exception as e:
            logger.error(f"Failed to generate strategies for {fingerprint.domain}: {e}")
            return []

    async def get_cached_strategy(self, domain: str) -> Optional[Strategy]:
        """Retrieve cached strategy for domain."""
        try:
            cache_key = f"strategy_{domain}"
            cached_data = await self.cache_manager.get(cache_key, CacheType.STRATEGY)

            if cached_data:
                logger.debug(f"Retrieved cached strategy for {domain}")
                return cached_data

            return None

        except Exception as e:
            logger.error(f"Failed to retrieve cached strategy for {domain}: {e}")
            return None

    async def save_strategy(self, domain: str, strategy: Strategy) -> None:
        """Save strategy to cache."""
        try:
            cache_key = f"strategy_{domain}"
            ttl = self.config.strategy_ttl_hours * 3600

            await self.cache_manager.set(cache_key, strategy, CacheType.STRATEGY, ttl)
            logger.debug(f"Saved strategy {strategy.name} for {domain}")

        except Exception as e:
            logger.error(f"Failed to save strategy for {domain}: {e}")

    async def invalidate_strategy_cache(self, domain: str) -> None:
        """Invalidate cached strategy for domain."""
        try:
            cache_key = f"strategy_{domain}"
            await self.cache_manager.invalidate(cache_key, CacheType.STRATEGY)
            logger.debug(f"Invalidated strategy cache for {domain}")

        except Exception as e:
            logger.error(f"Failed to invalidate strategy cache for {domain}: {e}")

    async def get_strategy_recommendations(
        self, domain: str, fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Get strategy recommendations based on domain and fingerprint."""
        try:
            # First try cached strategies
            cached_strategy = await self.get_cached_strategy(domain)
            if cached_strategy:
                return [cached_strategy]

            # Generate new strategies if no cache
            strategies = await self.generate_strategies(fingerprint)

            # Filter and rank strategies
            filtered_strategies = self._filter_strategies(strategies, fingerprint)
            ranked_strategies = self._rank_strategies(filtered_strategies, fingerprint)

            return ranked_strategies[:5]  # Return top 5 recommendations

        except Exception as e:
            logger.error(f"Failed to get strategy recommendations for {domain}: {e}")
            return []

    def _filter_strategies(
        self, strategies: List[Strategy], fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Filter strategies based on fingerprint characteristics."""
        filtered = []

        for strategy in strategies:
            # Filter based on confidence threshold
            if strategy.confidence_score >= self.config.confidence_threshold:
                filtered.append(strategy)

        return filtered

    def _rank_strategies(
        self, strategies: List[Strategy], fingerprint: DPIFingerprint
    ) -> List[Strategy]:
        """Rank strategies based on various factors."""
        # Sort by confidence score (primary) and strategy diversity (secondary)
        return sorted(
            strategies, key=lambda s: (s.confidence_score, len(s.attack_combination)), reverse=True
        )

    async def update_strategy_success_rate(
        self, domain: str, strategy_name: str, success: bool
    ) -> None:
        """Update success rate for a strategy."""
        try:
            cached_strategy = await self.get_cached_strategy(domain)
            if cached_strategy and cached_strategy.name == strategy_name:
                # Update success rate using simple moving average
                current_rate = cached_strategy.success_rate
                new_rate = (current_rate + (1.0 if success else 0.0)) / 2.0
                cached_strategy.success_rate = new_rate

                # Save updated strategy
                await self.save_strategy(domain, cached_strategy)
                logger.debug(f"Updated success rate for {strategy_name}: {new_rate:.2f}")

        except Exception as e:
            logger.error(f"Failed to update strategy success rate: {e}")

    async def get_strategy_statistics(self) -> Dict[str, Any]:
        """Get statistics about cached strategies and strategy service operations."""
        try:
            cache_stats = self.cache_manager.get_cache_stats()
            strategy_cache_stats = cache_stats.get("strategy", {})

            return {
                "total_generated": self._total_generated,
                "cache_hits": strategy_cache_stats.get("hit_count", 0),
                "cache_misses": strategy_cache_stats.get("miss_count", 0),
                "cached_strategies": strategy_cache_stats.get("active_entries", 0),
                "cache_hit_rate": strategy_cache_stats.get("hit_rate", 0.0),
                "cache_utilization": strategy_cache_stats.get("utilization", 0.0),
                "generation_config": {
                    "max_strategies_per_domain": self.config.max_strategies_per_domain,
                    "confidence_threshold": self.config.confidence_threshold,
                    "strategy_ttl_hours": self.config.strategy_ttl_hours,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get strategy statistics: {e}")
            return {
                "total_generated": self._total_generated,
                "cache_hits": 0,
                "cache_misses": 0,
                "cached_strategies": 0,
                "cache_hit_rate": 0.0,
                "cache_utilization": 0.0,
                "generation_config": {},
            }

    async def cleanup_expired_strategies(self) -> int:
        """Clean up expired strategy cache entries."""
        try:
            # This would be handled by the cache manager's cleanup process
            # For now, just return 0 as placeholder
            return 0

        except Exception as e:
            logger.error(f"Failed to cleanup expired strategies: {e}")
            return 0
