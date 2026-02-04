"""Auto recovery system for connection failures."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List


class AutoRecoverySystem:
    """Система автоматического восстановления соединений."""

    def __init__(self, learning_cache=None):
        self.learning_cache = learning_cache
        self.recovery_attempts: Dict[str, int] = {}
        self.last_recovery_time: Dict[str, datetime] = {}
        self.logger = logging.getLogger(__name__)

    async def attempt_recovery(self, health, available_strategies: List[str]) -> bool:
        """Пытается восстановить соединение с сайтом.

        Args:
            health: ConnectionHealth instance
            available_strategies: List of strategy strings to try

        Returns:
            True if recovery successful, False otherwise
        """
        domain_key = f"{health.domain}:{health.port}"
        if domain_key in self.last_recovery_time:
            time_since_last = datetime.now() - self.last_recovery_time[domain_key]
            if time_since_last < timedelta(minutes=5):
                self.logger.debug(
                    f"Skipping recovery for {domain_key} - too soon since last attempt"
                )
                return False
        self.logger.info(f"🔄 Attempting recovery for {health.domain}")
        if self.learning_cache:
            optimized_strategies = self.learning_cache.get_smart_strategy_order(
                available_strategies, health.domain, health.ip
            )
        else:
            optimized_strategies = available_strategies
        for strategy in optimized_strategies[:3]:
            self.logger.info(f"  Trying strategy: {strategy}")
            # TODO SR8: Consider if strategy should be applied during testing
            # Currently strategy parameter is logged but not used in connection test
            success = await self._test_strategy_recovery(health, strategy)
            if success:
                self.logger.info(f"✅ Recovery successful with strategy: {strategy}")
                health.bypass_active = True
                health.current_strategy = strategy
                health.consecutive_failures = 0
                self.recovery_attempts[domain_key] = 0
                self.last_recovery_time[domain_key] = datetime.now()
                return True
        self.recovery_attempts[domain_key] = self.recovery_attempts.get(domain_key, 0) + 1
        self.last_recovery_time[domain_key] = datetime.now()
        self.logger.warning(
            f"❌ Recovery failed for {health.domain} after trying {len(optimized_strategies[:3])} strategies"
        )
        return False

    async def _test_strategy_recovery(self, health, strategy: str) -> bool:
        """Тестирует восстановление с конкретной стратегией.

        Note: Currently performs basic connectivity test without applying strategy.
        TODO SR8: Implement actual strategy application during recovery testing.

        Args:
            health: ConnectionHealth instance
            strategy: Strategy string (currently unused - see SR8)

        Returns:
            True if connection successful, False otherwise
        """
        await asyncio.sleep(0.5)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(health.domain, health.port), timeout=3.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
