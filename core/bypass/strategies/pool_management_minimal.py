#!/usr/bin/env python3
"""
Minimal Strategy Pool Management System for testing
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class PoolPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class BypassStrategy:
    id: str
    name: str
    attacks: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_ports: List[int] = field(default_factory=lambda: [443])

    def to_zapret_format(self) -> str:
        params = []
        for attack in self.attacks:
            if attack == "tcp_fragmentation":
                params.append("--dpi-desync=fake")
        return " ".join(params)

    def to_native_format(self) -> Dict[str, Any]:
        return {
            "type": self.attacks[0] if self.attacks else "fakedisorder",
            "params": self.parameters.copy(),
            "no_fallbacks": True,
            "forced": True,
        }


@dataclass
class StrategyPool:
    id: str
    name: str
    description: str
    strategy: BypassStrategy
    domains: List[str] = field(default_factory=list)
    priority: PoolPriority = PoolPriority.NORMAL

    def add_domain(self, domain: str) -> None:
        if domain not in self.domains:
            self.domains.append(domain)

    def remove_domain(self, domain: str) -> bool:
        if domain in self.domains:
            self.domains.remove(domain)
            return True
        return False


class StrategyPoolManager:
    def __init__(self):
        self.pools: Dict[str, StrategyPool] = {}
        self.logger = logging.getLogger("StrategyPoolManager")

    def create_pool(
        self, name: str, strategy: BypassStrategy, description: str = ""
    ) -> StrategyPool:
        pool_id = name.lower().replace(" ", "_")
        counter = 1
        original_id = pool_id

        while pool_id in self.pools:
            pool_id = f"{original_id}_{counter}"
            counter += 1

        pool = StrategyPool(
            id=pool_id, name=name, description=description, strategy=strategy
        )

        self.pools[pool_id] = pool
        return pool

    def add_domain_to_pool(self, pool_id: str, domain: str) -> bool:
        pool = self.pools.get(pool_id)
        if not pool:
            return False

        pool.add_domain(domain)
        return True

    def get_strategy_for_domain(self, domain: str) -> Optional[BypassStrategy]:
        for pool in self.pools.values():
            if domain in pool.domains:
                return pool.strategy
        return None


# Test the classes
if __name__ == "__main__":
    print("Testing minimal pool management...")

    strategy = BypassStrategy(
        id="test", name="Test Strategy", attacks=["tcp_fragmentation"]
    )
    print(f"Created strategy: {strategy.name}")

    manager = StrategyPoolManager()
    pool = manager.create_pool("Test Pool", strategy)
    print(f"Created pool: {pool.name}")

    print("Minimal test passed!")
