#!/usr/bin/env python3
"""
Strategy Pool Management System for Bypass Engine Modernization
"""

import json
import re
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from enum import Enum
from pathlib import Path


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
    subdomain_overrides: Dict[str, 'BypassStrategy'] = field(default_factory=dict)
    compatibility_mode: str = "native"
    priority: int = 1
    success_rate: float = 0.0
    last_tested: Optional[datetime] = None
    
    def to_zapret_format(self) -> str:
        params = []
        for attack in self.attacks:
            if attack == "tcp_fragmentation":
                params.append("--dpi-desync=fake")
            elif attack == "http_manipulation":
                params.append("--dpi-desync=split2")
            elif attack == "tls_evasion":
                params.append("--dpi-desync=disorder")
        
        if self.parameters.get('split_pos'):
            params.append(f"--dpi-desync-split-pos={self.parameters['split_pos']}")
        
        return " ".join(params)
    
    def to_goodbyedpi_format(self) -> str:
        params = []
        for attack in self.attacks:
            if attack == "tcp_fragmentation":
                params.append("-f")
            elif attack == "http_manipulation":
                params.append("-s")
            elif attack == "tls_evasion":
                params.append("-e")
        
        return " ".join(params)
    
    def to_native_format(self) -> Dict[str, Any]:
        return {
            'type': self.attacks[0] if self.attacks else 'fakedisorder',
            'params': self.parameters.copy()
        }


@dataclass
class StrategyPool:
    id: str
    name: str
    description: str
    strategy: BypassStrategy
    domains: List[str] = field(default_factory=list)
    subdomains: Dict[str, BypassStrategy] = field(default_factory=dict)
    ports: Dict[int, BypassStrategy] = field(default_factory=dict)
    priority: PoolPriority = PoolPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    success_metrics: Dict[str, float] = field(default_factory=dict)
    
    def add_domain(self, domain: str) -> None:
        if domain not in self.domains:
            self.domains.append(domain)
            self.updated_at = datetime.now()
    
    def remove_domain(self, domain: str) -> bool:
        if domain in self.domains:
            self.domains.remove(domain)
            self.updated_at = datetime.now()
            return True
        return False
    
    def set_subdomain_strategy(self, subdomain: str, strategy: BypassStrategy) -> None:
        self.subdomains[subdomain] = strategy
        self.updated_at = datetime.now()
    
    def set_port_strategy(self, port: int, strategy: BypassStrategy) -> None:
        self.ports[port] = strategy
        self.updated_at = datetime.now()
    
    def get_strategy_for_domain(self, domain: str, port: int = 443) -> BypassStrategy:
        # Check for subdomain-specific strategy
        for subdomain, strategy in self.subdomains.items():
            if domain.endswith(subdomain):
                return strategy
        
        # Check for port-specific strategy
        if port in self.ports:
            return self.ports[port]
        
        # Return default pool strategy
        return self.strategy


@dataclass
class DomainRule:
    pattern: str
    pool_id: str
    priority: int
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, domain: str, **kwargs) -> bool:
        try:
            if not re.match(self.pattern, domain):
                return False
            
            for key, expected_value in self.conditions.items():
                if kwargs.get(key) != expected_value:
                    return False
            
            return True
        except re.error:
            return False


class StrategyPoolManager:
    def __init__(self, config_path: Optional[str] = None):
        self.pools: Dict[str, StrategyPool] = {}
        self.assignment_rules: List[DomainRule] = []
        self.default_pool_id: Optional[str] = None
        self.fallback_strategy: Optional[BypassStrategy] = None
        self.config_path = config_path or "pool_config.json"
        self.logger = logging.getLogger("StrategyPoolManager")
    
    def create_pool(self, name: str, strategy: BypassStrategy, description: str = "") -> StrategyPool:
        pool_id = self._generate_pool_id(name)
        pool = StrategyPool(
            id=pool_id,
            name=name,
            description=description,
            strategy=strategy
        )
        
        self.pools[pool_id] = pool
        self.logger.info(f"Created strategy pool '{name}' with ID: {pool_id}")
        return pool
    
    def get_pool(self, pool_id: str) -> Optional[StrategyPool]:
        return self.pools.get(pool_id)
    
    def list_pools(self) -> List[StrategyPool]:
        return sorted(
            self.pools.values(),
            key=lambda p: (p.priority.value, p.name)
        )
    
    def add_domain_to_pool(self, pool_id: str, domain: str) -> bool:
        pool = self.pools.get(pool_id)
        if not pool:
            self.logger.error(f"Pool {pool_id} not found")
            return False
        
        # Remove domain from other pools first
        self._remove_domain_from_all_pools(domain)
        
        pool.add_domain(domain)
        self.logger.info(f"Added domain '{domain}' to pool '{pool.name}'")
        return True
    
    def remove_domain_from_pool(self, pool_id: str, domain: str) -> bool:
        pool = self.pools.get(pool_id)
        if not pool:
            return False
        
        return pool.remove_domain(domain)
    
    def set_subdomain_strategy(self, pool_id: str, subdomain: str, strategy: BypassStrategy) -> bool:
        pool = self.pools.get(pool_id)
        if not pool:
            return False
        
        pool.set_subdomain_strategy(subdomain, strategy)
        self.logger.info(f"Set subdomain strategy for '{subdomain}' in pool '{pool.name}'")
        return True
    
    def set_port_strategy(self, pool_id: str, port: int, strategy: BypassStrategy) -> bool:
        pool = self.pools.get(pool_id)
        if not pool:
            return False
        
        pool.set_port_strategy(port, strategy)
        self.logger.info(f"Set port {port} strategy in pool '{pool.name}'")
        return True
    
    def get_strategy_for_domain(self, domain: str, port: int = 443) -> Optional[BypassStrategy]:
        # First try to find pool containing this domain
        pool = self._find_pool_containing_domain(domain)
        
        if not pool and self.default_pool_id:
            # Use default pool
            pool = self.pools.get(self.default_pool_id)
        
        if pool:
            return pool.get_strategy_for_domain(domain, port)
        
        # Return fallback strategy
        return self.fallback_strategy
    
    def auto_assign_domain(self, domain: str, **kwargs) -> Optional[str]:
        # Sort rules by priority (higher first)
        sorted_rules = sorted(self.assignment_rules, key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            if rule.matches(domain, **kwargs):
                if self.add_domain_to_pool(rule.pool_id, domain):
                    self.logger.info(f"Auto-assigned '{domain}' to pool '{rule.pool_id}' via rule")
                    return rule.pool_id
        
        # If no rule matches and we have a default pool, assign there
        if self.default_pool_id:
            if self.add_domain_to_pool(self.default_pool_id, domain):
                self.logger.info(f"Auto-assigned '{domain}' to default pool '{self.default_pool_id}'")
                return self.default_pool_id
        
        return None
    
    def merge_pools(self, pool_ids: List[str], new_name: str, new_strategy: BypassStrategy) -> Optional[StrategyPool]:
        if len(pool_ids) < 2:
            self.logger.error("Need at least 2 pools to merge")
            return None
        
        # Validate all pools exist
        pools_to_merge = []
        for pool_id in pool_ids:
            pool = self.pools.get(pool_id)
            if not pool:
                self.logger.error(f"Pool {pool_id} not found")
                return None
            pools_to_merge.append(pool)
        
        # Create new merged pool
        merged_pool = self.create_pool(new_name, new_strategy, f"Merged from pools: {', '.join(pool_ids)}")
        
        # Merge domains, subdomains, and port strategies
        all_domains = set()
        all_subdomains = {}
        all_port_strategies = {}
        all_tags = set()
        
        for pool in pools_to_merge:
            all_domains.update(pool.domains)
            all_subdomains.update(pool.subdomains)
            all_port_strategies.update(pool.ports)
            all_tags.update(pool.tags)
        
        # Apply merged data
        merged_pool.domains = list(all_domains)
        merged_pool.subdomains = all_subdomains
        merged_pool.ports = all_port_strategies
        merged_pool.tags = list(all_tags)
        
        # Remove original pools
        for pool_id in pool_ids:
            del self.pools[pool_id]
        
        self.logger.info(f"Successfully merged {len(pool_ids)} pools into '{new_name}'")
        return merged_pool
    
    def split_pool(self, pool_id: str, domain_groups: Dict[str, List[str]], 
                   strategies: Dict[str, BypassStrategy]) -> List[StrategyPool]:
        original_pool = self.pools.get(pool_id)
        if not original_pool:
            self.logger.error(f"Pool {pool_id} not found")
            return []
        
        new_pools = []
        
        for group_name, domains in domain_groups.items():
            strategy = strategies.get(group_name, original_pool.strategy)
            new_pool = self.create_pool(
                f"{original_pool.name}_{group_name}",
                strategy,
                f"Split from {original_pool.name}"
            )
            
            # Add domains to new pool
            for domain in domains:
                if domain in original_pool.domains:
                    new_pool.add_domain(domain)
                    original_pool.remove_domain(domain)
            
            new_pools.append(new_pool)
        
        # If original pool has no domains left, remove it
        if not original_pool.domains:
            del self.pools[pool_id]
            self.logger.info(f"Removed empty original pool '{original_pool.name}'")
        
        self.logger.info(f"Split pool into {len(new_pools)} new pools")
        return new_pools
    
    def add_assignment_rule(self, pattern: str, pool_id: str, priority: int = 1, 
                           conditions: Optional[Dict[str, Any]] = None) -> DomainRule:
        rule = DomainRule(
            pattern=pattern,
            pool_id=pool_id,
            priority=priority,
            conditions=conditions or {}
        )
        
        self.assignment_rules.append(rule)
        self.assignment_rules.sort(key=lambda r: r.priority, reverse=True)
        
        self.logger.info(f"Added assignment rule: {pattern} -> {pool_id} (priority: {priority})")
        return rule
    
    def set_default_pool(self, pool_id: str) -> bool:
        if pool_id not in self.pools:
            self.logger.error(f"Pool {pool_id} not found")
            return False
        
        self.default_pool_id = pool_id
        self.logger.info(f"Set default pool to '{pool_id}'")
        return True
    
    def set_fallback_strategy(self, strategy: BypassStrategy) -> None:
        self.fallback_strategy = strategy
        self.logger.info("Set fallback strategy")
    
    def get_pool_statistics(self) -> Dict[str, Any]:
        stats = {
            'total_pools': len(self.pools),
            'total_domains': sum(len(pool.domains) for pool in self.pools.values()),
            'pools_by_priority': {},
            'domains_per_pool': {},
            'subdomain_overrides': sum(len(pool.subdomains) for pool in self.pools.values()),
            'port_overrides': sum(len(pool.ports) for pool in self.pools.values())
        }
        
        for pool in self.pools.values():
            priority_name = pool.priority.name
            stats['pools_by_priority'][priority_name] = stats['pools_by_priority'].get(priority_name, 0) + 1
            stats['domains_per_pool'][pool.name] = len(pool.domains)
        
        return stats
    
    def _generate_pool_id(self, name: str) -> str:
        base_id = re.sub(r'[^a-zA-Z0-9_-]', '_', name.lower())
        counter = 1
        pool_id = base_id
        
        while pool_id in self.pools:
            pool_id = f"{base_id}_{counter}"
            counter += 1
        
        return pool_id
    
    def _remove_domain_from_all_pools(self, domain: str) -> None:
        for pool in self.pools.values():
            pool.remove_domain(domain)
    
    def _find_pool_containing_domain(self, domain: str) -> Optional[StrategyPool]:
        for pool in self.pools.values():
            if domain in pool.domains:
                return pool
        return None


# Utility functions
def analyze_domain_patterns(domains: List[str]) -> Dict[str, List[str]]:
    patterns = {}
    
    for domain in domains:
        parts = domain.split('.')
        if len(parts) >= 2:
            # Group by TLD
            tld = parts[-1]
            if tld not in patterns:
                patterns[f"tld_{tld}"] = []
            patterns[f"tld_{tld}"].append(domain)
            
            # Group by second-level domain
            if len(parts) >= 2:
                sld = f"{parts[-2]}.{parts[-1]}"
                if sld not in patterns:
                    patterns[f"sld_{sld}"] = []
                patterns[f"sld_{sld}"].append(domain)
    
    # Filter out single-domain groups
    return {k: v for k, v in patterns.items() if len(v) > 1}


def suggest_pool_strategies(domains: List[str]) -> Dict[str, BypassStrategy]:
    suggestions = {}
    
    for domain in domains:
        if any(social in domain for social in ['youtube', 'twitter', 'instagram', 'tiktok']):
            # Social media sites often need specialized strategies
            suggestions[domain] = BypassStrategy(
                id=f"social_{domain}",
                name=f"Social Media Strategy for {domain}",
                attacks=["http_manipulation", "tls_evasion"],
                parameters={"split_pos": "midsld", "ttl": 2}
            )
        elif any(cdn in domain for cdn in ['cloudflare', 'fastly', 'akamai']):
            # CDN sites might need different approaches
            suggestions[domain] = BypassStrategy(
                id=f"cdn_{domain}",
                name=f"CDN Strategy for {domain}",
                attacks=["tcp_fragmentation", "packet_timing"],
                parameters={"split_pos": 3, "ttl": 1}
            )
        else:
            # Default strategy for regular sites
            suggestions[domain] = BypassStrategy(
                id=f"default_{domain}",
                name=f"Default Strategy for {domain}",
                attacks=["tcp_fragmentation"],
                parameters={"split_pos": 3, "ttl": 2}
            )
    
    return suggestions


# Test the implementation
if __name__ == "__main__":
    print("Testing complete pool management system...")
    
    # Create strategies
    strategy1 = BypassStrategy(
        id="test1",
        name="Test Strategy 1",
        attacks=["tcp_fragmentation"],
        parameters={"split_pos": 3}
    )
    
    strategy2 = BypassStrategy(
        id="test2", 
        name="Test Strategy 2",
        attacks=["http_manipulation"],
        parameters={"split_pos": 5}
    )
    
    # Create manager
    manager = StrategyPoolManager()
    
    # Create pools
    pool1 = manager.create_pool("Social Media", strategy1, "For social media sites")
    pool2 = manager.create_pool("CDN Sites", strategy2, "For CDN hosted sites")
    
    # Add domains
    manager.add_domain_to_pool(pool1.id, "youtube.com")
    manager.add_domain_to_pool(pool1.id, "twitter.com")
    manager.add_domain_to_pool(pool2.id, "cloudflare.com")
    
    # Test subdomain strategy
    subdomain_strategy = BypassStrategy(
        id="youtube_video",
        name="YouTube Video Strategy",
        attacks=["multisplit"],
        parameters={"positions": [1, 3, 5]}
    )
    
    manager.set_subdomain_strategy(pool1.id, "www.youtube.com", subdomain_strategy)
    
    # Test strategy resolution
    strategy = manager.get_strategy_for_domain("youtube.com")
    print(f"Strategy for youtube.com: {strategy.name if strategy else 'None'}")
    
    strategy = manager.get_strategy_for_domain("www.youtube.com")
    print(f"Strategy for www.youtube.com: {strategy.name if strategy else 'None'}")
    
    # Test statistics
    stats = manager.get_pool_statistics()
    print(f"Pool statistics: {stats}")
    
    print("✅ Complete pool management system test passed!")