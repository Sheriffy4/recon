"""
Comprehensive tests for Strategy Pool Management System
"""

import pytest
import tempfile
import os

# Add the parent directories to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.dirname(current_dir)
recon_dir = os.path.dirname(tests_dir)
sys.path.insert(0, recon_dir)

from core.bypass.strategies.pool_management import (
    StrategyPoolManager,
    StrategyPool,
    BypassStrategy,
    DomainRule,
    PoolPriority,
    analyze_domain_patterns,
    suggest_pool_strategies,
)


class TestBypassStrategy:
    """Test BypassStrategy functionality"""

    def test_strategy_creation(self):
        """Test basic strategy creation"""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation", "http_manipulation"],
            parameters={"split_pos": 3, "ttl": 2},
        )
        assert strategy.id == "test_strategy"
        assert strategy.name == "Test Strategy"
        assert len(strategy.attacks) == 2
        assert strategy.parameters["split_pos"] == 3
        assert strategy.target_ports == [443]

    def test_zapret_format_conversion(self):
        """Test conversion to zapret format"""
        strategy = BypassStrategy(
            id="zapret_test",
            name="Zapret Test",
            attacks=["tcp_fragmentation", "http_manipulation"],
            parameters={"split_pos": 5},
        )
        zapret_format = strategy.to_zapret_format()
        assert "--dpi-desync=fake" in zapret_format
        assert "--dpi-desync=split2" in zapret_format
        assert "--dpi-desync-split-pos=5" in zapret_format

    def test_goodbyedpi_format_conversion(self):
        """Test conversion to goodbyedpi format"""
        strategy = BypassStrategy(
            id="gdpi_test",
            name="GoodbyeDPI Test",
            attacks=["tcp_fragmentation", "tls_evasion"],
        )
        gdpi_format = strategy.to_goodbyedpi_format()
        assert "-f" in gdpi_format
        assert "-e" in gdpi_format

    def test_native_format_conversion(self):
        """Test conversion to native format"""
        strategy = BypassStrategy(
            id="native_test",
            name="Native Test",
            attacks=["multisplit"],
            parameters={"positions": [1, 3, 5]},
        )
        native_format = strategy.to_native_format()
        assert native_format["type"] == "multisplit"
        assert native_format["params"]["positions"] == [1, 3, 5]


class TestStrategyPool:
    """Test StrategyPool functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.strategy = BypassStrategy(
            id="test_strategy", name="Test Strategy", attacks=["tcp_fragmentation"]
        )
        self.pool = StrategyPool(
            id="test_pool",
            name="Test Pool",
            description="Test pool for unit tests",
            strategy=self.strategy,
        )

    def test_pool_creation(self):
        """Test basic pool creation"""
        assert self.pool.id == "test_pool"
        assert self.pool.name == "Test Pool"
        assert self.pool.strategy == self.strategy
        assert len(self.pool.domains) == 0
        assert self.pool.priority == PoolPriority.NORMAL

    def test_add_domain(self):
        """Test adding domains to pool"""
        self.pool.add_domain("example.com")
        assert "example.com" in self.pool.domains
        self.pool.add_domain("example.com")
        assert self.pool.domains.count("example.com") == 1

    def test_remove_domain(self):
        """Test removing domains from pool"""
        self.pool.add_domain("example.com")
        self.pool.add_domain("test.com")
        result = self.pool.remove_domain("example.com")
        assert result is True
        assert "example.com" not in self.pool.domains
        assert "test.com" in self.pool.domains
        result = self.pool.remove_domain("nonexistent.com")
        assert result is False

    def test_subdomain_strategy(self):
        """Test subdomain-specific strategies"""
        subdomain_strategy = BypassStrategy(
            id="subdomain_strategy",
            name="Subdomain Strategy",
            attacks=["http_manipulation"],
        )
        self.pool.set_subdomain_strategy("api.example.com", subdomain_strategy)
        assert "api.example.com" in self.pool.subdomains
        assert self.pool.subdomains["api.example.com"] == subdomain_strategy

    def test_port_strategy(self):
        """Test port-specific strategies"""
        port_strategy = BypassStrategy(
            id="port_strategy", name="Port Strategy", attacks=["tls_evasion"]
        )
        self.pool.set_port_strategy(80, port_strategy)
        assert 80 in self.pool.ports
        assert self.pool.ports[80] == port_strategy

    def test_get_strategy_for_domain(self):
        """Test strategy resolution for domains"""
        strategy = self.pool.get_strategy_for_domain("example.com")
        assert strategy == self.strategy
        subdomain_strategy = BypassStrategy(
            id="subdomain_strategy",
            name="Subdomain Strategy",
            attacks=["http_manipulation"],
        )
        self.pool.set_subdomain_strategy("api.example.com", subdomain_strategy)
        strategy = self.pool.get_strategy_for_domain("api.example.com")
        assert strategy == subdomain_strategy
        port_strategy = BypassStrategy(
            id="port_strategy", name="Port Strategy", attacks=["tls_evasion"]
        )
        self.pool.set_port_strategy(80, port_strategy)
        strategy = self.pool.get_strategy_for_domain("example.com", port=80)
        assert strategy == port_strategy


class TestDomainRule:
    """Test DomainRule functionality"""

    def test_rule_creation(self):
        """Test basic rule creation"""
        rule = DomainRule(
            pattern=".*\\.google\\.com$", pool_id="google_pool", priority=5
        )
        assert rule.pattern == ".*\\.google\\.com$"
        assert rule.pool_id == "google_pool"
        assert rule.priority == 5

    def test_rule_matching(self):
        """Test domain matching"""
        rule = DomainRule(
            pattern=".*\\.google\\.com$", pool_id="google_pool", priority=5
        )
        assert rule.matches("www.google.com") is True
        assert rule.matches("mail.google.com") is True
        assert rule.matches("google.com") is True
        assert rule.matches("example.com") is False
        assert rule.matches("google.org") is False

    def test_rule_with_conditions(self):
        """Test rule matching with additional conditions"""
        rule = DomainRule(
            pattern=".*\\.example\\.com$",
            pool_id="example_pool",
            priority=3,
            conditions={"port": 443, "protocol": "https"},
        )
        assert rule.matches("www.example.com", port=443, protocol="https") is True
        assert rule.matches("www.example.com", port=80, protocol="https") is False
        assert rule.matches("www.example.com", port=443, protocol="http") is False

    def test_invalid_regex(self):
        """Test handling of invalid regex patterns"""
        rule = DomainRule(pattern="[invalid regex", pool_id="test_pool", priority=1)
        assert rule.matches("example.com") is False


class TestStrategyPoolManager:
    """Test StrategyPoolManager functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.temp_config = tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json"
        )
        self.temp_config.close()
        self.manager = StrategyPoolManager(config_path=self.temp_config.name)
        self.test_strategy = BypassStrategy(
            id="test_strategy", name="Test Strategy", attacks=["tcp_fragmentation"]
        )

    def teardown_method(self):
        """Cleanup test fixtures"""
        if os.path.exists(self.temp_config.name):
            os.unlink(self.temp_config.name)

    def test_create_pool(self):
        """Test pool creation"""
        pool = self.manager.create_pool(
            "Test Pool", self.test_strategy, "Test description"
        )
        assert pool.name == "Test Pool"
        assert pool.strategy == self.test_strategy
        assert pool.description == "Test description"
        assert pool.id in self.manager.pools

    def test_unique_pool_ids(self):
        """Test that pool IDs are unique"""
        pool1 = self.manager.create_pool("Test Pool", self.test_strategy)
        pool2 = self.manager.create_pool("Test Pool", self.test_strategy)
        assert pool1.id != pool2.id
        assert pool1.id == "test_pool"
        assert pool2.id == "test_pool_1"

    def test_add_domain_to_pool(self):
        """Test adding domains to pools"""
        pool = self.manager.create_pool("Test Pool", self.test_strategy)
        result = self.manager.add_domain_to_pool(pool.id, "example.com")
        assert result is True
        assert "example.com" in pool.domains
        result = self.manager.add_domain_to_pool("nonexistent", "test.com")
        assert result is False

    def test_domain_moves_between_pools(self):
        """Test that domains move between pools correctly"""
        pool1 = self.manager.create_pool("Pool 1", self.test_strategy)
        pool2 = self.manager.create_pool("Pool 2", self.test_strategy)
        self.manager.add_domain_to_pool(pool1.id, "example.com")
        assert "example.com" in pool1.domains
        self.manager.add_domain_to_pool(pool2.id, "example.com")
        assert "example.com" not in pool1.domains
        assert "example.com" in pool2.domains

    def test_get_strategy_for_domain(self):
        """Test strategy resolution for domains"""
        pool = self.manager.create_pool("Test Pool", self.test_strategy)
        self.manager.add_domain_to_pool(pool.id, "example.com")
        strategy = self.manager.get_strategy_for_domain("example.com")
        assert strategy == self.test_strategy
        strategy = self.manager.get_strategy_for_domain("unknown.com")
        assert strategy is None

    def test_auto_assignment_rules(self):
        """Test automatic domain assignment"""
        pool = self.manager.create_pool("Google Pool", self.test_strategy)
        self.manager.add_assignment_rule(".*\\.google\\.com$", pool.id, priority=5)
        assigned_pool_id = self.manager.auto_assign_domain("www.google.com")
        assert assigned_pool_id == pool.id
        assert "www.google.com" in pool.domains

    def test_rule_priority(self):
        """Test rule priority handling"""
        pool1 = self.manager.create_pool("Pool 1", self.test_strategy)
        pool2 = self.manager.create_pool("Pool 2", self.test_strategy)
        self.manager.add_assignment_rule(".*\\.example\\.com$", pool1.id, priority=1)
        self.manager.add_assignment_rule(".*\\.example\\.com$", pool2.id, priority=5)
        assigned_pool_id = self.manager.auto_assign_domain("www.example.com")
        assert assigned_pool_id == pool2.id

    def test_default_pool(self):
        """Test default pool functionality"""
        pool = self.manager.create_pool("Default Pool", self.test_strategy)
        self.manager.set_default_pool(pool.id)
        assigned_pool_id = self.manager.auto_assign_domain("unknown.com")
        assert assigned_pool_id == pool.id
        assert "unknown.com" in pool.domains

    def test_fallback_strategy(self):
        """Test fallback strategy"""
        fallback_strategy = BypassStrategy(
            id="fallback", name="Fallback Strategy", attacks=["http_manipulation"]
        )
        self.manager.set_fallback_strategy(fallback_strategy)
        strategy = self.manager.get_strategy_for_domain("unknown.com")
        assert strategy == fallback_strategy

    def test_merge_pools(self):
        """Test pool merging"""
        pool1 = self.manager.create_pool("Pool 1", self.test_strategy)
        pool2 = self.manager.create_pool("Pool 2", self.test_strategy)
        self.manager.add_domain_to_pool(pool1.id, "example1.com")
        self.manager.add_domain_to_pool(pool2.id, "example2.com")
        pool1.tags = ["tag1", "tag2"]
        pool2.tags = ["tag2", "tag3"]
        new_strategy = BypassStrategy(
            id="merged_strategy", name="Merged Strategy", attacks=["tls_evasion"]
        )
        merged_pool = self.manager.merge_pools(
            [pool1.id, pool2.id], "Merged Pool", new_strategy
        )
        assert merged_pool is not None
        assert "example1.com" in merged_pool.domains
        assert "example2.com" in merged_pool.domains
        assert set(merged_pool.tags) == {"tag1", "tag2", "tag3"}
        assert pool1.id not in self.manager.pools
        assert pool2.id not in self.manager.pools

    def test_split_pool(self):
        """Test pool splitting"""
        pool = self.manager.create_pool("Original Pool", self.test_strategy)
        domains = ["google.com", "youtube.com", "facebook.com", "twitter.com"]
        for domain in domains:
            self.manager.add_domain_to_pool(pool.id, domain)
        domain_groups = {
            "google": ["google.com", "youtube.com"],
            "social": ["facebook.com", "twitter.com"],
        }
        strategies = {
            "google": BypassStrategy(
                id="google_strategy",
                name="Google Strategy",
                attacks=["tcp_fragmentation"],
            ),
            "social": BypassStrategy(
                id="social_strategy",
                name="Social Strategy",
                attacks=["http_manipulation"],
            ),
        }
        new_pools = self.manager.split_pool(pool.id, domain_groups, strategies)
        assert len(new_pools) == 2
        assert pool.id not in self.manager.pools
        google_pool = next((p for p in new_pools if "google" in p.name))
        social_pool = next((p for p in new_pools if "social" in p.name))
        assert "google.com" in google_pool.domains
        assert "youtube.com" in google_pool.domains
        assert "facebook.com" in social_pool.domains
        assert "twitter.com" in social_pool.domains

    def test_pool_statistics(self):
        """Test pool statistics generation"""
        pool1 = self.manager.create_pool("Pool 1", self.test_strategy)
        pool1.priority = PoolPriority.HIGH
        pool2 = self.manager.create_pool("Pool 2", self.test_strategy)
        pool2.priority = PoolPriority.LOW
        self.manager.add_domain_to_pool(pool1.id, "example1.com")
        self.manager.add_domain_to_pool(pool1.id, "example2.com")
        self.manager.add_domain_to_pool(pool2.id, "example3.com")
        stats = self.manager.get_pool_statistics()
        assert stats["total_pools"] == 2
        assert stats["total_domains"] == 3
        assert stats["pools_by_priority"]["HIGH"] == 1
        assert stats["pools_by_priority"]["LOW"] == 1
        assert stats["domains_per_pool"]["Pool 1"] == 2
        assert stats["domains_per_pool"]["Pool 2"] == 1

    def test_configuration_save_load(self):
        """Test configuration persistence"""
        pool = self.manager.create_pool(
            "Test Pool", self.test_strategy, "Test description"
        )
        self.manager.add_domain_to_pool(pool.id, "example.com")
        self.manager.add_assignment_rule(".*\\.test\\.com$", pool.id, priority=3)
        self.manager.set_default_pool(pool.id)
        fallback_strategy = BypassStrategy(
            id="fallback", name="Fallback Strategy", attacks=["http_manipulation"]
        )
        self.manager.set_fallback_strategy(fallback_strategy)
        result = self.manager.save_configuration()
        assert result is True
        new_manager = StrategyPoolManager(config_path=self.temp_config.name)
        assert len(new_manager.pools) == 1
        loaded_pool = list(new_manager.pools.values())[0]
        assert loaded_pool.name == "Test Pool"
        assert "example.com" in loaded_pool.domains
        assert len(new_manager.assignment_rules) == 1
        assert new_manager.assignment_rules[0].pattern == ".*\\.test\\.com$"
        assert new_manager.default_pool_id == pool.id
        assert new_manager.fallback_strategy.name == "Fallback Strategy"


class TestUtilityFunctions:
    """Test utility functions"""

    def test_analyze_domain_patterns(self):
        """Test domain pattern analysis"""
        domains = [
            "www.google.com",
            "mail.google.com",
            "youtube.com",
            "www.facebook.com",
            "api.facebook.com",
            "example.org",
        ]
        patterns = analyze_domain_patterns(domains)
        assert "tld_com" in patterns
        assert "tld_org" in patterns
        assert "sld_google.com" in patterns
        assert "sld_facebook.com" in patterns
        assert len(patterns["tld_com"]) == 5
        assert len(patterns["sld_google.com"]) == 2
        assert len(patterns["sld_facebook.com"]) == 2

    def test_suggest_pool_strategies(self):
        """Test strategy suggestions"""
        domains = ["youtube.com", "twitter.com", "cloudflare.com", "example.com"]
        suggestions = suggest_pool_strategies(domains)
        assert len(suggestions) == 4
        youtube_strategy = suggestions["youtube.com"]
        assert "http_manipulation" in youtube_strategy.attacks
        assert "tls_evasion" in youtube_strategy.attacks
        cloudflare_strategy = suggestions["cloudflare.com"]
        assert "tcp_fragmentation" in cloudflare_strategy.attacks
        assert "packet_timing" in cloudflare_strategy.attacks
        example_strategy = suggestions["example.com"]
        assert "tcp_fragmentation" in example_strategy.attacks


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
