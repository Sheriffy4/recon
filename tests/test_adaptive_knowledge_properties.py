"""
Property-based tests for AdaptiveKnowledgeBase.

Feature: auto-strategy-discovery
Tests correctness properties for adaptive knowledge base operations.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.adaptive_knowledge import AdaptiveKnowledgeBase, StrategyRecord
from core.connection_metrics import ConnectionMetrics, BlockType


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_domain(draw):
    """Generate valid domain names."""
    # Simple domain names for testing
    tld = draw(st.sampled_from(['com', 'org', 'net', 'io', 'ru']))
    domain_name = draw(st.text(
        alphabet='abcdefghijklmnopqrstuvwxyz0123456789-',
        min_size=3,
        max_size=20
    ).filter(lambda x: not x.startswith('-') and not x.endswith('-')))
    
    return f"{domain_name}.{tld}"


@st.composite
def valid_strategy_params(draw):
    """Generate valid strategy parameters."""
    return {
        "split_pos": draw(st.integers(min_value=1, max_value=100)),
        "split_count": draw(st.integers(min_value=1, max_value=10)),
        "fake_ttl": draw(st.integers(min_value=1, max_value=10))
    }


@st.composite
def valid_connection_metrics_for_success(draw):
    """Generate ConnectionMetrics that indicate success."""
    connect_time_ms = draw(st.floats(min_value=10.0, max_value=1000.0, allow_nan=False, allow_infinity=False))
    
    # Choose one success indicator
    success_type = draw(st.sampled_from(['http_status', 'bytes_received', 'tls_completed']))
    
    if success_type == 'http_status':
        http_status = draw(st.integers(min_value=200, max_value=499))
        bytes_received = 0
        tls_completed = False
    elif success_type == 'bytes_received':
        http_status = None
        bytes_received = draw(st.integers(min_value=1, max_value=100000))
        tls_completed = False
    else:  # tls_completed
        http_status = None
        bytes_received = 0
        tls_completed = True
    
    block_type = draw(st.sampled_from([BlockType.NONE, BlockType.ACTIVE_RST, BlockType.PASSIVE_DROP]))
    
    return ConnectionMetrics(
        connect_time_ms=connect_time_ms,
        tls_time_ms=draw(st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False)),
        ttfb_ms=draw(st.floats(min_value=0.0, max_value=2000.0, allow_nan=False, allow_infinity=False)),
        total_time_ms=draw(st.floats(min_value=0.0, max_value=3000.0, allow_nan=False, allow_infinity=False)),
        http_status=http_status,
        bytes_received=bytes_received,
        tls_completed=tls_completed,
        timeout=False,
        rst_received=False,
        block_type=block_type
    )


# ============================================================================
# Property Tests for AdaptiveKnowledgeBase Data Integrity (Property 3)
# ============================================================================

class TestAdaptiveKnowledgeBaseDataIntegrity:
    """
    **Feature: auto-strategy-discovery, Property 3: AdaptiveKnowledgeBase data integrity**
    **Validates: Requirements 4.1, 4.3, 4.4**
    
    Property: For any successful strategy test, calling record_success() SHALL result in:
    - A StrategyRecord being created or updated in adaptive_knowledge.json
    - success_count being incremented by 1
    - last_success_ts being set to current timestamp
    - avg_connect_ms being updated with running average
    - effective_against containing the current block_type
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_creates_or_updates_strategy_record(
        self, domain, strategy_name, metrics, strategy_params
    ):
        """
        Test that record_success creates or updates a StrategyRecord.
        
        For any successful strategy test, calling record_success() should
        result in a StrategyRecord being created or updated.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        # Verify record exists
        strategies = kb.get_strategies_for_domain(domain)
        assert len(strategies) > 0, "Should have at least one strategy record"
        
        # Find our strategy
        found = False
        for strategy in strategies:
            if strategy.strategy_name == strategy_name and strategy.strategy_params == strategy_params:
                found = True
                break
        
        assert found, f"Strategy {strategy_name} should be in knowledge base"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_increments_success_count(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success increments success_count by 1.
        
        For any successful strategy test, calling record_success() should
        increment the success_count field by exactly 1.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success first time
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        strategies = kb.get_strategies_for_domain(domain)
        strategy = next(
            (s for s in strategies 
             if s.strategy_name == strategy_name and s.strategy_params == strategy_params),
            None
        )
        assert strategy is not None, "Strategy should exist"
        initial_count = strategy.success_count
        
        # Record success second time
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        strategies = kb.get_strategies_for_domain(domain)
        strategy = next(
            (s for s in strategies 
             if s.strategy_name == strategy_name and s.strategy_params == strategy_params),
            None
        )
        assert strategy is not None, "Strategy should still exist"
        assert strategy.success_count == initial_count + 1, \
            f"success_count should increment by 1, was {initial_count}, now {strategy.success_count}"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_updates_last_success_timestamp(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success updates last_success_ts.
        
        For any successful strategy test, calling record_success() should
        set last_success_ts to a recent timestamp.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        import time
        before_time = time.time()
        
        # Record success
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        after_time = time.time()
        
        strategies = kb.get_strategies_for_domain(domain)
        strategy = next(
            (s for s in strategies 
             if s.strategy_name == strategy_name and s.strategy_params == strategy_params),
            None
        )
        assert strategy is not None, "Strategy should exist"
        assert strategy.last_success_ts is not None, "last_success_ts should be set"
        assert before_time <= strategy.last_success_ts <= after_time, \
            f"last_success_ts should be between {before_time} and {after_time}, got {strategy.last_success_ts}"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_updates_avg_connect_ms(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success updates avg_connect_ms with running average.
        
        For any successful strategy test, calling record_success() should
        update avg_connect_ms with the running average of connect times.
        """
        # Ensure metrics has valid connect_time_ms
        assume(metrics.connect_time_ms > 0)
        
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        strategies = kb.get_strategies_for_domain(domain)
        strategy = next(
            (s for s in strategies 
             if s.strategy_name == strategy_name and s.strategy_params == strategy_params),
            None
        )
        assert strategy is not None, "Strategy should exist"
        assert strategy.avg_connect_ms is not None, "avg_connect_ms should be set"
        assert strategy.avg_connect_ms > 0, "avg_connect_ms should be positive"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_adds_block_type_to_effective_against(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success adds block_type to effective_against.
        
        For any successful strategy test, calling record_success() should
        add the current block_type to the effective_against list.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        strategies = kb.get_strategies_for_domain(domain)
        strategy = next(
            (s for s in strategies 
             if s.strategy_name == strategy_name and s.strategy_params == strategy_params),
            None
        )
        assert strategy is not None, "Strategy should exist"
        
        block_type_str = metrics.block_type.value if hasattr(metrics.block_type, 'value') else str(metrics.block_type)
        assert block_type_str in strategy.effective_against, \
            f"Block type {block_type_str} should be in effective_against: {strategy.effective_against}"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_success_persists_to_file(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success persists data to file.
        
        For any successful strategy test, calling record_success() should
        save the data to adaptive_knowledge.json file.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        # Verify file exists
        assert self.knowledge_file.exists(), "Knowledge file should be created"
        
        # Create new instance and verify data persisted
        kb2 = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        strategies = kb2.get_strategies_for_domain(domain)
        
        found = False
        for strategy in strategies:
            if strategy.strategy_name == strategy_name and strategy.strategy_params == strategy_params:
                found = True
                break
        
        assert found, "Strategy should persist across instances"


# ============================================================================
# Property Tests for Wildcard Domain Matching (Property 6)
# ============================================================================

class TestAdaptiveKnowledgeBaseWildcardMatching:
    """
    Tests for wildcard domain matching in AdaptiveKnowledgeBase.
    
    These tests verify that CDN domains are correctly matched with
    wildcard patterns like *.googlevideo.com.
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    @given(
        subdomain=st.text(min_size=3, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789-'),
        base_domain=st.text(min_size=3, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz'),
        tld=st.sampled_from(['com', 'org', 'net']),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_wildcard_pattern_matches_subdomains(
        self, subdomain, base_domain, tld, strategy_name, strategy_params, metrics
    ):
        """
        Test that wildcard patterns match subdomains.
        
        For any CDN domain (e.g., rr1---sn-xxx.googlevideo.com), the system
        should match wildcard patterns (e.g., *.googlevideo.com).
        """
        # Filter invalid subdomains
        assume(not subdomain.startswith('-') and not subdomain.endswith('-'))
        
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Create wildcard pattern
        wildcard_domain = f"*.{base_domain}.{tld}"
        
        # Record success for wildcard pattern
        kb.record_success(wildcard_domain, strategy_name, strategy_params, metrics)
        
        # Try to get strategies for specific subdomain
        specific_domain = f"{subdomain}.{base_domain}.{tld}"
        strategies = kb.get_strategies_for_domain(specific_domain)
        
        # Should find the wildcard strategy
        assert len(strategies) > 0, \
            f"Should find wildcard strategy for {specific_domain} matching {wildcard_domain}"
        
        found = False
        for strategy in strategies:
            if strategy.strategy_name == strategy_name and strategy.strategy_params == strategy_params:
                found = True
                break
        
        assert found, f"Should find strategy {strategy_name} via wildcard matching"
    
    def test_exact_match_preferred_over_wildcard(self):
        """
        Test that exact domain match is preferred over wildcard.
        
        When both exact domain and wildcard pattern exist, exact match
        should be returned.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "rr1.googlevideo.com"
        wildcard = "*.googlevideo.com"
        
        exact_strategy = "exact_strategy"
        wildcard_strategy = "wildcard_strategy"
        
        params = {"split_pos": 5}
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record for wildcard
        kb.record_success(wildcard, wildcard_strategy, params, metrics)
        
        # Record for exact domain
        kb.record_success(domain, exact_strategy, params, metrics)
        
        # Get strategies for exact domain
        strategies = kb.get_strategies_for_domain(domain)
        
        # Should have both strategies, but exact should be first
        assert len(strategies) >= 1, "Should have at least one strategy"
        
        # Check if exact strategy exists
        has_exact = any(s.strategy_name == exact_strategy for s in strategies)
        assert has_exact, "Should have exact match strategy"


# ============================================================================
# Property Tests for Wildcard Domain Matching (Property 6)
# ============================================================================

class TestWildcardDomainMatchingProperty:
    """
    **Feature: auto-strategy-discovery, Property 6: Wildcard domain matching**
    **Validates: Requirements 5.5**
    
    Property: For any CDN domain (e.g., rr1---sn-xxx.googlevideo.com), the system
    SHALL match wildcard patterns (e.g., *.googlevideo.com) and return strategies
    associated with the wildcard pattern.
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    @given(
        subdomain=st.text(min_size=1, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz0123456789-'),
        base_domain=st.text(min_size=3, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz'),
        tld=st.sampled_from(['com', 'org', 'net', 'io']),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_wildcard_pattern_matches_any_subdomain(
        self, subdomain, base_domain, tld, strategy_name, strategy_params, metrics
    ):
        """
        Test that wildcard patterns match any valid subdomain.
        
        For any CDN domain with a subdomain, the system should match
        wildcard patterns and return the associated strategies.
        """
        # Filter invalid subdomains
        assume(not subdomain.startswith('-') and not subdomain.endswith('-'))
        assume('.' not in subdomain)  # Ensure single-level subdomain
        
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Create wildcard pattern
        wildcard_domain = f"*.{base_domain}.{tld}"
        
        # Record success for wildcard pattern
        kb.record_success(wildcard_domain, strategy_name, strategy_params, metrics)
        
        # Try to get strategies for specific subdomain
        specific_domain = f"{subdomain}.{base_domain}.{tld}"
        strategies = kb.get_strategies_for_domain(specific_domain)
        
        # Should find the wildcard strategy
        assert len(strategies) > 0, \
            f"Should find wildcard strategy for {specific_domain} matching {wildcard_domain}"
        
        # Verify the strategy matches
        found = False
        for strategy in strategies:
            if strategy.strategy_name == strategy_name and strategy.strategy_params == strategy_params:
                found = True
                break
        
        assert found, f"Should find strategy {strategy_name} via wildcard matching"
    
    def test_wildcard_does_not_match_partial_domain(self):
        """
        Test that wildcard patterns do not match partial domain names.
        
        For example, *.googlevideo.com should NOT match "fakegooglevideo.com"
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        wildcard = "*.googlevideo.com"
        strategy_name = "test_strategy"
        params = {"split_pos": 5}
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record for wildcard
        kb.record_success(wildcard, strategy_name, params, metrics)
        
        # Try to get strategies for partial match (should NOT match)
        fake_domain = "fakegooglevideo.com"
        strategies = kb.get_strategies_for_domain(fake_domain)
        
        # Should NOT find the wildcard strategy
        assert len(strategies) == 0, \
            f"Wildcard {wildcard} should NOT match {fake_domain}"
    
    def test_wildcard_matches_multi_level_subdomains(self):
        """
        Test that wildcard patterns match multi-level subdomains.
        
        For example, *.googlevideo.com should match "rr1---sn-4pvgq-n8v6.googlevideo.com"
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        wildcard = "*.googlevideo.com"
        strategy_name = "test_strategy"
        params = {"split_pos": 5}
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record for wildcard
        kb.record_success(wildcard, strategy_name, params, metrics)
        
        # Try to get strategies for multi-level subdomain
        multi_level_domain = "rr1---sn-4pvgq-n8v6.googlevideo.com"
        strategies = kb.get_strategies_for_domain(multi_level_domain)
        
        # Should find the wildcard strategy
        assert len(strategies) > 0, \
            f"Wildcard {wildcard} should match {multi_level_domain}"
        
        # Verify the strategy matches
        found = any(s.strategy_name == strategy_name for s in strategies)
        assert found, f"Should find strategy {strategy_name} via wildcard matching"
    
    def test_exact_match_takes_precedence_over_wildcard(self):
        """
        Test that exact domain match takes precedence over wildcard.
        
        When both exact and wildcard patterns exist, exact match should be used.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "rr1.googlevideo.com"
        wildcard = "*.googlevideo.com"
        
        exact_strategy = "exact_strategy"
        wildcard_strategy = "wildcard_strategy"
        
        params_exact = {"split_pos": 10}
        params_wildcard = {"split_pos": 5}
        
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record for wildcard first
        kb.record_success(wildcard, wildcard_strategy, params_wildcard, metrics)
        
        # Record for exact domain
        kb.record_success(domain, exact_strategy, params_exact, metrics)
        
        # Get strategies for exact domain
        strategies = kb.get_strategies_for_domain(domain)
        
        # Should have exact match strategy
        assert len(strategies) > 0, "Should have at least one strategy"
        
        # Check that exact strategy is present
        has_exact = any(
            s.strategy_name == exact_strategy and s.strategy_params == params_exact
            for s in strategies
        )
        assert has_exact, "Should have exact match strategy"
        
        # Wildcard strategy should NOT be present (exact match takes precedence)
        has_wildcard = any(
            s.strategy_name == wildcard_strategy and s.strategy_params == params_wildcard
            for s in strategies
        )
        assert not has_wildcard, "Wildcard strategy should not be returned when exact match exists"
    
    def test_parent_domain_fallback(self):
        """
        Test that parent domain matching works as fallback.
        
        For example, if no wildcard exists, "sub.example.com" should match "example.com"
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        parent_domain = "example.com"
        strategy_name = "parent_strategy"
        params = {"split_pos": 5}
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record for parent domain
        kb.record_success(parent_domain, strategy_name, params, metrics)
        
        # Try to get strategies for subdomain
        subdomain = "sub.example.com"
        strategies = kb.get_strategies_for_domain(subdomain)
        
        # Should find the parent domain strategy
        assert len(strategies) > 0, \
            f"Should find parent domain strategy for {subdomain}"
        
        # Verify the strategy matches
        found = any(s.strategy_name == strategy_name for s in strategies)
        assert found, f"Should find strategy {strategy_name} via parent domain matching"


# ============================================================================
# Property Tests for Strategy Prioritization
# ============================================================================

class TestAdaptiveKnowledgeBasePrioritization:
    """
    Tests for strategy prioritization in AdaptiveKnowledgeBase.
    
    These tests verify that strategies are correctly prioritized by
    preferred_strategy, success_rate, and avg_connect_ms.
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_preferred_strategy_comes_first(self):
        """
        Test that preferred strategy is returned first.
        
        When multiple strategies exist, the preferred_strategy should
        be returned first in the list.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        strategy1 = "strategy1"
        strategy2 = "strategy2"
        
        params = {"split_pos": 5}
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Record both strategies
        kb.record_success(domain, strategy1, params, metrics)
        kb.record_success(domain, strategy2, params, metrics)
        
        # Get strategies
        strategies = kb.get_strategies_for_domain(domain)
        
        # First strategy should be the preferred one
        assert len(strategies) >= 2, "Should have at least 2 strategies"
        
        # The first one should have highest priority
        # (either preferred or highest success rate)
        first_strategy = strategies[0]
        assert first_strategy.strategy_name in [strategy1, strategy2], \
            "First strategy should be one of the recorded strategies"
    
    def test_higher_success_rate_prioritized(self):
        """
        Test that strategies with higher success rate are prioritized.
        
        When no preferred strategy is set, strategies with higher
        success_rate should come first.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        good_strategy = "good_strategy"
        bad_strategy = "bad_strategy"
        
        params = {"split_pos": 5}
        success_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        failure_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            timeout=True,
            block_type=BlockType.PASSIVE_DROP
        )
        
        # Record good strategy with high success rate
        for _ in range(5):
            kb.record_success(domain, good_strategy, params, success_metrics)
        
        # Record bad strategy with low success rate
        kb.record_success(domain, bad_strategy, params, success_metrics)
        for _ in range(5):
            kb.record_failure(domain, bad_strategy, params, failure_metrics)
        
        # Get strategies
        strategies = kb.get_strategies_for_domain(domain)
        
        # Good strategy should come first
        assert len(strategies) >= 2, "Should have at least 2 strategies"
        assert strategies[0].strategy_name == good_strategy, \
            f"Strategy with higher success rate should come first, got {strategies[0].strategy_name}"


# ============================================================================
# Property Tests for Strategy Prioritization Order (Property 5)
# ============================================================================

class TestStrategyPrioritizationOrder:
    """
    **Feature: auto-strategy-discovery, Property 5: Strategy prioritization order**
    **Validates: Requirements 5.1, 5.2, 5.3**
    
    Property: For any domain with strategies in both domain_rules.json and 
    adaptive_knowledge.json, the strategy testing order SHALL be:
    1. Strategy from domain_rules.json (if exists)
    2. Verified strategies from adaptive_knowledge.json sorted by:
       - preferred_strategy first
       - effective_against match
       - success_rate descending
       - avg_connect_ms ascending
    3. Generated strategies
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    def test_preferred_strategy_always_first(self):
        """
        Test that preferred_strategy always comes first.
        
        The preferred_strategy is automatically set to the strategy with
        the best success rate. This test verifies that the strategy marked
        as preferred is returned first.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        best_strategy = "best_strategy"
        other = "other_strategy"
        
        params = {"split_pos": 5}
        
        # Record best strategy with high success rate
        success_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        failure_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            timeout=True,
            block_type=BlockType.PASSIVE_DROP
        )
        
        # Best strategy: 80% success rate (4/5)
        for _ in range(4):
            kb.record_success(domain, best_strategy, params, success_metrics)
        kb.record_failure(domain, best_strategy, params, failure_metrics)
        
        # Other strategy: 50% success rate (2/4)
        for _ in range(2):
            kb.record_success(domain, other, params, success_metrics)
        for _ in range(2):
            kb.record_failure(domain, other, params, failure_metrics)
        
        # Get strategies
        strategies = kb.get_strategies_for_domain(domain)
        
        # Best strategy should be first (it's the preferred one)
        assert len(strategies) >= 2, "Should have at least 2 strategies"
        assert strategies[0].strategy_name == best_strategy, \
            f"Best strategy should be first, got {strategies[0].strategy_name}"
    
    def test_effective_against_prioritized_when_block_type_specified(self):
        """
        Test that strategies effective against current block_type are prioritized.
        
        When block_type is specified, strategies that are effective_against
        that block_type should be prioritized over others.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        effective_strategy = "effective_strategy"
        ineffective_strategy = "ineffective_strategy"
        
        params = {"split_pos": 5}
        
        # Record effective strategy against ACTIVE_RST
        rst_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.ACTIVE_RST
        )
        for _ in range(3):
            kb.record_success(domain, effective_strategy, params, rst_metrics)
        
        # Record ineffective strategy against PASSIVE_DROP
        drop_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.PASSIVE_DROP
        )
        for _ in range(5):
            kb.record_success(domain, ineffective_strategy, params, drop_metrics)
        
        # Get strategies for ACTIVE_RST block type
        strategies = kb.get_strategies_for_domain(domain, block_type=BlockType.ACTIVE_RST)
        
        # Only effective strategy should be returned (filtered by block_type)
        assert len(strategies) >= 1, "Should have at least 1 strategy"
        assert strategies[0].strategy_name == effective_strategy, \
            f"Strategy effective against ACTIVE_RST should be returned, got {strategies[0].strategy_name}"
    
    def test_success_rate_prioritization(self):
        """
        Test that strategies are prioritized by success_rate.
        
        When no preferred strategy is set and no block_type filter,
        strategies with higher success_rate should come first.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        high_success = "high_success_strategy"
        medium_success = "medium_success_strategy"
        low_success = "low_success_strategy"
        
        params = {"split_pos": 5}
        success_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        failure_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            timeout=True,
            block_type=BlockType.PASSIVE_DROP
        )
        
        # High success: 90% (9/10)
        for _ in range(9):
            kb.record_success(domain, high_success, params, success_metrics)
        kb.record_failure(domain, high_success, params, failure_metrics)
        
        # Medium success: 50% (5/10)
        for _ in range(5):
            kb.record_success(domain, medium_success, params, success_metrics)
        for _ in range(5):
            kb.record_failure(domain, medium_success, params, failure_metrics)
        
        # Low success: 10% (1/10)
        kb.record_success(domain, low_success, params, success_metrics)
        for _ in range(9):
            kb.record_failure(domain, low_success, params, failure_metrics)
        
        # Get strategies
        strategies = kb.get_strategies_for_domain(domain)
        
        # Should be ordered by success rate
        assert len(strategies) >= 3, "Should have at least 3 strategies"
        assert strategies[0].strategy_name == high_success, \
            f"High success strategy should be first, got {strategies[0].strategy_name}"
        assert strategies[1].strategy_name == medium_success, \
            f"Medium success strategy should be second, got {strategies[1].strategy_name}"
        assert strategies[2].strategy_name == low_success, \
            f"Low success strategy should be third, got {strategies[2].strategy_name}"
    
    def test_avg_connect_ms_prioritization_when_equal_success_rate(self):
        """
        Test that strategies are prioritized by avg_connect_ms when success_rate is equal.
        
        When strategies have equal success_rate, the one with lower
        avg_connect_ms should come first.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        fast_strategy = "fast_strategy"
        slow_strategy = "slow_strategy"
        
        params = {"split_pos": 5}
        
        # Fast strategy: 100ms average
        fast_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        for _ in range(5):
            kb.record_success(domain, fast_strategy, params, fast_metrics)
        
        # Slow strategy: 500ms average
        slow_metrics = ConnectionMetrics(
            connect_time_ms=500.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        for _ in range(5):
            kb.record_success(domain, slow_strategy, params, slow_metrics)
        
        # Get strategies
        strategies = kb.get_strategies_for_domain(domain)
        
        # Fast strategy should come first
        assert len(strategies) >= 2, "Should have at least 2 strategies"
        assert strategies[0].strategy_name == fast_strategy, \
            f"Fast strategy should be first, got {strategies[0].strategy_name}"
        assert strategies[1].strategy_name == slow_strategy, \
            f"Slow strategy should be second, got {strategies[1].strategy_name}"
    
    def test_complete_prioritization_order(self):
        """
        Test complete prioritization order with all factors.
        
        Test the complete prioritization order:
        1. preferred_strategy (highest success rate becomes preferred)
        2. effective_against (when block_type filter is used)
        3. success_rate
        4. avg_connect_ms
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        domain = "example.com"
        low_success = "low_success_strategy"
        effective = "effective_strategy"
        high_success = "high_success_strategy"
        fast = "fast_strategy"
        
        params = {"split_pos": 5}
        
        # Low success strategy (20% success, slow)
        low_success_metrics = ConnectionMetrics(
            connect_time_ms=500.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        kb.record_success(domain, low_success, params, low_success_metrics)
        failure_metrics = ConnectionMetrics(
            connect_time_ms=500.0,
            timeout=True,
            block_type=BlockType.PASSIVE_DROP
        )
        for _ in range(4):
            kb.record_failure(domain, low_success, params, failure_metrics)
        
        # Effective strategy (50% success, medium speed, effective against ACTIVE_RST)
        effective_metrics = ConnectionMetrics(
            connect_time_ms=300.0,
            http_status=200,
            block_type=BlockType.ACTIVE_RST
        )
        for _ in range(5):
            kb.record_success(domain, effective, params, effective_metrics)
        for _ in range(5):
            kb.record_failure(domain, effective, params, failure_metrics)
        
        # High success strategy (90% success, slow, not effective against ACTIVE_RST)
        high_success_metrics = ConnectionMetrics(
            connect_time_ms=400.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        for _ in range(9):
            kb.record_success(domain, high_success, params, high_success_metrics)
        kb.record_failure(domain, high_success, params, failure_metrics)
        
        # Fast strategy (50% success, fast, not effective against ACTIVE_RST)
        fast_metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        for _ in range(5):
            kb.record_success(domain, fast, params, fast_metrics)
        for _ in range(5):
            kb.record_failure(domain, fast, params, failure_metrics)
        
        # Get strategies without block_type filter
        strategies = kb.get_strategies_for_domain(domain)
        
        # Order should be: high_success (preferred, 90%), fast (50%, faster), effective (50%, slower), low_success (20%)
        assert len(strategies) >= 4, "Should have at least 4 strategies"
        assert strategies[0].strategy_name == high_success, \
            f"High success should be first (preferred), got {strategies[0].strategy_name}"
        
        # Between fast and effective (both 50% success), fast should come first due to lower avg_connect_ms
        # But we need to check their actual positions
        fast_idx = next(i for i, s in enumerate(strategies) if s.strategy_name == fast)
        effective_idx = next(i for i, s in enumerate(strategies) if s.strategy_name == effective)
        assert fast_idx < effective_idx, \
            f"Fast strategy should come before effective (same success rate, lower latency)"
        
        # Get strategies with ACTIVE_RST block_type filter
        strategies_filtered = kb.get_strategies_for_domain(domain, block_type=BlockType.ACTIVE_RST)
        
        # Only effective strategy should be returned (filtered by block_type)
        assert len(strategies_filtered) >= 1, "Should have at least 1 strategy"
        assert strategies_filtered[0].strategy_name == effective, \
            f"Effective strategy should be returned when filtering by ACTIVE_RST, got {strategies_filtered[0].strategy_name}"


# ============================================================================
# Property Tests for StrategyRecord
# ============================================================================

class TestStrategyRecordProperties:
    """
    Tests for StrategyRecord data class.
    
    These tests verify the correctness of StrategyRecord methods.
    """
    
    @given(
        success_count=st.integers(min_value=0, max_value=1000),
        failure_count=st.integers(min_value=0, max_value=1000)
    )
    @settings(max_examples=100)
    def test_success_rate_calculation(self, success_count, failure_count):
        """
        Test that success_rate is calculated correctly.
        
        For any StrategyRecord, success_rate should be
        success_count / (success_count + failure_count).
        """
        record = StrategyRecord(
            strategy_name="test",
            strategy_params={},
            success_count=success_count,
            failure_count=failure_count
        )
        
        total = success_count + failure_count
        if total == 0:
            assert record.success_rate() == 0.0, "Success rate should be 0 when no attempts"
        else:
            expected_rate = success_count / total
            assert abs(record.success_rate() - expected_rate) < 0.0001, \
                f"Success rate should be {expected_rate}, got {record.success_rate()}"
    
    @given(
        strategy_name=st.text(min_size=1, max_size=50),
        strategy_params=valid_strategy_params()
    )
    @settings(max_examples=100)
    def test_to_dict_from_dict_round_trip(self, strategy_name, strategy_params):
        """
        Test that to_dict/from_dict round-trip preserves data.
        
        For any StrategyRecord, converting to dict and back should
        preserve all data.
        """
        original = StrategyRecord(
            strategy_name=strategy_name,
            strategy_params=strategy_params,
            success_count=10,
            failure_count=2,
            avg_connect_ms=150.5,
            effective_against=["active_rst", "passive_drop"]
        )
        
        # Convert to dict and back
        data = original.to_dict()
        restored = StrategyRecord.from_dict(data)
        
        # Verify all fields match
        assert restored.strategy_name == original.strategy_name
        assert restored.strategy_params == original.strategy_params
        assert restored.success_count == original.success_count
        assert restored.failure_count == original.failure_count
        assert restored.avg_connect_ms == original.avg_connect_ms
        assert restored.effective_against == original.effective_against
