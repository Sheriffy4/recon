"""
Property-based tests for domain rules isolation.

Feature: auto-strategy-discovery
Tests that adaptive_knowledge.json operations never modify domain_rules.json.
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume, HealthCheck
import hashlib

from core.adaptive_knowledge import AdaptiveKnowledgeBase, StrategyRecord
from core.connection_metrics import ConnectionMetrics, BlockType


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_domain(draw):
    """Generate valid domain names."""
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


@st.composite
def valid_connection_metrics_for_failure(draw):
    """Generate ConnectionMetrics that indicate failure."""
    connect_time_ms = draw(st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False))
    
    # Choose one failure indicator
    failure_type = draw(st.sampled_from(['timeout', 'rst']))
    
    if failure_type == 'timeout':
        timeout = True
        rst_received = False
        rst_timing_ms = None
        block_type = BlockType.PASSIVE_DROP
    else:  # rst
        timeout = False
        rst_received = True
        rst_timing_ms = draw(st.floats(min_value=0.0, max_value=99.9, allow_nan=False, allow_infinity=False))
        block_type = BlockType.ACTIVE_RST
    
    return ConnectionMetrics(
        connect_time_ms=connect_time_ms,
        tls_time_ms=0.0,
        ttfb_ms=0.0,
        total_time_ms=draw(st.floats(min_value=0.0, max_value=30000.0, allow_nan=False, allow_infinity=False)),
        http_status=None,
        bytes_received=0,
        tls_completed=False,
        timeout=timeout,
        rst_received=rst_received,
        rst_timing_ms=rst_timing_ms,
        block_type=block_type
    )


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    if not file_path.exists():
        return ""
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def create_sample_domain_rules(file_path: Path) -> None:
    """Create a sample domain_rules.json file."""
    sample_rules = {
        "version": "1.0",
        "last_updated": "2025-01-01T00:00:00",
        "domain_rules": {
            "example.com": {
                "type": "split",
                "attacks": ["split"],
                "params": {
                    "split_pos": 5,
                    "split_count": 2
                },
                "metadata": {
                    "source": "manual",
                    "discovered_at": "2025-01-01T00:00:00"
                }
            },
            "test.org": {
                "type": "fake",
                "attacks": ["fake"],
                "params": {
                    "ttl": 1,
                    "fooling": "badseq"
                },
                "metadata": {
                    "source": "manual",
                    "discovered_at": "2025-01-01T00:00:00"
                }
            }
        }
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(sample_rules, f, indent=2, ensure_ascii=False)


# ============================================================================
# Property Tests for Domain Rules Isolation (Property 4)
# ============================================================================

class TestDomainRulesIsolation:
    """
    **Feature: auto-strategy-discovery, Property 4: Domain rules isolation**
    **Validates: Requirements 4.2, 6.1**
    
    Property: For any strategy discovery execution without --update-rules flag,
    the content of domain_rules.json SHALL remain unchanged after execution completes.
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
        self.domain_rules_file = Path(self.temp_dir) / "domain_rules.json"
        
        # Create sample domain_rules.json
        create_sample_domain_rules(self.domain_rules_file)
    
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
    def test_record_success_does_not_modify_domain_rules(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_success does not modify domain_rules.json.
        
        For any successful strategy test, calling record_success() should
        NOT modify the domain_rules.json file.
        """
        # Compute hash before operation
        hash_before = compute_file_hash(self.domain_rules_file)
        
        # Create knowledge base and record success
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        # Compute hash after operation
        hash_after = compute_file_hash(self.domain_rules_file)
        
        # Verify domain_rules.json was not modified
        assert hash_before == hash_after, \
            "domain_rules.json should not be modified by record_success()"
        
        # Verify the file still exists and is readable
        assert self.domain_rules_file.exists(), "domain_rules.json should still exist"
        
        with open(self.domain_rules_file, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Verify structure is intact
        assert "domain_rules" in rules, "domain_rules.json structure should be intact"
        assert "example.com" in rules["domain_rules"], "Original domains should still exist"
        assert "test.org" in rules["domain_rules"], "Original domains should still exist"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_failure()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_record_failure_does_not_modify_domain_rules(
        self, domain, strategy_name, strategy_params, metrics
    ):
        """
        Test that record_failure does not modify domain_rules.json.
        
        For any failed strategy test, calling record_failure() should
        NOT modify the domain_rules.json file.
        """
        # Compute hash before operation
        hash_before = compute_file_hash(self.domain_rules_file)
        
        # Create knowledge base and record failure
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        kb.record_failure(domain, strategy_name, strategy_params, metrics)
        
        # Compute hash after operation
        hash_after = compute_file_hash(self.domain_rules_file)
        
        # Verify domain_rules.json was not modified
        assert hash_before == hash_after, \
            "domain_rules.json should not be modified by record_failure()"
    
    @given(
        domains=st.lists(valid_domain(), min_size=1, max_size=10, unique=True),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        metrics=valid_connection_metrics_for_success()
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_batch_operations_do_not_modify_domain_rules(
        self, domains, strategy_name, strategy_params, metrics
    ):
        """
        Test that batch operations do not modify domain_rules.json.
        
        For any batch of strategy tests (simulating batch mode),
        multiple record_success() calls should NOT modify domain_rules.json.
        """
        # Compute hash before operations
        hash_before = compute_file_hash(self.domain_rules_file)
        
        # Create knowledge base and record multiple successes
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        for domain in domains:
            kb.record_success(domain, strategy_name, strategy_params, metrics)
        
        # Compute hash after operations
        hash_after = compute_file_hash(self.domain_rules_file)
        
        # Verify domain_rules.json was not modified
        assert hash_before == hash_after, \
            "domain_rules.json should not be modified by batch operations"
        
        # Verify all domains were saved to adaptive_knowledge.json instead
        for domain in domains:
            strategies = kb.get_strategies_for_domain(domain)
            assert len(strategies) > 0, \
                f"Domain {domain} should be in adaptive_knowledge.json"
    
    @given(
        domain=valid_domain(),
        strategy_name=st.text(min_size=3, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz_'),
        strategy_params=valid_strategy_params(),
        success_metrics=valid_connection_metrics_for_success(),
        failure_metrics=valid_connection_metrics_for_failure()
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.too_slow])
    def test_mixed_operations_do_not_modify_domain_rules(
        self, domain, strategy_name, strategy_params, success_metrics, failure_metrics
    ):
        """
        Test that mixed success/failure operations do not modify domain_rules.json.
        
        For any combination of success and failure recordings,
        domain_rules.json should remain unchanged.
        """
        # Compute hash before operations
        hash_before = compute_file_hash(self.domain_rules_file)
        
        # Create knowledge base and record mixed results
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record some successes and failures
        kb.record_success(domain, strategy_name, strategy_params, success_metrics)
        kb.record_failure(domain, strategy_name, strategy_params, failure_metrics)
        kb.record_success(domain, strategy_name, strategy_params, success_metrics)
        
        # Compute hash after operations
        hash_after = compute_file_hash(self.domain_rules_file)
        
        # Verify domain_rules.json was not modified
        assert hash_before == hash_after, \
            "domain_rules.json should not be modified by mixed operations"
    
    def test_domain_rules_isolation_with_existing_domain(self):
        """
        Test that operations on domains in domain_rules.json don't modify it.
        
        Even when operating on domains that exist in domain_rules.json,
        the file should not be modified.
        """
        # Compute hash before operations
        hash_before = compute_file_hash(self.domain_rules_file)
        
        # Create knowledge base
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        # Record success for a domain that exists in domain_rules.json
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        kb.record_success("example.com", "new_strategy", {"split_pos": 10}, metrics)
        
        # Compute hash after operations
        hash_after = compute_file_hash(self.domain_rules_file)
        
        # Verify domain_rules.json was not modified
        assert hash_before == hash_after, \
            "domain_rules.json should not be modified even for existing domains"
        
        # Verify the new strategy is in adaptive_knowledge.json, not domain_rules.json
        strategies = kb.get_strategies_for_domain("example.com")
        assert len(strategies) > 0, "Strategy should be in adaptive_knowledge.json"
        
        # Verify domain_rules.json still has original data
        with open(self.domain_rules_file, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        original_params = rules["domain_rules"]["example.com"]["params"]
        assert original_params["split_pos"] == 5, \
            "Original domain_rules.json params should be unchanged"
    
    def test_knowledge_base_operations_create_separate_file(self):
        """
        Test that AdaptiveKnowledgeBase creates a separate file.
        
        AdaptiveKnowledgeBase should create adaptive_knowledge.json
        as a separate file from domain_rules.json.
        """
        # Initially, adaptive_knowledge.json should not exist
        assert not self.knowledge_file.exists(), \
            "adaptive_knowledge.json should not exist initially"
        
        # Create knowledge base and record success
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        kb.record_success("newdomain.com", "test_strategy", {"split_pos": 5}, metrics)
        
        # Now adaptive_knowledge.json should exist
        assert self.knowledge_file.exists(), \
            "adaptive_knowledge.json should be created"
        
        # Verify it's a different file
        assert self.knowledge_file != self.domain_rules_file, \
            "adaptive_knowledge.json should be separate from domain_rules.json"
        
        # Verify both files exist
        assert self.domain_rules_file.exists(), \
            "domain_rules.json should still exist"
        assert self.knowledge_file.exists(), \
            "adaptive_knowledge.json should exist"
        
        # Verify they have different content
        with open(self.domain_rules_file, 'r', encoding='utf-8') as f:
            rules_content = f.read()
        
        with open(self.knowledge_file, 'r', encoding='utf-8') as f:
            knowledge_content = f.read()
        
        assert rules_content != knowledge_content, \
            "Files should have different content"


# ============================================================================
# Additional Tests for File Integrity
# ============================================================================

class TestDomainRulesFileIntegrity:
    """
    Additional tests to ensure domain_rules.json file integrity.
    
    These tests verify that the file remains valid JSON and maintains
    its structure after AdaptiveKnowledgeBase operations.
    """
    
    def setup_method(self):
        """Create temporary directory for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.knowledge_file = Path(self.temp_dir) / "adaptive_knowledge.json"
        self.domain_rules_file = Path(self.temp_dir) / "domain_rules.json"
        
        # Create sample domain_rules.json
        create_sample_domain_rules(self.domain_rules_file)
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if hasattr(self, 'temp_dir') and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)
    
    @given(
        operations_count=st.integers(min_value=1, max_value=20)
    )
    @settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
    def test_domain_rules_remains_valid_json_after_operations(self, operations_count):
        """
        Test that domain_rules.json remains valid JSON after operations.
        
        After any number of AdaptiveKnowledgeBase operations,
        domain_rules.json should still be valid JSON.
        """
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        # Perform multiple operations
        for i in range(operations_count):
            kb.record_success(
                f"domain{i}.com",
                "test_strategy",
                {"split_pos": i + 1},
                metrics
            )
        
        # Verify domain_rules.json is still valid JSON
        try:
            with open(self.domain_rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            # Verify structure
            assert "domain_rules" in rules, "Should have domain_rules key"
            assert isinstance(rules["domain_rules"], dict), "domain_rules should be a dict"
        except json.JSONDecodeError as e:
            pytest.fail(f"domain_rules.json is not valid JSON after operations: {e}")
    
    def test_domain_rules_permissions_unchanged(self):
        """
        Test that domain_rules.json file permissions remain unchanged.
        
        AdaptiveKnowledgeBase operations should not modify file permissions
        of domain_rules.json.
        """
        # Get initial file stats
        initial_stat = self.domain_rules_file.stat()
        
        # Perform operations
        kb = AdaptiveKnowledgeBase(knowledge_file=self.knowledge_file)
        
        metrics = ConnectionMetrics(
            connect_time_ms=100.0,
            http_status=200,
            block_type=BlockType.NONE
        )
        
        kb.record_success("test.com", "strategy", {"split_pos": 5}, metrics)
        
        # Get final file stats
        final_stat = self.domain_rules_file.stat()
        
        # Verify permissions unchanged (mode includes permissions)
        assert initial_stat.st_mode == final_stat.st_mode, \
            "File permissions should remain unchanged"
