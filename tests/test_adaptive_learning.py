"""
Tests for the adaptive learning and caching system used in DPI bypass strategy optimization.
"""

import pytest
import pickle
import time
from pathlib import Path
from datetime import datetime

# Fix import for local cli.py
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
from cli import AdaptiveLearningCache, StrategyPerformanceRecord

# Test Data
TEST_STRATEGY = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
TEST_DOMAIN = "test.example.com"
TEST_IP = "192.168.1.1"
TEST_DPI_HASH = "abcd1234"


@pytest.fixture
def temp_cache_file(tmp_path):
    """Create temporary cache file for testing"""
    cache_file = tmp_path / "test_learning_cache.pkl"
    return str(cache_file)


@pytest.fixture
def learning_cache(temp_cache_file):
    """Create learning cache instance for testing"""
    return AdaptiveLearningCache(cache_file=temp_cache_file)


def test_strategy_performance_record_initialization():
    """Test StrategyPerformanceRecord initialization"""
    record = StrategyPerformanceRecord(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
        timestamp=datetime.now().isoformat(),
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    assert record.strategy == TEST_STRATEGY
    assert record.domain == TEST_DOMAIN
    assert record.ip == TEST_IP
    assert record.success_rate == 0.8
    assert record.avg_latency == 100.0
    assert record.test_count == 1
    assert record.dpi_fingerprint_hash == TEST_DPI_HASH


def test_strategy_performance_record_update():
    """Test StrategyPerformanceRecord performance update"""
    record = StrategyPerformanceRecord(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
        timestamp=datetime.now().isoformat(),
    )

    # Update with new performance metrics
    record.update_performance(success_rate=0.9, latency=90.0)

    # Check exponential smoothing (alpha=0.3)
    expected_success_rate = 0.3 * 0.9 + 0.7 * 0.8  # 0.83
    expected_latency = 0.3 * 90.0 + 0.7 * 100.0  # 97.0

    assert abs(record.success_rate - expected_success_rate) < 0.01
    assert abs(record.avg_latency - expected_latency) < 0.1
    assert record.test_count == 2


def test_learning_cache_initialization(learning_cache):
    """Test AdaptiveLearningCache initialization"""
    assert isinstance(learning_cache.cache_file, Path)
    assert learning_cache.strategy_records == {}
    assert learning_cache.domain_patterns == {}
    assert learning_cache.dpi_patterns == {}


def test_strategy_key_generation(learning_cache):
    """Test strategy key generation"""
    key = learning_cache._strategy_key(
        strategy=TEST_STRATEGY, domain=TEST_DOMAIN, ip=TEST_IP
    )

    assert isinstance(key, str)
    assert TEST_DOMAIN in key
    assert TEST_IP in key
    # Key should include MD5 hash of strategy
    assert len(key.split("_")[2]) == 8


def test_strategy_type_extraction(learning_cache):
    """Test strategy type extraction from full strategy string"""
    # Test fakedisorder strategy
    strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3"
    assert learning_cache._extract_strategy_type(strategy) == "fakedisorder"

    # Test multisplit strategy
    strategy = "--dpi-desync=multisplit --dpi-desync-split-count=3"
    assert learning_cache._extract_strategy_type(strategy) == "multisplit"

    # Test unknown strategy
    strategy = "--some-unknown-option"
    assert learning_cache._extract_strategy_type(strategy) == "unknown"


def test_record_strategy_performance(learning_cache):
    """Test recording strategy performance"""
    # Record initial performance
    learning_cache.record_strategy_performance(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    key = learning_cache._strategy_key(TEST_STRATEGY, TEST_DOMAIN, TEST_IP)
    assert key in learning_cache.strategy_records
    assert learning_cache.strategy_records[key].success_rate == 0.8

    # Record updated performance
    learning_cache.record_strategy_performance(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.9,
        avg_latency=90.0,
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    # Check exponential smoothing
    record = learning_cache.strategy_records[key]
    expected_success_rate = 0.3 * 0.9 + 0.7 * 0.8  # 0.83
    assert abs(record.success_rate - expected_success_rate) < 0.01
    assert record.test_count == 2


def test_domain_pattern_learning(learning_cache):
    """Test domain-specific pattern learning"""
    # Record performances for different strategies
    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=fake,fakeddisorder",
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
    )

    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=multisplit",
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.6,
        avg_latency=120.0,
    )

    assert TEST_DOMAIN in learning_cache.domain_patterns
    patterns = learning_cache.domain_patterns[TEST_DOMAIN]
    assert "fakedisorder" in patterns
    assert "multisplit" in patterns
    assert patterns["fakedisorder"] > patterns["multisplit"]


def test_dpi_pattern_learning(learning_cache):
    """Test DPI-specific pattern learning"""
    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=fake,fakeddisorder",
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    assert TEST_DPI_HASH in learning_cache.dpi_patterns
    patterns = learning_cache.dpi_patterns[TEST_DPI_HASH]
    assert "fakedisorder" in patterns
    assert abs(patterns["fakedisorder"] - 0.8) < 0.01


def test_get_strategy_prediction(learning_cache):
    """Test strategy success prediction"""
    # Record initial performance
    learning_cache.record_strategy_performance(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
    )

    # Get prediction for same strategy
    prediction = learning_cache.get_strategy_prediction(
        strategy=TEST_STRATEGY, domain=TEST_DOMAIN, ip=TEST_IP
    )

    assert isinstance(prediction, float)
    assert 0.0 <= prediction <= 1.0

    # Prediction should be adjusted by age
    time.sleep(0.1)  # Add small delay to test age adjustment
    aged_prediction = learning_cache.get_strategy_prediction(
        strategy=TEST_STRATEGY, domain=TEST_DOMAIN, ip=TEST_IP
    )
    assert aged_prediction <= prediction


def test_domain_recommendations(learning_cache):
    """Test domain-specific strategy recommendations"""
    # Record performances for different strategies
    strategies = [
        ("--dpi-desync=fake,fakeddisorder", 0.8),
        ("--dpi-desync=multisplit", 0.6),
        ("--dpi-desync=seqovl", 0.4),
    ]

    for strategy, success_rate in strategies:
        learning_cache.record_strategy_performance(
            strategy=strategy,
            domain=TEST_DOMAIN,
            ip=TEST_IP,
            success_rate=success_rate,
            avg_latency=100.0,
        )

    # Get top 2 recommendations
    recommendations = learning_cache.get_domain_recommendations(TEST_DOMAIN, top_n=2)

    assert len(recommendations) == 2
    assert recommendations[0][0] == "fakedisorder"  # Best performing strategy
    assert recommendations[1][0] == "multisplit"  # Second best
    assert (
        recommendations[0][1] > recommendations[1][1]
    )  # Success rates should be ordered


def test_dpi_recommendations(learning_cache):
    """Test DPI-specific strategy recommendations"""
    strategies = [
        ("--dpi-desync=fake,fakeddisorder", 0.8),
        ("--dpi-desync=multisplit", 0.6),
        ("--dpi-desync=seqovl", 0.4),
    ]

    for strategy, success_rate in strategies:
        learning_cache.record_strategy_performance(
            strategy=strategy,
            domain=TEST_DOMAIN,
            ip=TEST_IP,
            success_rate=success_rate,
            avg_latency=100.0,
            dpi_fingerprint_hash=TEST_DPI_HASH,
        )

    recommendations = learning_cache.get_dpi_recommendations(TEST_DPI_HASH, top_n=2)

    assert len(recommendations) == 2
    assert (
        recommendations[0][1] > recommendations[1][1]
    )  # Should be ordered by success rate


def test_smart_strategy_ordering(learning_cache):
    """Test smart strategy ordering based on learning history"""
    # Record some history
    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=fake,fakeddisorder",
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    strategies = [
        "--dpi-desync=fake,fakeddisorder",
        "--dpi-desync=multisplit",
        "--dpi-desync=seqovl",
    ]

    ordered_strategies = learning_cache.get_smart_strategy_order(
        strategies=strategies,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        dpi_fingerprint_hash=TEST_DPI_HASH,
    )

    assert len(ordered_strategies) == len(strategies)
    assert ordered_strategies[0] == "--dpi-desync=fake,fakeddisorder"  # Should be first


def test_cache_persistence(temp_cache_file):
    """Test cache saving and loading"""
    # Create and populate cache
    cache1 = AdaptiveLearningCache(cache_file=temp_cache_file)
    cache1.record_strategy_performance(
        strategy=TEST_STRATEGY,
        domain=TEST_DOMAIN,
        ip=TEST_IP,
        success_rate=0.8,
        avg_latency=100.0,
    )
    cache1.save_cache()

    # Load cache in new instance
    cache2 = AdaptiveLearningCache(cache_file=temp_cache_file)
    assert len(cache2.strategy_records) == 1

    key = cache2._strategy_key(TEST_STRATEGY, TEST_DOMAIN, TEST_IP)
    assert key in cache2.strategy_records
    assert abs(cache2.strategy_records[key].success_rate - 0.8) < 0.01


def test_cache_statistics(learning_cache):
    """Test cache statistics calculation"""
    # Record some test data
    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=fake,fakeddisorder",
        domain="domain1.com",
        ip="192.168.1.1",
        success_rate=0.8,
        avg_latency=100.0,
    )

    learning_cache.record_strategy_performance(
        strategy="--dpi-desync=multisplit",
        domain="domain2.com",
        ip="192.168.1.2",
        success_rate=0.6,
        avg_latency=120.0,
        dpi_fingerprint_hash="dpi1",
    )

    stats = learning_cache.get_cache_stats()

    assert stats["total_strategy_records"] == 2
    assert stats["domains_learned"] == 2
    assert stats["dpi_patterns_learned"] == 1
    assert 0.6 <= stats["average_success_rate"] <= 0.8


def test_cache_version_compatibility(temp_cache_file):
    """Test cache version compatibility handling"""
    # Create old format cache data
    old_cache_data = {
        "strategy_records": {},
        "domain_patterns": {},
        "version": "0.9",
        "saved_at": datetime.now().isoformat(),
    }

    # Save old format
    with open(temp_cache_file, "wb") as f:
        pickle.dump(old_cache_data, f)

    # Load with new version
    cache = AdaptiveLearningCache(cache_file=temp_cache_file)
    assert isinstance(cache.strategy_records, dict)
    assert isinstance(cache.domain_patterns, dict)
    assert isinstance(cache.dpi_patterns, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
