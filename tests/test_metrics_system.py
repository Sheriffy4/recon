"""
Tests for Attack Parity Metrics System

Tests the metrics collection, aggregation, and reporting functionality.
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta

from core.metrics.attack_parity_metrics import (
    AttackParityMetricsCollector,
    ComplianceMetric,
    AttackDetectionMetric,
    StrategyApplicationMetric,
    PCAPValidationMetric,
    get_metrics_collector,
    set_metrics_collector
)


@pytest.fixture
def temp_metrics_file():
    """Create temporary file for metrics storage."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        yield f.name
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def collector(temp_metrics_file):
    """Create fresh metrics collector for each test."""
    collector = AttackParityMetricsCollector(
        retention_hours=24,
        auto_save=False,
        save_path=temp_metrics_file
    )
    return collector


def test_record_compliance_metric(collector):
    """Test recording compliance metrics."""
    collector.record_compliance(
        domain="example.com",
        score=28,
        max_score=30,
        issues_count=1,
        expected_attacks=["fake", "multisplit", "disorder"],
        detected_attacks=["fake", "multisplit"],
        mode="production"
    )
    
    assert len(collector.compliance_metrics) == 1
    metric = collector.compliance_metrics[0]
    assert metric.domain == "example.com"
    assert metric.score == 28
    assert metric.max_score == 30
    assert metric.percentage == pytest.approx(93.33, rel=0.01)
    assert metric.issues_count == 1
    assert len(metric.expected_attacks) == 3
    assert len(metric.detected_attacks) == 2


def test_record_attack_detection_metric(collector):
    """Test recording attack detection metrics."""
    collector.record_attack_detection(
        attack_type="multisplit",
        total_attempts=10,
        successful_detections=9,
        failed_detections=1,
        average_confidence=0.95
    )
    
    assert len(collector.detection_metrics) == 1
    metric = collector.detection_metrics[0]
    assert metric.attack_type == "multisplit"
    assert metric.total_attempts == 10
    assert metric.successful_detections == 9
    assert metric.failed_detections == 1
    assert metric.detection_rate == 90.0
    assert metric.average_confidence == 0.95


def test_record_strategy_application_metric(collector):
    """Test recording strategy application metrics."""
    collector.record_strategy_application(
        domain="example.com",
        strategy_id="recipe_12345",
        attacks=["fake", "multisplit"],
        success=True,
        error_message=None,
        application_time_ms=15.3,
        mode="production"
    )
    
    assert len(collector.application_metrics) == 1
    metric = collector.application_metrics[0]
    assert metric.domain == "example.com"
    assert metric.strategy_id == "recipe_12345"
    assert len(metric.attacks) == 2
    assert metric.success is True
    assert metric.error_message is None
    assert metric.application_time_ms == 15.3


def test_record_pcap_validation_metric(collector):
    """Test recording PCAP validation metrics."""
    collector.record_pcap_validation(
        pcap_file="test.pcap",
        validation_success=True,
        error_type=None,
        error_message=None,
        packets_analyzed=150,
        streams_found=3,
        clienthello_found=True,
        validation_time_ms=45.2
    )
    
    assert len(collector.validation_metrics) == 1
    metric = collector.validation_metrics[0]
    assert metric.pcap_file == "test.pcap"
    assert metric.validation_success is True
    assert metric.packets_analyzed == 150
    assert metric.streams_found == 3
    assert metric.clienthello_found is True
    assert metric.validation_time_ms == 45.2


def test_get_summary_empty(collector):
    """Test getting summary with no metrics."""
    summary = collector.get_summary(time_window_minutes=60)
    
    assert summary.total_compliance_checks == 0
    assert summary.total_attack_detections == 0
    assert summary.total_strategy_applications == 0
    assert summary.total_pcap_validations == 0


def test_get_summary_with_metrics(collector):
    """Test getting summary with various metrics."""
    # Add compliance metrics
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    collector.record_compliance("test.com", 20, 30, 2, ["fake", "split"], ["fake"], "production")
    
    # Add detection metrics
    collector.record_attack_detection("fake", 10, 9, 1, 0.9)
    collector.record_attack_detection("split", 10, 8, 2, 0.8)
    
    # Add application metrics
    collector.record_strategy_application("example.com", "s1", ["fake"], True, None, 10.0, "production")
    collector.record_strategy_application("test.com", "s2", ["split"], False, "Error", 15.0, "production")
    
    # Add validation metrics
    collector.record_pcap_validation("test.pcap", True, None, None, 100, 2, True, 30.0)
    
    summary = collector.get_summary(time_window_minutes=60)
    
    # Check compliance
    assert summary.total_compliance_checks == 2
    assert summary.average_compliance_score == pytest.approx(83.33, rel=0.01)
    assert summary.perfect_compliance_count == 1
    
    # Check detection
    assert summary.total_attack_detections == 20
    assert summary.successful_detections == 17
    assert summary.failed_detections == 3
    assert summary.overall_detection_rate == 85.0
    
    # Check application
    assert summary.total_strategy_applications == 2
    assert summary.successful_applications == 1
    assert summary.failed_applications == 1
    assert summary.application_success_rate == 50.0
    
    # Check validation
    assert summary.total_pcap_validations == 1
    assert summary.successful_validations == 1
    assert summary.validation_success_rate == 100.0


def test_get_compliance_history(collector):
    """Test getting compliance history."""
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    collector.record_compliance("test.com", 20, 30, 2, ["fake"], ["fake"], "production")
    collector.record_compliance("example.com", 25, 30, 1, ["fake"], ["fake"], "production")
    
    # Get all history
    history = collector.get_compliance_history()
    assert len(history) == 3
    
    # Get filtered by domain
    history = collector.get_compliance_history(domain="example.com")
    assert len(history) == 2
    assert all(m.domain == "example.com" for m in history)
    
    # Get limited
    history = collector.get_compliance_history(limit=2)
    assert len(history) == 2


def test_save_and_load_metrics(collector, temp_metrics_file):
    """Test saving and loading metrics from disk."""
    # Add some metrics
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    collector.record_attack_detection("fake", 10, 9, 1, 0.9)
    
    # Save metrics
    collector._save_metrics()
    
    # Create new collector and load
    new_collector = AttackParityMetricsCollector(
        retention_hours=24,
        auto_save=False,
        save_path=temp_metrics_file
    )
    
    assert len(new_collector.compliance_metrics) == 1
    assert len(new_collector.detection_metrics) == 1


def test_export_to_json(temp_metrics_file):
    """Test exporting metrics to JSON."""
    # Create a fresh collector for this test to avoid lock issues
    collector = AttackParityMetricsCollector(
        retention_hours=24,
        auto_save=False,
        save_path=temp_metrics_file
    )
    
    # Add some metrics
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    collector.record_attack_detection("fake", 10, 9, 1, 0.9)
    
    # Export
    export_path = temp_metrics_file.replace('.json', '_export.json')
    collector.export_to_json(export_path)
    
    # Verify export
    assert Path(export_path).exists()
    with open(export_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    assert 'compliance' in data
    assert 'detection' in data
    assert 'application' in data
    assert 'validation' in data
    assert 'summary' in data
    
    # Cleanup
    try:
        Path(export_path).unlink()
    except Exception:
        pass  # Ignore cleanup errors


def test_cleanup_old_metrics(collector):
    """Test cleanup of old metrics."""
    # Add old metric (manually set timestamp)
    old_metric = ComplianceMetric(
        domain="old.com",
        timestamp=datetime.now() - timedelta(hours=25),
        score=30,
        max_score=30,
        percentage=100.0,
        issues_count=0,
        expected_attacks=["fake"],
        detected_attacks=["fake"],
        mode="production"
    )
    collector.compliance_metrics.append(old_metric)
    
    # Add recent metric (manually to avoid auto-cleanup)
    recent_metric = ComplianceMetric(
        domain="new.com",
        timestamp=datetime.now(),
        score=30,
        max_score=30,
        percentage=100.0,
        issues_count=0,
        expected_attacks=["fake"],
        detected_attacks=["fake"],
        mode="production"
    )
    collector.compliance_metrics.append(recent_metric)
    
    assert len(collector.compliance_metrics) == 2
    
    # Cleanup (retention is 24 hours)
    collector._cleanup_old_metrics()
    
    # Old metric should be removed
    assert len(collector.compliance_metrics) == 1
    assert collector.compliance_metrics[0].domain == "new.com"


def test_clear_all_metrics(collector):
    """Test clearing all metrics."""
    # Add various metrics
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    collector.record_attack_detection("fake", 10, 9, 1, 0.9)
    collector.record_strategy_application("example.com", "s1", ["fake"], True, None, 10.0, "production")
    collector.record_pcap_validation("test.pcap", True, None, None, 100, 2, True, 30.0)
    
    assert len(collector.compliance_metrics) > 0
    assert len(collector.detection_metrics) > 0
    assert len(collector.application_metrics) > 0
    assert len(collector.validation_metrics) > 0
    
    # Clear all
    collector.clear_all_metrics()
    
    assert len(collector.compliance_metrics) == 0
    assert len(collector.detection_metrics) == 0
    assert len(collector.application_metrics) == 0
    assert len(collector.validation_metrics) == 0


def test_global_collector():
    """Test global collector instance."""
    # Get global collector
    collector1 = get_metrics_collector()
    collector2 = get_metrics_collector()
    
    # Should be same instance
    assert collector1 is collector2
    
    # Set new collector
    new_collector = AttackParityMetricsCollector(auto_save=False)
    set_metrics_collector(new_collector)
    
    collector3 = get_metrics_collector()
    assert collector3 is new_collector
    assert collector3 is not collector1


def test_detection_rates_by_attack(collector):
    """Test per-attack detection rates in summary."""
    # Add detection metrics for different attacks
    collector.record_attack_detection("fake", 10, 9, 1, 0.9)
    collector.record_attack_detection("split", 10, 8, 2, 0.8)
    collector.record_attack_detection("disorder", 10, 10, 0, 1.0)
    
    summary = collector.get_summary(time_window_minutes=60)
    
    assert "fake" in summary.detection_rates_by_attack
    assert "split" in summary.detection_rates_by_attack
    assert "disorder" in summary.detection_rates_by_attack
    
    assert summary.detection_rates_by_attack["fake"] == 90.0
    assert summary.detection_rates_by_attack["split"] == 80.0
    assert summary.detection_rates_by_attack["disorder"] == 100.0


def test_failures_by_error_type(collector):
    """Test failure tracking by error type in summary."""
    # Add application metrics with different errors
    collector.record_strategy_application("test1.com", "s1", ["fake"], False, "TimeoutError: Connection timeout", 10.0, "production")
    collector.record_strategy_application("test2.com", "s2", ["split"], False, "TimeoutError: Read timeout", 15.0, "production")
    collector.record_strategy_application("test3.com", "s3", ["disorder"], False, "ValueError: Invalid parameter", 20.0, "production")
    
    summary = collector.get_summary(time_window_minutes=60)
    
    assert "TimeoutError" in summary.failures_by_error_type
    assert "ValueError" in summary.failures_by_error_type
    
    assert summary.failures_by_error_type["TimeoutError"] == 2
    assert summary.failures_by_error_type["ValueError"] == 1


def test_metric_to_dict_serialization(collector):
    """Test that metrics can be serialized to dict."""
    collector.record_compliance("example.com", 30, 30, 0, ["fake"], ["fake"], "production")
    
    metric = collector.compliance_metrics[0]
    metric_dict = metric.to_dict()
    
    assert isinstance(metric_dict, dict)
    assert 'domain' in metric_dict
    assert 'timestamp' in metric_dict
    assert 'score' in metric_dict
    assert isinstance(metric_dict['timestamp'], str)  # Should be ISO format


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
