"""
Simple tests for DPI Behavior Monitoring System - Task 11 Implementation

Basic functionality tests that can run without complex dependencies.
"""

import pytest
import time
from datetime import datetime
from unittest.mock import Mock
from core.fingerprint.dpi_behavior_monitor import (
    MonitoringConfig,
    PerformanceMonitor,
    BehaviorAnalyzer,
    AlertSeverity,
    MonitoringState,
    BehaviorChange,
    MonitoringAlert,
)


def test_monitoring_config_creation():
    """Test monitoring configuration creation"""
    config = MonitoringConfig()
    assert config.check_interval_seconds == 300
    assert config.min_check_interval == 60
    assert config.max_check_interval == 3600
    assert config.enable_adaptive_frequency == True
    assert config.enable_alerts == True
    assert config.enable_strategy_testing == True


def test_monitoring_config_custom():
    """Test custom monitoring configuration"""
    config = MonitoringConfig(
        check_interval_seconds=120, enable_alerts=False, alert_retention_days=14
    )
    assert config.check_interval_seconds == 120
    assert config.enable_alerts == False
    assert config.alert_retention_days == 14


def test_performance_monitor_basic():
    """Test basic performance monitor functionality"""
    monitor = PerformanceMonitor()
    assert monitor._cpu_usage == 0.0
    assert monitor._memory_usage == 0.0
    assert monitor._last_check <= time.time()
    interval = monitor.get_adaptive_interval(60, 30, 300, 80.0, 85.0)
    assert interval == 60


def test_behavior_analyzer_initialization():
    """Test behavior analyzer initialization"""
    config = MonitoringConfig()
    analyzer = BehaviorAnalyzer(config)
    assert analyzer.config == config
    assert len(analyzer._known_patterns) > 0
    assert "roskomnadzor_tspu" in analyzer._known_patterns
    assert "commercial_dpi" in analyzer._known_patterns


def test_behavior_change_creation():
    """Test behavior change object creation"""
    fingerprint = Mock()
    fingerprint.target = "example.com:443"
    change = BehaviorChange(
        target="example.com:443",
        timestamp=datetime.now(),
        change_type="new_blocking",
        old_fingerprint=None,
        new_fingerprint=fingerprint,
        confidence=0.8,
        details={"test": "data"},
    )
    assert change.target == "example.com:443"
    assert change.change_type == "new_blocking"
    assert change.old_fingerprint is None
    assert change.new_fingerprint == fingerprint
    assert change.confidence == 0.8
    assert change.details["test"] == "data"


def test_monitoring_alert_creation():
    """Test monitoring alert creation"""
    fingerprint = Mock()
    alert = MonitoringAlert(
        id="test123",
        target="example.com:443",
        timestamp=datetime.now(),
        severity=AlertSeverity.HIGH,
        title="Test Alert",
        description="Test description",
        fingerprint=fingerprint,
        suggested_actions=["action1", "action2"],
    )
    assert alert.id == "test123"
    assert alert.target == "example.com:443"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.title == "Test Alert"
    assert alert.description == "Test description"
    assert alert.fingerprint == fingerprint
    assert len(alert.suggested_actions) == 2
    assert not alert.acknowledged
    assert not alert.resolved


def test_alert_severity_enum():
    """Test alert severity enumeration"""
    assert AlertSeverity.LOW.value == "low"
    assert AlertSeverity.MEDIUM.value == "medium"
    assert AlertSeverity.HIGH.value == "high"
    assert AlertSeverity.CRITICAL.value == "critical"


def test_monitoring_state_enum():
    """Test monitoring state enumeration"""
    assert MonitoringState.STOPPED.value == "stopped"
    assert MonitoringState.STARTING.value == "starting"
    assert MonitoringState.RUNNING.value == "running"
    assert MonitoringState.PAUSED.value == "paused"
    assert MonitoringState.STOPPING.value == "stopping"
    assert MonitoringState.ERROR.value == "error"


def test_behavior_change_to_dict():
    """Test behavior change serialization"""
    fingerprint = Mock()
    fingerprint.to_dict.return_value = {"test": "data"}
    timestamp = datetime.now()
    change = BehaviorChange(
        target="example.com:443",
        timestamp=timestamp,
        change_type="test_change",
        old_fingerprint=None,
        new_fingerprint=fingerprint,
        confidence=0.7,
        details={"key": "value"},
    )
    data = change.to_dict()
    assert data["target"] == "example.com:443"
    assert data["timestamp"] == timestamp.isoformat()
    assert data["change_type"] == "test_change"
    assert data["old_fingerprint"] is None
    assert data["new_fingerprint"] == {"test": "data"}
    assert data["confidence"] == 0.7
    assert data["details"] == {"key": "value"}


def test_monitoring_alert_to_dict():
    """Test monitoring alert serialization"""
    fingerprint = Mock()
    fingerprint.to_dict.return_value = {"test": "data"}
    timestamp = datetime.now()
    alert = MonitoringAlert(
        id="test123",
        target="example.com:443",
        timestamp=timestamp,
        severity=AlertSeverity.MEDIUM,
        title="Test Alert",
        description="Test description",
        fingerprint=fingerprint,
        suggested_actions=["action1"],
        acknowledged=True,
        resolved=False,
    )
    data = alert.to_dict()
    assert data["id"] == "test123"
    assert data["target"] == "example.com:443"
    assert data["timestamp"] == timestamp.isoformat()
    assert data["severity"] == "medium"
    assert data["title"] == "Test Alert"
    assert data["description"] == "Test description"
    assert data["fingerprint"] == {"test": "data"}
    assert data["suggested_actions"] == ["action1"]
    assert data["acknowledged"] == True
    assert data["resolved"] == False


def test_behavior_analyzer_known_patterns():
    """Test behavior analyzer known patterns"""
    config = MonitoringConfig()
    analyzer = BehaviorAnalyzer(config)
    tspu_pattern = analyzer._known_patterns.get("roskomnadzor_tspu", set())
    assert "rst_injection_detected" in tspu_pattern
    assert "dns_hijacking_detected" in tspu_pattern
    commercial_pattern = analyzer._known_patterns.get("commercial_dpi", set())
    assert "content_inspection_depth_high" in commercial_pattern
    assert "user_agent_filtering" in commercial_pattern


def test_behavior_analyzer_extract_signature():
    """Test behavior signature extraction"""
    config = MonitoringConfig()
    analyzer = BehaviorAnalyzer(config)
    fingerprint = Mock()
    fingerprint.rst_injection_detected = True
    fingerprint.tcp_window_manipulation = False
    fingerprint.http_header_filtering = True
    fingerprint.dns_hijacking_detected = True
    fingerprint.user_agent_filtering = False
    fingerprint.content_type_filtering = False
    fingerprint.content_inspection_depth = 1500
    fingerprint.connection_reset_timing = 50.0
    signature = analyzer._extract_behavior_signature(fingerprint)
    expected_elements = {
        "rst_injection_detected",
        "http_header_filtering",
        "dns_hijacking_detected",
        "content_inspection_depth_high",
        "fast_connection_reset",
    }
    assert signature == expected_elements


def test_monitoring_config_to_dict():
    """Test monitoring configuration serialization"""
    config = MonitoringConfig(check_interval_seconds=120, enable_alerts=False)
    data = config.to_dict()
    assert isinstance(data, dict)
    assert data["check_interval_seconds"] == 120
    assert data["enable_alerts"] == False
    assert "min_check_interval" in data
    assert "max_check_interval" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
