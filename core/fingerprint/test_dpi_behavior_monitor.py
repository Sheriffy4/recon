"""
Tests for DPI Behavior Monitoring System - Task 11 Implementation

Tests cover:
- Background monitoring for DPI behavior changes
- Automatic fingerprint updates when behavior changes detected
- Alert system for unknown DPI behavior patterns
- Performance-aware monitoring with adaptive frequency
- Alert generation and management

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""
import pytest
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from recon.core.fingerprint.dpi_behavior_monitor import DPIBehaviorMonitor, MonitoringConfig, BehaviorAnalyzer, PerformanceMonitor, BehaviorChange, MonitoringAlert, AlertSeverity, MonitoringState
from recon.core.fingerprint.advanced_models import DPIFingerprint, DPIType
from recon.core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter

@pytest.fixture
def mock_fingerprinter():
    """Mock advanced fingerprinter"""
    fingerprinter = Mock(spec=AdvancedFingerprinter)
    fingerprinter.fingerprint_target = AsyncMock()
    fingerprinter.invalidate_cache = Mock()
    return fingerprinter

@pytest.fixture
def sample_fingerprint():
    """Sample DPI fingerprint for testing"""
    return DPIFingerprint(target='example.com:443', timestamp=time.time(), dpi_type=DPIType.ROSKOMNADZOR_TSPU, confidence=0.85, analysis_duration=2.5, reliability_score=0.9, rst_injection_detected=True, rst_source_analysis='middlebox', tcp_window_manipulation=False, sequence_number_anomalies=False, tcp_options_filtering=True, connection_reset_timing=50.0, handshake_anomalies=['window_size_anomaly'], fragmentation_handling='blocked', mss_clamping_detected=False, tcp_timestamp_manipulation=False, http_header_filtering=True, content_inspection_depth=500, user_agent_filtering=False, host_header_manipulation=True, http_method_restrictions=['POST'], content_type_filtering=False, redirect_injection=False, http_response_modification=False, keep_alive_manipulation=False, chunked_encoding_handling='normal', dns_hijacking_detected=True, dns_response_modification=True, dns_query_filtering=False, doh_blocking=True, dot_blocking=False, dns_cache_poisoning=False, dns_timeout_manipulation=False, recursive_resolver_blocking=False, dns_over_tcp_blocking=False, edns_support=True, supports_ipv6=True, ip_fragmentation_handling='normal', packet_size_limitations=None, protocol_whitelist=['https', 'http'], geographic_restrictions=False, time_based_filtering=False, raw_metrics={}, analysis_methods_used=['tcp_analysis', 'http_analysis', 'dns_analysis'])

@pytest.fixture
def monitoring_config():
    """Test monitoring configuration"""
    return MonitoringConfig(check_interval_seconds=60, min_check_interval=30, max_check_interval=300, max_concurrent_monitors=5, enable_adaptive_frequency=True, performance_threshold_cpu=80.0, performance_threshold_memory=85.0, fingerprint_similarity_threshold=0.8, behavior_change_confidence_threshold=0.7, unknown_pattern_threshold=0.3, enable_alerts=True, alert_retention_days=7, max_alerts_per_target=5, enable_strategy_testing=True, strategy_test_timeout=10.0, max_strategies_to_test=3, save_behavior_changes=False, behavior_log_file='test_behavior_changes.json', alerts_file='test_alerts.json')

class TestPerformanceMonitor:
    """Test performance monitoring functionality"""

    def test_performance_monitor_initialization(self):
        """Test performance monitor initialization"""
        monitor = PerformanceMonitor()
        assert monitor._cpu_usage == 0.0
        assert monitor._memory_usage == 0.0
        assert monitor._last_check <= time.time()

    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    def test_get_system_metrics_with_psutil(self, mock_memory, mock_cpu):
        """Test system metrics collection with psutil"""
        mock_cpu.return_value = 45.5
        mock_memory.return_value = Mock(percent=67.8)
        monitor = PerformanceMonitor()
        cpu = monitor.get_cpu_usage()
        memory = monitor.get_memory_usage()
        assert cpu == 45.5
        assert memory == 67.8

    @patch('psutil.cpu_percent', side_effect=ImportError)
    @patch('os.getloadavg')
    @patch('os.cpu_count')
    def test_get_cpu_usage_fallback(self, mock_cpu_count, mock_loadavg):
        """Test CPU usage fallback when psutil unavailable"""
        mock_cpu_count.return_value = 4
        mock_loadavg.return_value = [2.0, 1.5, 1.0]
        monitor = PerformanceMonitor()
        cpu = monitor.get_cpu_usage()
        assert cpu == 50.0

    def test_is_system_overloaded(self):
        """Test system overload detection"""
        monitor = PerformanceMonitor()
        monitor._cpu_usage = 85.0
        monitor._memory_usage = 70.0
        monitor._last_check = time.time()
        assert monitor.is_system_overloaded(80.0, 90.0) == True
        monitor._cpu_usage = 70.0
        monitor._memory_usage = 95.0
        assert monitor.is_system_overloaded(80.0, 90.0) == True
        monitor._cpu_usage = 70.0
        monitor._memory_usage = 80.0
        assert monitor.is_system_overloaded(80.0, 90.0) == False

    def test_get_adaptive_interval(self):
        """Test adaptive interval calculation"""
        monitor = PerformanceMonitor()
        monitor._cpu_usage = 50.0
        monitor._memory_usage = 60.0
        interval = monitor.get_adaptive_interval(60, 30, 300, 80.0, 85.0)
        assert interval == 60
        monitor._cpu_usage = 90.0
        monitor._memory_usage = 70.0
        interval = monitor.get_adaptive_interval(60, 30, 300, 80.0, 85.0)
        assert interval > 60
        assert interval <= 300

class TestBehaviorAnalyzer:
    """Test behavior analysis functionality"""

    def test_behavior_analyzer_initialization(self, monitoring_config):
        """Test behavior analyzer initialization"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        assert analyzer.config == monitoring_config
        assert len(analyzer._known_patterns) > 0
        assert 'roskomnadzor_tspu' in analyzer._known_patterns

    def test_analyze_new_target(self, monitoring_config, sample_fingerprint):
        """Test analysis of new target (no previous fingerprint)"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        change = analyzer.analyze_behavior_change(None, sample_fingerprint)
        assert change is not None
        assert change.target == sample_fingerprint.target
        assert change.old_fingerprint is None
        assert change.new_fingerprint == sample_fingerprint
        assert change.change_type in ['known_pattern', 'new_blocking', 'unknown_pattern']

    def test_analyze_no_change(self, monitoring_config, sample_fingerprint):
        """Test analysis when no significant change occurred"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        change = analyzer.analyze_behavior_change(sample_fingerprint, sample_fingerprint)
        assert change is None

    def test_analyze_significant_change(self, monitoring_config, sample_fingerprint):
        """Test analysis of significant behavior change"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        modified_fp = DPIFingerprint(target=sample_fingerprint.target, timestamp=time.time(), dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.75, analysis_duration=2.0, reliability_score=0.8, rst_injection_detected=False, tcp_window_manipulation=True, http_header_filtering=False, content_inspection_depth=2000, user_agent_filtering=True, dns_hijacking_detected=sample_fingerprint.dns_hijacking_detected, supports_ipv6=sample_fingerprint.supports_ipv6, rst_source_analysis='unknown', sequence_number_anomalies=False, tcp_options_filtering=False, connection_reset_timing=0.0, handshake_anomalies=[], fragmentation_handling='unknown', mss_clamping_detected=False, tcp_timestamp_manipulation=False, host_header_manipulation=False, http_method_restrictions=[], content_type_filtering=False, redirect_injection=False, http_response_modification=False, keep_alive_manipulation=False, chunked_encoding_handling='unknown', dns_response_modification=False, dns_query_filtering=False, doh_blocking=False, dot_blocking=False, dns_cache_poisoning=False, dns_timeout_manipulation=False, recursive_resolver_blocking=False, dns_over_tcp_blocking=False, edns_support=False, ip_fragmentation_handling='unknown', packet_size_limitations=None, protocol_whitelist=[], geographic_restrictions=False, time_based_filtering=False, raw_metrics={}, analysis_methods_used=[])
        change = analyzer.analyze_behavior_change(sample_fingerprint, modified_fp)
        assert change is not None
        assert change.target == sample_fingerprint.target
        assert change.old_fingerprint == sample_fingerprint
        assert change.new_fingerprint == modified_fp
        assert change.confidence > 0.0
        assert 'dpi_type_changed' in change.details
        assert change.details['dpi_type_changed'] == True

    def test_calculate_fingerprint_similarity(self, monitoring_config, sample_fingerprint):
        """Test fingerprint similarity calculation"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        similarity = analyzer._calculate_fingerprint_similarity(sample_fingerprint, sample_fingerprint)
        assert similarity == 1.0
        modified_fp = DPIFingerprint(target=sample_fingerprint.target, timestamp=time.time(), dpi_type=sample_fingerprint.dpi_type, confidence=sample_fingerprint.confidence, analysis_duration=2.0, reliability_score=0.8, rst_injection_detected=sample_fingerprint.rst_injection_detected, tcp_window_manipulation=not sample_fingerprint.tcp_window_manipulation, http_header_filtering=sample_fingerprint.http_header_filtering, rst_source_analysis='unknown', sequence_number_anomalies=False, tcp_options_filtering=False, connection_reset_timing=0.0, handshake_anomalies=[], fragmentation_handling='unknown', mss_clamping_detected=False, tcp_timestamp_manipulation=False, content_inspection_depth=0, user_agent_filtering=False, host_header_manipulation=False, http_method_restrictions=[], content_type_filtering=False, redirect_injection=False, http_response_modification=False, keep_alive_manipulation=False, chunked_encoding_handling='unknown', dns_hijacking_detected=False, dns_response_modification=False, dns_query_filtering=False, doh_blocking=False, dot_blocking=False, dns_cache_poisoning=False, dns_timeout_manipulation=False, recursive_resolver_blocking=False, dns_over_tcp_blocking=False, edns_support=False, supports_ipv6=True, ip_fragmentation_handling='unknown', packet_size_limitations=None, protocol_whitelist=[], geographic_restrictions=False, time_based_filtering=False, raw_metrics={}, analysis_methods_used=[])
        similarity = analyzer._calculate_fingerprint_similarity(sample_fingerprint, modified_fp)
        assert 0.0 < similarity < 1.0

    def test_generate_alert(self, monitoring_config, sample_fingerprint):
        """Test alert generation"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        change = BehaviorChange(target='test.com:443', timestamp=datetime.now(), change_type='unknown_pattern', old_fingerprint=None, new_fingerprint=sample_fingerprint, confidence=0.9, details={'reason': 'test'})
        alert = analyzer.generate_alert(change)
        assert alert is not None
        assert alert.target == change.target
        assert alert.severity == AlertSeverity.HIGH
        assert alert.title.startswith('Unknown DPI pattern')
        assert len(alert.suggested_actions) > 0
        assert not alert.acknowledged
        assert not alert.resolved

    def test_alert_severity_determination(self, monitoring_config, sample_fingerprint):
        """Test alert severity determination"""
        analyzer = BehaviorAnalyzer(monitoring_config)
        test_cases = [('unknown_pattern', AlertSeverity.HIGH), ('enhanced_blocking', AlertSeverity.MEDIUM), ('dpi_type_change', AlertSeverity.MEDIUM), ('new_blocking', AlertSeverity.MEDIUM), ('reduced_blocking', AlertSeverity.LOW), ('minor_change', AlertSeverity.LOW)]
        for change_type, expected_severity in test_cases:
            change = BehaviorChange(target='test.com:443', timestamp=datetime.now(), change_type=change_type, old_fingerprint=None, new_fingerprint=sample_fingerprint, confidence=0.8)
            severity = analyzer._determine_alert_severity(change)
            assert severity == expected_severity

class TestDPIBehaviorMonitor:
    """Test main DPI behavior monitor functionality"""

    def test_monitor_initialization(self, mock_fingerprinter, monitoring_config):
        """Test monitor initialization"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        assert monitor.fingerprinter == mock_fingerprinter
        assert monitor.config == monitoring_config
        assert monitor.state == MonitoringState.STOPPED
        assert len(monitor.monitored_targets) == 0
        assert len(monitor.monitoring_tasks) == 0

    def test_add_remove_target(self, mock_fingerprinter, monitoring_config):
        """Test adding and removing monitoring targets"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        monitor.add_target('example.com', 443)
        monitor.remove_target('example.com', 443)
        assert 'example.com:443' not in monitor.monitored_targets

    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self, mock_fingerprinter, monitoring_config):
        """Test starting and stopping monitoring"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        await monitor.start_monitoring()
        assert monitor.state == MonitoringState.RUNNING
        await monitor.stop_monitoring()
        assert monitor.state == MonitoringState.STOPPED

    @pytest.mark.asyncio
    async def test_pause_resume_monitoring(self, mock_fingerprinter, monitoring_config):
        """Test pausing and resuming monitoring"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        await monitor.start_monitoring()
        assert monitor.state == MonitoringState.RUNNING
        await monitor.pause_monitoring()
        assert monitor.state == MonitoringState.PAUSED
        await monitor.resume_monitoring()
        assert monitor.state == MonitoringState.RUNNING
        await monitor.stop_monitoring()

    @pytest.mark.asyncio
    async def test_force_check(self, mock_fingerprinter, monitoring_config, sample_fingerprint):
        """Test force check functionality"""
        mock_fingerprinter.fingerprint_target.return_value = sample_fingerprint
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        change = await monitor.force_check('example.com', 443)
        assert change is not None
        assert change.target == 'example.com:443'
        assert change.old_fingerprint is None
        assert change.new_fingerprint == sample_fingerprint
        mock_fingerprinter.fingerprint_target.assert_called_with('example.com', 443, force_refresh=True)

    @pytest.mark.asyncio
    async def test_behavior_change_handling(self, mock_fingerprinter, monitoring_config, sample_fingerprint):
        """Test behavior change handling"""
        modified_fp = DPIFingerprint(target=sample_fingerprint.target, timestamp=time.time(), dpi_type=DPIType.COMMERCIAL_DPI, confidence=0.75, analysis_duration=2.0, reliability_score=0.8, rst_injection_detected=False, tcp_window_manipulation=True, http_header_filtering=False, content_inspection_depth=2000, user_agent_filtering=True, rst_source_analysis='unknown', sequence_number_anomalies=False, tcp_options_filtering=False, connection_reset_timing=0.0, handshake_anomalies=[], fragmentation_handling='unknown', mss_clamping_detected=False, tcp_timestamp_manipulation=False, host_header_manipulation=False, http_method_restrictions=[], content_type_filtering=False, redirect_injection=False, http_response_modification=False, keep_alive_manipulation=False, chunked_encoding_handling='unknown', dns_hijacking_detected=False, dns_response_modification=False, dns_query_filtering=False, doh_blocking=False, dot_blocking=False, dns_cache_poisoning=False, dns_timeout_manipulation=False, recursive_resolver_blocking=False, dns_over_tcp_blocking=False, edns_support=False, supports_ipv6=True, ip_fragmentation_handling='unknown', packet_size_limitations=None, protocol_whitelist=[], geographic_restrictions=False, time_based_filtering=False, raw_metrics={}, analysis_methods_used=[])
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        monitor.monitored_targets['example.com:443'] = sample_fingerprint
        mock_fingerprinter.fingerprint_target.return_value = modified_fp
        change = await monitor.force_check('example.com', 443)
        assert change is not None
        assert len(monitor.behavior_changes) > 0
        assert monitor.stats['behavior_changes_detected'] > 0
        assert monitor.stats['fingerprints_updated'] > 0
        mock_fingerprinter.invalidate_cache.assert_called()

    def test_alert_management(self, mock_fingerprinter, monitoring_config):
        """Test alert acknowledgment and resolution"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        alert = MonitoringAlert(id='test123', target='example.com:443', timestamp=datetime.now(), severity=AlertSeverity.MEDIUM, title='Test Alert', description='Test alert description', fingerprint=Mock(), suggested_actions=['Test action'])
        monitor.alerts.append(alert)
        result = monitor.acknowledge_alert('test123')
        assert result == True
        assert alert.acknowledged == True
        result = monitor.resolve_alert('test123')
        assert result == True
        assert alert.resolved == True
        result = monitor.acknowledge_alert('nonexistent')
        assert result == False

    def test_get_alerts_filtering(self, mock_fingerprinter, monitoring_config):
        """Test alert filtering functionality"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        alerts = [MonitoringAlert(id='alert1', target='example.com:443', timestamp=datetime.now(), severity=AlertSeverity.HIGH, title='High Alert', description='High severity alert', fingerprint=Mock(), resolved=False), MonitoringAlert(id='alert2', target='test.com:443', timestamp=datetime.now(), severity=AlertSeverity.LOW, title='Low Alert', description='Low severity alert', fingerprint=Mock(), resolved=True), MonitoringAlert(id='alert3', target='example.com:443', timestamp=datetime.now(), severity=AlertSeverity.MEDIUM, title='Medium Alert', description='Medium severity alert', fingerprint=Mock(), resolved=False)]
        monitor.alerts.extend(alerts)
        target_alerts = monitor.get_alerts(target='example.com:443')
        assert len(target_alerts) == 2
        high_alerts = monitor.get_alerts(severity=AlertSeverity.HIGH)
        assert len(high_alerts) == 1
        assert high_alerts[0].severity == AlertSeverity.HIGH
        unresolved_alerts = monitor.get_alerts(unresolved_only=True)
        assert len(unresolved_alerts) == 2
        assert all((not alert.resolved for alert in unresolved_alerts))

    def test_monitoring_status(self, mock_fingerprinter, monitoring_config):
        """Test monitoring status reporting"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        status = monitor.get_monitoring_status()
        assert 'state' in status
        assert 'monitored_targets' in status
        assert 'active_tasks' in status
        assert 'behavior_changes' in status
        assert 'active_alerts' in status
        assert 'total_alerts' in status
        assert 'stats' in status
        assert 'config' in status
        assert status['state'] == MonitoringState.STOPPED.value
        assert status['monitored_targets'] == 0
        assert status['active_tasks'] == 0

    def test_target_status(self, mock_fingerprinter, monitoring_config, sample_fingerprint):
        """Test target-specific status reporting"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        status = monitor.get_target_status('example.com', 443)
        assert status is None
        monitor.monitored_targets['example.com:443'] = sample_fingerprint
        status = monitor.get_target_status('example.com', 443)
        assert status is not None
        assert status['target'] == 'example.com:443'
        assert 'current_fingerprint' in status
        assert 'behavior_changes' in status
        assert 'recent_changes' in status
        assert 'active_alerts' in status
        assert 'total_alerts' in status
        assert 'last_check' in status

class TestMonitoringIntegration:
    """Test integration scenarios"""

    @pytest.mark.asyncio
    async def test_alert_callback(self, mock_fingerprinter, monitoring_config, sample_fingerprint):
        """Test alert callback functionality"""
        callback_called = False
        received_alert = None

        def alert_callback(alert):
            nonlocal callback_called, received_alert
            callback_called = True
            received_alert = alert
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config, alert_callback)
        change = BehaviorChange(target='test.com:443', timestamp=datetime.now(), change_type='unknown_pattern', old_fingerprint=None, new_fingerprint=sample_fingerprint, confidence=0.9)
        await monitor._handle_behavior_change(change)
        assert callback_called
        assert received_alert is not None
        assert received_alert.target == 'test.com:443'
        assert received_alert.severity == AlertSeverity.HIGH

    @pytest.mark.asyncio
    async def test_performance_adaptive_monitoring(self, mock_fingerprinter, monitoring_config):
        """Test performance-aware adaptive monitoring"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        with patch.object(monitor.performance_monitor, 'is_system_overloaded', return_value=True):
            with patch.object(monitor.performance_monitor, '_cpu_usage', 90.0):
                with patch.object(monitor.performance_monitor, '_memory_usage', 85.0):
                    interval = monitor.performance_monitor.get_adaptive_interval(monitoring_config.check_interval_seconds, monitoring_config.min_check_interval, monitoring_config.max_check_interval, monitoring_config.performance_threshold_cpu, monitoring_config.performance_threshold_memory)
                    assert interval > monitoring_config.check_interval_seconds

    def test_data_persistence_disabled(self, mock_fingerprinter, monitoring_config):
        """Test that data persistence is properly disabled in test config"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        assert not Path(monitoring_config.behavior_log_file).exists()
        assert not Path(monitoring_config.alerts_file).exists()

    def test_cleanup_old_data(self, mock_fingerprinter, monitoring_config):
        """Test cleanup of old behavior changes and alerts"""
        monitor = DPIBehaviorMonitor(mock_fingerprinter, monitoring_config)
        old_change = BehaviorChange(target='old.com:443', timestamp=datetime.now() - timedelta(days=10), change_type='test', old_fingerprint=None, new_fingerprint=Mock(), confidence=0.5)
        recent_change = BehaviorChange(target='recent.com:443', timestamp=datetime.now(), change_type='test', old_fingerprint=None, new_fingerprint=Mock(), confidence=0.5)
        monitor.behavior_changes.extend([old_change, recent_change])
        monitor._cleanup_old_data()
        assert len(monitor.behavior_changes) == 1
        assert monitor.behavior_changes[0] == recent_change
if __name__ == '__main__':
    pytest.main([__file__, '-v'])