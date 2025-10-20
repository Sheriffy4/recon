"""
Pytest configuration and shared fixtures for DPI strategy tests.

This module provides common fixtures and configuration for all test modules.
"""

import pytest
import logging
import tempfile
import os
from typing import Dict, Any

from core.bypass.strategies.dpi_strategy_engine import DPIStrategyEngine
from core.bypass.strategies.position_resolver import PositionResolver
from core.bypass.strategies.sni_detector import SNIDetector
from core.bypass.strategies.checksum_fooler import ChecksumFooler
from core.bypass.strategies.config_models import DPIConfig, FoolingConfig


# Configure logging for tests
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Disable verbose logging from components during tests unless specifically needed
logging.getLogger('core.bypass.strategies').setLevel(logging.WARNING)


@pytest.fixture(scope="session")
def test_config():
    """Provide test configuration."""
    return {
        'timeout': 30,
        'temp_dir': tempfile.mkdtemp(prefix='dpi_strategy_tests_'),
        'verbose': False,  # Set to True for debugging
        'performance_threshold_ms': 100
    }


@pytest.fixture
def dpi_config_basic():
    """Provide basic DPI configuration for testing."""
    return DPIConfig(
        desync_mode="split",
        split_positions=[3, 10],
        fooling_methods=[],
        enabled=True
    )


@pytest.fixture
def dpi_config_full():
    """Provide full DPI configuration with all features enabled."""
    return DPIConfig(
        desync_mode="split",
        split_positions=[3, 10, "sni"],
        fooling_methods=["badsum"],
        enabled=True
    )


@pytest.fixture
def dpi_config_sni_only():
    """Provide SNI-only DPI configuration."""
    return DPIConfig(
        desync_mode="split",
        split_positions=["sni"],
        fooling_methods=[],
        enabled=True
    )


@pytest.fixture
def dpi_config_badsum_only():
    """Provide badsum-only DPI configuration."""
    return DPIConfig(
        desync_mode="split",
        split_positions=[3],
        fooling_methods=["badsum"],
        enabled=True
    )


@pytest.fixture
def dpi_config_disabled():
    """Provide disabled DPI configuration."""
    return DPIConfig(
        desync_mode="split",
        split_positions=[3, 10],
        fooling_methods=[],
        enabled=False
    )


@pytest.fixture
def position_resolver():
    """Provide PositionResolver instance."""
    return PositionResolver()


@pytest.fixture
def sni_detector():
    """Provide SNIDetector instance."""
    return SNIDetector()


@pytest.fixture
def checksum_fooler_enabled():
    """Provide ChecksumFooler with badsum enabled."""
    config = FoolingConfig(badsum=True)
    return ChecksumFooler(config)


@pytest.fixture
def checksum_fooler_disabled():
    """Provide ChecksumFooler with badsum disabled."""
    config = FoolingConfig(badsum=False)
    return ChecksumFooler(config)


@pytest.fixture
def dpi_engine_basic(dpi_config_basic):
    """Provide basic DPI strategy engine."""
    return DPIStrategyEngine(dpi_config_basic)


@pytest.fixture
def dpi_engine_full(dpi_config_full):
    """Provide full-featured DPI strategy engine."""
    engine = DPIStrategyEngine(dpi_config_full)
    
    # Set up real components
    engine.set_position_resolver(PositionResolver())
    engine.set_sni_detector(SNIDetector())
    engine.set_checksum_fooler(ChecksumFooler(FoolingConfig(badsum=True)))
    
    return engine


@pytest.fixture
def sample_packets():
    """Provide sample packets for testing."""
    import struct
    import socket
    
    def create_tcp_packet(payload: bytes, src_port: int = 54321, dst_port: int = 443) -> bytes:
        """Create a TCP packet with specified payload."""
        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00, 20 + 20 + len(payload),
            0x1234, 0x4000,
            0x40, 0x06, 0x0000,
            socket.inet_aton('192.168.1.100'),
            socket.inet_aton('93.184.216.34')
        )
        
        # TCP header
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port,
            1000, 2000,
            0x50, 0x18,
            65535, 0x1234, 0
        )
        
        return ip_header + tcp_header + payload
    
    def create_tls_client_hello(hostname: str) -> bytes:
        """Create TLS Client Hello packet."""
        # Simplified TLS Client Hello
        record = bytearray()
        record.extend(b'\x16\x03\x03')  # TLS record header
        
        # Client Hello with SNI
        client_hello = bytearray()
        client_hello.extend(b'\x01\x00\x00\x50')  # Handshake header
        client_hello.extend(b'\x03\x03')  # Version
        client_hello.extend(b'\x00' * 32)  # Random
        client_hello.extend(b'\x00')  # Session ID length
        client_hello.extend(b'\x00\x02\x00\x35')  # Cipher suites
        client_hello.extend(b'\x01\x00')  # Compression methods
        
        # Extensions with SNI
        extensions = bytearray()
        sni_ext = bytearray()
        sni_ext.extend(b'\x00\x00')  # SNI extension type
        
        hostname_bytes = hostname.encode('utf-8')
        sni_data = bytearray()
        sni_data.extend(struct.pack('!H', len(hostname_bytes) + 3))
        sni_data.extend(b'\x00')
        sni_data.extend(struct.pack('!H', len(hostname_bytes)))
        sni_data.extend(hostname_bytes)
        
        sni_ext.extend(struct.pack('!H', len(sni_data)))
        sni_ext.extend(sni_data)
        extensions.extend(sni_ext)
        
        client_hello.extend(struct.pack('!H', len(extensions)))
        client_hello.extend(extensions)
        
        record.extend(struct.pack('!H', len(client_hello)))
        record.extend(client_hello)
        
        return bytes(record)
    
    return {
        'small_packet': create_tcp_packet(b'AB'),
        'medium_packet': create_tcp_packet(b'A' * 100),
        'large_packet': create_tcp_packet(b'A' * 1000),
        'tls_youtube': create_tcp_packet(create_tls_client_hello('www.youtube.com')),
        'tls_google': create_tcp_packet(create_tls_client_hello('www.google.com')),
        'tls_example': create_tcp_packet(create_tls_client_hello('example.com')),
        'http_packet': create_tcp_packet(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', dst_port=80),
        'empty_packet': b'',
        'malformed_packet': b'\xFF' * 50
    }


@pytest.fixture
def performance_monitor():
    """Provide performance monitoring utilities."""
    import time
    
    class PerformanceMonitor:
        def __init__(self):
            self.measurements = {}
        
        def start_timer(self, name: str):
            self.measurements[name] = {'start': time.time()}
        
        def end_timer(self, name: str):
            if name in self.measurements:
                self.measurements[name]['end'] = time.time()
                self.measurements[name]['duration'] = (
                    self.measurements[name]['end'] - self.measurements[name]['start']
                )
        
        def get_duration_ms(self, name: str) -> float:
            if name in self.measurements and 'duration' in self.measurements[name]:
                return self.measurements[name]['duration'] * 1000
            return 0.0
        
        def assert_performance(self, name: str, max_duration_ms: float):
            duration_ms = self.get_duration_ms(name)
            assert duration_ms <= max_duration_ms, (
                f"Performance test '{name}' took {duration_ms:.2f}ms, "
                f"expected <= {max_duration_ms}ms"
            )
        
        def get_summary(self) -> Dict[str, Any]:
            summary = {}
            for name, measurement in self.measurements.items():
                if 'duration' in measurement:
                    summary[name] = {
                        'duration_ms': measurement['duration'] * 1000,
                        'start_time': measurement['start'],
                        'end_time': measurement['end']
                    }
            return summary
    
    return PerformanceMonitor()


@pytest.fixture
def temp_directory(test_config):
    """Provide temporary directory for test files."""
    temp_dir = test_config['temp_dir']
    yield temp_dir
    
    # Cleanup after tests
    import shutil
    try:
        shutil.rmtree(temp_dir)
    except:
        pass  # Best effort cleanup


# Test markers
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "pcap: mark test as PCAP validation test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


# Test collection hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add markers based on test file names
        if "test_position_resolver" in item.nodeid or \
           "test_sni_detector" in item.nodeid or \
           "test_checksum_fooler" in item.nodeid or \
           "test_dpi_strategy_engine" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        
        elif "test_strategy_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        
        elif "test_pcap_validation" in item.nodeid:
            item.add_marker(pytest.mark.pcap)
        
        # Add performance marker for performance tests
        if "performance" in item.name.lower() or "benchmark" in item.name.lower():
            item.add_marker(pytest.mark.performance)
        
        # Add slow marker for tests that might take longer
        if "stress" in item.name.lower() or "large_volume" in item.name.lower():
            item.add_marker(pytest.mark.slow)


# Session-level setup and teardown
@pytest.fixture(scope="session", autouse=True)
def test_session_setup(test_config):
    """Set up test session."""
    print(f"\nStarting DPI strategy test session")
    print(f"Temporary directory: {test_config['temp_dir']}")
    
    # Create test data directory
    from tests import create_test_data_dir
    create_test_data_dir()
    
    yield
    
    print(f"\nTest session completed")


# Function-level setup for debugging
@pytest.fixture(autouse=True)
def test_function_setup(request, test_config):
    """Set up individual test functions."""
    if test_config['verbose']:
        print(f"\nRunning test: {request.node.name}")
    
    yield
    
    if test_config['verbose']:
        print(f"Completed test: {request.node.name}")


# Error handling and reporting
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Create test reports with additional information."""
    outcome = yield
    rep = outcome.get_result()
    
    # Add custom information to test reports
    if rep.when == "call":
        if hasattr(item, 'funcargs'):
            # Add performance information if available
            if 'performance_monitor' in item.funcargs:
                monitor = item.funcargs['performance_monitor']
                summary = monitor.get_summary()
                if summary:
                    rep.sections.append(('Performance Summary', str(summary)))
    
    return rep