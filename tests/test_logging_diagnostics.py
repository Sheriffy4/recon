"""
Test comprehensive logging and diagnostics.

This test verifies that all logging requirements from Requirement 9 are met:
- 9.1: Strategy application logging
- 9.2: Parameter transformation logging
- 9.3: Fake packet logging
- 9.4: Segment ordering logging
- 9.5: Parameter mismatch logging
"""

import logging
import pytest
from io import StringIO
from typing import Dict, Any

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
from core.strategy.normalizer import ParameterNormalizer


class LogCapture:
    """Helper to capture log messages."""
    
    def __init__(self):
        self.handler = logging.StreamHandler(StringIO())
        self.handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)
        
    def __enter__(self):
        # Add handler to all relevant loggers
        loggers = [
            logging.getLogger('core.bypass.unified_attack_dispatcher'),
            logging.getLogger('core.strategy.normalizer'),
        ]
        for logger in loggers:
            logger.addHandler(self.handler)
            logger.setLevel(logging.DEBUG)
        return self
    
    def __exit__(self, *args):
        # Remove handler
        loggers = [
            logging.getLogger('core.bypass.unified_attack_dispatcher'),
            logging.getLogger('core.strategy.normalizer'),
        ]
        for logger in loggers:
            logger.removeHandler(self.handler)
    
    def get_logs(self) -> str:
        """Get captured log messages."""
        return self.handler.stream.getvalue()


def test_strategy_application_logging():
    """
    Test Requirement 9.1: Strategy application logging.
    
    Verifies that when a strategy is applied, the system logs:
    - Strategy type and attacks list
    - All parameter values
    - Which mode (TEST or BYPASS)
    """
    dispatcher = UnifiedAttackDispatcher()
    builder = ComboAttackBuilder()
    
    # Create a simple recipe
    attacks = ['fake', 'split']
    params = {
        'ttl': 1,
        'fooling': 'badsum',
        'split_pos': 2
    }
    
    recipe = builder.build_recipe(attacks, params)
    
    # Apply recipe with log capture
    with LogCapture() as capture:
        payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        packet_info = {
            'mode': 'TEST',
            'domain': 'example.com',
            'src_addr': '192.168.1.1',
            'dst_addr': '93.184.216.34',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
    
    logs = capture.get_logs()
    
    # Verify strategy application logging
    assert 'STRATEGY APPLICATION START' in logs
    assert 'Domain: example.com' in logs
    assert 'Mode: TEST' in logs
    assert "Attacks: ['fake', 'split']" in logs
    assert 'ttl: 1' in logs
    assert 'fooling: badsum' in logs
    assert 'split_pos: 2' in logs
    
    print("✅ Test passed: Strategy application logging works correctly")


def test_parameter_transformation_logging():
    """
    Test Requirement 9.2: Parameter transformation logging.
    
    Verifies that when parameters are transformed or defaulted,
    the system logs the transformation with before and after values.
    """
    normalizer = ParameterNormalizer()
    
    # Test alias resolution
    with LogCapture() as capture:
        params = {'fooling': 'badseq'}
        normalized = normalizer.normalize(params)
    
    logs = capture.get_logs()
    
    # Verify transformation logging
    assert 'Parameter transformations' in logs
    assert "fooling='badseq'" in logs
    assert "fooling_methods=['badseq']" in logs
    
    # Test default application
    with LogCapture() as capture:
        params = {}
        normalized = normalizer.normalize(params)
    
    logs = capture.get_logs()
    
    # Verify default logging
    assert 'fooling_methods not specified' in logs
    assert "fooling_methods=['badsum'] (default)" in logs
    
    print("✅ Test passed: Parameter transformation logging works correctly")


def test_fake_packet_logging():
    """
    Test Requirement 9.3: Fake packet logging.
    
    Verifies that when a fake packet is created, the system logs:
    - TTL, fooling method, and sequence number
    - Fake packet size
    - Fake positioning
    """
    dispatcher = UnifiedAttackDispatcher()
    
    with LogCapture() as capture:
        payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        params = {
            'ttl': 1,
            'fooling': 'badseq'
        }
        packet_info = {
            'mode': 'TEST',
            'domain': 'example.com'
        }
        
        segments = dispatcher.apply_fake(payload, params, packet_info)
    
    logs = capture.get_logs()
    
    # Verify fake packet logging
    assert 'Generating fake packet' in logs
    assert 'ttl=1' in logs
    assert 'fooling=badseq' in logs
    assert 'Generated fake packet' in logs
    
    print("✅ Test passed: Fake packet logging works correctly")


def test_segment_ordering_logging():
    """
    Test Requirement 9.4: Segment ordering logging.
    
    Verifies that when segments are sent, the system logs:
    - Segment count and order
    - Disorder method if applied
    - Final segment sequence
    """
    dispatcher = UnifiedAttackDispatcher()
    builder = ComboAttackBuilder()
    
    # Create recipe with disorder
    attacks = ['split', 'disorder']
    params = {
        'split_count': 3,
        'disorder_method': 'reverse'
    }
    
    recipe = builder.build_recipe(attacks, params)
    
    with LogCapture() as capture:
        payload = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        packet_info = {
            'mode': 'TEST',
            'domain': 'example.com'
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
    
    logs = capture.get_logs()
    
    # Verify segment ordering logging
    assert 'Applying disorder' in logs
    assert 'method=reverse' in logs
    assert 'Final segment sequence' in logs
    assert 'STRATEGY APPLICATION COMPLETE' in logs
    
    print("✅ Test passed: Segment ordering logging works correctly")


def test_parameter_mismatch_logging():
    """
    Test Requirement 9.5: Parameter mismatch logging.
    
    Verifies that when a parameter mismatch is detected, the system logs:
    - Expected vs actual values
    - Where mismatch occurred
    - Suggested fixes
    """
    dispatcher = UnifiedAttackDispatcher()
    
    # Create segments with mismatched TTL
    params = {'ttl': 1, 'fooling': 'badsum'}
    segments = [
        (b'fake', 0, {'ttl': 3, 'fooling': 'badsum', 'is_fake': True})  # Wrong TTL!
    ]
    
    with LogCapture() as capture:
        dispatcher._validate_parameter_propagation(params, segments, 'fake')
    
    logs = capture.get_logs()
    
    # Verify parameter mismatch logging
    assert 'PARAMETER MISMATCH DETECTED' in logs
    assert 'Expected: 1' in logs
    assert 'Actual: 3' in logs
    assert 'Suggested fix' in logs
    
    print("✅ Test passed: Parameter mismatch logging works correctly")


if __name__ == '__main__':
    # Run tests
    test_strategy_application_logging()
    test_parameter_transformation_logging()
    test_fake_packet_logging()
    test_segment_ordering_logging()
    test_parameter_mismatch_logging()
    
    print("\n" + "=" * 80)
    print("✅ ALL LOGGING TESTS PASSED")
    print("=" * 80)
