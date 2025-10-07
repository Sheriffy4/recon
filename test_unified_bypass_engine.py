#!/usr/bin/env python3
"""
Unit tests for UnifiedBypassEngine

Tests all functionality of the unified bypass engine wrapper:
1. Forced override application
2. No_fallbacks behavior
3. Strategy application
4. Testing mode compatibility
5. Service mode integration
6. Packet building consistency

Requirements tested:
- 1.2: Forced override creation for identical behavior
- 4.2: Strategy application with forced override
- 4.3: Packet building consistency
"""

import pytest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, Set

# Import the module under test
from core.unified_bypass_engine import (
    UnifiedBypassEngine,
    UnifiedEngineConfig,
    UnifiedBypassEngineError,
    create_unified_engine,
    create_service_mode_engine,
    create_testing_mode_engine
)

# Import related modules
from core.unified_strategy_loader import NormalizedStrategy


class TestUnifiedEngineConfig:
    """Test the UnifiedEngineConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = UnifiedEngineConfig()
        
        assert config.debug is True
        assert config.force_override is True  # CRITICAL: Must be True by default
        assert config.enable_diagnostics is True
        assert config.log_all_strategies is True
        assert config.track_forced_override is True
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = UnifiedEngineConfig(
            debug=False,
            force_override=True,  # Should always be True
            enable_diagnostics=False,
            log_all_strategies=False,
            track_forced_override=False
        )
        
        assert config.debug is False
        assert config.force_override is True  # CRITICAL: Always True
        assert config.enable_diagnostics is False
        assert config.log_all_strategies is False
        assert config.track_forced_override is False


class TestUnifiedBypassEngine:
    """Test the UnifiedBypassEngine class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Mock the underlying engine to avoid actual network operations
        with patch('core.unified_bypass_engine.WindowsBypassEngine') as mock_engine_class:
            self.mock_engine = Mock()
            mock_engine_class.return_value = self.mock_engine
            
            # Create engine with test configuration
            config = UnifiedEngineConfig(debug=True, force_override=True)
            self.engine = UnifiedBypassEngine(config)
    
    def test_engine_initialization(self):
        """Test engine initialization with forced override enabled."""
        assert self.engine.config.force_override is True  # CRITICAL
        assert self.engine.config.debug is True
        assert self.engine._forced_override_count == 0
        assert self.engine._running is False
        assert self.engine._start_time is None
        
        # Check that strategy loader is initialized
        assert self.engine.strategy_loader is not None
        
        # Check that underlying engine is initialized
        assert self.engine.engine is not None
    
    def test_engine_initialization_without_forced_override_warning(self):
        """Test that disabling forced override logs a warning."""
        with patch('core.unified_bypass_engine.WindowsBypassEngine'):
            config = UnifiedEngineConfig(force_override=False)  # Dangerous setting
            
            with patch('core.unified_bypass_engine.logging.getLogger') as mock_logger:
                mock_log = Mock()
                mock_logger.return_value = mock_log
                
                engine = UnifiedBypassEngine(config)
                
                # Should log warning about disabled forced override
                mock_log.warning.assert_called()
                warning_calls = [call for call in mock_log.warning.call_args_list 
                               if 'FORCED OVERRIDE: Disabled' in str(call)]
                assert len(warning_calls) > 0
    
    def test_start_with_strategy_map(self):
        """Test starting engine with strategy map."""
        target_ips = {'192.168.1.1', '10.0.0.1'}
        strategy_map = {
            'youtube.com': 'fakeddisorder(ttl=8, fooling=badsum)',
            'rutracker.org': '--dpi-desync=multisplit --dpi-desync-split-pos=2'
        }
        
        # Mock the underlying engine start method
        mock_thread = Mock(spec=threading.Thread)
        self.mock_engine.start.return_value = mock_thread
        
        # Start the engine
        thread = self.engine.start(target_ips, strategy_map)
        
        # Verify underlying engine was called
        self.mock_engine.start.assert_called_once()
        call_args = self.mock_engine.start.call_args
        
        # Check that target_ips were passed correctly
        assert call_args[1]['target_ips'] == target_ips
        
        # Check that strategies were normalized and forced override applied
        normalized_strategies = call_args[1]['strategy_map']
        assert len(normalized_strategies) == 2
        
        # All strategies should have forced override
        for strategy in normalized_strategies.values():
            assert strategy['no_fallbacks'] is True  # CRITICAL
            assert strategy['forced'] is True  # CRITICAL
            assert strategy['override_mode'] is True
        
        # Check that engine is marked as running
        assert self.engine.is_running() is True
        
        # Check that thread is returned
        assert thread == mock_thread
    
    def test_start_with_strategy_override(self):
        """Test starting engine with strategy override."""
        target_ips = {'192.168.1.1'}
        strategy_map = {'test.com': 'disorder()'}
        strategy_override = 'fakeddisorder(ttl=5)'
        
        mock_thread = Mock(spec=threading.Thread)
        self.mock_engine.start.return_value = mock_thread
        
        # Start with override
        thread = self.engine.start(target_ips, strategy_map, strategy_override=strategy_override)
        
        # Verify underlying engine was called with processed override
        self.mock_engine.start.assert_called_once()
        call_args = self.mock_engine.start.call_args
        
        processed_override = call_args[1]['strategy_override']
        assert processed_override is not None
        assert processed_override['type'] == 'fakeddisorder'
        assert processed_override['params']['ttl'] == 5
        assert processed_override['no_fallbacks'] is True  # CRITICAL
        assert processed_override['forced'] is True  # CRITICAL
    
    def test_start_with_config_service_mode(self):
        """Test starting engine in service mode."""
        config = {'test': 'config'}
        strategy_override = {'type': 'multisplit', 'params': {'split_pos': 2}}
        
        mock_thread = Mock(spec=threading.Thread)
        self.mock_engine.start_with_config.return_value = mock_thread
        
        # Start in service mode
        thread = self.engine.start_with_config(config, strategy_override)
        
        # Verify underlying engine was called
        self.mock_engine.start_with_config.assert_called_once()
        call_args = self.mock_engine.start_with_config.call_args
        
        # Check config was passed
        assert call_args[0][0] == config
        
        # Check strategy override was processed with forced override
        processed_override = call_args[1]['strategy_override']
        assert processed_override['no_fallbacks'] is True  # CRITICAL
        assert processed_override['forced'] is True  # CRITICAL
    
    def test_apply_strategy_with_forced_override(self):
        """Test applying strategy with forced override (CRITICAL test)."""
        target_ip = '192.168.1.1'
        strategy_input = 'fakeddisorder(ttl=8, fooling=badsum)'
        domain = 'youtube.com'
        
        # Mock strategy loader methods
        mock_strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8, 'fooling': 'badsum'},
            no_fallbacks=True,
            forced=True
        )
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                    forced_config = {
                        'type': 'fakeddisorder',
                        'params': {'ttl': 8, 'fooling': 'badsum'},
                        'no_fallbacks': True,
                        'forced': True,
                        'override_mode': True
                    }
                    mock_create_forced.return_value = forced_config
                    
                    # Apply strategy
                    result = self.engine.apply_strategy(target_ip, strategy_input, domain)
                    
                    # Verify success
                    assert result is True
                    
                    # Verify forced override was created
                    mock_create_forced.assert_called_once_with(mock_strategy)
                    
                    # Verify underlying engine received forced override
                    self.mock_engine.set_strategy_override.assert_called_once()
                    applied_config = self.mock_engine.set_strategy_override.call_args[0][0]
                    
                    # CRITICAL: Verify forced override parameters
                    assert applied_config['no_fallbacks'] is True
                    assert applied_config['forced'] is True
                    assert applied_config['type'] == 'fakeddisorder'
                    assert applied_config['params']['ttl'] == 8
                    
                    # Verify tracking
                    assert self.engine.get_forced_override_count() == 1
    
    def test_apply_strategy_failure_handling(self):
        """Test strategy application failure handling."""
        target_ip = '192.168.1.1'
        strategy_input = 'invalid_strategy_format'
        
        # Mock strategy loader to raise exception
        with patch.object(self.engine.strategy_loader, 'load_strategy', side_effect=Exception("Invalid strategy")):
            result = self.engine.apply_strategy(target_ip, strategy_input)
            
            # Should return False on failure
            assert result is False
            
            # Should not call underlying engine
            self.mock_engine.set_strategy_override.assert_not_called()
            
            # Should not increment forced override count
            assert self.engine.get_forced_override_count() == 0
    
    def test_ensure_testing_mode_compatibility(self):
        """Test that strategies are made compatible with testing mode."""
        forced_config = {
            'type': 'fakeddisorder',
            'params': {
                'ttl': 8,
                'fooling': 'badsum',  # String format
                'split_pos': '2'  # String that should be converted to int
            },
            'no_fallbacks': False,  # Should be forced to True
            'forced': False  # Should be forced to True
        }
        
        # Apply testing mode compatibility
        compatible_config = self.engine._ensure_testing_mode_compatibility(forced_config)
        
        # CRITICAL: Verify forced override flags
        assert compatible_config['no_fallbacks'] is True
        assert compatible_config['forced'] is True
        
        # Verify parameter normalization
        params = compatible_config['params']
        assert isinstance(params['split_pos'], int)
        assert params['split_pos'] == 2
        
        # Verify fooling parameter is converted to list (matches testing mode)
        assert isinstance(params['fooling'], list)
        assert params['fooling'] == ['badsum']
        
        # Verify fake_ttl is set for fake attacks
        assert 'fake_ttl' in params
        assert params['fake_ttl'] == 8
        
        # Verify TCP flags are set
        assert 'tcp_flags' in params
        assert params['tcp_flags'] == {'psh': True, 'ack': True}
        
        # Verify window division is set
        assert 'window_div' in params
        assert params['window_div'] == 8  # For fakeddisorder
    
    def test_test_strategy_like_testing_mode(self):
        """Test strategy testing that mimics testing mode exactly."""
        target_ip = '192.168.1.1'
        strategy_input = 'multisplit(split_pos=2)'
        domain = 'test.com'
        
        # Mock strategy loading
        mock_strategy = NormalizedStrategy(
            type='multisplit',
            params={'split_pos': 2},
            no_fallbacks=True,
            forced=True
        )
        
        # Mock telemetry
        baseline_telemetry = {'aggregate': {'segments_sent': 0, 'fake_packets_sent': 0}}
        final_telemetry = {'aggregate': {'segments_sent': 5, 'fake_packets_sent': 2}}
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                    with patch.object(self.engine, '_simulate_testing_mode_connection', return_value=True):
                        with patch.object(self.engine.engine, 'get_telemetry_snapshot', side_effect=[baseline_telemetry, final_telemetry]):
                            
                            forced_config = {
                                'type': 'multisplit',
                                'params': {'split_pos': 2},
                                'no_fallbacks': True,
                                'forced': True,
                                'override_mode': True
                            }
                            mock_create_forced.return_value = forced_config
                            
                            # Test strategy like testing mode
                            result = self.engine.test_strategy_like_testing_mode(target_ip, strategy_input, domain)
                            
                            # Verify result structure
                            assert result['success'] is True
                            assert result['strategy_type'] == 'multisplit'
                            assert result['target_ip'] == target_ip
                            assert result['domain'] == domain
                            assert result['forced_override'] is True
                            assert result['no_fallbacks'] is True
                            
                            # Verify telemetry delta calculation
                            assert 'telemetry_delta' in result
                            delta = result['telemetry_delta']
                            assert delta['segments_sent'] == 5
                            assert delta['fake_packets_sent'] == 2
                            
                            # Verify strategy was applied with forced override
                            self.mock_engine.set_strategy_override.assert_called_once()
    
    def test_stop_engine(self):
        """Test stopping the engine."""
        # Start engine first
        self.engine._running = True
        self.engine._start_time = time.time()
        
        # Stop engine
        self.engine.stop()
        
        # Verify engine is stopped
        assert self.engine.is_running() is False
        
        # Verify underlying engine stop was called
        self.mock_engine.stop.assert_called_once()
    
    def test_debug_mode_toggle(self):
        """Test enabling and disabling debug mode."""
        # Initially debug should be enabled
        assert self.engine.config.debug is True
        
        # Disable debug mode
        self.engine.disable_debug_mode()
        assert self.engine.config.debug is False
        assert self.engine.config.enable_diagnostics is False
        assert self.engine.config.log_all_strategies is False
        
        # Enable debug mode
        self.engine.enable_debug_mode()
        assert self.engine.config.debug is True
        assert self.engine.config.enable_diagnostics is True
        assert self.engine.config.log_all_strategies is True
        assert self.engine.config.track_forced_override is True
    
    def test_diagnostics_report_generation(self):
        """Test generating diagnostics report."""
        # Set up some test data
        self.engine._running = True
        self.engine._start_time = time.time() - 10  # 10 seconds ago
        self.engine._forced_override_count = 5
        
        # Add some strategy applications
        self.engine._strategy_applications = {
            'test1.com': [
                {'strategy_type': 'fakeddisorder', 'timestamp': time.time(), 'forced_override': True, 'success': True},
                {'strategy_type': 'multisplit', 'timestamp': time.time(), 'forced_override': True, 'success': False}
            ],
            'test2.com': [
                {'strategy_type': 'disorder', 'timestamp': time.time(), 'forced_override': True, 'success': True}
            ]
        }
        
        # Mock engine telemetry
        mock_telemetry = {'test': 'telemetry'}
        with patch.object(self.engine, 'get_telemetry_snapshot', return_value=mock_telemetry):
            
            report = self.engine.get_diagnostics_report()
            
            # Verify report structure
            assert 'unified_engine_diagnostics' in report
            assert 'engine_telemetry' in report
            assert 'timestamp' in report
            
            diag = report['unified_engine_diagnostics']
            
            # Verify diagnostics data
            assert diag['running'] is True
            assert diag['forced_override_count'] == 5
            assert diag['strategy_applications_count'] == 3
            assert diag['unique_targets'] == 2
            assert diag['total_tests'] == 3
            assert diag['successful_tests'] == 2
            assert diag['test_success_rate'] == 2/3 * 100  # 66.67%
            
            # Verify strategy type distribution
            expected_distribution = {'fakeddisorder': 1, 'multisplit': 1, 'disorder': 1}
            assert diag['strategy_type_distribution'] == expected_distribution
            
            # Verify configuration
            config = diag['configuration']
            assert config['force_override'] is True  # CRITICAL
            assert config['debug'] is True
    
    def test_validate_forced_override_behavior(self):
        """Test validation of forced override behavior."""
        # Set up test data with all forced overrides
        self.engine._strategy_applications = {
            'test1.com': [
                {'strategy_type': 'fakeddisorder', 'forced_override': True},
                {'strategy_type': 'multisplit', 'forced_override': True}
            ],
            'test2.com': [
                {'strategy_type': 'disorder', 'forced_override': True}
            ]
        }
        
        validation = self.engine.validate_forced_override_behavior()
        
        # Should pass all validations
        assert validation['forced_override_enabled'] is True
        assert validation['all_strategies_forced'] is True
        assert validation['no_fallbacks_enforced'] is True
        assert len(validation['issues']) == 0
    
    def test_validate_forced_override_behavior_with_issues(self):
        """Test validation detects forced override issues."""
        # Set up test data with some non-forced strategies
        self.engine._strategy_applications = {
            'test1.com': [
                {'strategy_type': 'fakeddisorder', 'forced_override': True},
                {'strategy_type': 'multisplit', 'forced_override': False}  # Issue!
            ]
        }
        
        validation = self.engine.validate_forced_override_behavior()
        
        # Should detect issues
        assert validation['all_strategies_forced'] is False
        assert len(validation['issues']) > 0
        assert any('not applied with forced override' in issue for issue in validation['issues'])
    
    def test_get_strategy_loader(self):
        """Test getting the strategy loader instance."""
        loader = self.engine.get_strategy_loader()
        assert loader is self.engine.strategy_loader
    
    def test_get_underlying_engine(self):
        """Test getting the underlying engine instance."""
        engine = self.engine.get_underlying_engine()
        assert engine is self.engine.engine
    
    def test_forced_override_count_tracking(self):
        """Test that forced override count is tracked correctly."""
        initial_count = self.engine.get_forced_override_count()
        assert initial_count == 0
        
        # Simulate strategy applications
        self.engine.track_forced_override_usage('fakeddisorder', 'test1.com')
        self.engine.track_forced_override_usage('multisplit', 'test2.com')
        
        final_count = self.engine.get_forced_override_count()
        assert final_count == 2


class TestConvenienceFunctions:
    """Test convenience functions for creating engines."""
    
    @patch('core.unified_bypass_engine.WindowsBypassEngine')
    def test_create_unified_engine(self, mock_engine_class):
        """Test creating unified engine with convenience function."""
        engine = create_unified_engine(debug=True, force_override=True)
        
        assert isinstance(engine, UnifiedBypassEngine)
        assert engine.config.debug is True
        assert engine.config.force_override is True  # CRITICAL
        assert engine.config.enable_diagnostics is True
        assert engine.config.log_all_strategies is True
        assert engine.config.track_forced_override is True
    
    @patch('core.unified_bypass_engine.WindowsBypassEngine')
    def test_create_service_mode_engine(self, mock_engine_class):
        """Test creating service mode engine."""
        engine = create_service_mode_engine(debug=False)
        
        assert isinstance(engine, UnifiedBypassEngine)
        assert engine.config.debug is False
        assert engine.config.force_override is True  # CRITICAL: Always True
        assert engine.config.enable_diagnostics is False  # Reduced for service mode
        assert engine.config.log_all_strategies is False
        assert engine.config.track_forced_override is True
    
    @patch('core.unified_bypass_engine.WindowsBypassEngine')
    def test_create_testing_mode_engine(self, mock_engine_class):
        """Test creating testing mode engine."""
        engine = create_testing_mode_engine(debug=True)
        
        assert isinstance(engine, UnifiedBypassEngine)
        assert engine.config.debug is True
        assert engine.config.force_override is True  # CRITICAL: Always True
        assert engine.config.enable_diagnostics is True
        assert engine.config.log_all_strategies is True
        assert engine.config.track_forced_override is True


class TestCriticalBehavior:
    """Test critical behavior requirements."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('core.unified_bypass_engine.WindowsBypassEngine') as mock_engine_class:
            self.mock_engine = Mock()
            mock_engine_class.return_value = self.mock_engine
            
            config = UnifiedEngineConfig(debug=True, force_override=True)
            self.engine = UnifiedBypassEngine(config)
    
    def test_forced_override_always_enabled_requirement_1_2(self):
        """Test that forced override is ALWAYS enabled (Requirement 1.2)."""
        # Test different strategy formats
        test_strategies = [
            'fakeddisorder(ttl=8)',
            '--dpi-desync=multisplit --dpi-desync-split-pos=2',
            {'type': 'disorder', 'params': {'repeats': 2}}
        ]
        
        for strategy_input in test_strategies:
            # Mock strategy loading
            mock_strategy = NormalizedStrategy(
                type='test',
                params={},
                no_fallbacks=True,
                forced=True
            )
            
            with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
                with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                    with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                        forced_config = {
                            'type': 'test',
                            'params': {},
                            'no_fallbacks': True,  # CRITICAL
                            'forced': True,        # CRITICAL
                            'override_mode': True
                        }
                        mock_create_forced.return_value = forced_config
                        
                        # Apply strategy
                        result = self.engine.apply_strategy('192.168.1.1', strategy_input)
                        
                        # Verify forced override was applied
                        assert result is True
                        mock_create_forced.assert_called_once_with(mock_strategy)
                        
                        # Verify underlying engine received forced config
                        self.mock_engine.set_strategy_override.assert_called()
                        applied_config = self.mock_engine.set_strategy_override.call_args[0][0]
                        
                        # CRITICAL: These must ALWAYS be True
                        assert applied_config['no_fallbacks'] is True
                        assert applied_config['forced'] is True
                        
                        # Reset mocks for next iteration
                        self.mock_engine.reset_mock()
    
    def test_no_fallbacks_behavior_requirement_4_2(self):
        """Test that no_fallbacks behavior is enforced (Requirement 4.2)."""
        # Test strategy that might normally use fallbacks
        strategy_input = 'complex_strategy_that_might_fail(param1=value1)'
        
        mock_strategy = NormalizedStrategy(
            type='complex_strategy_that_might_fail',
            params={'param1': 'value1'},
            no_fallbacks=True,
            forced=True
        )
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                    forced_config = {
                        'type': 'complex_strategy_that_might_fail',
                        'params': {'param1': 'value1'},
                        'no_fallbacks': True,  # CRITICAL: Must be True
                        'forced': True,
                        'override_mode': True
                    }
                    mock_create_forced.return_value = forced_config
                    
                    # Apply strategy
                    result = self.engine.apply_strategy('192.168.1.1', strategy_input)
                    
                    # Verify no_fallbacks is enforced
                    assert result is True
                    applied_config = self.mock_engine.set_strategy_override.call_args[0][0]
                    assert applied_config['no_fallbacks'] is True
                    
                    # Verify that testing mode compatibility ensures no_fallbacks
                    compatible_config = self.engine._ensure_testing_mode_compatibility(applied_config)
                    assert compatible_config['no_fallbacks'] is True
    
    def test_packet_building_consistency_requirement_4_3(self):
        """Test that packet building parameters are consistent (Requirement 4.3)."""
        strategy_input = 'fakeddisorder(ttl=8, fooling=badsum)'
        
        mock_strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 8, 'fooling': 'badsum'},
            no_fallbacks=True,
            forced=True
        )
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                    base_forced_config = {
                        'type': 'fakeddisorder',
                        'params': {'ttl': 8, 'fooling': 'badsum'},
                        'no_fallbacks': True,
                        'forced': True,
                        'override_mode': True
                    }
                    mock_create_forced.return_value = base_forced_config
                    
                    # Apply strategy
                    result = self.engine.apply_strategy('192.168.1.1', strategy_input)
                    
                    # Get the final configuration sent to engine
                    applied_config = self.mock_engine.set_strategy_override.call_args[0][0]
                    params = applied_config['params']
                    
                    # Verify packet building parameters are set consistently
                    assert 'tcp_flags' in params
                    assert params['tcp_flags'] == {'psh': True, 'ack': True}
                    
                    assert 'window_div' in params
                    assert params['window_div'] == 8  # For fakeddisorder
                    
                    assert 'ipid_step' in params
                    assert params['ipid_step'] == 2048
                    
                    # Verify fake_ttl is set for fake attacks
                    assert 'fake_ttl' in params
                    assert params['fake_ttl'] == 8
                    
                    # Verify fooling is normalized to list format
                    assert isinstance(params['fooling'], list)
                    assert params['fooling'] == ['badsum']
    
    def test_identical_behavior_across_modes(self):
        """Test that service mode and testing mode produce identical configurations."""
        strategy_input = 'multisplit(split_pos=2, repeats=3)'
        
        mock_strategy = NormalizedStrategy(
            type='multisplit',
            params={'split_pos': 2, 'repeats': 3},
            no_fallbacks=True,
            forced=True
        )
        
        # Test both service mode and testing mode engines
        with patch('core.unified_bypass_engine.WindowsBypassEngine'):
            service_engine = create_service_mode_engine()
            testing_engine = create_testing_mode_engine()
            
            # Mock strategy loading for both engines
            for engine in [service_engine, testing_engine]:
                with patch.object(engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
                    with patch.object(engine.strategy_loader, 'validate_strategy', return_value=True):
                        with patch.object(engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                            forced_config = {
                                'type': 'multisplit',
                                'params': {'split_pos': 2, 'repeats': 3},
                                'no_fallbacks': True,
                                'forced': True,
                                'override_mode': True
                            }
                            mock_create_forced.return_value = forced_config
                            
                            # Apply strategy
                            result = engine.apply_strategy('192.168.1.1', strategy_input)
                            assert result is True
                            
                            # Get applied configuration
                            applied_config = engine.engine.set_strategy_override.call_args[0][0]
                            
                            # Both modes should produce identical configurations
                            assert applied_config['no_fallbacks'] is True
                            assert applied_config['forced'] is True
                            assert applied_config['type'] == 'multisplit'
                            assert applied_config['params']['split_pos'] == 2
                            assert applied_config['params']['repeats'] == 3


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('core.unified_bypass_engine.WindowsBypassEngine') as mock_engine_class:
            self.mock_engine = Mock()
            mock_engine_class.return_value = self.mock_engine
            
            config = UnifiedEngineConfig(debug=True, force_override=True)
            self.engine = UnifiedBypassEngine(config)
    
    def test_strategy_loading_error_handling(self):
        """Test handling of strategy loading errors."""
        strategy_input = 'invalid_strategy_format'
        
        # Mock strategy loader to raise exception
        with patch.object(self.engine.strategy_loader, 'load_strategy', side_effect=Exception("Invalid format")):
            result = self.engine.apply_strategy('192.168.1.1', strategy_input)
            
            # Should handle error gracefully
            assert result is False
            
            # Should not call underlying engine
            self.mock_engine.set_strategy_override.assert_not_called()
    
    def test_strategy_validation_error_handling(self):
        """Test handling of strategy validation errors."""
        strategy_input = 'fakeddisorder(ttl=999)'  # Invalid TTL
        
        mock_strategy = NormalizedStrategy(
            type='fakeddisorder',
            params={'ttl': 999},
            no_fallbacks=True,
            forced=True
        )
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', return_value=mock_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', side_effect=Exception("Invalid TTL")):
                result = self.engine.apply_strategy('192.168.1.1', strategy_input)
                
                # Should handle validation error gracefully
                assert result is False
                
                # Should not call underlying engine
                self.mock_engine.set_strategy_override.assert_not_called()
    
    def test_engine_start_with_invalid_strategies(self):
        """Test starting engine with some invalid strategies."""
        target_ips = {'192.168.1.1'}
        strategy_map = {
            'valid.com': 'fakeddisorder(ttl=8)',
            'invalid.com': 'completely_invalid_format',
            'another_valid.com': 'disorder()'
        }
        
        mock_thread = Mock(spec=threading.Thread)
        self.mock_engine.start.return_value = mock_thread
        
        # Mock strategy loading to fail for invalid strategy
        def mock_load_strategy(strategy_input):
            if 'completely_invalid_format' in str(strategy_input):
                raise Exception("Invalid format")
            return NormalizedStrategy(
                type='test',
                params={},
                no_fallbacks=True,
                forced=True
            )
        
        with patch.object(self.engine.strategy_loader, 'load_strategy', side_effect=mock_load_strategy):
            with patch.object(self.engine.strategy_loader, 'validate_strategy', return_value=True):
                with patch.object(self.engine.strategy_loader, 'create_forced_override') as mock_create_forced:
                    mock_create_forced.return_value = {
                        'type': 'test',
                        'params': {},
                        'no_fallbacks': True,
                        'forced': True,
                        'override_mode': True
                    }
                    
                    # Start engine
                    thread = self.engine.start(target_ips, strategy_map)
                    
                    # Should start successfully despite invalid strategy
                    assert thread == mock_thread
                    
                    # Should only process valid strategies
                    call_args = self.mock_engine.start.call_args
                    normalized_strategies = call_args[1]['strategy_map']
                    
                    # Should have 2 valid strategies (invalid one skipped)
                    assert len(normalized_strategies) == 2
                    assert 'valid.com' in normalized_strategies
                    assert 'another_valid.com' in normalized_strategies
                    assert 'invalid.com' not in normalized_strategies


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])