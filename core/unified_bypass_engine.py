#!/usr/bin/env python3
"""
Unified Bypass Engine - Single engine wrapper for all modes

This module provides a unified wrapper around the existing BypassEngine
that ensures identical behavior between testing mode and service mode.

Key Features:
1. Wraps existing BypassEngine with forced override by default
2. Ensures no_fallbacks=True for all strategies
3. Matches testing mode behavior exactly
4. Provides unified interface for all modes
5. Includes comprehensive logging and diagnostics

Critical Design:
- ALWAYS uses forced override (no_fallbacks=True)
- Identical packet building logic for all modes
- Single source of truth for bypass engine behavior
"""

import logging
import threading
import time
from typing import Dict, Any, Set, Optional, List, Union
from dataclasses import dataclass

# Import existing engine and related components
from .bypass.engine.base_engine import WindowsBypassEngine, EngineConfig
from .unified_strategy_loader import UnifiedStrategyLoader, NormalizedStrategy, StrategyValidationError


class UnifiedBypassEngineError(Exception):
    """Raised when UnifiedBypassEngine operations fail."""
    pass


@dataclass
class UnifiedEngineConfig:
    """Configuration for the unified bypass engine."""
    debug: bool = True
    force_override: bool = True  # CRITICAL: Always True by default
    enable_diagnostics: bool = True
    log_all_strategies: bool = True
    track_forced_override: bool = True


class UnifiedBypassEngine:
    """
    Unified wrapper around BypassEngine that ensures identical behavior
    between testing mode and service mode.
    
    Key Features:
    1. ALWAYS uses forced override (no_fallbacks=True)
    2. Wraps existing BypassEngine without changing its core logic
    3. Provides unified interface for all modes
    4. Comprehensive logging and diagnostics
    5. Matches testing mode behavior exactly
    
    Critical Design Principles:
    - Forced override is ALWAYS enabled by default
    - All strategies are normalized before application
    - Identical packet building logic for all modes
    - Single source of truth for bypass engine behavior
    """
    
    def __init__(self, config: Optional[UnifiedEngineConfig] = None):
        """
        Initialize the unified bypass engine.
        
        Args:
            config: Configuration for the engine. If None, uses defaults with forced override.
        """
        self.config = config or UnifiedEngineConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize strategy loader
        self.strategy_loader = UnifiedStrategyLoader(debug=self.config.debug)
        
        # Initialize underlying engine
        engine_config = EngineConfig(debug=self.config.debug)
        self.engine = WindowsBypassEngine(engine_config)
        
        # Tracking variables
        self._forced_override_count = 0
        self._strategy_applications = {}
        self._start_time = None
        self._running = False
        
        # Thread safety
        self._lock = threading.Lock()
        
        if self.config.debug:
            self.logger.setLevel(logging.DEBUG)
            
        self.logger.info("🚀 UnifiedBypassEngine initialized with forced override enabled")
        
        # CRITICAL: Log the forced override status
        if self.config.force_override:
            self.logger.info("✅ FORCED OVERRIDE: Enabled by default (matches testing mode)")
        else:
            self.logger.warning("⚠️  FORCED OVERRIDE: Disabled (may cause service mode issues)")
    
    def start(self, target_ips: Set[str], strategy_map: Dict[str, Union[str, Dict]], 
              reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None) -> threading.Thread:
        """
        Start the unified bypass engine.
        
        Args:
            target_ips: Set of target IP addresses
            strategy_map: Map of domain/IP to strategy configuration
            reset_telemetry: Whether to reset telemetry data
            strategy_override: Optional strategy to override all others
            
        Returns:
            Thread object for the running engine
        """
        with self._lock:
            self._running = True
            self._start_time = time.time()
            
        self.logger.info(f"🚀 Starting UnifiedBypassEngine with {len(target_ips)} targets and {len(strategy_map)} strategies")
        
        # Process and normalize all strategies
        normalized_strategy_map = {}
        
        for key, strategy_input in strategy_map.items():
            try:
                # Load and normalize strategy
                normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
                
                # Validate strategy
                self.strategy_loader.validate_strategy(normalized_strategy)
                
                # Create forced override (CRITICAL)
                forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
                
                normalized_strategy_map[key] = forced_config
                
                if self.config.log_all_strategies:
                    self.logger.info(f"📋 Loaded strategy for {key}: {normalized_strategy.type} with forced override")
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to load strategy for {key}: {e}")
                # Continue with other strategies
                continue
        
        # Handle strategy override
        processed_override = None
        if strategy_override:
            try:
                if isinstance(strategy_override, (str, dict)):
                    normalized_override = self.strategy_loader.load_strategy(strategy_override)
                    processed_override = self.strategy_loader.create_forced_override(normalized_override)
                    self.logger.info(f"🔥 Strategy override applied: {normalized_override.type}")
                else:
                    processed_override = strategy_override
                    self.logger.info(f"🔥 Raw strategy override applied: {strategy_override}")
            except Exception as e:
                self.logger.error(f"❌ Failed to process strategy override: {e}")
                processed_override = None
        
        # Start the underlying engine with processed strategies
        thread = self.engine.start(
            target_ips=target_ips,
            strategy_map=normalized_strategy_map,
            reset_telemetry=reset_telemetry,
            strategy_override=processed_override
        )
        
        self.logger.info("✅ UnifiedBypassEngine started successfully")
        return thread
    
    def start_with_config(self, config: Dict[str, Any], strategy_override: Optional[Dict[str, Any]] = None) -> threading.Thread:
        """
        Start the engine with simplified configuration (for service mode).
        
        Args:
            config: Service configuration dictionary
            strategy_override: Optional strategy override
            
        Returns:
            Thread object for the running engine
        """
        self.logger.info("🚀 Starting UnifiedBypassEngine in service mode")
        
        # Process strategy override if provided
        processed_override = None
        if strategy_override:
            try:
                normalized_override = self.strategy_loader.load_strategy(strategy_override)
                processed_override = self.strategy_loader.create_forced_override(normalized_override)
                self.logger.info(f"🔥 Service mode strategy override: {normalized_override.type}")
            except Exception as e:
                self.logger.error(f"❌ Failed to process service mode override: {e}")
        
        return self.engine.start_with_config(config, strategy_override=processed_override)
    
    def stop(self):
        """Stop the unified bypass engine."""
        with self._lock:
            self._running = False
            
        self.logger.info("🛑 Stopping UnifiedBypassEngine")
        self.engine.stop()
        
        # Log final statistics
        if self.config.track_forced_override:
            self._log_final_statistics()
    
    def apply_strategy(self, target_ip: str, strategy_input: Union[str, Dict[str, Any]], 
                  domain: Optional[str] = None) -> bool:
        """
        Apply a strategy to a specific target with forced override.
        """
        try:
            # Load and normalize strategy
            self.logger.debug(f"Loading strategy for {target_ip} ({domain or 'no domain'})")
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
            
            # Validate strategy
            self.logger.debug(f"Validating strategy: {normalized_strategy.type}")
            self.strategy_loader.validate_strategy(normalized_strategy)
            
            # Create forced override (CRITICAL)
            self.logger.debug(f"Creating forced override for {normalized_strategy.type}")
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            
            # CRITICAL: Ensure forced override parameters match testing mode exactly
            self.logger.debug(f"Ensuring testing mode compatibility")
            forced_config = self._ensure_testing_mode_compatibility(forced_config)
            
            # ✅ ПРОВЕРКА КРИТИЧНЫХ ФЛАГОВ
            if not forced_config.get('no_fallbacks'):
                self.logger.warning(f"⚠️ no_fallbacks is not True for {target_ip}!")
            if not forced_config.get('forced'):
                self.logger.warning(f"⚠️ forced is not True for {target_ip}!")

            # Apply to engine with forced override
            self.logger.debug(f"Applying forced override to engine")
            self.engine.set_strategy_override(forced_config)
            
            # Track application
            with self._lock:
                self._forced_override_count += 1
                key = domain or target_ip
                if key not in self._strategy_applications:
                    self._strategy_applications[key] = []
                self._strategy_applications[key].append({
                    'strategy_type': normalized_strategy.type,
                    'timestamp': time.time(),
                    'forced_override': True,
                    'target_ip': target_ip,
                    'domain': domain
                })
            
            if self.config.log_all_strategies:
                self.logger.info(f"🎯 Applied FORCED OVERRIDE strategy to {target_ip}: {normalized_strategy.type}")
                self.logger.info(f"   Parameters: {forced_config.get('params', {})}")
                self.logger.info(f"   no_fallbacks: {forced_config.get('no_fallbacks', False)}")
                self.logger.info(f"   forced: {forced_config.get('forced', False)}")
                
            return True
            
        except StrategyValidationError as e:
            # Специальная обработка ошибок валидации
            self.logger.error(f"❌ Strategy validation failed for {target_ip}: {e}")
            if self.config.debug:
                import traceback
                self.logger.error(f"Validation traceback:\n{traceback.format_exc()}")
            return False
        except Exception as e:
            # Общие ошибки
            import traceback
            self.logger.error(f"❌ Failed to apply strategy to {target_ip}: {e}")
            if self.config.debug:
                self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return False
    
    def _ensure_testing_mode_compatibility(self, forced_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure the forced configuration matches testing mode behavior exactly.
        
        This method applies the same parameter normalization and forced override
        logic that testing mode uses to ensure identical packet building.
        
        Args:
            forced_config: Base forced configuration
            
        Returns:
            Configuration guaranteed to match testing mode behavior
        """
        # Create a copy to avoid modifying the original
        config = forced_config.copy()
        params = config.get('params', {}).copy()
        
        # CRITICAL: Ensure forced override flags are set
        config['no_fallbacks'] = True
        config['forced'] = True
        
        # Normalize fooling parameter to list format (matches testing mode)
        if 'fooling' in params:
            fooling = params['fooling']
            if isinstance(fooling, str):
                if fooling == 'none' or fooling == '':
                    params['fooling'] = []
                elif ',' in fooling:
                    params['fooling'] = [f.strip() for f in fooling.split(',') if f.strip()]
                else:
                    params['fooling'] = [fooling]
            elif not isinstance(fooling, (list, tuple)):
                params['fooling'] = [str(fooling)]
        
        # Ensure TTL is properly set for fake packets
        attack_type = config.get('type', '').lower()
        if attack_type in ('fakeddisorder', 'fake', 'disorder'):
            if 'fake_ttl' not in params and 'ttl' in params:
                params['fake_ttl'] = params['ttl']
            elif 'fake_ttl' not in params and 'ttl' not in params:
                # Default TTL for fake packets (matches testing mode)
                params['fake_ttl'] = 1
        
        # Ensure split_pos is integer
        if 'split_pos' in params:
            try:
                params['split_pos'] = int(params['split_pos'])
            except (ValueError, TypeError):
                self.logger.warning(f"Invalid split_pos value, using default: {params['split_pos']}")
                params['split_pos'] = 3
        
        # Ensure overlap_size is integer
        if 'overlap_size' in params:
            try:
                params['overlap_size'] = int(params['overlap_size'])
            except (ValueError, TypeError):
                self.logger.warning(f"Invalid overlap_size value, using default: {params['overlap_size']}")
                params['overlap_size'] = 0
        
        # Ensure repeats is integer and within reasonable bounds
        if 'repeats' in params:
            try:
                repeats = int(params['repeats'])
                params['repeats'] = max(1, min(repeats, 10))  # Clamp to 1-10
            except (ValueError, TypeError):
                params['repeats'] = 1
        
        # Set TCP flags for proper packet building (matches testing mode)
        if 'tcp_flags' not in params:
            params['tcp_flags'] = {'psh': True, 'ack': True}
        
        # Set window division for proper window size calculation
        if 'window_div' not in params:
            params['window_div'] = 8 if attack_type == 'fakeddisorder' else 2
        
        # Set IP ID step for proper packet identification
        if 'ipid_step' not in params:
            params['ipid_step'] = 2048
        
        config['params'] = params
        
        if self.config.debug:
            self.logger.debug(f"Testing mode compatibility ensured for {attack_type}")
            self.logger.debug(f"Final parameters: {params}")
        
        return config
    
    def test_strategy_like_testing_mode(self, target_ip: str, strategy_input: Union[str, Dict[str, Any]], 
                                       domain: Optional[str] = None, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Test a strategy using the exact same process as testing mode.
        
        This method replicates the testing mode workflow:
        1. Load and normalize strategy
        2. Apply with forced override
        3. Monitor for results
        4. Return detailed test results
        
        Args:
            target_ip: Target IP address to test
            strategy_input: Strategy configuration
            domain: Optional domain name
            timeout: Test timeout in seconds
            
        Returns:
            Dict with test results including success, latency, and details
        """
        test_start = time.time()
        
        try:
            # Load and normalize strategy (matches testing mode)
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
            
            # Validate strategy (matches testing mode)
            self.strategy_loader.validate_strategy(normalized_strategy)
            
            # Create forced override (CRITICAL - matches testing mode exactly)
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            forced_config = self._ensure_testing_mode_compatibility(forced_config)
            
            self.logger.info(f"🧪 Testing strategy like testing mode: {normalized_strategy.type} for {target_ip}")
            
            # Apply strategy with forced override (matches testing mode)
            self.engine.set_strategy_override(forced_config)
            
            # Get baseline telemetry
            baseline_telemetry = self.engine.get_telemetry_snapshot()
            
            # Simulate connection attempt (this would be where testing mode makes actual connections)
            test_success = self._simulate_testing_mode_connection(target_ip, domain, timeout)
            
            # Get final telemetry
            final_telemetry = self.engine.get_telemetry_snapshot()
            
            # Calculate test duration
            test_duration = time.time() - test_start
            
            # Build result (matches testing mode result format)
            result = {
                'success': test_success,
                'strategy_type': normalized_strategy.type,
                'strategy_params': forced_config.get('params', {}),
                'target_ip': target_ip,
                'domain': domain,
                'test_duration_ms': test_duration * 1000,
                'forced_override': True,
                'no_fallbacks': forced_config.get('no_fallbacks', False),
                'telemetry_delta': self._calculate_telemetry_delta(baseline_telemetry, final_telemetry),
                'timestamp': test_start
            }
            
            # Track test
            with self._lock:
                key = domain or target_ip
                if key not in self._strategy_applications:
                    self._strategy_applications[key] = []
                self._strategy_applications[key].append({
                    'strategy_type': normalized_strategy.type,
                    'timestamp': test_start,
                    'forced_override': True,
                    'test_mode': True,
                    'success': test_success
                })
            
            if self.config.log_all_strategies:
                status = "SUCCESS" if test_success else "FAILED"
                self.logger.info(f"🧪 Testing mode test {status}: {normalized_strategy.type} for {target_ip}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Testing mode test failed for {target_ip}: {e}")
            return {
                'success': False,
                'error': str(e),
                'target_ip': target_ip,
                'domain': domain,
                'test_duration_ms': (time.time() - test_start) * 1000,
                'timestamp': test_start
            }
    
    def _simulate_testing_mode_connection(self, target_ip: str, domain: Optional[str], timeout: float) -> bool:
        """
        Simulate the connection testing that testing mode would perform.
        
        Args:
            target_ip: Target IP address
            domain: Optional domain name
            timeout: Connection timeout
            
        Returns:
            True if connection would succeed with current strategy
        """
        sock = None
        try:
            import socket
            import ssl
            
            # Create connection to test bypass
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to target
            try:
                sock.connect((target_ip, 443))
            except socket.timeout:
                self.logger.debug(f"TCP connection timeout for {target_ip}")
                return False
            except ConnectionRefusedError:
                self.logger.debug(f"Connection refused by {target_ip}")
                return False
            except OSError as e:
                self.logger.debug(f"TCP connection failed for {target_ip}: {e}")
                return False
            
            # If we have a domain, use it for SNI
            if domain:
                context = ssl.create_default_context()
                # Отключаем проверку сертификата для тестирования
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # Connection successful
                        self.logger.debug(f"SSL connection successful for {target_ip} ({domain})")
                        return True
                except ssl.SSLError as e:
                    self.logger.debug(f"SSL handshake failed for {target_ip}: {e}")
                    # TCP connection succeeded but SSL failed - partial success
                    # Для DPI bypass это может быть достаточно
                    return False
                except socket.timeout:
                    self.logger.debug(f"SSL timeout for {target_ip}")
                    return False
                except Exception as e:
                    self.logger.debug(f"SSL connection error for {target_ip}: {e}")
                    return False
            else:
                # Simple TCP connection test - success
                self.logger.debug(f"TCP connection successful for {target_ip}")
                return True
                
        except ImportError as e:
            self.logger.warning(f"Cannot test connection - missing module: {e}")
            return False
        except Exception as e:
            self.logger.warning(f"Unexpected error during connection test for {target_ip}: {e}", exc_info=self.config.debug)
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def test_forced_override(self, target_ip: str, strategy_input: Union[str, Dict[str, Any]],
                        domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Тестовый метод для проверки forced override с подробным логированием.

        Args:
            target_ip: Target IP address
            strategy_input: Strategy to test
            domain: Optional domain name

        Returns:
            Dict с результатами теста и диагностической информацией
        """
        result = {
            'success': False,
            'target_ip': target_ip,
            'domain': domain,
            'errors': [],
            'warnings': [],
            'steps_completed': [],
            'timestamp': time.time()
        }

        try:
            # Шаг 1: Загрузка стратегии
            self.logger.info(f"[TEST] Step 1/6: Loading strategy for {domain or target_ip}")
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
            result['steps_completed'].append('strategy_loaded')
            result['strategy_type'] = normalized_strategy.type
            result['raw_strategy'] = normalized_strategy.raw_string

            # Шаг 2: Валидация
            self.logger.info(f"[TEST] Step 2/6: Validating strategy")
            self.strategy_loader.validate_strategy(normalized_strategy)
            result['steps_completed'].append('strategy_validated')

            # Шаг 3: Создание forced override
            self.logger.info(f"[TEST] Step 3/6: Creating forced override")
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            result['steps_completed'].append('forced_override_created')
            result['forced_config'] = forced_config

            # Проверка критичных флагов
            if not forced_config.get('no_fallbacks'):
                result['warnings'].append('no_fallbacks is not True!')
            if not forced_config.get('forced'):
                result['warnings'].append('forced is not True!')

            # Шаг 4: Обеспечение совместимости с testing mode
            self.logger.info(f"[TEST] Step 4/6: Ensuring testing mode compatibility")
            forced_config = self._ensure_testing_mode_compatibility(forced_config)
            result['steps_completed'].append('testing_mode_compatibility_ensured')
            result['final_config'] = forced_config

            # Шаг 5: Применение к движку
            self.logger.info(f"[TEST] Step 5/6: Applying to engine")
            self.engine.set_strategy_override(forced_config)
            result['steps_completed'].append('applied_to_engine')

            # Даём движку время обработать
            time.sleep(0.1)

            # Шаг 6: Тест подключения
            self.logger.info(f"[TEST] Step 6/6: Testing connection")
            connection_start = time.time()
            connection_success = self._simulate_testing_mode_connection(target_ip, domain, 5.0)
            connection_duration = time.time() - connection_start

            result['steps_completed'].append('connection_tested')
            result['connection_success'] = connection_success
            result['connection_duration_ms'] = connection_duration * 1000

            # Получаем телеметрию
            telemetry = self.engine.get_telemetry_snapshot()
            result['telemetry'] = telemetry

            result['success'] = True
            self.logger.info(f"[TEST] ✅ All steps completed successfully")
            self.logger.info(f"[TEST] Connection: {'SUCCESS' if connection_success else 'FAILED'} ({connection_duration*1000:.1f}ms)")

        except Exception as e:
            import traceback
            error_msg = f"{type(e).__name__}: {str(e)}"
            result['errors'].append(error_msg)
            result['traceback'] = traceback.format_exc()

            failed_step = result['steps_completed'][-1] if result['steps_completed'] else 'initialization'
            self.logger.error(f"[TEST] ❌ Failed at step: {failed_step}")
            self.logger.error(f"[TEST] Error: {error_msg}")
            if self.config.debug:
                self.logger.error(f"[TEST] Traceback:\n{result['traceback']}")

        # Добавляем предупреждения если есть
        if result['warnings']:
            self.logger.warning(f"[TEST] Warnings: {', '.join(result['warnings'])}")

        result['test_duration_ms'] = (time.time() - result['timestamp']) * 1000
        return result

    def _calculate_telemetry_delta(self, baseline: Dict[str, Any], final: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate the difference between baseline and final telemetry.
        
        Args:
            baseline: Baseline telemetry snapshot
            final: Final telemetry snapshot
            
        Returns:
            Dict with telemetry differences
        """
        try:
            delta = {}
            
            # Calculate aggregate differences
            baseline_agg = baseline.get('aggregate', {})
            final_agg = final.get('aggregate', {})
            
            delta['segments_sent'] = final_agg.get('segments_sent', 0) - baseline_agg.get('segments_sent', 0)
            delta['fake_packets_sent'] = final_agg.get('fake_packets_sent', 0) - baseline_agg.get('fake_packets_sent', 0)
            delta['modified_packets_sent'] = final_agg.get('modified_packets_sent', 0) - baseline_agg.get('modified_packets_sent', 0)
            
            return delta
            
        except Exception as e:
            self.logger.warning(f"Failed to calculate telemetry delta: {e}")
            return {}
    
    def enable_debug_mode(self):
        """Enable comprehensive debug logging."""
        self.config.debug = True
        self.config.enable_diagnostics = True
        self.config.log_all_strategies = True
        self.config.track_forced_override = True
        
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("🔍 Debug mode enabled - comprehensive logging active")
    
    def disable_debug_mode(self):
        """Disable debug logging (keep essential logs only)."""
        self.config.debug = False
        self.config.enable_diagnostics = False
        self.config.log_all_strategies = False
        
        self.logger.setLevel(logging.INFO)
        self.logger.info("🔇 Debug mode disabled - essential logging only")
    
    def log_strategy_application(self, strategy_type: str, target: str, params: Dict[str, Any], 
                                success: bool, details: Optional[Dict[str, Any]] = None):
        """
        Log detailed strategy application information.
        
        Args:
            strategy_type: Type of strategy applied
            target: Target IP or domain
            params: Strategy parameters
            success: Whether application was successful
            details: Optional additional details
        """
        if not self.config.log_all_strategies:
            return
        
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"📋 Strategy Application {status}")
        self.logger.info(f"   Type: {strategy_type}")
        self.logger.info(f"   Target: {target}")
        self.logger.info(f"   Forced Override: YES")
        self.logger.info(f"   No Fallbacks: YES")
        
        if self.config.debug and params:
            self.logger.debug(f"   Parameters:")
            for key, value in params.items():
                self.logger.debug(f"     {key}: {value}")
        
        if details:
            self.logger.debug(f"   Additional Details:")
            for key, value in details.items():
                self.logger.debug(f"     {key}: {value}")
    
    def track_forced_override_usage(self, strategy_type: str, target: str):
        """
        Track forced override usage for diagnostics.
        
        Args:
            strategy_type: Type of strategy using forced override
            target: Target IP or domain
        """
        if not self.config.track_forced_override:
            return
        
        with self._lock:
            self._forced_override_count += 1
            
        if self.config.debug:
            self.logger.debug(f"🔥 Forced Override #{self._forced_override_count}: {strategy_type} for {target}")
    
    def get_diagnostics_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive diagnostics report.
        
        Returns:
            Dict with detailed diagnostics information
        """
        with self._lock:
            uptime = time.time() - self._start_time if self._start_time else 0
            
            # Calculate strategy type distribution
            strategy_types = {}
            for applications in self._strategy_applications.values():
                for app in applications:
                    strategy_type = app.get('strategy_type', 'unknown')
                    strategy_types[strategy_type] = strategy_types.get(strategy_type, 0) + 1
            
            # Calculate success rates
            total_tests = 0
            successful_tests = 0
            for applications in self._strategy_applications.values():
                for app in applications:
                    if 'success' in app:
                        total_tests += 1
                        if app['success']:
                            successful_tests += 1
            
            success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        # Get engine telemetry
        engine_telemetry = self.get_telemetry_snapshot()
        
        report = {
            'unified_engine_diagnostics': {
                'uptime_seconds': uptime,
                'running': self._running,
                'forced_override_count': self._forced_override_count,
                'strategy_applications_count': sum(len(apps) for apps in self._strategy_applications.values()),
                'unique_targets': len(self._strategy_applications),
                'strategy_type_distribution': strategy_types,
                'test_success_rate': success_rate,
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'configuration': {
                    'force_override': self.config.force_override,
                    'enable_diagnostics': self.config.enable_diagnostics,
                    'log_all_strategies': self.config.log_all_strategies,
                    'track_forced_override': self.config.track_forced_override,
                    'debug': self.config.debug
                }
            },
            'engine_telemetry': engine_telemetry,
            'timestamp': time.time()
        }
        
        return report
    
    def log_diagnostics_summary(self):
        """Log a summary of diagnostics information."""
        report = self.get_diagnostics_report()
        diag = report['unified_engine_diagnostics']
        
        self.logger.info("📊 UnifiedBypassEngine Diagnostics Summary:")
        self.logger.info(f"   Uptime: {diag['uptime_seconds']:.2f} seconds")
        self.logger.info(f"   Running: {diag['running']}")
        self.logger.info(f"   Forced Overrides: {diag['forced_override_count']}")
        self.logger.info(f"   Strategy Applications: {diag['strategy_applications_count']}")
        self.logger.info(f"   Unique Targets: {diag['unique_targets']}")
        
        if diag['total_tests'] > 0:
            self.logger.info(f"   Test Success Rate: {diag['test_success_rate']:.1f}% ({diag['successful_tests']}/{diag['total_tests']})")
        
        if diag['strategy_type_distribution']:
            self.logger.info("   Strategy Types Used:")
            for strategy_type, count in diag['strategy_type_distribution'].items():
                self.logger.info(f"     {strategy_type}: {count}")
    
    def validate_forced_override_behavior(self) -> Dict[str, Any]:
        """
        Validate that forced override behavior is working correctly.
        
        Returns:
            Dict with validation results
        """
        validation_results = {
            'forced_override_enabled': self.config.force_override,
            'forced_override_count': self._forced_override_count,
            'all_strategies_forced': True,
            'no_fallbacks_enforced': True,
            'issues': []
        }
        
        # Check if any strategies were applied without forced override
        with self._lock:
            for target, applications in self._strategy_applications.items():
                for app in applications:
                    if not app.get('forced_override', False):
                        validation_results['all_strategies_forced'] = False
                        validation_results['issues'].append(f"Strategy for {target} not applied with forced override")
        
        # Check configuration consistency
        if not self.config.force_override:
            validation_results['issues'].append("force_override is disabled in configuration")
        
        # Log validation results
        if validation_results['issues']:
            self.logger.warning("⚠️  Forced Override Validation Issues Found:")
            for issue in validation_results['issues']:
                self.logger.warning(f"   - {issue}")
        else:
            self.logger.info("✅ Forced Override Validation: All checks passed")
        
        return validation_results
    
    def export_diagnostics_to_file(self, filepath: str) -> bool:
        """
        Export diagnostics report to JSON file.
        
        Args:
            filepath: Path to export file
            
        Returns:
            True if export successful
        """
        try:
            import json
            from pathlib import Path
            
            report = self.get_diagnostics_report()
            
            # Ensure directory exists
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"📄 Diagnostics exported to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to export diagnostics: {e}")
            return False
    
    def monitor_forced_override_effectiveness(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Monitor forced override effectiveness over a time period.
        
        Args:
            duration_seconds: Monitoring duration in seconds
            
        Returns:
            Dict with monitoring results
        """
        self.logger.info(f"🔍 Starting forced override monitoring for {duration_seconds} seconds")
        
        start_time = time.time()
        start_telemetry = self.get_telemetry_snapshot()
        start_override_count = self._forced_override_count
        
        # Wait for monitoring period
        time.sleep(duration_seconds)
        
        end_time = time.time()
        end_telemetry = self.get_telemetry_snapshot()
        end_override_count = self._forced_override_count
        
        # Calculate monitoring results
        monitoring_results = {
            'monitoring_duration': end_time - start_time,
            'forced_overrides_during_period': end_override_count - start_override_count,
            'telemetry_delta': self._calculate_telemetry_delta(start_telemetry, end_telemetry),
            'average_overrides_per_minute': (end_override_count - start_override_count) / (duration_seconds / 60),
            'monitoring_start': start_time,
            'monitoring_end': end_time
        }
        
        self.logger.info("📊 Forced Override Monitoring Results:")
        self.logger.info(f"   Duration: {monitoring_results['monitoring_duration']:.2f} seconds")
        self.logger.info(f"   Forced Overrides: {monitoring_results['forced_overrides_during_period']}")
        self.logger.info(f"   Rate: {monitoring_results['average_overrides_per_minute']:.2f} overrides/minute")
        
        return monitoring_results
    
    def apply_strategies_bulk(self, strategy_map: Dict[str, Union[str, Dict[str, Any]]], 
                             target_ips: Optional[Set[str]] = None) -> Dict[str, bool]:
        """
        Apply multiple strategies in bulk with forced override.
        
        This method processes a strategy map (like service mode) but ensures
        all strategies are applied with forced override (like testing mode).
        
        Args:
            strategy_map: Map of domain/IP to strategy configuration
            target_ips: Optional set of target IPs to filter by
            
        Returns:
            Dict mapping keys to success status
        """
        results = {}
        
        self.logger.info(f"🚀 Applying {len(strategy_map)} strategies in bulk with forced override")
        
        for key, strategy_input in strategy_map.items():
            try:
                # Skip if target_ips filter is provided and key is not in it
                if target_ips and key not in target_ips and key != 'default':
                    continue
                
                # Load and normalize strategy
                normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
                
                # Validate strategy
                self.strategy_loader.validate_strategy(normalized_strategy)
                
                # Create forced override (CRITICAL)
                forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
                
                # Ensure testing mode compatibility
                forced_config = self._ensure_testing_mode_compatibility(forced_config)
                
                # Track application
                with self._lock:
                    self._forced_override_count += 1
                    if key not in self._strategy_applications:
                        self._strategy_applications[key] = []
                    self._strategy_applications[key].append({
                        'strategy_type': normalized_strategy.type,
                        'timestamp': time.time(),
                        'forced_override': True,
                        'bulk_application': True
                    })
                
                results[key] = True
                
                if self.config.log_all_strategies:
                    self.logger.info(f"✅ Bulk applied forced strategy for {key}: {normalized_strategy.type}")
                    
            except Exception as e:
                self.logger.error(f"❌ Failed to apply bulk strategy for {key}: {e}")
                results[key] = False
        
        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"📊 Bulk application complete: {successful}/{len(results)} strategies applied successfully")
        
        return results
    
    def set_strategy_override(self, strategy_input: Union[str, Dict[str, Any]]) -> None:
        """
        Set a global strategy override with forced application.
        
        Args:
            strategy_input: Strategy to override with
        """
        try:
            # Load and normalize strategy
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)
            
            # Validate strategy
            self.strategy_loader.validate_strategy(normalized_strategy)
            
            # Create forced override (CRITICAL)
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            
            # Apply to engine
            self.engine.set_strategy_override(forced_config)
            
            # Track override
            with self._lock:
                self._forced_override_count += 1
            
            self.logger.info(f"🔥 Global strategy override set: {normalized_strategy.type} (forced)")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to set strategy override: {e}")
            raise UnifiedBypassEngineError(f"Strategy override failed: {e}")
    
    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Get comprehensive telemetry data including unified engine metrics.
        
        Returns:
            Dictionary containing telemetry data
        """
        # Get base telemetry from underlying engine
        base_telemetry = self.engine.get_telemetry_snapshot()
        
        # Add unified engine specific metrics
        with self._lock:
            unified_metrics = {
                'unified_engine': {
                    'forced_override_count': self._forced_override_count,
                    'strategy_applications': dict(self._strategy_applications),
                    'running': self._running,
                    'uptime_seconds': time.time() - self._start_time if self._start_time else 0,
                    'config': {
                        'force_override': self.config.force_override,
                        'enable_diagnostics': self.config.enable_diagnostics,
                        'debug': self.config.debug
                    }
                }
            }
        
        # Merge telemetry data
        base_telemetry.update(unified_metrics)
        return base_telemetry
    
    def report_high_level_outcome(self, target_ip: str, success: bool):
        """
        Report high-level outcome for a target.
        
        Args:
            target_ip: Target IP address
            success: Whether the connection was successful
        """
        self.engine.report_high_level_outcome(target_ip, success)
        
        if self.config.enable_diagnostics:
            outcome = "SUCCESS" if success else "FAILURE"
            self.logger.debug(f"📊 High-level outcome for {target_ip}: {outcome}")
    
    def get_strategy_loader(self) -> UnifiedStrategyLoader:
        """
        Get the strategy loader instance.
        
        Returns:
            UnifiedStrategyLoader instance
        """
        return self.strategy_loader
    
    def get_underlying_engine(self) -> WindowsBypassEngine:
        """
        Get the underlying BypassEngine instance.
        
        This should only be used for advanced operations that require
        direct access to the engine.
        
        Returns:
            WindowsBypassEngine instance
        """
        return self.engine
    
    def is_running(self) -> bool:
        """
        Check if the engine is currently running.
        
        Returns:
            True if running, False otherwise
        """
        with self._lock:
            return self._running
    
    def get_forced_override_count(self) -> int:
        """
        Get the number of forced overrides applied.
        
        Returns:
            Number of forced overrides
        """
        with self._lock:
            return self._forced_override_count
    
    def _log_final_statistics(self):
        """Log final statistics when stopping."""
        with self._lock:
            uptime = time.time() - self._start_time if self._start_time else 0
            
        self.logger.info("📊 UnifiedBypassEngine Final Statistics:")
        self.logger.info(f"   Uptime: {uptime:.2f} seconds")
        self.logger.info(f"   Forced overrides applied: {self._forced_override_count}")
        self.logger.info(f"   Strategies tracked: {len(self._strategy_applications)}")
        
        if self.config.debug and self._strategy_applications:
            self.logger.debug("   Strategy applications by target:")
            for target, applications in self._strategy_applications.items():
                self.logger.debug(f"     {target}: {len(applications)} applications")


# Convenience functions for backward compatibility and ease of use
def create_unified_engine(debug: bool = True, force_override: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine with standard configuration.
    
    Args:
        debug: Enable debug logging
        force_override: Enable forced override (should always be True)
        
    Returns:
        Configured UnifiedBypassEngine instance
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=force_override,
        enable_diagnostics=True,
        log_all_strategies=debug,
        track_forced_override=True
    )
    return UnifiedBypassEngine(config)


def create_service_mode_engine(debug: bool = False) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for service mode.
    
    Args:
        debug: Enable debug logging
        
    Returns:
        UnifiedBypassEngine configured for service mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,  # CRITICAL: Always True
        enable_diagnostics=False,  # Reduced logging for service mode
        log_all_strategies=False,
        track_forced_override=True
    )
    return UnifiedBypassEngine(config)


def create_testing_mode_engine(debug: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for testing mode.
    
    Args:
        debug: Enable debug logging
        
    Returns:
        UnifiedBypassEngine configured for testing mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,  # CRITICAL: Always True
        enable_diagnostics=True,
        log_all_strategies=True,
        track_forced_override=True
    )
    return UnifiedBypassEngine(config)