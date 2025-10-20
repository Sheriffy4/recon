# Файл: core/unified_bypass_engine.py
"""
Unified Bypass Engine - Single engine wrapper for all modes

This module provides a unified wrapper around the existing BypassEngine
that ensures identical behavior between testing mode and service mode.
"""

import logging
import threading
import time
from typing import Dict, Any, Set, Optional, List, Union, Tuple
from dataclasses import dataclass
import asyncio
import aiohttp
import socket
import ssl
from urllib.parse import urlparse
import hashlib
from collections import defaultdict
import random

# Import the new unified loader and its exceptions
from .unified_strategy_loader import UnifiedStrategyLoader, StrategyLoadError, StrategyValidationError

# Import existing engine and related components
from .bypass.engine.base_engine import WindowsBypassEngine, EngineConfig

# Fallbacks and optional imports from the original file
def synthesize_strategy_fallback(ctx):
    return None
synthesize_strategy = synthesize_strategy_fallback
AttackContext = None
try:
    from core.strategy_synthesizer import AttackContext, synthesize as synthesize_strategy
except (ImportError, ModuleNotFoundError):
    pass

MODERN_BYPASS_ENGINE_AVAILABLE = False
BypassStrategy = Any
try:
    from core.bypass.attacks.modern_registry import ModernAttackRegistry
    from core.bypass.strategies.pool_management import StrategyPoolManager, BypassStrategy
    from core.bypass.modes.mode_controller import ModeController, OperationMode
    from core.bypass.validation.reliability_validator import ReliabilityValidator
    from core.bypass.protocols.multi_port_handler import MultiPortHandler
    MODERN_BYPASS_ENGINE_AVAILABLE = True
except ImportError:
    OperationMode = Any

try:
    from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
except Exception:
    CdnAsnKnowledgeBase = None

from core.bypass.attacks.alias_map import normalize_attack_name
from core.bypass.types import BlockType

ADVANCED_FINGERPRINTING_AVAILABLE = False
try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType, FingerprintingError
    ADVANCED_FINGERPRINTING_AVAILABLE = True
except ImportError:
    pass

ECH_AVAILABLE = False
try:
    from core.fingerprint.ech_detector import ECHDetector
    ECH_AVAILABLE = True
except Exception:
    pass

LOG = logging.getLogger('unified_engine')
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36'}


class UnifiedBypassEngineError(Exception):
    """Raised when UnifiedBypassEngine operations fail."""
    pass


@dataclass
class UnifiedEngineConfig:
    """Configuration for the unified bypass engine."""
    debug: bool = True
    force_override: bool = True
    enable_diagnostics: bool = True
    log_all_strategies: bool = True
    track_forced_override: bool = True


class UnifiedBypassEngine:
    """
    High-level orchestrator engine that uses the new unified loading and parsing system.
    This class replaces the old HybridEngine.
    """
    
    def __init__(self, config: Optional[UnifiedEngineConfig] = None,
                 enable_advanced_fingerprinting: bool = True,
                 enable_modern_bypass: bool = True,
                 verbosity: str = "normal",
                 enable_enhanced_tracking: bool = False,
                 enable_online_optimization: bool = False):
        self.config = config or UnifiedEngineConfig()
        self.logger = LOG
        self.debug = self.config.debug
        self.verbosity = verbosity
        self.enhanced_tracking = bool(enable_enhanced_tracking)
        self.enable_online_optimization = bool(enable_online_optimization)
        
        # Initialize the new unified strategy loader
        self.strategy_loader = UnifiedStrategyLoader(debug=self.config.debug)
        
        # Initialize underlying low-level engine
        engine_config = EngineConfig(debug=self.config.debug)
        self.engine = WindowsBypassEngine(engine_config)
        
        # --- Migrated from HybridEngine.__init__ ---
        self.modern_bypass_enabled = enable_modern_bypass and MODERN_BYPASS_ENGINE_AVAILABLE
        if self.modern_bypass_enabled:
            try:
                self.attack_registry = ModernAttackRegistry()
                self.pool_manager = StrategyPoolManager()
                self.mode_controller = ModeController()
                self.reliability_validator = ReliabilityValidator()
                self.multi_port_handler = MultiPortHandler()
                self.logger.info('Modern bypass engine components initialized successfully')
            except Exception as e:
                self.logger.error(f'Failed to initialize modern bypass engine: {e}')
                self.modern_bypass_enabled = False
        else:
            self.attack_registry = None
            self.pool_manager = None
            self.mode_controller = None
            self.reliability_validator = None
            self.multi_port_handler = None

        self.advanced_fingerprinting_enabled = enable_advanced_fingerprinting and ADVANCED_FINGERPRINTING_AVAILABLE
        if self.advanced_fingerprinting_enabled:
            try:
                fingerprint_config = FingerprintingConfig(cache_ttl=3600, enable_ml=True, enable_cache=True, timeout=15.0, fallback_on_error=True)
                self.advanced_fingerprinter = AdvancedFingerprinter(config=fingerprint_config)
                self.logger.info('Advanced fingerprinting initialized successfully')
            except Exception as e:
                self.logger.error(f'Failed to initialize advanced fingerprinting: {e}')
                self.advanced_fingerprinting_enabled = False
                self.advanced_fingerprinter = None
        else:
            self.advanced_fingerprinter = None

        self.fingerprint_stats = defaultdict(int)
        self.bypass_stats = defaultdict(int)
        self.knowledge_base = CdnAsnKnowledgeBase() if CdnAsnKnowledgeBase else None
        
        self._start_time = None
        self._running = False
        self._lock = threading.Lock()
        
        # FIX: Initialize missing attributes
        self._strategy_applications = {}
        self._forced_override_count = 0
        
        self.logger.info("🚀 UnifiedBypassEngine (Orchestrator) initialized.")

    def _ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        REFACTORED: Uses the new UnifiedStrategyLoader for parsing and normalization.
        This is now the single source of truth for strategy processing.
        """
        try:
            # Use the new loader for consistent parsing and forced override.
            normalized_strategy = self.strategy_loader.load_strategy(strategy)
            self.strategy_loader.validate_strategy(normalized_strategy)
            
            # Convert to engine format
            engine_task = normalized_strategy.to_engine_format()
            
            # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Применяем совместимость с тестовым режимом
            engine_task = self._ensure_testing_mode_compatibility(engine_task)
            
            return engine_task
        except (StrategyLoadError, StrategyValidationError) as e:
            self.logger.error(f"Failed to process strategy: '{strategy}'. Error: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error processing strategy: '{strategy}'. Error: {e}")
            return None

    def _task_to_str(self, task: Dict[str, Any]) -> str:
        try:
            t = task.get('type') or 'unknown'
            p = task.get('params', {})
            pairs = [f"{k}={v}" for k, v in sorted(p.items())]
            return f"{t}({', '.join(pairs)})"
        except Exception:
            return str(task)

    def _is_rst_error(self, e: BaseException) -> bool:
        msg = str(e) if e else ""
        rep = repr(e)
        return (
            isinstance(e, ConnectionResetError)
            or "ECONNRESET" in rep
            or "Connection reset" in msg
            or isinstance(e, (getattr(aiohttp, "ServerDisconnectedError", Exception),
                              getattr(aiohttp, "ClientOSError", Exception)))
        )

    async def _test_sites_connectivity(
        self,
        sites: List[str],
        dns_cache: Dict[str, str],
        max_concurrent: int = 10,
        retries: int = 0,
        backoff_base: float = 0.4,
        timeout_profile: str = "balanced",
        connect_timeout: Optional[float] = None,
        sock_read_timeout: Optional[float] = None,
        total_timeout: Optional[float] = None
    ) -> Dict[str, Tuple[str, str, float, int]]:
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        class CustomResolver(aiohttp.resolver.AsyncResolver):
            def __init__(self, cache):
                super().__init__()
                self._custom_cache = cache

            async def resolve(self, host, port, family=socket.AF_INET):
                if host in self._custom_cache:
                    ip = self._custom_cache[host]
                    return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
                return await super().resolve(host, port, family)

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit_per_host=5, resolver=CustomResolver(dns_cache))

        def _make_timeouts(profile: str) -> aiohttp.ClientTimeout:
            presets = {
                "fast":      dict(connect=5.0,  sock_read=8.0,  total=15.0),
                "balanced":  dict(connect=8.0,  sock_read=15.0, total=25.0),
                "slow":      dict(connect=12.0, sock_read=25.0, total=40.0),
            }
            p = presets.get(profile, presets["balanced"]).copy()
            if connect_timeout is not None:   p["connect"] = float(connect_timeout)
            if sock_read_timeout is not None: p["sock_read"] = float(sock_read_timeout)
            if total_timeout is not None:     p["total"] = float(total_timeout)
            return aiohttp.ClientTimeout(total=p["total"], connect=p["connect"], sock_read=p["sock_read"])

        async def test_with_semaphore(session, site):
            async with semaphore:
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, 'N/A')
                attempt = 0
                while True:
                    start_time = time.time()
                    try:
                        prof = timeout_profile if attempt == 0 else "slow"
                        client_timeout = _make_timeouts(prof)
                        async with session.get(site, headers=HEADERS, allow_redirects=True, timeout=client_timeout) as response:
                            await response.content.readexactly(1)
                            latency = (time.time() - start_time) * 1000
                            return (site, ('WORKING', ip_used, latency, response.status))
                    except aiohttp.ClientResponseError as e:
                        # HTTP ошибки (400, 403, 404, etc.) означают, что TCP соединение установлено
                        # Это считается успехом для DPI обхода
                        latency = (time.time() - start_time) * 1000
                        if e.status in [400, 403, 404, 500, 502, 503]:
                            self.logger.debug(f"HTTP error {e.status} for {site} - TCP connection successful")
                            return (site, ('WORKING', ip_used, latency, e.status))
                        else:
                            return (site, ('HTTP_ERROR', ip_used, latency, e.status))
                    except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError, OSError) as e:
                        latency = (time.time() - start_time) * 1000
                        if self._is_rst_error(e):
                            return (site, ('RST', ip_used, latency, 0))
                        if attempt < retries:
                            delay = backoff_base * (2 ** attempt) + random.uniform(0.0, 0.2)
                            await asyncio.sleep(delay)
                            attempt += 1
                            continue
                        return (site, ('TIMEOUT', ip_used, latency, 0))
                    except Exception as e:
                        latency = (time.time() - start_time) * 1000
                        # Проверяем, не является ли это HTTP ошибкой в другом формате
                        error_msg = str(e).lower()
                        if any(phrase in error_msg for phrase in ['400', 'bad request', 'header value is too long', 'got more than', 'when reading']):
                            self.logger.info(f"HTTP 400-like error for {site} - TCP connection successful, DPI bypass working: {e}")
                            return (site, ('WORKING', ip_used, latency, 400))
                        return (site, ('ERROR', ip_used, latency, 0))
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [test_with_semaphore(session, site) for site in sites]
                task_results = await asyncio.gather(*tasks)
                for site, result_tuple in task_results:
                    results[site] = result_tuple
        finally:
            await connector.close()
        return results

    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        self.logger.info('Testing baseline connectivity with DNS cache...')
        return await self._test_sites_connectivity(test_sites, dns_cache)

    async def execute_strategy_real_world(
        self,
        strategy: Union[str, Dict[str, Any]],
        test_sites: List[str],
        target_ips: Set[str],
        dns_cache: Dict[str, str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
        fingerprint: Optional[DPIFingerprint] = None,
        return_details: bool = False,
        prefer_retry_on_timeout: bool = False,
        warmup_ms: Optional[float] = None,
        enable_online_optimization: bool = False,
        engine_override: Optional[str] = None
    ) -> Union[Tuple[str, int, int, float], Tuple[str, int, int, float, Dict, Dict]]:
        
        # REFACTORED: Use the new unified parsing method
        engine_task = self._ensure_engine_task(strategy)
        if not engine_task:
            self.logger.error(f"Could not translate strategy to a valid engine task: {strategy}")
            if return_details:
                return ('TRANSLATION_FAILED', 0, len(test_sites), 0.0, {}, {})
            return ('TRANSLATION_FAILED', 0, len(test_sites), 0.0)

        # The low-level engine is now an internal detail
        bypass_engine = self.engine
        
        strategy_map = {"default": engine_task}
        bypass_thread = None
        try:
            # The unified loader ensures the task has forced override flags,
            # so we can use the strategy_override path for consistent behavior.
            bypass_thread = bypass_engine.start(
                target_ips=target_ips,
                strategy_map=strategy_map,
                strategy_override=engine_task
            )
        except Exception as e:
            self.logger.error(f"Engine failed to start: {e}", exc_info=self.debug)
            if return_details:
                return ('ENGINE_START_FAILED', 0, len(test_sites), 0.0, {}, {})
            return ('ENGINE_START_FAILED', 0, len(test_sites), 0.0)

        try:
            await asyncio.sleep(warmup_ms / 1000.0 if warmup_ms is not None else 2.0)
            
            results = await self._test_sites_connectivity(
                test_sites,
                dns_cache,
                retries=(2 if prefer_retry_on_timeout else 0)
            )
            
            successful_count = sum(1 for status, _, _, _ in results.values() if status == 'WORKING')
            successful_latencies = [latency for status, _, latency, _ in results.values() if status == 'WORKING']
            avg_latency = sum(successful_latencies) / len(successful_latencies) if successful_latencies else 0.0
            
            if successful_count == 0:
                result_status = 'NO_SITES_WORKING'
            elif successful_count == len(test_sites):
                result_status = 'ALL_SITES_WORKING'
            else:
                result_status = 'PARTIAL_SUCCESS'

            self.logger.info(f'Test result: {successful_count}/{len(test_sites)} sites working, avg latency: {avg_latency:.1f}ms')

            telemetry = bypass_engine.get_telemetry_snapshot() if hasattr(bypass_engine, 'get_telemetry_snapshot') else {}
            
            if return_details:
                return (result_status, successful_count, len(test_sites), avg_latency, results, telemetry)
            return (result_status, successful_count, len(test_sites), avg_latency)
        except Exception as e:
            self.logger.error(f'Error during real-world testing: {e}', exc_info=self.debug)
            if return_details:
                return ('REAL_WORLD_ERROR', 0, len(test_sites), 0.0, {}, {})
            return ('REAL_WORLD_ERROR', 0, len(test_sites), 0.0)
        finally:
            if bypass_engine and bypass_thread:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, lambda: (bypass_engine.stop(), bypass_thread.join(timeout=2.0)))
                
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
    
    # --- START OF FINAL FIX ---
    def _ensure_testing_mode_compatibility(self, forced_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures that the strategy configuration is 100% identical to how it would be
        processed in the service mode, preventing discrepancies.
        This is the final fix to unify behavior.
        """
        config = forced_config.copy()
        params = config.get('params', {}).copy()
        attack_type = (config.get('type') or '').lower()

        # 1) Принудительные флаги
        config['no_fallbacks'] = True
        config['forced'] = True

        # 2) fooling -> list
        if 'fooling' in params:
            fool = params['fooling']
            if isinstance(fool, str):
                if fool.lower() in ('none',''):
                    params['fooling'] = []
                else:
                    params['fooling'] = [x.strip() for x in fool.split(',') if x.strip()]
            elif not isinstance(fool, (list, tuple)):
                params['fooling'] = [str(fool)]

        # 3) fake_ttl: используем ttl/autottl; по умолчанию 3 для fakeddisorder
        if attack_type in ('fakeddisorder','fake','disorder','multidisorder','disorder2','seqovl'):
            if 'fake_ttl' not in params and 'ttl' in params and params['ttl'] is not None:
                params['fake_ttl'] = params['ttl']
            elif 'fake_ttl' not in params and 'autottl' not in params:
                params['fake_ttl'] = 3 # Default to 3 for consistency

        # 4) split_pos
        if 'split_pos' in params and params['split_pos'] is not None:
            from core.bypass.engine.base_engine import safe_split_pos_conversion
            sp_val = params['split_pos']
            if isinstance(sp_val, list) and sp_val:
                sp_val = sp_val[0]
            params['split_pos'] = safe_split_pos_conversion(sp_val, 3)

        # 5) КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: overlap_size для fakeddisorder
        # Для атаки fakeddisorder, overlap_size ДОЛЖЕН быть 0, чтобы активировать
        # правильную 'disorder' логику в primitives.py. Удаляем все мешающие параметры.
        if attack_type == 'fakeddisorder':
            # Принудительно очищаем все параметры, которые могут сбить fakeddisorder с толку
            params['overlap_size'] = 0
            params.pop('split_seqovl', None)
            params.pop('split_count', None)
            # Убеждаемся, что используется правильная логика disorder
            self.logger.debug(f"✅ FAKEDDISORDER SANITIZED: Removed split_seqovl/split_count, set overlap_size=0")
        elif attack_type in ('disorder', 'disorder2', 'multidisorder'):
            params['overlap_size'] = 0
            params.pop('split_seqovl', None)
            self.logger.debug(f"Sanitized for '{attack_type}': overlap_size forced to 0.")
        elif attack_type == 'seqovl':
            ovl_raw = params.get("overlap_size", params.get("split_seqovl", 336))
            try:
                params['overlap_size'] = int(ovl_raw)
            except (ValueError, TypeError):
                params['overlap_size'] = 336

        # 6) низкоуровневые дефолты
        if 'repeats' in params:
            try:
                params['repeats'] = max(1, min(int(params['repeats']), 10))
            except (ValueError, TypeError):
                params['repeats'] = 1
        if 'tcp_flags' not in params:
            params['tcp_flags'] = {'psh': True, 'ack': True}
        if 'window_div' not in params:
            params['window_div'] = 8 if 'disorder' in attack_type else 2
        if 'ipid_step' not in params:
            params['ipid_step'] = 2048

        config['params'] = params
        if self.config.debug:
            self.logger.debug(f"✅ Testing‑compat for '{attack_type}': {params}")
        return config
    # --- END OF FINAL FIX ---
    
    def test_strategy_like_testing_mode(self, target_ip: str, strategy_input: Union[str, Dict[str, Any]],
                                       domain: Optional[str] = None, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Тестирует стратегию, используя тот же процесс, что и в режиме тестирования.

        Этот метод в точности воспроизводит рабочий процесс режима тестирования:
        1. Загружает и нормализует стратегию.
        2. Применяет ее с принудительным переопределением (forced override).
        3. Симулирует попытку соединения для проверки результата.
        4. Возвращает детальный словарь с результатами теста.

        Args:
            target_ip: Целевой IP-адрес для теста.
            strategy_input: Конфигурация стратегии (строка или словарь).
            domain: Опциональное доменное имя для теста.
            timeout: Таймаут на выполнение теста в секундах.

        Returns:
            Словарь с результатами теста, включая 'success', 'latency' и 'error' (в случае неудачи).
        """
        test_start = time.time()

        try:
            # Шаг 1: Загрузка и нормализация стратегии (как в режиме тестирования)
            normalized_strategy = self.strategy_loader.load_strategy(strategy_input)

            # Шаг 2: Валидация стратегии (как в режиме тестирования)
            self.strategy_loader.validate_strategy(normalized_strategy)

            # Шаг 3: Создание конфигурации принудительного переопределения (КРИТИЧЕСКИ ВАЖНО)
            forced_config = self.strategy_loader.create_forced_override(normalized_strategy)
            forced_config = self._ensure_testing_mode_compatibility(forced_config)

            self.logger.info(f"🧪 Testing strategy like testing mode: {normalized_strategy.type} for {target_ip}")

            # Шаг 4: Применение стратегии к движку с принудительным переопределением
            self.engine.set_strategy_override(forced_config)

            # Получение базовой телеметрии для сравнения
            baseline_telemetry = self.engine.get_telemetry_snapshot()

            # Шаг 5: Симуляция попытки соединения для проверки обхода
            # <<< НАЧАЛО ИЗМЕНЕНИЙ: Теперь получаем и статус, и причину >>>
            test_success, reason = self._simulate_testing_mode_connection(target_ip, domain, timeout)
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>

            # Получение итоговой телеметрии
            final_telemetry = self.engine.get_telemetry_snapshot()

            # Расчет длительности теста
            test_duration = time.time() - test_start

            # Шаг 6: Формирование словаря с результатами
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
            
            # <<< НАЧАЛО ИЗМЕНЕНИЙ: Если тест не прошел, добавляем причину в результат >>>
            if not test_success:
                result['error'] = reason
            # <<< КОНЕЦ ИЗМЕНЕНИЙ >>>

            # Трекинг и логирование результатов теста
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
    
    def _simulate_testing_mode_connection(self, target_ip: str, domain: Optional[str], timeout: float) -> Tuple[bool, str]:
        """
        Симулирует попытку соединения для проверки работоспособности стратегии,
        аналогично тому, как это делает режим тестирования.

        Args:
            target_ip: Целевой IP-адрес для проверки.
            domain: Опциональное доменное имя для выполнения SSL/TLS рукопожатия.
            timeout: Таймаут на операцию соединения в секундах.

        Returns:
            Кортеж (success: bool, reason: str), где:
            - success: True, если соединение успешно, иначе False.
            - reason: Строка, описывающая причину успеха или сбоя.
        """
        sock = None
        try:
            import socket
            import ssl

            # Создаем сокет для проверки обхода блокировки
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # Шаг 1: Попытка установить TCP-соединение
            try:
                sock.connect((target_ip, 443))
            except socket.timeout:
                msg = f"TCP connection timeout for {target_ip}"
                self.logger.debug(msg)
                return False, msg
            except ConnectionRefusedError:
                msg = f"Connection refused by {target_ip}"
                self.logger.debug(msg)
                return False, msg
            except OSError as e:
                msg = f"TCP connection failed for {target_ip}: {e}"
                self.logger.debug(msg)
                return False, msg

            # Шаг 2: Если TCP-соединение успешно и указан домен, выполняем SSL/TLS рукопожатие
            if domain:
                context = ssl.create_default_context()
                # Отключаем проверку сертификата, так как цель - только проверка соединения
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                try:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        # Соединение успешно установлено
                        msg = f"SSL connection successful for {target_ip} ({domain})"
                        self.logger.debug(msg)
                        return True, msg
                except ssl.SSLError as e:
                    msg = f"SSL handshake failed for {target_ip}: {e}"
                    self.logger.debug(msg)
                    return False, msg
                except socket.timeout:
                    msg = f"SSL timeout for {target_ip}"
                    self.logger.debug(msg)
                    return False, msg
                except Exception as e:
                    msg = f"SSL connection error for {target_ip}: {e}"
                    self.logger.debug(msg)
                    return False, msg
            else:
                # Если домен не указан, успешное TCP-соединение считается успехом
                msg = f"TCP connection successful for {target_ip}"
                self.logger.debug(msg)
                return True, msg

        except ImportError as e:
            msg = f"Cannot test connection - missing module: {e}"
            self.logger.warning(msg)
            return False, msg
        except Exception as e:
            msg = f"Unexpected error during connection test for {target_ip}: {e}"
            self.logger.warning(msg, exc_info=self.config.debug)
            return False, msg
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
    
    def clear_strategy_override(self) -> None:
        """Сбрасывает глобальное переопределение стратегии в низкоуровневом движке."""
        self.engine.clear_strategy_override()
    
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
    
    def _enhance_strategies_with_registry(self, strategies: List[str], fingerprint: Optional[DPIFingerprint], domain: str, port: int) -> List[str]:
        """
        Enhance strategies using the modern attack registry.
        """
        if not self.attack_registry:
            # Нормализуем на случай, если сюда попали dict
            return [s if isinstance(s, str) else self._task_to_str(s) for s in strategies]

        normalized_in: List[str] = [s if isinstance(s, str) else self._task_to_str(s) for s in strategies]
        enhanced_strategies: List[str] = []

        # Fast fingerprint-based templates
        if fingerprint:
            if getattr(fingerprint, "rst_injection_detected", False):
                enhanced_strategies.extend([
                    "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                    "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
                ])
            if getattr(fingerprint, "tcp_window_manipulation", False):
                enhanced_strategies.append("--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10")
            if getattr(fingerprint, "http_header_filtering", False):
                enhanced_strategies.append("--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum")
            if getattr(fingerprint, "dns_hijacking_detected", False):
                enhanced_strategies.append("--dns-over-https=on --dpi-desync=fake --dpi-desync-ttl=2")
            try:
                sni_sens = fingerprint.raw_metrics.get("sni_sensitivity", {})
                if sni_sens.get("likely") or sni_sens.get("confirmed"):
                    enhanced_strategies.extend([
                        "--dpi-desync=split --dpi-desync-split-pos=midsld",
                        "--dpi-desync=fake,split --dpi-desync-split-pos=midsld --dpi-desync-ttl=1",
                        "--dpi-desync=fake,disorder --dpi-desync-split-pos=midsld --dpi-desync-ttl=2"
                    ])
                quic_blocked = fingerprint.raw_metrics.get("quic_probe", {}).get("blocked")
                if quic_blocked:
                    enhanced_strategies.append("--filter-udp=443 --dpi-desync=fake,disorder --dpi-desync-ttl=1")
            except Exception:
                pass

        available_attacks = self.attack_registry.list_attacks(enabled_only=True)
        LOG.info(f'Found {len(available_attacks)} available attacks in registry')

        for strategy in normalized_in:
            enhanced_strategy = self._enhance_single_strategy(strategy, available_attacks, fingerprint)
            if enhanced_strategy:
                enhanced_strategies.append(enhanced_strategy)

        if fingerprint and available_attacks:
            try:
                registry_strategies = self._generate_registry_strategies(available_attacks, fingerprint, domain, port)
                enhanced_strategies.extend(registry_strategies)
            except Exception as e:
                LOG.debug(f"Registry strategy generation failed: {e}")

        seen = set()
        unique_strategies = []
        for strategy in enhanced_strategies + normalized_in:
            if strategy not in seen:
                seen.add(strategy)
                unique_strategies.append(strategy)
        LOG.info(f'Enhanced {len(strategies)} strategies to {len(unique_strategies)} registry-optimized strategies')
        return unique_strategies
        
    def _enhance_single_strategy(self, strategy: str, available_attacks: List[str], fingerprint: Optional[DPIFingerprint]) -> Optional[str]:
        """Enhance a single strategy using registry information."""
        return strategy
    
    async def test_strategies_hybrid(
        self,
        strategies: List[Union[str, Dict[str, Any]]],
        test_sites: List[str],
        ips: Set[str],
        dns_cache: Dict[str, str],
        port: int,
        domain: str,
        fast_filter: bool = True,
        initial_ttl: Optional[int] = None,
        enable_fingerprinting: bool = True,
        use_modern_engine: bool = True,
        capturer: Optional[Any] = None,
        telemetry_full: bool = False,
        # --- Online optimization hooks ---
        optimization_callback: Optional[callable] = None,
        strategy_evaluation_mode: bool = False,
        engine_override: Optional[str] = None,
        fingerprint: Optional[DPIFingerprint] = None
    ) -> List[Dict]:
        """
        Гибридное тестирование стратегий с продвинутым фингерпринтингом DPI:
        - optimization_callback: функция, вызываемая после каждого теста сайта для онлайн-оптимизации
        - strategy_evaluation_mode: если True, возвращает только необработанные данные о производительности
        1. Выполняет фингерпринтинг DPI для целевого домена
        2. Адаптирует стратегии под обнаруженный тип DPI
        3. Использует современный движок обхода если доступен
        4. Проводит реальное тестирование с помощью BypassEngine
        """
        results = []
        use_modern = use_modern_engine and self.modern_bypass_enabled
        if use_modern:
            self.bypass_stats['modern_engine_tests'] += 1
            LOG.info('Using modern bypass engine for strategy testing')
        else:
            self.bypass_stats['legacy_engine_tests'] += 1
            LOG.info('Using legacy bypass engine for strategy testing')
        if use_modern and self.pool_manager:
            existing_strategy = self.pool_manager.get_strategy_for_domain(domain, port)
            if existing_strategy:
                LOG.info(f'Found existing pool strategy for {domain}:{port}')
                pool_strategy_str = existing_strategy.to_zapret_format()
                if pool_strategy_str not in strategies:
                    strategies.insert(0, pool_strategy_str)
        
        if enable_fingerprinting and self.advanced_fingerprinting_enabled and not fingerprint:
            try:
                LOG.info(f'Performing DPI fingerprinting for {domain}:{port}')
                fingerprint = await self.fingerprint_target(domain, port)
                if fingerprint:
                    self.fingerprint_stats['fingerprint_aware_tests'] += 1
                    LOG.info(f'DPI fingerprint obtained: {self._get_dpi_type_value(fingerprint)} (confidence: {self._get_fingerprint_confidence(fingerprint):.2f}, reliability: {self._get_fingerprint_reliability(fingerprint):.2f})')
                else:
                    LOG.warning('DPI fingerprinting failed, proceeding with standard testing')
                    self.fingerprint_stats['fallback_tests'] += 1
            except Exception as e:
                LOG.error(f'DPI fingerprinting error: {e}')
                self.fingerprint_stats['fingerprint_failures'] += 1
                self.fingerprint_stats['fallback_tests'] += 1
                # Анализ PCAP даже при неудачном фингерпринтинге
                if capturer and self.enhanced_tracking:
                    capturer.trigger_pcap_analysis(force=True)
                else:
                    self.fingerprint_stats['fallback_tests'] += 1
        elif fingerprint:
             LOG.info(f'Using pre-computed DPI fingerprint: {self._get_dpi_type_value(fingerprint)} (confidence: {self._get_fingerprint_confidence(fingerprint):.2f})')
        
        # Knowledge init: derive CDN/ASN profile for primary domain
        cdn = None
        asn = None
        kb_profile = {}
        primary_ip = dns_cache.get(domain) if dns_cache else None
        kb_recs: Dict[str, Any] = {}
        if self.knowledge_base and primary_ip:
            try:
                # Новая интеграция с KB: используем get_recommendations(ip)
                if hasattr(self.knowledge_base, "get_recommendations"):
                    kb_recs = self.knowledge_base.get_recommendations(primary_ip) or {}
                    cdn = kb_recs.get("cdn")
                    LOG.info(f"KB: recommendations for {primary_ip}: {kb_recs}")
                else:
                    # совместимость, если есть иной API (не ожидается)
                    LOG.debug("Knowledge base without get_recommendations, skipping")
            except Exception as e:
                LOG.debug(f"KB identify failed: {e}")

        # QUIC/ECH detection (fast) to auto-prepend QUIC strategies
        quic_signals = {"ech_present": False, "quic_ping_ok": False, "http3_support": False}
        if ECH_AVAILABLE:
            try:
                det = ECHDetector(dns_timeout=1.0)
                ech = await det.detect_ech_dns(domain)
                quic_signals["ech_present"] = bool(ech and ech.get("ech_present"))
                quic = await det.probe_quic(domain, port, timeout=0.5)
                quic_signals["quic_ping_ok"] = bool(quic and quic.get("success"))
                http3_ok = await det.probe_http3(domain, port, timeout=1.2)
                quic_signals["http3_support"] = bool(http3_ok)
                LOG.info(f"QUIC/ECH signals for {domain}: {quic_signals}")
            except Exception as e:
                LOG.debug(f"QUIC/ECH detection failed: {e}")

        # <<< FIX: Correctly instantiate AttackContext with dst_ip >>>
        synthesized = None
        if synthesize_strategy and AttackContext:
            try:
                ctx = AttackContext(
                    domain=domain,
                    dst_ip=primary_ip,  # Pass the resolved IP here
                    port=port,
                    fingerprint=fingerprint,
                    cdn=cdn,
                    asn=asn,
                    kb_profile=kb_profile or kb_recs
                )
                synthesized = synthesize_strategy(ctx)
            except Exception as e:
                LOG.debug(f"Strategy synthesis failed: {e}")
        else:
            if not synthesize_strategy:
                LOG.debug("Strategy synthesis not available (synthesize_strategy is None/fallback)")
            if not AttackContext:
                LOG.debug("Strategy synthesis not available (AttackContext is None)")
        # <<< END FIX >>>

        base: List[Union[str, Dict[str, Any]]] = strategies[:]  # сохранить тип
        # Рабочие списки
        dict_only = [s for s in base if isinstance(s, dict)]
        str_only  = [s for s in base if isinstance(s, str)]

        # Для ветки с реестром/адаптацией работаем только со строками, dict добавим как есть
        strategies_to_test: List[Union[str, Dict[str, Any]]] = []
        if use_modern and self.attack_registry:
            if str_only:
                boosted = self._enhance_strategies_with_registry(str_only, fingerprint, domain, port)
                strategies_to_test = dict_only + boosted
                self.bypass_stats['attack_registry_queries'] += 1
            else:
                strategies_to_test = dict_only
        elif fingerprint:
            adapted = self._adapt_strategies_for_fingerprint(str_only, fingerprint)
            strategies_to_test = dict_only + adapted
            LOG.info(f'Using {len(strategies_to_test)} fingerprint-adapted strategies')
        else:
            strategies_to_test = base
            LOG.info(f'Using {len(strategies_to_test)} standard strategies (no fingerprint)')

        # synthesized dict — prepend
        if synthesized and isinstance(synthesized, dict):
            merged = [synthesized] + strategies_to_test
            uniq, seen = [], set()
            for s in merged:
                key = s if isinstance(s, str) else self._task_to_str(s)
                if key not in seen:
                    seen.add(key)
                    uniq.append(s)
            strategies_to_test = uniq

        # Препенд рекомендаций KB: dict для современного движка + строка для совместимости
        if kb_recs:
            try:
                split_pos = kb_recs.get("split_pos")
                overlap_size = kb_recs.get("overlap_size")
                fool = kb_recs.get("fooling_methods") or []
                if isinstance(fool, str):
                    fool = [x.strip() for x in fool.split(",") if x.strip()]
                kb_dict = {
                    "type": "fakeddisorder",
                    "params": {
                        "fooling": fool if fool else ["badsum"],
                        "split_pos": int(split_pos) if isinstance(split_pos, int) else 76,
                        "overlap_size": 0,  # критично: без перекрытия
                        "ttl": 3,
                    }
                }
                kb_str = (
                    f"--dpi-desync=fake,disorder "
                    f"--dpi-desync-fooling={','.join(fool) if fool else 'badsum'} "
                    f"--dpi-desync-split-pos={kb_dict['params']['split_pos']} "
                    f"--dpi-desync-ttl=3"
                )
                merged = [kb_dict, kb_str] + strategies_to_test
                uniq, seen = [], set()
                for s in merged:
                    key = s if isinstance(s, str) else self._task_to_str(s)
                    if key not in seen:
                        seen.add(key)
                        uniq.append(s)
                strategies_to_test = uniq
                LOG.info("KB‑recommended strategies prepended")
            except Exception as e:
                LOG.debug(f"Failed to prepend KB recommendations: {e}")

        # Auto-prepend QUIC fragmentation strategies if signals say QUIC/HTTP3/ECH
        try:
            if quic_signals.get("quic_ping_ok") or quic_signals.get("http3_support") or quic_signals.get("ech_present"):
                frag_size = 300
                if kb_profile and kb_profile.get("optimal_fragment_size"):
                    frag_size = int(kb_profile["optimal_fragment_size"])
                quic_strats: List[Dict[str, Any]] = [
                    {"type": "quic_fragmentation", "params": {"fragment_size": frag_size, "add_version_negotiation": True}},
                    {"type": "quic_fragmentation", "params": {"fragment_size": max(200, frag_size - 100)}}
                ]
                # prepend unique
                seen_keys = set()
                def _key(s):
                    return s if isinstance(s, str) else (s.get("type"), tuple(sorted((s.get("params") or {}).items())))
                merged = []
                for s in quic_strats + strategies_to_test:
                    k = _key(s)
                    if k in seen_keys: continue
                    seen_keys.add(k)
                    merged.append(s)
                strategies_to_test = merged
                LOG.info("QUIC fragmentation strategies prepended")
        except Exception as e:
            LOG.debug(f"Prepend QUIC strategies failed: {e}")

        if not strategies_to_test:
            # fallback: если ничего не осталось
            strategies_to_test = base or ["--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3"]
            LOG.warning(f"No strategies after optimization, falling back to {len(strategies_to_test)}")

        LOG.info(f'Начинаем реальное тестирование {len(strategies_to_test)} стратегий с помощью BypassEngine...')
        for i, strategy in enumerate(strategies_to_test):
            pretty = strategy if isinstance(strategy, str) else self._task_to_str(strategy)
            sid = hashlib.sha1(str(pretty).encode('utf-8')).hexdigest()[:12]
            LOG.info(f'--> Тест {i + 1}/{len(strategies_to_test)}: {pretty}')
            if capturer:
                try: capturer.mark_strategy_start(sid)
                except Exception: pass
            ret = await self.execute_strategy_real_world(
                strategy, test_sites, ips, dns_cache, port, initial_ttl, fingerprint,
                prefer_retry_on_timeout=(i < 2),
                return_details=True,
                enable_online_optimization=self.enable_online_optimization,
                engine_override=engine_override
            )
            engine_telemetry = {}
            if len(ret) == 6:
                result_status, successful_count, total_count, avg_latency, site_results, engine_telemetry = ret
            elif len(ret) == 5:
                result_status, successful_count, total_count, avg_latency, site_results = ret
            else:
                result_status, successful_count, total_count, avg_latency = ret
                site_results = {}

            if capturer:
                try: capturer.mark_strategy_end(sid)
                except Exception: pass
            success_rate = successful_count / total_count if total_count > 0 else 0.0

            tel_sum = {}
            if engine_telemetry:
                aggr = engine_telemetry.get("aggregate", {})
                tel_sum = {
                    "segments_sent": aggr.get("segments_sent", 0),
                    "fake_packets_sent": aggr.get("fake_packets_sent", 0),
                    "CH": engine_telemetry.get("clienthellos", 0),
                    "SH": engine_telemetry.get("serverhellos", 0),
                    "RST": engine_telemetry.get("rst_count", 0),
                }
            # --- START OF FIX: Add detailed site_results to the final result object ---
            result_data = {
                'strategy_id': sid, 
                'strategy': pretty, 
                'result_status': result_status, 
                'successful_sites': successful_count, 
                'total_sites': total_count, 
                'success_rate': success_rate, 
                'avg_latency_ms': avg_latency, 
                'fingerprint_used': fingerprint is not None, 
                'dpi_type': fingerprint.dpi_type.value if (fingerprint and hasattr(fingerprint.dpi_type, 'value')) else (str(fingerprint.dpi_type) if fingerprint else None), 
                'dpi_confidence': fingerprint.confidence if fingerprint else None, 
                'engine_telemetry': tel_sum,
                'site_results': site_results  # Pass the detailed results up
            }
            # --- END OF FIX ---
            if telemetry_full and engine_telemetry:
                result_data['engine_telemetry_full'] = engine_telemetry

            results.append(result_data)
            # Пишем результат по каждому домену в KB
            try:
                if self.knowledge_base and site_results:
                    for site, (st, ip_used, lat_ms, _http) in site_results.items():
                        dname = urlparse(site).hostname or site
                        self.knowledge_base.update_with_result(
                            domain=dname,
                            ip=ip_used or "",
                            strategy={"raw": pretty},
                            success=(st == "WORKING"),
                            block_type=(BlockType.NONE if st == "WORKING" else BlockType.TIMEOUT),
                            latency_ms=float(lat_ms or 0.0)
                        )
            except Exception as e:
                LOG.debug(f"KB update failed: {e}")
            if success_rate > 0:
                LOG.info(f'✓ Успех: {success_rate:.0%} ({successful_count}/{total_count}), задержка: {avg_latency:.1f}ms')
            else:
                LOG.info(f'✗ Провал: ни один сайт не заработал. Причина: {result_status}')
            if tel_sum:
                # Печатаем чуть расширенную сводку
                LOG.info(f"   Telemetry: SegsSent={tel_sum.get('segments_sent',0)} FakesSent={tel_sum.get('fake_packets_sent',0)} CH={tel_sum.get('CH',0)} SH={tel_sum.get('SH',0)} RST={tel_sum.get('RST',0)}")
        if results:
            if fingerprint:
                results.sort(key=lambda x: (x.get('success_rate', 0.0), -x.get('avg_latency_ms', 0.0), 1 if x.get('fingerprint_used') else 0), reverse=True)
            else:
                results.sort(key=lambda x: (x.get('success_rate', 0.0), -x.get('avg_latency_ms', 0.0)), reverse=True)
        if results and fingerprint:
            LOG.info(f'Strategy testing completed with DPI fingerprint: {self._get_dpi_type_value(fingerprint)} (confidence: {self._get_fingerprint_confidence(fingerprint):.2f})')

        # ==== NEW: Enhanced tracking auto-analysis and second pass ====
        try:
            if self.enhanced_tracking and capturer and hasattr(capturer, "analyze_pcap_file"):
                cap_path = getattr(capturer, "pcap_file", None)
                cap_metrics = capturer.analyze_pcap_file(cap_path)
                if self.knowledge_base and isinstance(cap_metrics, dict):
                    total_ch = sum(m.get('tls_clienthellos', 0) for m in cap_metrics.values())
                    total_sh = sum(m.get('tls_serverhellos', 0) for m in cap_metrics.values())
                    ratio = total_sh / total_ch if total_ch > 0 else 0.0
                    primary_ip = dns_cache.get(domain)
                    if domain and primary_ip:
                        self.knowledge_base.update_quic_metrics(domain, primary_ip, ratio)

                self._merge_capture_metrics_into_results(results, cap_metrics if isinstance(cap_metrics, dict) else {})
                # Update KB QUIC score
                try:
                    if self.knowledge_base and isinstance(cap_metrics, dict):
                        # simple aggregate score per domain: use first test_sites domain
                        dname = (urlparse(test_sites[0]).hostname if test_sites else domain) or domain
                        sc = 0.0
                        for m in cap_metrics.values():
                            sc = max(sc, float(m.get("success_score", 0.0)))
                        if hasattr(self.knowledge_base, "domain_quic_scores"):
                            self.knowledge_base.domain_quic_scores[dname] = sc
                except Exception as e:
                    LOG.debug(f"KB QUIC update failed: {e}")

                # Генерация доп. стратегий на основе PCAP
                extra = self._suggest_strategies_from_pcap(cap_metrics if isinstance(cap_metrics, dict) else {}, fingerprint)
                # Дедупликация
                already = {r.get("strategy") for r in results}
                extra = [s for s in extra if s not in already]

                # full-pool booster
                try:
                    booster = self._boost_with_full_pool(fingerprint)
                    already = {r.get("strategy") for r in results}
                    booster = [s for s in booster if s not in already]
                    if booster:
                        LOG.info(f'Full-pool booster added {len(booster)} strategies for second pass')
                        extra.extend([s for s in booster if s not in extra])
                except Exception as e:
                    LOG.debug(f'Full-pool booster failed: {e}')

                if extra:
                    LOG.info(f'Enhanced tracking generated {len(extra)} additional strategies for second pass')
                    for i, strategy in enumerate(extra[:6]):
                        pretty = strategy if isinstance(strategy, str) else self._task_to_str(strategy)
                        LOG.info(f'--> [2nd pass] {i + 1}/{min(6, len(extra))}: {pretty}')
                        if capturer:
                            try: capturer.mark_strategy_start(str(strategy))
                            except Exception: pass
                        ret = await self.execute_strategy_real_world(
                            strategy, test_sites, ips, dns_cache, port, initial_ttl, fingerprint,
                            prefer_retry_on_timeout=True,  # агрессивнее ретраи для 2го прохода
                            return_details=True,
                            enable_online_optimization=self.enable_online_optimization,
                            engine_override=engine_override
                        )
                        if len(ret) == 5:
                            result_status, successful_count, total_count, avg_latency, site_results = ret
                        else:
                            result_status, successful_count, total_count, avg_latency = ret
                            site_results = {}
                        if capturer:
                            try: capturer.mark_strategy_end(str(strategy))
                            except Exception: pass
                        success_rate = successful_count / total_count if total_count > 0 else 0.0
                        result_data = {'strategy': pretty, 'result_status': result_status, 'successful_sites': successful_count, 'total_sites': total_count, 'success_rate': success_rate, 'avg_latency_ms': avg_latency, 'fingerprint_used': fingerprint is not None, 'dpi_type': fingerprint.dpi_type.value if (fingerprint and hasattr(fingerprint.dpi_type, 'value')) else (str(fingerprint.dpi_type) if fingerprint else None), 'dpi_confidence': fingerprint.confidence if fingerprint else None}
                        results.append(result_data)
                    # Пересортировка после добавления
                    if results:
                        if fingerprint:
                            results.sort(key=lambda x: (x.get('success_rate', 0.0), -x.get('avg_latency_ms', 0.0), 1 if x.get('fingerprint_used') else 0), reverse=True)
                        else:
                            results.sort(key=lambda x: (x.get('success_rate', 0.0), -x.get('avg_latency_ms', 0.0)), reverse=True)
        except Exception as e:
            LOG.debug(f'Enhanced tracking second pass failed: {e}')

        # Сохраняем обновленную базу знаний (если используется)
        if self.knowledge_base and any(r.get('success_rate', 0) > 0 for r in results):
            try:
                self.knowledge_base.save()
                LOG.info('Knowledge base updated and saved after successful strategy tests')
            except Exception as e:
                LOG.error(f'Failed to save knowledge base: {e}')

        return results
    
    
    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность, отправляя ClientHello, чтобы спровоцировать DPI.
        Использует aiohttp, так как он корректно обрабатывает сброс соединения.
        """
        LOG.info('Тестируем базовую доступность сайтов (без bypass) с DNS-кэшем...')
        return await self._test_sites_connectivity(test_sites, dns_cache)
    
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

    def _get_dpi_type_value(self, fingerprint):
        """Safely get DPI type value from fingerprint."""
        if not fingerprint:
            return None
        
        dpi_type = getattr(fingerprint, 'dpi_type', None)
        if not dpi_type:
            return None
        
        # If it has a .value attribute (enum), use it
        if hasattr(dpi_type, 'value'):
            return dpi_type.value
        
        # Otherwise, it's probably already a string
        return str(dpi_type)

    def _get_fingerprint_confidence(self, fingerprint):
        """Safely get confidence value from fingerprint."""
        if not fingerprint:
            return 0.0
        
        confidence = getattr(fingerprint, 'confidence', 0.0)
        try:
            return float(confidence)
        except (TypeError, ValueError):
            return 0.0

    def _get_fingerprint_reliability(self, fingerprint):
        """Safely get reliability score from fingerprint."""
        if not fingerprint:
            return 0.0
        
        reliability = getattr(fingerprint, 'reliability_score', 0.0)
        try:
            return float(reliability)
        except (TypeError, ValueError):
            return 0.0
    
    def cleanup(self):
        """Очистка ресурсов, аналогично старому HybridEngine."""
        if self.advanced_fingerprinter and hasattr(self.advanced_fingerprinter, 'executor'):
            try:
                self.advanced_fingerprinter.executor.shutdown(wait=False)
                self.logger.info("Advanced fingerprinter executor shut down.")
            except Exception as e:
                self.logger.error(f'Error shutting down fingerprinter executor: {e}')
        
        if self.modern_bypass_enabled:
            self.logger.info("Cleaning up modern bypass engine components...")
            try:
                if self.attack_registry and hasattr(self.attack_registry, 'cleanup'):
                    self.attack_registry.cleanup()
                if self.pool_manager and hasattr(self.pool_manager, 'cleanup'):
                    self.pool_manager.cleanup()
                if self.mode_controller and hasattr(self.mode_controller, 'cleanup'):
                    self.mode_controller.cleanup()
                if self.reliability_validator and hasattr(self.reliability_validator, 'cleanup'):
                    self.reliability_validator.cleanup()
                if self.multi_port_handler and hasattr(self.multi_port_handler, 'cleanup'):
                    self.multi_port_handler.cleanup()
                self.logger.info('Modern bypass engine components cleaned up successfully.')
            except Exception as e:
                self.logger.error(f'Error during modern bypass components cleanup: {e}')
        
        self.logger.info("UnifiedBypassEngine cleanup complete.")


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