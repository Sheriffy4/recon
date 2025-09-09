import logging
import time
import asyncio
import inspect
import aiohttp
import socket
import ssl
from collections import defaultdict
import random
import hashlib
from typing import Dict, List, Tuple, Optional, Set, Any, Union
from urllib.parse import urlparse
from core.bypass_engine import BypassEngine
from core.zapret_parser import ZapretStrategyParser
from core.bypass.attacks.alias_map import normalize_attack_name
from core.bypass.types import BlockType
try:
    from core.knowledge.cdn_asn_db import CdnAsnKnowledgeBase
except Exception:
    CdnAsnKnowledgeBase = None
try:
    from core.strategy_synthesizer import AttackContext, synthesize as synthesize_strategy
except Exception:
    AttackContext = None
    def synthesize_strategy(ctx): return None

# Initialize modern bypass engine availability
MODERN_BYPASS_ENGINE_AVAILABLE = False
BypassStrategy = Any  # Default fallback

try:
    from core.bypass.attacks.modern_registry import ModernAttackRegistry
    from core.bypass.strategies.pool_management import StrategyPoolManager, BypassStrategy
    from core.bypass.modes.mode_controller import ModeController
    from core.bypass.validation.reliability_validator import ReliabilityValidator
    from core.bypass.protocols.multi_port_handler import MultiPortHandler
    from core.bypass.modes.mode_controller import OperationMode  # Move the import statement here
    MODERN_BYPASS_ENGINE_AVAILABLE = True
except ImportError as e:
    logging.getLogger('hybrid_engine').warning(f'Modern bypass engine not available: {e}')
    OperationMode = Any


# Initialize advanced fingerprinting availability
ADVANCED_FINGERPRINTING_AVAILABLE = False
try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType, FingerprintingError
    ADVANCED_FINGERPRINTING_AVAILABLE = True
except ImportError as e:
    logging.getLogger('hybrid_engine').warning(f'Advanced fingerprinting not available: {e}')
try:
    from core.fingerprint.ech_detector import ECHDetector
    ECH_AVAILABLE = True
except Exception as e:
    logging.getLogger('hybrid_engine').debug(f'ECHDetector not available: {e}')
    ECH_AVAILABLE = False

LOG = logging.getLogger('hybrid_engine')
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36'}

class HybridEngine:
    """
    Гибридный движок, который сочетает:
    1. Парсинг zapret-стратегий.
    2. Реальное тестирование через запущенный BypassEngine с синхронизированным DNS.
    3. Продвинутый фингерпринтинг DPI для контекстно-зависимой генерации стратегий.
    """

    def __init__(self, debug: bool=False, enable_advanced_fingerprinting: bool=True,
                 enable_modern_bypass: bool=True, verbosity: str="normal",
                 enable_enhanced_tracking: bool=False, enable_online_optimization: bool=False):
        self.debug = debug
        self.verbosity = verbosity
        self.parser = ZapretStrategyParser()
        self.enhanced_tracking = bool(enable_enhanced_tracking)
        self.enable_online_optimization = bool(enable_online_optimization)

        # Initialize modern bypass engine components
        self.modern_bypass_enabled = enable_modern_bypass and MODERN_BYPASS_ENGINE_AVAILABLE
        if self.modern_bypass_enabled:
            try:
                self.attack_registry = ModernAttackRegistry()
                self.pool_manager = StrategyPoolManager()
                self.mode_controller = ModeController()
                self.reliability_validator = ReliabilityValidator()
                self.multi_port_handler = MultiPortHandler()
                LOG.info('Modern bypass engine components initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize modern bypass engine: {e}')
                self.modern_bypass_enabled = False
        else:
            self.attack_registry = None
            self.pool_manager = None
            self.mode_controller = None
            self.reliability_validator = None
            self.multi_port_handler = None

        # Initialize advanced fingerprinting
        self.advanced_fingerprinting_enabled = enable_advanced_fingerprinting and ADVANCED_FINGERPRINTING_AVAILABLE
        if self.advanced_fingerprinting_enabled:
            try:
                fingerprint_config = FingerprintingConfig(cache_ttl=3600, enable_ml=True, enable_cache=True, timeout=15.0, fallback_on_error=True)
                self.advanced_fingerprinter = AdvancedFingerprinter(config=fingerprint_config)
                LOG.info('Advanced fingerprinting initialized successfully')
            except Exception as e:
                LOG.error(f'Failed to initialize advanced fingerprinting: {e}')
                self.advanced_fingerprinting_enabled = False
                self.advanced_fingerprinter = None
        else:
            self.advanced_fingerprinter = None
            if not ADVANCED_FINGERPRINTING_AVAILABLE:
                LOG.info('Advanced fingerprinting disabled - module not available')
            else:
                LOG.info('Advanced fingerprinting disabled by configuration')

        # Initialize statistics
        self.fingerprint_stats = {
            'fingerprints_created': 0,
            'fingerprint_cache_hits': 0,
            'fingerprint_failures': 0,
            'fingerprint_aware_tests': 0,
            'fallback_tests': 0
        }

        self.bypass_stats = {
            'modern_engine_tests': 0,
            'legacy_engine_tests': 0,
            'pool_assignments': 0,
            'attack_registry_queries': 0,
            'mode_switches': 0
        }
        # Knowledge base (optional)
        self.knowledge_base = CdnAsnKnowledgeBase() if CdnAsnKnowledgeBase else None
        # Tuning noisy loggers if verbosity is quiet
        if self.verbosity.lower() in ("quiet", "warn", "warning"):
            for noisy in ("core.fingerprint.advanced_fingerprinter", "core.fingerprint.http_analyzer",
                          "core.fingerprint.dns_analyzer", "core.fingerprint.tcp_analyzer"):
                try:
                    logging.getLogger(noisy).setLevel(logging.WARNING)
                except Exception:
                    pass

    def _translate_zapret_to_engine_task(self, params: Dict) -> Optional[Dict]:
        """
        ИСПРАВЛЕНИЕ: Унифицированный и надежный транслятор zapret-строки в задачу для BypassEngine.
        """
        # Нормализуем имена атак для консистентности
        desync = [normalize_attack_name(d) for d in params.get('dpi_desync', [])]
        fooling = [normalize_attack_name(f) for f in params.get('dpi_desync_fooling', [])]

        if not desync:
            # Support QUIC fragmentation from zapret-like flag
            qfrag = params.get('quic_frag') or params.get('quic_fragment')
            if qfrag:
                try: fs = int(qfrag)
                except Exception: fs = 120
                return {'type': 'quic_fragmentation', 'params': {'fragment_size': fs}}
            return None
        task_type = 'none'
        task_params = {}
        if 'fakeddisorder' in desync:
            task_type = 'fakeddisorder'
        elif 'multidisorder' in desync:
            task_type = 'multidisorder'
        elif 'multisplit' in desync:
            task_type = 'multisplit'
        elif 'disorder' in desync or 'disorder2' in desync: # Legacy aliases
            task_type = 'fakeddisorder'
        if task_type in ['fakedisorder', 'multidisorder', 'multisplit']:
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            if any((p.get('type') == 'midsld' for p in split_pos_raw)):
                task_params['split_pos'] = 'midsld'
            else:
                positions = [p['value'] for p in split_pos_raw if p.get('type') == 'absolute']
                if task_type == 'fakedisorder':
                    task_params['split_pos'] = positions[0] if positions else 3
                else:
                    task_params['positions'] = positions if positions else [1, 5, 10]
        if 'fake' in desync:
            if 'badsum' in fooling:
                task_type = 'badsum_race'
            elif 'md5sig' in fooling:
                task_type = 'md5sig_race'
            elif params.get('dpi_desync_ttl') or params.get('dpi_desync_fake_tls'):
                # есть 'fake' без fooling — поддерживаем чистый fake
                task_type = 'fake' if task_type == 'none' else task_type
            else:
                # чистый 'fake' без TTL/параметров — тоже поддержим
                if task_type == 'none':
                    task_type = 'fake'
        if params.get('dpi_desync_split_seqovl'):
            task_type = 'seqovl'
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            if any((p.get('type') == 'midsld' for p in split_pos_raw)):
                task_params['split_pos'] = 'midsld'
            else:
                positions = [p['value'] for p in split_pos_raw if p.get('type') == 'absolute']
                task_params['split_pos'] = positions[0] if positions else 3
            task_params['overlap_size'] = params.get('dpi_desync_split_seqovl')
        if params.get('dpi_desync_ttl'):
            task_params['ttl'] = params.get('dpi_desync_ttl')
        # split без seqovl → простая фрагментация
        if task_type == 'none' and 'split' in desync:
            task_type = 'simple_fragment'
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            positions = [p['value'] for p in split_pos_raw if p.get('type') == 'absolute']
            task_params['split_pos'] = positions[0] if positions else 3

        if task_type == 'none':
            LOG.warning(f'Не удалось транслировать zapret-стратегию в задачу для движка: {params}')
            return None
        return {'type': task_type, 'params': task_params}

    def _task_to_str(self, task: Dict[str, Any]) -> str:
        try:
            t = task.get('type') or task.get('name') or 'unknown'
            p = task.get('params', {})
            pairs = []
            for k, v in sorted(p.items(), key=lambda kv: kv[0]):
                try:
                    pairs.append(f"{k}={v}")
                except Exception:
                    pairs.append(f"{k}=<obj>")
            return f"{t}({', '.join(pairs)})"
        except Exception:
            return str(task)

    def _ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if isinstance(strategy, dict):
            t = strategy.get('type') or strategy.get('name')
            if not t:
                return None
            return {'type': t, 'params': strategy.get('params', {})}

        s = str(strategy).strip()

        # 1) Simple DSL parser: func(key=value, ...)
        import re
        match = re.match(r'(\w+)\((.*)\)', s)
        if match:
            func_name = match.group(1).strip()
            params_str = match.group(2).strip()
            params = {}
            if params_str:
                try:
                    for part in params_str.split(','):
                        if '=' in part:
                            key, value = part.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            if value.isdigit():
                                params[key] = int(value)
                            elif value.lower() == 'true':
                                params[key] = True
                            elif value.lower() == 'false':
                                params[key] = False
                            else:
                                params[key] = value.strip('\'"')
                except Exception:
                     pass

            from core.bypass.attacks.alias_map import normalize_attack_name
            ntp = normalize_attack_name(func_name)
            if ntp == 'desync':
                ntp = 'fakeddisorder'
            return {'type': ntp, 'params': params}

        # 2) zapret CLI style
        if s.startswith('--'):
            try:
                parsed_params = self.parser.parse(s)
                task = self._translate_zapret_to_engine_task(parsed_params)
                if task:
                    return task
            except Exception:
                pass

        # 3) Fallback for adhoc strategy names like "desync" or "multisplit"
        try:
            from core.strategy_interpreter import interpret_strategy as interp
            ps = interp(s) or {}
            tp = ps.get('type')
            p = ps.get('params', {}) or {}
            if tp:
                from core.bypass.attacks.alias_map import normalize_attack_name
                ntp = normalize_attack_name(tp)
                if ntp == 'desync':
                    ntp = 'fakeddisorder'
                return {'type': ntp, 'params': p}
        except Exception:
            pass

        return None

    def _is_rst_error(self, e: BaseException) -> bool:
        """Эвристика: распознать сброс соединения (RST) по типу/сообщению исключения."""
        try:
            from aiohttp.client_exceptions import ServerDisconnectedError, ClientOSError, ClientConnectorError
        except Exception:
            ServerDisconnectedError = ClientOSError = ClientConnectorError = tuple()
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
        """
        ИСПРАВЛЕНИЕ: Более устойчивый тестовый клиент на aiohttp с принудительным DNS и увеличенными таймаутами.
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)

        class CustomResolver(aiohttp.resolver.AsyncResolver):

            def __init__(self, cache):
                super().__init__()
                self._custom_cache = cache

            async def resolve(self, host, port, family=socket.AF_INET):
                if host in self._custom_cache:
                    ip = self._custom_cache[host]
                    LOG.debug(f'CustomResolver: Forcing {host} -> {ip}')
                    return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
                LOG.debug(f'CustomResolver: Fallback for {host}')
                return await super().resolve(host, port, family)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit_per_host=5, resolver=CustomResolver(dns_cache))

        def _make_timeouts(profile: str) -> aiohttp.ClientTimeout:
            # Профили таймаутов: подбираем под худшие сети
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
                        # Эскалация профиля на повторных попытках
                        prof = timeout_profile if attempt == 0 else "slow"
                        client_timeout = _make_timeouts(prof)
                        async with session.get(site, headers=HEADERS, allow_redirects=True, timeout=client_timeout) as response:
                            # немного данных достаточно, чтобы проверить установку канала
                            await response.content.readexactly(1)
                            latency = (time.time() - start_time) * 1000
                            return (site, ('WORKING', ip_used, latency, response.status))
                    except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError) as e:
                        latency = (time.time() - start_time) * 1000
                        # Классифицируем RST отдельно
                        if self._is_rst_error(e):
                            LOG.debug(f'Connectivity test for {site} -> RST ({type(e).__name__})')
                            return (site, ('RST', ip_used, latency, 0))
                        # TIMEOUT с экспоненциальным бэкоффом
                        if attempt < retries:
                            delay = backoff_base * (2 ** attempt) + random.uniform(0.0, 0.2)
                            LOG.debug(f'Connectivity TIMEOUT for {site}, retrying in {delay:.2f}s (attempt {attempt+1}/{retries})')
                            await asyncio.sleep(delay)
                            attempt += 1
                            continue
                        LOG.debug(f'Connectivity test for {site} failed with TIMEOUT ({type(e).__name__})')
                        return (site, ('TIMEOUT', ip_used, latency, 0))
                    except Exception as e:
                        latency = (time.time() - start_time) * 1000
                        LOG.debug(f'Неожиданная ошибка при тестировании {site}: {e}')
                        return (site, ('ERROR', ip_used, latency, 0))
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [test_with_semaphore(session, site) for site in sites]
                task_results = await asyncio.gather(*tasks)
                for site, result_tuple in task_results:
                    results[site] = result_tuple
        finally:
            try:
                await connector.close()
            except Exception:
                pass
        return results

    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность, отправляя ClientHello, чтобы спровоцировать DPI.
        Использует aiohttp, так как он корректно обрабатывает сброс соединения.
        """
        LOG.info('Тестируем базовую доступность сайтов (без bypass) с DNS-кэшем...')
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
        enable_online_optimization: bool = False
    ) -> Tuple[str, int, int, float]:
        """
        Реальное тестирование стратегии с использованием нового BypassEngine.
        Теперь с поддержкой контекстной информации от фингерпринтинга.
        """
        engine_task = self._ensure_engine_task(strategy)
        if not engine_task:
            return ('TRANSLATION_FAILED', 0, len(test_sites), 0.0)
        bypass_engine = BypassEngine(debug=self.debug)
        # Опционально подключаем онлайн-контроллер
        if enable_online_optimization:
            try:
                base_rules = {}
                try:
                    from core.strategy_manager import StrategyManager
                    sm = StrategyManager()
                    base_rules = sm.get_strategies_for_service() or {}
                except Exception:
                    base_rules = {}
                # Если нет готовых правил — используем текущую стратегию как default
                if not base_rules:
                    base_rules = {"default": strategy if isinstance(strategy, str) else self._task_to_str(strategy)}
                parser = self.parser
                def task_translator(parsed_params: Dict[str, Any]) -> Dict[str, Any]:
                    return self._translate_zapret_to_engine_task(parsed_params)
                bypass_engine.attach_controller(base_rules, parser, task_translator, store_path="learned_strategies.json", epsilon=0.1)
            except Exception as e:
                LOG.debug(f"Adaptive controller attach failed: {e}")
        strategy_map = {'default': engine_task}
        bypass_thread = bypass_engine.start(target_ips, strategy_map)
        try:
            # Чуть больше времени на прогрев хука
            wait_time_s = 2.5 # default
            if warmup_ms is not None:
                 wait_time_s = warmup_ms / 1000.0
            elif fingerprint:
                if fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU:
                    wait_time_s = 1.0
                elif fingerprint.dpi_type == DPIType.COMMERCIAL_DPI:
                    wait_time_s = 2.0
                elif fingerprint.connection_reset_timing > 0:
                    wait_time_s = max(1.0, fingerprint.connection_reset_timing / 1000.0 + 0.5)

            await asyncio.sleep(wait_time_s)
            try:
                # Первичный прогон с ретраями для «первых» стратегий по желанию
                results = await self._test_sites_connectivity(
                    test_sites,
                    dns_cache,
                    max_concurrent=10,
                    retries=(2 if prefer_retry_on_timeout else 0),
                    backoff_base=0.4,
                    timeout_profile="balanced"
                )
            except Exception as connectivity_error:
                LOG.error(f'Connectivity test failed: {connectivity_error}')
                if fingerprint and fingerprint.tcp_window_manipulation:
                    LOG.info('Retrying with adjusted parameters due to TCP window manipulation')
                    await asyncio.sleep(0.5)
                    results = await self._test_sites_connectivity(test_sites, dns_cache, timeout_profile="slow", retries=1, max_concurrent=6)
                else:
                    raise
            # Эвристика: подозрение на TCP window manipulation даже без фингерпринта
            try:
                statuses = [st for (st, _, _, _) in results.values()]
                latencies = [lt for (_, _, lt, _) in results.values()]
                min_lat = min(latencies) if latencies else 0.0
                rst_cnt = sum(1 for st in statuses if st == 'RST')
                to_cnt = sum(1 for st in statuses if st == 'TIMEOUT')
                if (rst_cnt >= 2 or (to_cnt == len(test_sites) and min_lat < 150.0)) and not (fingerprint and getattr(fingerprint, "tcp_window_manipulation", False)):
                    LOG.info('Heuristic trigger: possible TCP window manipulation. Retesting with slow timeouts and limited concurrency...')
                    await asyncio.sleep(0.4)
                    results = await self._test_sites_connectivity(test_sites, dns_cache, max_concurrent=5, retries=1, backoff_base=0.5, timeout_profile="slow")
            except Exception:
                pass
            successful_count = sum((1 for status, _, _, _ in results.values() if status == 'WORKING'))
            successful_latencies = [latency for status, _, latency, _ in results.values() if status == 'WORKING']
            avg_latency = sum(successful_latencies) / len(successful_latencies) if successful_latencies else 0.0
            if successful_count == 0:
                result_status = 'NO_SITES_WORKING'
            elif successful_count == len(test_sites):
                result_status = 'ALL_SITES_WORKING'
            else:
                result_status = 'PARTIAL_SUCCESS'
            if fingerprint and self.debug:
                LOG.debug(f'Strategy test with DPI context: {fingerprint.dpi_type.value}, RST injection: {fingerprint.rst_injection_detected}, TCP manipulation: {fingerprint.tcp_window_manipulation}')
            LOG.info(f'Результат реального теста: {successful_count}/{len(test_sites)} сайтов работают, ср. задержка: {avg_latency:.1f}ms')

            telemetry = {}
            try:
                telemetry = bypass_engine.get_telemetry_snapshot()
            except Exception:
                telemetry = {}
            if return_details:
                return (result_status, successful_count, len(test_sites), avg_latency, results, telemetry)
            return (result_status, successful_count, len(test_sites), avg_latency)
        except Exception as e:
            LOG.error(f'Ошибка во время реального тестирования: {e}', exc_info=self.debug)
            if fingerprint:
                if fingerprint.rst_injection_detected and 'reset' in str(e).lower():
                    LOG.info('Connection reset detected - consistent with fingerprint analysis')
                elif fingerprint.dns_hijacking_detected and 'dns' in str(e).lower():
                    LOG.info('DNS issues detected - consistent with fingerprint analysis')
            return ('REAL_WORLD_ERROR', 0, len(test_sites), 0.0)
        finally:
            bypass_engine.stop()
            if bypass_thread:
                bypass_thread.join(timeout=2.0)
            await asyncio.sleep(0.5)

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
        strategy_evaluation_mode: bool = False
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
        fingerprint = None
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
        if enable_fingerprinting and self.advanced_fingerprinting_enabled:
            try:
                LOG.info(f'Performing DPI fingerprinting for {domain}:{port}')
                fingerprint = await self.fingerprint_target(domain, port)
                if fingerprint:
                    self.fingerprint_stats['fingerprint_aware_tests'] += 1
                    LOG.info(f'DPI fingerprint obtained: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f}, reliability: {fingerprint.reliability_score:.2f})')
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

        # Prepend synthesized strategy based on context (fingerprint + KB)
        try:
            ctx = AttackContext(domain=domain, ip=primary_ip, port=port,
                                fingerprint=fingerprint, cdn=cdn, asn=asn,
                                kb_profile=kb_profile or kb_recs)
            synthesized = synthesize_strategy(ctx)
        except Exception as e:
            synthesized = None
            LOG.debug(f"Strategy synthesis failed: {e}")

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
                # Dict‑стратегия (для modern engine)
                kb_dict = {
                    "type": "desync",
                    "params": {
                        "fooling": ",".join(fool) if fool else "badsum",
                        "split_pos": int(split_pos) if isinstance(split_pos, int) else 76,
                        "overlap_size": int(overlap_size) if isinstance(overlap_size, int) else 336,
                        "ttl": 3,
                    }
                }
                # Zapret‑строка (legacy совместимость; overlap напрямую может не поддерживаться)
                kb_str = f"--dpi-desync={','.join(fool) if fool else 'badsum'},disorder --dpi-desync-split-pos={kb_dict['params']['split_pos']} --dpi-desync-ttl=3"
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
                quic_strats: List[Dict[str, Any]] = [
                    {"type": "quic_fragmentation", "params": {"fragment_size": 300, "add_version_negotiation": True}},
                    {"type": "quic_fragmentation", "params": {"fragment_size": 200}}
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
                enable_online_optimization=self.enable_online_optimization
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
            result_data = {'strategy_id': sid, 'strategy': pretty, 'result_status': result_status, 'successful_sites': successful_count, 'total_sites': total_count, 'success_rate': success_rate, 'avg_latency_ms': avg_latency, 'fingerprint_used': fingerprint is not None, 'dpi_type': fingerprint.dpi_type.value if fingerprint else None, 'dpi_confidence': fingerprint.confidence if fingerprint else None, 'engine_telemetry': tel_sum}
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
            LOG.info(f'Strategy testing completed with DPI fingerprint: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})')

        # ==== NEW: Enhanced tracking auto-analysis and second pass ====
        try:
            if self.enhanced_tracking and capturer and hasattr(capturer, "analyze_pcap_file"):
                cap_path = getattr(capturer, "pcap_file", None)
                cap_metrics = capturer.analyze_pcap_file(cap_path)
                self._merge_capture_metrics_into_results(results, cap_metrics if isinstance(cap_metrics, dict) else {})
                # KB: update QUIC metrics (ServerHello/ClientHello ratio) per domain
                try:
                    if self.knowledge_base and isinstance(cap_metrics, dict) and cap_metrics:
                        total_ch = sum(m.get("tls_clienthellos", 0) for m in cap_metrics.values())
                        total_sh = sum(m.get("tls_serverhellos", 0) for m in cap_metrics.values())
                        quic_score = (total_sh / total_ch) if total_ch > 0 else 0.0
                        primary_ip = dns_cache.get(domain) if dns_cache else None
                        if primary_ip:
                            self.knowledge_base.update_quic_metrics(domain, primary_ip, quic_score)
                            LOG.info(f'KB: updated QUIC success score for {domain}: {quic_score:.2f}')
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
                            enable_online_optimization=self.enable_online_optimization
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
                        result_data = {'strategy': pretty, 'result_status': result_status, 'successful_sites': successful_count, 'total_sites': total_count, 'success_rate': success_rate, 'avg_latency_ms': avg_latency, 'fingerprint_used': fingerprint is not None, 'dpi_type': fingerprint.dpi_type.value if fingerprint else None, 'dpi_confidence': fingerprint.confidence if fingerprint else None}
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

    # ==== NEW: Enhanced tracking helpers ====
    def _merge_capture_metrics_into_results(self, results: List[Dict[str, Any]], cap_metrics: Dict[str, Dict[str, Any]]) -> None:
        """
        Вливает PCAP‑метрики по стратегиям в результирующие записи.
        Ключ соответствия — pretty‑строка стратегии (как передавалась в mark_strategy_start).
        """
        if not cap_metrics or "error" in cap_metrics:
            return
        # cap_metrics: { strategy_id: {tls_clienthellos, tls_serverhellos, ...} }
        map_by_strategy = cap_metrics
        for r in results:
            sid = r.get("strategy_id") or r.get("strategy")
            if not sid:
                continue
            m = map_by_strategy.get(str(sid)) or map_by_strategy.get(str(r.get("strategy")))
            if not m:
                continue
            r["pcap_total_packets"] = m.get("total_packets", 0)
            r["pcap_tls_clienthellos"] = m.get("tls_clienthellos", 0)
            r["pcap_tls_serverhellos"] = m.get("tls_serverhellos", 0)
            r["pcap_rst_packets"] = m.get("rst_packets", 0)
            r["pcap_success_indicator"] = m.get("success_indicator", False)
            r["pcap_success_score"] = m.get("success_score", 0.0)

    def _suggest_strategies_from_pcap(self, cap_metrics: Dict[str, Dict[str, Any]], fingerprint: Optional["DPIFingerprint"]) -> List[str]:
        """
        На основании PCAP‑метрик предлагает дополнительные стратегии для второго прохода.
        Простые эвристики:
          - много RST или ServerHello=0 → попробовать fake+badsum TTL=1..2 и multisplit/multidisorder
          - если какой‑то класс уже частично сработал → варьировать параметры
        """
        if not cap_metrics or "error" in cap_metrics:
            return []
        # Аггрегированные признаки
        total_ch = sum(m.get("tls_clienthellos", 0) for m in cap_metrics.values())
        total_sh = sum(m.get("tls_serverhellos", 0) for m in cap_metrics.values())
        total_rst = sum(m.get("rst_packets", 0) for m in cap_metrics.values())

        suggestions: List[str] = []
        # 1) Полный провал (нет ServerHello): усилить агрессивные техники
        if total_sh == 0:
            suggestions.extend([
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
                "--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-ttl=64",
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4"
            ])
        # 2) Много RST → упор на badsum/badseq и низкий TTL
        if total_rst >= 3:
            suggestions.extend([
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum,badseq"
            ])
        # 3) Если какая‑то стратегия дала success_score>0 (ServerHello/ClientHello), усилим её семейство
        best_sid = None
        best_score = 0.0
        for sid, m in cap_metrics.items():
            sc = float(m.get("success_score", 0.0))
            if sc > best_score:
                best_score = sc
                best_sid = sid
        if best_sid and best_score >= 0.1:
            sid_low = best_sid.lower()
            if "multidisorder" in sid_low:
                suggestions.append("--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-ttl=64")
                suggestions.append("--dpi-desync=multidisorder --dpi-desync-split-count=3 --dpi-desync-ttl=64")
            elif "multisplit" in sid_low:
                suggestions.append("--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-ttl=4")
            elif "fake" in sid_low:
                suggestions.append("--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum")
        # Небольшой лимит
        # Дедупликат
        out, seen = [], set()
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out[:6]

    def _boost_with_full_pool(self, fingerprint: Optional["DPIFingerprint"]) -> List[str]:
        """
        Быстрые шаблоны по всему пулу атак реестра.
        Возвращает zapret-строки, которые стоит прогнать второй волной.
        """
        if not self.attack_registry:
            return []

        # Получим доступные атаки
        try:
            attacks = self.attack_registry.list_attacks(enabled_only=True) or []
        except Exception:
            attacks = []

        out: List[str] = []

        # Базовые «универсалы»
        out.extend([
            "--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-ttl=64",
            "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4",
            "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
            "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
        ])

        # Если DPI “commercial” → добавим ещё reordering/seqovl
        if fingerprint and getattr(fingerprint, "dpi_type", None) and fingerprint.dpi_type.name.lower().startswith("commercial"):
            out.extend([
                "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=2",
                "--dpi-desync=fake,split --dpi-desync-split-pos=5 --dpi-desync-ttl=2",
            ])

        # Дедуп
        uniq, seen = [], set()
        for s in out:
            if s not in seen:
                uniq.append(s)
                seen.add(s)
        return uniq[:10]

    async def fingerprint_target(self, domain: str, port: int=443, force_refresh: bool=False) -> Optional[DPIFingerprint]:
        """
        Perform advanced DPI fingerprinting for target.

        Args:
            domain: Target domain name
            port: Target port
            force_refresh: Force new analysis even if cached

        Returns:
            DPIFingerprint object or None if fingerprinting fails/disabled
        """
        if not self.advanced_fingerprinting_enabled:
            return None
        try:
            LOG.info(f'Starting DPI fingerprinting for {domain}:{port}')
            start_time = time.time()
            fingerprint = await self.advanced_fingerprinter.fingerprint_target(target=domain, port=port, force_refresh=force_refresh)
            analysis_time = time.time() - start_time
            self.fingerprint_stats['fingerprints_created'] += 1
            LOG.info(f'DPI fingerprinting completed for {domain}:{port} in {analysis_time:.2f}s')
            LOG.info(f'Detected DPI type: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})')
            return fingerprint
        except FingerprintingError as e:
            LOG.error(f'Fingerprinting failed for {domain}:{port}: {e}')
            self.fingerprint_stats['fingerprint_failures'] += 1
            return None
        except Exception as e:
            LOG.error(f'Unexpected error during fingerprinting {domain}:{port}: {e}')
            self.fingerprint_stats['fingerprint_failures'] += 1
            return None

    def _adapt_strategies_for_fingerprint(self, strategies: List[str], fingerprint: DPIFingerprint) -> List[str]:
        """
        Adapt and prioritize strategies based on DPI fingerprint.

        Args:
            strategies: Original list of strategies
            fingerprint: DPI fingerprint with detected characteristics

        Returns:
            Reordered and potentially modified strategy list
        """
        if not fingerprint:
            return strategies
        adapted_strategies = []
        dpi_type = fingerprint.dpi_type
        confidence = fingerprint.confidence
        LOG.info(f'Adapting strategies for DPI type: {dpi_type.value} (confidence: {confidence:.2f})')
        if dpi_type == DPIType.ROSKOMNADZOR_TSPU:
            priority_patterns = ['--dpi-desync-ttl=[1-5]', '--dpi-desync=fake.*disorder', '--dpi-desync-fooling=badsum']
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
        elif dpi_type == DPIType.ROSKOMNADZOR_DPI:
            priority_patterns = ['--dpi-desync=.*split', '--dpi-desync-split-pos=midsld', '--dpi-desync=fake']
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
        elif dpi_type == DPIType.COMMERCIAL_DPI:
            priority_patterns = ['--dpi-desync=multisplit', '--dpi-desync-split-seqovl', '--dpi-desync-repeats=[2-5]']
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
            adapted_strategies.extend(['--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10', '--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum'])
        elif dpi_type == DPIType.FIREWALL_BASED:
            priority_patterns = ['--dpi-desync=disorder', '--dpi-desync-ttl=[64,127,128]']
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
        elif dpi_type == DPIType.ISP_TRANSPARENT_PROXY:
            priority_patterns = ['--dpi-desync=fake.*disorder', '--dpi-desync-fooling=.*seq']
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
        if fingerprint.rst_injection_detected and fingerprint.connection_reset_timing < 100:
            adapted_strategies.extend([
                '--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum',
                '--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq',
                '--dpi-desync-stealth-mode --dpi-desync-rst-evasion'  # Новая стратегия
            ])
        if fingerprint.tcp_window_manipulation:
            adapted_strategies.extend(['--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10'])
        if fingerprint.http_header_filtering:
            adapted_strategies.extend(['--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum'])
        seen = set()
        unique_strategies = []
        for strategy in adapted_strategies + strategies:
            if strategy not in seen:
                seen.add(strategy)
                unique_strategies.append(strategy)
        LOG.info(f'Adapted {len(strategies)} strategies to {len(unique_strategies)} fingerprint-aware strategies')
        return unique_strategies

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

    def _generate_registry_strategies(self, available_attacks: List[str], fingerprint: DPIFingerprint, domain: str, port: int) -> List[str]:
        """Generate new strategies based on registry attacks and fingerprint."""
        registry_strategies = []
        if fingerprint.rst_injection_detected and fingerprint.connection_reset_timing < 100:
            registry_strategies.extend(['--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum', '--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq'])
        if fingerprint.tcp_window_manipulation:
            registry_strategies.extend(['--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10', '--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-fooling=badsum'])
        return registry_strategies[:5]

    def assign_domain_to_pool(self, domain: str, port: int=443, strategy: Optional[BypassStrategy]=None) -> bool:
        """
        Assign a domain to a strategy pool.

        Args:
            domain: Domain to assign
            port: Target port
            strategy: Optional specific strategy to use

        Returns:
            True if assignment successful
        """
        if not self.modern_bypass_enabled or not self.pool_manager:
            return False
        try:
            pool_id = self.pool_manager.auto_assign_domain(domain, port=port)
            if not pool_id and strategy:
                pool = self.pool_manager.create_pool(f'Pool for {domain}', strategy, f'Auto-created pool for {domain}:{port}')
                self.pool_manager.add_domain_to_pool(pool.id, domain)
                pool_id = pool.id
            if pool_id:
                self.bypass_stats['pool_assignments'] += 1
                LOG.info(f'Assigned {domain}:{port} to pool {pool_id}')
                return True
            return False
        except Exception as e:
            LOG.error(f'Failed to assign domain to pool: {e}')
            return False

    def get_pool_strategy_for_domain(self, domain: str, port: int=443) -> Optional[BypassStrategy]:
        """Get the pool strategy for a domain."""
        if not self.modern_bypass_enabled or not self.pool_manager:
            return None
        return self.pool_manager.get_strategy_for_domain(domain, port)

    def switch_bypass_mode(self, mode: OperationMode) -> bool:
        """
        Switch the bypass engine operation mode.

        Args:
            mode: Target operation mode

        Returns:
            True if switch successful
        """
        if not self.modern_bypass_enabled or not self.mode_controller:
            return False
        try:
            success = self.mode_controller.switch_mode(mode)
            if success:
                self.bypass_stats['mode_switches'] += 1
                LOG.info(f'Switched bypass mode to {mode.value}')
            return success
        except Exception as e:
            LOG.error(f'Failed to switch bypass mode: {e}')
            return False

    def validate_strategy_reliability(self, domain: str, strategy: BypassStrategy, port: int=443) -> Optional[float]:
        """
        Validate strategy reliability using the modern validation system.

        Args:
            domain: Target domain
            strategy: Strategy to validate
            port: Target port

        Returns:
            Reliability score (0.0-1.0) or None if validation failed
        """
        if not self.modern_bypass_enabled or not self.reliability_validator:
            return None
        try:
            validation_result = asyncio.run(self.reliability_validator.validate_strategy(domain, strategy))
            if validation_result:
                return validation_result.reliability_score
            return None
        except Exception as e:
            LOG.error(f'Strategy reliability validation failed: {e}')
            return None

    def _prioritize_strategies(self, strategies: List[str], priority_patterns: List[str]) -> List[str]:
        """
        Prioritize strategies matching given patterns.

        Args:
            strategies: List of strategies to prioritize
            priority_patterns: List of regex patterns for prioritization

        Returns:
            List of strategies matching priority patterns
        """
        import re
        prioritized = []
        for pattern in priority_patterns:
            for strategy in strategies:
                if re.search(pattern, strategy) and strategy not in prioritized:
                    prioritized.append(strategy)
        return prioritized

    def get_fingerprint_stats(self) -> Dict[str, int]:
        """Get fingerprinting statistics"""
        stats = self.fingerprint_stats.copy()
        if self.advanced_fingerprinter:
            try:
                advanced_stats = self.advanced_fingerprinter.get_stats()
                stats.update({'advanced_' + k: v for k, v in advanced_stats.items()})
            except Exception as e:
                LOG.error(f'Failed to get advanced fingerprinter stats: {e}')
        return stats

    def get_bypass_stats(self) -> Dict[str, Any]:
        """Get bypass engine statistics"""
        stats = self.bypass_stats.copy()
        if self.modern_bypass_enabled:
            if self.attack_registry:
                try:
                    registry_stats = self.attack_registry.get_stats()
                    stats.update({'registry_' + k: v for k, v in registry_stats.items()})
                except Exception as e:
                    LOG.error(f'Failed to get attack registry stats: {e}')
            if self.pool_manager:
                try:
                    pool_stats = self.pool_manager.get_pool_statistics()
                    stats.update({'pool_' + k: v for k, v in pool_stats.items()})
                except Exception as e:
                    LOG.error(f'Failed to get pool manager stats: {e}')
            if self.mode_controller:
                try:
                    mode_info = self.mode_controller.get_mode_info()
                    stats.update({'mode_' + k: v for k, v in mode_info.items()})
                except Exception as e:
                    LOG.error(f'Failed to get mode controller info: {e}')
        return stats

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all components"""
        return {'fingerprint_stats': self.get_fingerprint_stats(), 'bypass_stats': self.get_bypass_stats(), 'modern_engine_enabled': self.modern_bypass_enabled, 'advanced_fingerprinting_enabled': self.advanced_fingerprinting_enabled}

    def cleanup(self):
        """Очистка ресурсов."""
        if self.advanced_fingerprinter and hasattr(self.advanced_fingerprinter, 'executor'):
            try:
                self.advanced_fingerprinter.executor.shutdown(wait=True)
            except Exception as e:
                LOG.error(f'Error shutting down fingerprinter executor: {e}')
        if self.modern_bypass_enabled:
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
                LOG.info('Modern bypass engine components cleaned up')
            except Exception as e:
                LOG.error(f'Error cleaning up modern bypass engine: {e}')