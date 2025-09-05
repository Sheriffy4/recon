import logging
import time
import asyncio
import aiohttp
import socket
import ssl
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

LOG = logging.getLogger('hybrid_engine')
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36'}

class HybridEngine:
    """
    Гибридный движок, который сочетает:
    1. Парсинг zapret-стратегий.
    2. Реальное тестирование через запущенный BypassEngine с синхронизированным DNS.
    3. Продвинутый фингерпринтинг DPI для контекстно-зависимой генерации стратегий.
    """

    def __init__(self, debug: bool=False, enable_advanced_fingerprinting: bool=True, enable_modern_bypass: bool=True, verbosity: str="normal"):
        self.debug = debug
        self.verbosity = verbosity
        self.parser = ZapretStrategyParser()
        
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
            elif task_type == 'none' and (params.get('dpi_desync_ttl') or params.get('dpi_desync_fake_tls')):
                task_type = 'badsum_race'
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
        if task_type == 'none':
            LOG.warning(f'Не удалось транслировать zapret-стратегию в задачу для движка: {params}')
            return None
        return {'type': task_type, 'params': task_params}

    def _task_to_str(self, task: Dict[str, Any]) -> str:
        try:
            t = task.get('type') or task.get('name') or 'unknown'
            p = task.get('params', {})
            pairs = []
            for k, v in p.items():
                try:
                    pairs.append(f"{k}={v}")
                except Exception:
                    pairs.append(f"{k}=<obj>")
            return f"{t}({', '.join(pairs)})"
        except Exception:
            return str(task)

    def _ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        # dict → нормализуем
        if isinstance(strategy, dict):
            t = strategy.get('type') or strategy.get('name')
            if not t:
                return None
            return {'type': t, 'params': strategy.get('params', {})}
        # str → парсим zapret-строку
        parsed_params = self.parser.parse(strategy)
        return self._translate_zapret_to_engine_task(parsed_params)

    async def _test_sites_connectivity(self, sites: List[str], dns_cache: Dict[str, str], max_concurrent: int=10) -> Dict[str, Tuple[str, str, float, int]]:
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

        async def test_with_semaphore(session, site):
            async with semaphore:
                start_time = time.time()
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, 'N/A')
                try:
                    client_timeout = aiohttp.ClientTimeout(total=15.0, connect=5.0, sock_read=10.0)
                    async with session.get(site, headers=HEADERS, allow_redirects=True, timeout=client_timeout) as response:
                        await response.content.readexactly(1)
                        latency = (time.time() - start_time) * 1000
                        return (site, ('WORKING', ip_used, latency, response.status))
                except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError) as e:
                    latency = (time.time() - start_time) * 1000
                    LOG.debug(f'Connectivity test for {site} failed with {type(e).__name__}')
                    return (site, ('TIMEOUT', ip_used, latency, 0))
                except Exception as e:
                    latency = (time.time() - start_time) * 1000
                    LOG.debug(f'Неожиданная ошибка при тестировании {site}: {e}')
                    return (site, ('ERROR', ip_used, latency, 0))
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [test_with_semaphore(session, site) for site in sites]
            task_results = await asyncio.gather(*tasks)
            for site, result_tuple in task_results:
                results[site] = result_tuple
        await connector.close()
        return results

    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность, отправляя ClientHello, чтобы спровоцировать DPI.
        Использует aiohttp, так как он корректно обрабатывает сброс соединения.
        """
        LOG.info('Тестируем базовую доступность сайтов (без bypass) с DNS-кэшем...')
        return await self._test_sites_connectivity(test_sites, dns_cache)

    async def execute_strategy_real_world(self, strategy: Union[str, Dict[str, Any]], test_sites: List[str], target_ips: Set[str], dns_cache: Dict[str, str], target_port: int=443, initial_ttl: Optional[int]=None, fingerprint: Optional[DPIFingerprint]=None, return_details: bool=False) -> Tuple[str, int, int, float]:
        """
        Реальное тестирование стратегии с использованием нового BypassEngine.
        Теперь с поддержкой контекстной информации от фингерпринтинга.
        """
        engine_task = self._ensure_engine_task(strategy)
        if not engine_task:
            return ('TRANSLATION_FAILED', 0, len(test_sites), 0.0)
        bypass_engine = BypassEngine(debug=self.debug)
        strategy_map = {'default': engine_task}
        bypass_thread = bypass_engine.start(target_ips, strategy_map)
        try:
            wait_time = 1.5
            if fingerprint:
                if fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU:
                    wait_time = 1.0
                elif fingerprint.dpi_type == DPIType.COMMERCIAL_DPI:
                    wait_time = 2.0
                elif fingerprint.connection_reset_timing > 0:
                    wait_time = max(1.0, fingerprint.connection_reset_timing / 1000.0 + 0.5)
            await asyncio.sleep(wait_time)
            try:
                results = await self._test_sites_connectivity(test_sites, dns_cache)
            except Exception as connectivity_error:
                LOG.error(f'Connectivity test failed: {connectivity_error}')
                if fingerprint and fingerprint.tcp_window_manipulation:
                    LOG.info('Retrying with adjusted parameters due to TCP window manipulation')
                    await asyncio.sleep(0.5)
                    results = await self._test_sites_connectivity(test_sites, dns_cache)
                else:
                    raise
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
            
            # Обновляем KB по результатам (если доступна)
            try:
                if self.knowledge_base:
                    pretty_strategy = strategy if isinstance(strategy, str) else self._task_to_str(strategy)
                    for site, (status, ip_used, lat_ms, _http) in (results or {}).items():
                        domain = urlparse(site).hostname or site
                        ok = (status == 'WORKING')
                        bt = BlockType.NONE if ok else BlockType.UNKNOWN
                        self.knowledge_base.update_with_result(
                            domain=domain, ip=ip_used or "", strategy={"raw": pretty_strategy},
                            success=ok, block_type=bt, latency_ms=float(lat_ms or 0.0)
                        )
                    self.knowledge_base.save()
            except Exception as e:
                LOG.debug(f"KB update failed: {e}")

            if return_details:
                return (result_status, successful_count, len(test_sites), avg_latency, results)
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

    async def test_strategies_hybrid(self, strategies: List[Union[str, Dict[str, Any]]], test_sites: List[str], ips: Set[str], dns_cache: Dict[str, str], port: int, domain: str, fast_filter: bool=True, initial_ttl: Optional[int]=None, enable_fingerprinting: bool=True, use_modern_engine: bool=True, capturer: Optional[Any]=None) -> List[Dict]:
        """
        Гибридное тестирование стратегий с продвинутым фингерпринтингом DPI:
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
        else:
            self.fingerprint_stats['fallback_tests'] += 1
        # Knowledge init: derive CDN/ASN profile for primary domain
        cdn = None
        asn = None
        kb_profile = {}
        primary_ip = dns_cache.get(domain) if dns_cache else None
        if self.knowledge_base and primary_ip:
            try:
                info = self.knowledge_base.identify(primary_ip)
                cdn = info.get("cdn")
                asn = info.get("asn")
                kb_profile = self.knowledge_base.get_profile(cdn=cdn, asn=asn) or {}
                LOG.info(f"KB: identified cdn={cdn}, asn={asn}")
            except Exception as e:
                LOG.debug(f"KB identify failed: {e}")

        # Prepend synthesized strategy based on context (fingerprint + KB)
        try:
            ctx = AttackContext(domain=domain, ip=primary_ip, port=port,
                                fingerprint=fingerprint, cdn=cdn, asn=asn,
                                kb_profile=kb_profile)
            synthesized = synthesize_strategy(ctx)
        except Exception as e:
            synthesized = None
            LOG.debug(f"Strategy synthesis failed: {e}")

        # Базовый список (может содержать dict/str). ВАЖНО: dict оставляем dict, str оставляем zapret-строкой
        base: List[Union[str, Dict[str, Any]]] = strategies[:]

        # Список кандидатов, которые будем реально тестировать (сохраняем тип)
        strategies_to_test: List[Union[str, Dict[str, Any]]] = []

        # Для modern registry и fingerprint адаптации работаем ТОЛЬКО со строками (zapret),
        # dict-стратегии не преобразуем в fake(...) текст
        base_strings: List[str] = [s for s in base if isinstance(s, str)]
        base_dicts: List[Dict[str, Any]] = [s for s in base if isinstance(s, dict)]

        if use_modern and self.attack_registry and base_strings:
            enhanced = self._enhance_strategies_with_registry(base_strings, fingerprint, domain, port)
            self.bypass_stats['attack_registry_queries'] += 1
            strategies_to_test.extend(enhanced)
        elif fingerprint and base_strings:
            adapted = self._adapt_strategies_for_fingerprint(base_strings, fingerprint)
            LOG.info(f'Using {len(adapted)} fingerprint-adapted strategies')
            strategies_to_test.extend(adapted)
        else:
            strategies_to_test.extend(base_strings)
            LOG.info(f'Using {len(base_strings)} standard zapret strategies (no fingerprint or no registry input)')

        # Добавляем dict-стратегии как есть (engine_task). Они уже интерпретированы и готовы для движка.
        strategies_to_test.extend(base_dicts)

        # Дедупликация по «ключу», но оставляем оригинальный объект (str/dict)
        seen_keys = set()
        unique_list: List[Union[str, Dict[str, Any]]] = []
        for s in strategies_to_test:
            key = s if isinstance(s, str) else self._task_to_str(s)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_list.append(s)
        strategies_to_test = unique_list

        # Merge synthesized first (dict), dedupe; synthesized добавляем как dict
        if synthesized and isinstance(synthesized, dict):
            pretty = self._task_to_str(synthesized)
            merged = [synthesized] + strategies_to_test
            seen = set()
            unique: List[Union[str, Dict[str, Any]]] = []
            for s in merged:
                key = s if isinstance(s, str) else self._task_to_str(s)
                if key not in seen:
                    seen.add(key)
                    unique.append(s)
            strategies_to_test = unique
            LOG.info(f"Prepended synthesized strategy: {pretty}")

        LOG.info(f'Начинаем реальное тестирование {len(strategies_to_test)} стратегий с помощью BypassEngine...')
        for i, strategy in enumerate(strategies_to_test):
            # Логируем красиво, но в движок отдаём исходный str/dict
            pretty = strategy if isinstance(strategy, str) else self._task_to_str(strategy)
            LOG.info(f'--> Тест {i + 1}/{len(strategies_to_test)}: {pretty}')
            if capturer:
                try: capturer.mark_strategy_start(str(strategy))
                except Exception: pass
            result_status, successful_count, total_count, avg_latency = await self.execute_strategy_real_world(
                strategy, test_sites, ips, dns_cache, port, initial_ttl, fingerprint
            )
            if capturer:
                try: capturer.mark_strategy_end(str(strategy))
                except Exception: pass
            success_rate = successful_count / total_count if total_count > 0 else 0.0
            result_data = {'strategy': pretty, 'result_status': result_status, 'successful_sites': successful_count, 'total_sites': total_count, 'success_rate': success_rate, 'avg_latency_ms': avg_latency, 'fingerprint_used': fingerprint is not None, 'dpi_type': fingerprint.dpi_type.value if fingerprint else None, 'dpi_confidence': fingerprint.confidence if fingerprint else None}
        
            results.append(result_data)
            # KB update per-domain (успех/провал + причина)
            try:
                if self.knowledge_base and site_results:
                    for site, (st, ip_used, lat_ms, http_code) in site_results.items():
                        d = urlparse(site).hostname or site
                        if st == "WORKING":
                            bt = BlockType.NONE
                            ok = True
                        elif st == "TIMEOUT":
                            bt = BlockType.TIMEOUT
                            ok = False
                        else:
                            bt = BlockType.UNKNOWN
                            ok = False
                        # нормализуем стратегию в dict
                        if isinstance(strategy, dict):
                            strat_obj = {"type": strategy.get("type"), "params": strategy.get("params", {})}
                        else:
                            strat_obj = {"raw": str(strategy)}
                        self.knowledge_base.update_with_result(
                            domain=d,
                            ip=ip_used or "",
                            strategy=strat_obj,
                            success=ok,
                            block_type=bt,
                            latency_ms=float(lat_ms or 0.0)
                        )
            except Exception as e:
                LOG.debug(f"KB update failed: {e}")
            if success_rate > 0:
                LOG.info(f'✓ Успех: {success_rate:.0%} ({successful_count}/{total_count}), задержка: {avg_latency:.1f}ms')
            else:
                LOG.info('✗ Провал: ни один сайт не заработал.')
        if fingerprint:
            results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms'], 1 if x['fingerprint_used'] else 0), reverse=True)
        else:
            results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms']), reverse=True)
        if results and fingerprint:
            LOG.info(f'Strategy testing completed with DPI fingerprint: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})')
            
        # Сохраняем KB после серии тестов
        try:
            if self.knowledge_base:
                self.knowledge_base.save()
        except Exception as e:
            LOG.debug(f"KB save failed: {e}")
                
        return results

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
            adapted_strategies.extend(['--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum', '--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq'])
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