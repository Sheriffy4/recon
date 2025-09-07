import logging
import time
import asyncio
import aiohttp
import socket
import ssl
import random
from collections import defaultdict
import re
import ast
from typing import Dict, List, Tuple, Optional, Set, Any, Union
from urllib.parse import urlparse
from core.bypass_engine import BypassEngine
from core.zapret_parser import ZapretStrategyParser
try:
    from core.fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    from core.fingerprint.advanced_models import DPIFingerprint, DPIType
    ADVANCED_FINGERPRINTING_AVAILABLE = True
except ImportError:
    ADVANCED_FINGERPRINTING_AVAILABLE = False

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
                 enable_modern_bypass: bool=True, verbosity: str="normal", enable_enhanced_tracking: bool=False):
        self.debug = debug
        self.verbosity = verbosity
        self.parser = ZapretStrategyParser()
        if enable_advanced_fingerprinting and ADVANCED_FINGERPRINTING_AVAILABLE:
            self.advanced_fingerprinter = AdvancedFingerprinter()
        else:
            self.advanced_fingerprinter = None

    def _translate_zapret_to_engine_task(self, params: Dict) -> Optional[Dict]:
        """
        ИСПРАВЛЕНИЕ: Унифицированный и надежный транслятор zapret-строки в задачу для BypassEngine.
        """
        desync = params.get('dpi_desync', [])
        fooling = params.get('dpi_desync_fooling', [])
        if not desync:
            return None
        task_type = 'none'
        task_params = {}
        if 'fakedisorder' in desync:
            task_type = 'fakedisorder'
        elif 'multidisorder' in desync:
            task_type = 'multidisorder'
        elif 'multisplit' in desync:
            task_type = 'multisplit'
        if task_type in ['fakeddisorder', 'multidisorder', 'multisplit']:
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
            else:
                task_type = 'fake' if task_type == 'none' else task_type
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

    def _parse_engine_pretty(self, s: str) -> Optional[Dict[str, Any]]:
        """
        Поддержка строк вида: fake(ttl=2, split_pos=3, fooling=['badsum'])
        Возвращает {'type': 'fake', 'params': {...}}
        """
        try:
            m = re.match(r'^\s*([A-Za-z0-9_]+)\s*(?:\((.*)\))?\s*$', s)
            if not m:
                return None
            name, args = m.group(1), (m.group(2) or "").strip()
            params = {}
            if args:
                # безоп. парсинг аргументов вида k=v через ast.literal_eval через dict()
                try:
                    params = ast.literal_eval("dict(" + args + ")")
                    if not isinstance(params, dict):
                        return None
                except Exception:
                    return None
            # normalize 'fooling_methods' -> 'fooling'
            if "fooling" not in params and "fooling_methods" in params:
                params["fooling"] = params.get("fooling_methods", [])
            return {"type": name, "params": params}
        except Exception:
            return None

    def _ensure_engine_task(self, strategy: Union[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        # dict → используем как есть
        if isinstance(strategy, dict):
            t = strategy.get('type') or strategy.get('name')
            if not t:
                return None
            return {'type': t, 'params': strategy.get('params', {})}
        # str → сначала пробуем «красивый» формат name(k=v,...), затем zapret
        s = (strategy or "").strip()
        pretty = self._parse_engine_pretty(s)
        if pretty:
            return pretty
        parsed_params = self.parser.parse(s)
        return self._translate_zapret_to_engine_task(parsed_params)

    async def _test_sites_connectivity(
        self,
        sites: List[str],
        dns_cache: Dict[str, str],
        max_concurrent: int = 10,
        timeouts: Optional[Dict[str, float]] = None,
        attempts: int = 1,
        backoff_factor: float = 1.6,
        jitter: float = 0.15,
        limit_per_host: int = 5
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Более устойчивый тестовый клиент на aiohttp с принудительным DNS.
        Добавлены параметризуемые таймауты и ретраи с экспоненциальным бэкоффом
        (ретраятся только сайты со статусами TIMEOUT/ERROR на предыдущих попытках).
        """
        results: Dict[str, Tuple[str, str, float, int]] = {}
        semaphore = asyncio.Semaphore(max_concurrent)
        # Профиль таймаутов (увеличены дефолты для «шумных» сетей)
        tprof = {
            "total": 20.0,
            "connect": 6.0,
            "sock_read": 12.0,
        }
        if timeouts:
            tprof.update({k: v for k, v in timeouts.items() if v})

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

        async def test_with_semaphore(session: aiohttp.ClientSession, site: str):
            async with semaphore:
                start_time = time.time()
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, 'N/A')
                try:
                    client_timeout = aiohttp.ClientTimeout(
                        total=float(tprof["total"]), connect=float(tprof["connect"]), sock_read=float(tprof["sock_read"])
                    )
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
        # Ретраи по TIMEOUT/ERROR с экспоненциальным бэкоффом
        pending = list(sites)
        for attempt in range(max(1, attempts)):
            connector = aiohttp.TCPConnector(
                ssl=ssl_context, limit_per_host=int(limit_per_host), resolver=CustomResolver(dns_cache)
            )
            try:
                async with aiohttp.ClientSession(connector=connector) as session:
                    tasks = [test_with_semaphore(session, site) for site in pending]
                    task_results = await asyncio.gather(*tasks)
                    next_pending = []
                    for site, result_tuple in task_results:
                        status = result_tuple[0]
                        if status == 'WORKING':
                            results[site] = result_tuple
                        else:
                            # Запланируем на след. попытку, если будут попытки
                            if attempt < attempts - 1:
                                next_pending.append(site)
                            else:
                                results[site] = result_tuple
                    pending = next_pending
            finally:
                try:
                    await connector.close()
                except Exception:
                    pass
            if not pending:
                break
            # экспоненциальный бэкофф с небольшим джиттером
            delay = (backoff_factor ** attempt) * (0.4 + random.random() * jitter)
            await asyncio.sleep(delay)
        return results

    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность, отправляя ClientHello, чтобы спровоцировать DPI.
        Использует aiohttp, так как он корректно обрабатывает сброс соединения.
        """
        LOG.info('Тестируем базовую доступность сайтов (без bypass) с DNS-кэшем...')
        return await self._test_sites_connectivity(test_sites, dns_cache, max_concurrent=10)

    async def execute_strategy_real_world(
        self,
        strategy: Union[str, Dict[str, Any]],
        test_sites: List[str],
        target_ips: Set[str],
        dns_cache: Dict[str, str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
        fingerprint: Optional["DPIFingerprint"] = None,
        prefer_retry_on_timeout: bool = False,
        return_details: bool = False
    ) -> Tuple[str, int, int, float]:
        """
        Реальное тестирование стратегии с использованием нового BypassEngine.
        Теперь с поддержкой контекстной информации от фингерпринтинга.
        """
        engine_task = self._ensure_engine_task(strategy)
        if not engine_task:
            LOG.warning(f"Strategy translation failed, skipping: {strategy}")
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
                # Первая попытка: стандартные/увеличенные таймауты, с опциональным retry для первых стратегий
                attempts = 2 if prefer_retry_on_timeout else 1
                results = await self._test_sites_connectivity(
                    test_sites, dns_cache,
                    max_concurrent=10,
                    timeouts={"total": 20.0, "connect": 6.0, "sock_read": 12.0},
                    attempts=attempts,
                    backoff_factor=1.7,
                    limit_per_host=4
                )
            except Exception as connectivity_error:
                LOG.error(f'Connectivity test failed: {connectivity_error}')
                if fingerprint and fingerprint.tcp_window_manipulation:
                    LOG.info('Retrying with adjusted parameters due to TCP window manipulation')
                    await asyncio.sleep(0.5)
                    results = await self._test_sites_connectivity(
                        test_sites, dns_cache,
                        max_concurrent=8,
                        timeouts={"total": 25.0, "connect": 8.0, "sock_read": 15.0},
                        attempts=2, backoff_factor=1.8, limit_per_host=3
                    )
                else:
                    raise
            successful_count = sum((1 for status, _, _, _ in results.values() if status == 'WORKING'))
            successful_latencies = [latency for status, _, latency, _ in results.values() if status == 'WORKING']
            avg_latency = sum(successful_latencies) / len(successful_latencies) if successful_latencies else 0.0
            # Эвристика: если всё TIMEOUT/ERROR и «пахнет» проблемой окна/агрессивным middlebox —
            # повторим с усиленными таймаутами даже без фингерпринта
            if successful_count == 0 and self._should_retry_timeout(results, dns_cache, target_ips) and not prefer_retry_on_timeout:
                LOG.info('Heuristic retry: suspected TCP window/middlebox issue → increasing timeouts and retrying once')
                await asyncio.sleep(0.4)
                results = await self._test_sites_connectivity(
                    test_sites, dns_cache,
                    max_concurrent=8,
                    timeouts={"total": 28.0, "connect": 9.0, "sock_read": 16.0},
                    attempts=2, backoff_factor=1.8, limit_per_host=3
                )
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

    def _should_retry_timeout(
        self,
        results: Dict[str, Tuple[str, str, float, int]],
        dns_cache: Dict[str, str],
        target_ips: Set[str]
    ) -> bool:
        """
        Эвристика «подозрения» на TCP window/middlebox:
          - 80%+ TIMEOUT/ERROR, ни одного WORKING
          - домены/цели попадают под крупные CDN/Google/Facebook/CF/Fastly и т.п.
        """
        if not results:
            return False
        total = len(results)
        if total == 0:
            return False
        timeouts = sum(1 for st, *_ in results.values() if st in ("TIMEOUT", "ERROR"))
        if timeouts < max(1, int(0.8 * total)):
            return False
        # Быстрая проверка по префиксам известных CDN/вендоров
        prefixes = {
            "104.", "172.64.", "172.67.", "162.158.", "162.159.",     # Cloudflare
            "151.101.", "199.232.",                                    # Fastly
            "216.58.", "172.217.", "142.250.", "172.253.", "209.85.",  # Google
            "31.13.", "157.240.", "69.171.",                           # Meta
            "104.244.", "199.59.",                                     # Twitter
        }
        def match_prefix(ip: str) -> bool:
            return any(ip.startswith(p) for p in prefixes)
        # Если в target_ips или dns_cache есть «подозрительные» префиксы — усиливаем вероятность ретрая
        if any(match_prefix(ip) for ip in list(target_ips) + list(dns_cache.values())):
            return True
        # иначе — ретрай не обязателен
        return False

    async def test_strategies_hybrid(self, strategies: List[Union[str, Dict[str, Any]]], test_sites: List[str], ips: Set[str], dns_cache: Dict[str, str], port: int, domain: str, fast_filter: bool=True, initial_ttl: Optional[int]=None, enable_fingerprinting: bool=True, use_modern_engine: bool=True, capturer: Optional[Any]=None) -> List[Dict]:
        """
        Гибридное тестирование стратегий с продвинутым фингерпринтингом DPI:
        1. Выполняет фингерпринтинг DPI для целевого домена
        2. Адаптирует стратегии под обнаруженный тип DPI
        3. Проводит реальное тестирование с помощью BypassEngine
        """
        results = []
        fingerprint = None
        if enable_fingerprinting and self.advanced_fingerprinter:
            try:
                LOG.info(f'Performing DPI fingerprinting for {domain}:{port}')
                fingerprint = await self.advanced_fingerprinter.fingerprint_target(domain, port)
                if fingerprint:
                    LOG.info(f'DPI fingerprint obtained: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})')
                else:
                    LOG.warning('DPI fingerprinting failed, proceeding with standard testing')
            except Exception as e:
                LOG.error(f'DPI fingerprinting error: {e}')

        # Базовый список может содержать dict/str — сохраняем типы как есть
        base: List[Union[str, Dict[str, Any]]] = strategies[:]
        str_only: List[str] = [s for s in base if isinstance(s, str)]
        dict_only: List[Dict[str, Any]] = [s for s in base if isinstance(s, dict)]
        strategies_to_test: List[Union[str, Dict[str, Any]]] = []

        if fingerprint and str_only:
            adapted = self._adapt_strategies_for_fingerprint(str_only, fingerprint)
            strategies_to_test = dict_only + adapted
            LOG.info(f'Using {len(strategies_to_test)} fingerprint-adapted strategies (dict+str)')
        else:
            strategies_to_test = base
            LOG.info(f'Using {len(strategies_to_test)} strategies as provided (mixed types)')

        # Merge synthesized first (dict), dedupe by pretty-string key
        synthesized = None # Placeholder for synthesis logic if it were here
        if synthesized and isinstance(synthesized, dict):
            pretty_key = self._task_to_str(synthesized)
            merged: List[Union[str, Dict[str, Any]]] = [synthesized] + strategies_to_test
            seen = set()
            unique: List[Union[str, Dict[str, Any]]] = []
            for s in merged:
                key = s if isinstance(s, str) else self._task_to_str(s)
                if key not in seen:
                    seen.add(key)
                    unique.append(s)
            strategies_to_test = unique
            LOG.info(f"Prepended synthesized strategy: {pretty_key}")

        # Если после всех оптимизаций стратегий нет — фолбэк к стандартному набору
        if not strategies_to_test:
            strategies_to_test = base or ["--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3"]
            LOG.warning(f"No strategies after optimization, falling back to {len(strategies_to_test)}")

        LOG.info(f'Начинаем реальное тестирование {len(strategies_to_test)} стратегий с помощью BypassEngine...')
        for i, strategy in enumerate(strategies_to_test):
            pretty = strategy if isinstance(strategy, str) else self._task_to_str(strategy)
            LOG.info(f'--> Тест {i + 1}/{len(strategies_to_test)}: {pretty}')
            if capturer:
                try: capturer.mark_strategy_start(str(strategy))
                except Exception: pass
            ret = await self.execute_strategy_real_world(
                strategy,  # передаём оригинал (dict или str)
                test_sites, ips, dns_cache, port, initial_ttl, fingerprint,
                prefer_retry_on_timeout=(i < 2),
                return_details=True
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
            if success_rate > 0:
                LOG.info(f'✓ Успех: {success_rate:.0%} ({successful_count}/{total_count}), задержка: {avg_latency:.1f}ms')
            else:
                LOG.info(f'✗ Провал: ни один сайт не заработал. Причина: {result_status}')
        if fingerprint:
            results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms'], 1 if x['fingerprint_used'] else 0), reverse=True)
        else:
            results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms']), reverse=True)
        return results

    def _adapt_strategies_for_fingerprint(self, strategies: List[str], fingerprint: DPIFingerprint) -> List[str]:
        """
        Адаптирует и приоритизирует стратегии на основе фингерпринта DPI.
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
        if fingerprint.rst_injection_detected and fingerprint.connection_reset_timing < 100:
            adapted_strategies.extend(['--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum', '--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq'])
        if fingerprint.tcp_window_manipulation:
            adapted_strategies.extend(['--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10'])
        seen = set()
        unique_strategies = []
        for strategy in adapted_strategies + strategies:
            if strategy not in seen:
                seen.add(strategy)
                unique_strategies.append(strategy)
        LOG.info(f'Adapted {len(strategies)} strategies to {len(unique_strategies)} fingerprint-aware strategies')
        return unique_strategies

    def _prioritize_strategies(self, strategies: List[str], priority_patterns: List[str]) -> List[str]:
        """
        Приоритизирует стратегии, совпадающие с заданными паттернами.
        """
        import re
        prioritized = []
        for pattern in priority_patterns:
            for strategy in strategies:
                if re.search(pattern, strategy) and strategy not in prioritized:
                    prioritized.append(strategy)
        return prioritized

    def cleanup(self):
        """Очистка ресурсов."""
        if self.advanced_fingerprinter and hasattr(self.advanced_fingerprinter, 'executor'):
            try:
                self.advanced_fingerprinter.executor.shutdown(wait=True)
            except Exception as e:
                LOG.error(f'Error shutting down fingerprinter executor: {e}')