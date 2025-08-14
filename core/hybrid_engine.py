# recon/core/hybrid_engine.py

import logging
import time
import asyncio
import aiohttp
import socket
import ssl
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse

# Импортируем наш новый движок и надежный парсер
from .bypass_engine import BypassEngine
from .zapret_parser import ZapretStrategyParser

# Import advanced fingerprinting system
try:
    from .fingerprint.advanced_fingerprinter import AdvancedFingerprinter, FingerprintingConfig
    from .fingerprint.advanced_models import DPIFingerprint, DPIType, FingerprintingError
    ADVANCED_FINGERPRINTING_AVAILABLE = True
except ImportError as e:
    logging.getLogger("hybrid_engine").warning(f"Advanced fingerprinting not available: {e}")
    ADVANCED_FINGERPRINTING_AVAILABLE = False

LOG = logging.getLogger("hybrid_engine")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36"
}

class HybridEngine:
    """
    Гибридный движок, который сочетает:
    1. Парсинг zapret-стратегий.
    2. Реальное тестирование через запущенный BypassEngine с синхронизированным DNS.
    3. Продвинутый фингерпринтинг DPI для контекстно-зависимой генерации стратегий.
    """
    
    def __init__(self, debug: bool = False, enable_advanced_fingerprinting: bool = True):
        self.debug = debug
        self.parser = ZapretStrategyParser()
        
        # Initialize advanced fingerprinting if available
        self.advanced_fingerprinting_enabled = (
            enable_advanced_fingerprinting and ADVANCED_FINGERPRINTING_AVAILABLE
        )
        
        if self.advanced_fingerprinting_enabled:
            try:
                fingerprint_config = FingerprintingConfig(
                    cache_ttl=3600,  # 1 hour cache
                    enable_ml=True,
                    enable_cache=True,
                    timeout=15.0,
                    fallback_on_error=True
                )
                self.advanced_fingerprinter = AdvancedFingerprinter(config=fingerprint_config)
                LOG.info("Advanced fingerprinting initialized successfully")
            except Exception as e:
                LOG.error(f"Failed to initialize advanced fingerprinting: {e}")
                self.advanced_fingerprinting_enabled = False
                self.advanced_fingerprinter = None
        else:
            self.advanced_fingerprinter = None
            if not ADVANCED_FINGERPRINTING_AVAILABLE:
                LOG.info("Advanced fingerprinting disabled - module not available")
            else:
                LOG.info("Advanced fingerprinting disabled by configuration")
        
        # Statistics for fingerprint-aware testing
        self.fingerprint_stats = {
            'fingerprints_created': 0,
            'fingerprint_cache_hits': 0,
            'fingerprint_failures': 0,
            'fingerprint_aware_tests': 0,
            'fallback_tests': 0
        }

    def _translate_zapret_to_engine_task(self, params: Dict) -> Optional[Dict]:
        """
        ИСПРАВЛЕНИЕ: Унифицированный и надежный транслятор zapret-строки в задачу для BypassEngine.
        """
        desync = params.get('dpi_desync', [])
        fooling = params.get('dpi_desync_fooling', [])
        if not desync: return None

        task_type = 'none'
        task_params = {}

        # Определяем основной тип сегментации
        if 'fakeddisorder' in desync: task_type = 'fakedisorder'
        elif 'multidisorder' in desync: task_type = 'multidisorder'
        elif 'multisplit' in desync: task_type = 'multisplit'
        elif 'disorder' in desync or 'disorder2' in desync: task_type = 'fakedisorder'
        
        # Обрабатываем параметры сегментации
        if task_type in ['fakedisorder', 'multidisorder', 'multisplit']:
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            if any(p.get('type') == 'midsld' for p in split_pos_raw):
                task_params['split_pos'] = 'midsld'
            else:
                positions = [p['value'] for p in split_pos_raw if p.get('type') == 'absolute']
                if task_type == 'fakedisorder':
                    task_params['split_pos'] = positions[0] if positions else 3
                else:
                    task_params['positions'] = positions if positions else [1, 5, 10]

        # Обрабатываем "гоночные" атаки с фейковыми пакетами
        if 'fake' in desync:
            if 'badsum' in fooling:
                # Если уже есть тип сегментации, делаем его гибридом
                # Для простоты пока отдаем приоритет badsum_race
                task_type = 'badsum_race'
            elif 'md5sig' in fooling:
                task_type = 'md5sig_race'
            # Если есть 'fake', но нет fooling, это может быть простая гонка с TTL или fake-tls
            elif task_type == 'none' and (params.get('dpi_desync_ttl') or params.get('dpi_desync_fake_tls')):
                 task_type = 'badsum_race' # Похоже на badsum_race, но без badsum

        # Обрабатываем seqovl, он имеет высокий приоритет
        if params.get('dpi_desync_split_seqovl'):
            task_type = 'seqovl'
            split_pos_raw = params.get('dpi_desync_split_pos', [])
            if any(p.get('type') == 'midsld' for p in split_pos_raw):
                task_params['split_pos'] = 'midsld'
            else:
                positions = [p['value'] for p in split_pos_raw if p.get('type') == 'absolute']
                task_params['split_pos'] = positions[0] if positions else 3
            task_params['overlap_size'] = params.get('dpi_desync_split_seqovl')

        # Добавляем TTL в параметры, если он есть
        if params.get('dpi_desync_ttl'):
            task_params['ttl'] = params.get('dpi_desync_ttl')

        if task_type == 'none':
            LOG.warning(f"Не удалось транслировать zapret-стратегию в задачу для движка: {params}")
            return None
            
        return {'type': task_type, 'params': task_params}

    async def _test_sites_connectivity(self, sites: List[str], dns_cache: Dict[str, str], max_concurrent: int = 10) -> Dict[str, Tuple[str, str, float, int]]:
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
                    LOG.debug(f"CustomResolver: Forcing {host} -> {ip}")
                    return [{'hostname': host, 'host': ip, 'port': port, 'family': family, 'proto': 0, 'flags': 0}]
                # Fallback для редиректов и других доменов
                LOG.debug(f"CustomResolver: Fallback for {host}")
                return await super().resolve(host, port, family)

        # Используем контекст SSL, который не проверяет сертификат, т.к. мы можем идти на IP
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context, limit_per_host=5, resolver=CustomResolver(dns_cache))

        async def test_with_semaphore(session, site):
            async with semaphore:
                start_time = time.time()
                hostname = urlparse(site).hostname or site
                ip_used = dns_cache.get(hostname, "N/A")
                try:
                    # Увеличиваем таймауты, чтобы дать стратегии время сработать
                    client_timeout = aiohttp.ClientTimeout(total=15.0, connect=5.0, sock_read=10.0)
                    async with session.get(site, headers=HEADERS, allow_redirects=True, timeout=client_timeout) as response:
                        # Читаем хотя бы один байт, чтобы убедиться, что соединение не сброшено
                        await response.content.readexactly(1)
                        latency = (time.time() - start_time) * 1000
                        return site, ("WORKING", ip_used, latency, response.status)
                except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError) as e:
                    latency = (time.time() - start_time) * 1000
                    LOG.debug(f"Connectivity test for {site} failed with {type(e).__name__}")
                    return site, ("TIMEOUT", ip_used, latency, 0)
                except Exception as e:
                    latency = (time.time() - start_time) * 1000
                    LOG.debug(f"Неожиданная ошибка при тестировании {site}: {e}")
                    return site, ("ERROR", ip_used, latency, 0)

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [test_with_semaphore(session, site) for site in sites]
            task_results = await asyncio.gather(*tasks)
            for site, result_tuple in task_results:
                results[site] = result_tuple
        await connector.close() # Явно закрываем коннектор
        return results

    async def test_baseline_connectivity(self, test_sites: List[str], dns_cache: Dict[str, str]) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Проверяет базовую доступность, отправляя ClientHello, чтобы спровоцировать DPI.
        Использует aiohttp, так как он корректно обрабатывает сброс соединения.
        """
        LOG.info("Тестируем базовую доступность сайтов (без bypass) с DNS-кэшем...")
        return await self._test_sites_connectivity(test_sites, dns_cache)

    async def execute_strategy_real_world(
        self, 
        strategy_str: str, 
        test_sites: List[str],
        target_ips: Set[str],
        dns_cache: Dict[str, str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
        fingerprint: Optional[DPIFingerprint] = None
    ) -> Tuple[str, int, int, float]:
        """
        Реальное тестирование стратегии с использованием нового BypassEngine.
        Теперь с поддержкой контекстной информации от фингерпринтинга.
        """
        parsed_params = self.parser.parse(strategy_str)
        engine_task = self._translate_zapret_to_engine_task(parsed_params)
        if not engine_task:
            return "TRANSLATION_FAILED", 0, len(test_sites), 0.0

        bypass_engine = BypassEngine(debug=self.debug)
        strategy_map = {'default': engine_task}
        bypass_thread = bypass_engine.start(target_ips, strategy_map)
        
        try:
            # Adjust wait time based on fingerprint information
            wait_time = 1.5
            if fingerprint:
                # Adjust timing based on DPI characteristics
                if fingerprint.dpi_type == DPIType.ROSKOMNADZOR_TSPU:
                    wait_time = 1.0  # TSPU responds quickly
                elif fingerprint.dpi_type == DPIType.COMMERCIAL_DPI:
                    wait_time = 2.0  # Commercial DPI may need more time
                elif fingerprint.connection_reset_timing > 0:
                    # Use detected timing characteristics
                    wait_time = max(1.0, fingerprint.connection_reset_timing / 1000.0 + 0.5)
            
            await asyncio.sleep(wait_time)
            
            # Test connectivity with enhanced error handling
            try:
                results = await self._test_sites_connectivity(test_sites, dns_cache)
            except Exception as connectivity_error:
                LOG.error(f"Connectivity test failed: {connectivity_error}")
                # Try with fallback settings if fingerprint suggests specific issues
                if fingerprint and fingerprint.tcp_window_manipulation:
                    LOG.info("Retrying with adjusted parameters due to TCP window manipulation")
                    await asyncio.sleep(0.5)
                    results = await self._test_sites_connectivity(test_sites, dns_cache)
                else:
                    raise
            
            successful_count = sum(1 for status, _, _, _ in results.values() if status == "WORKING")
            successful_latencies = [latency for status, _, latency, _ in results.values() if status == "WORKING"]
            avg_latency = sum(successful_latencies) / len(successful_latencies) if successful_latencies else 0.0
            
            if successful_count == 0: 
                result_status = "NO_SITES_WORKING"
            elif successful_count == len(test_sites): 
                result_status = "ALL_SITES_WORKING"
            else: 
                result_status = "PARTIAL_SUCCESS"
            
            # Log additional context if fingerprint is available
            if fingerprint and self.debug:
                LOG.debug(f"Strategy test with DPI context: {fingerprint.dpi_type.value}, "
                         f"RST injection: {fingerprint.rst_injection_detected}, "
                         f"TCP manipulation: {fingerprint.tcp_window_manipulation}")
            
            LOG.info(f"Результат реального теста: {successful_count}/{len(test_sites)} сайтов работают, ср. задержка: {avg_latency:.1f}ms")
            return result_status, successful_count, len(test_sites), avg_latency
            
        except Exception as e:
            LOG.error(f"Ошибка во время реального тестирования: {e}", exc_info=self.debug)
            
            # Enhanced error handling with fingerprint context
            if fingerprint:
                if fingerprint.rst_injection_detected and "reset" in str(e).lower():
                    LOG.info("Connection reset detected - consistent with fingerprint analysis")
                elif fingerprint.dns_hijacking_detected and "dns" in str(e).lower():
                    LOG.info("DNS issues detected - consistent with fingerprint analysis")
            
            return "REAL_WORLD_ERROR", 0, len(test_sites), 0.0
        finally:
            bypass_engine.stop()
            if bypass_thread:
                bypass_thread.join(timeout=2.0)
            await asyncio.sleep(0.5)

    async def test_strategies_hybrid(
        self,
        strategies: List[str],
        test_sites: List[str],
        ips: Set[str],
        dns_cache: Dict[str, str],
        port: int,
        domain: str,
        fast_filter: bool = True,
        initial_ttl: Optional[int] = None,
        enable_fingerprinting: bool = True
    ) -> List[Dict]:
        """
        Гибридное тестирование стратегий с продвинутым фингерпринтингом DPI:
        1. Выполняет фингерпринтинг DPI для целевого домена
        2. Адаптирует стратегии под обнаруженный тип DPI
        3. Проводит реальное тестирование с помощью BypassEngine
        """
        results = []
        fingerprint = None
        
        # Perform DPI fingerprinting if enabled
        if enable_fingerprinting and self.advanced_fingerprinting_enabled:
            try:
                LOG.info(f"Performing DPI fingerprinting for {domain}:{port}")
                fingerprint = await self.fingerprint_target(domain, port)
                
                if fingerprint:
                    self.fingerprint_stats['fingerprint_aware_tests'] += 1
                    LOG.info(f"DPI fingerprint obtained: {fingerprint.dpi_type.value} "
                           f"(confidence: {fingerprint.confidence:.2f}, "
                           f"reliability: {fingerprint.reliability_score:.2f})")
                else:
                    LOG.warning("DPI fingerprinting failed, proceeding with standard testing")
                    self.fingerprint_stats['fallback_tests'] += 1
            except Exception as e:
                LOG.error(f"DPI fingerprinting error: {e}")
                self.fingerprint_stats['fingerprint_failures'] += 1
                self.fingerprint_stats['fallback_tests'] += 1
        else:
            self.fingerprint_stats['fallback_tests'] += 1
        
        # Adapt strategies based on fingerprint
        if fingerprint:
            strategies_to_test = self._adapt_strategies_for_fingerprint(strategies, fingerprint)
            LOG.info(f"Using {len(strategies_to_test)} fingerprint-adapted strategies")
        else:
            strategies_to_test = strategies
            LOG.info(f"Using {len(strategies_to_test)} standard strategies (no fingerprint)")
        
        LOG.info(f"Начинаем реальное тестирование {len(strategies_to_test)} стратегий с помощью BypassEngine...")
        
        for i, strategy in enumerate(strategies_to_test):
            LOG.info(f"--> Тест {i+1}/{len(strategies_to_test)}: {strategy}")
            
            result_status, successful_count, total_count, avg_latency = await self.execute_strategy_real_world(
                strategy, test_sites, ips, dns_cache, port, initial_ttl
            )
            
            success_rate = successful_count / total_count if total_count > 0 else 0.0
            
            result_data = {
                'strategy': strategy,
                'result_status': result_status,
                'successful_sites': successful_count,
                'total_sites': total_count,
                'success_rate': success_rate,
                'avg_latency_ms': avg_latency,
                'fingerprint_used': fingerprint is not None,
                'dpi_type': fingerprint.dpi_type.value if fingerprint else None,
                'dpi_confidence': fingerprint.confidence if fingerprint else None
            }
            results.append(result_data)
            
            if success_rate > 0:
                LOG.info(f"✓ Успех: {success_rate:.0%} ({successful_count}/{total_count}), задержка: {avg_latency:.1f}ms")
            else:
                LOG.info(f"✗ Провал: ни один сайт не заработал.")
        
        # Sort results with fingerprint-aware scoring
        if fingerprint:
            # Prioritize results that match expected DPI behavior
            results.sort(key=lambda x: (
                x['success_rate'],
                -x['avg_latency_ms'],
                1 if x['fingerprint_used'] else 0  # Prefer fingerprint-aware results
            ), reverse=True)
        else:
            results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms']), reverse=True)
        
        # Add fingerprint information to results summary
        if results and fingerprint:
            LOG.info(f"Strategy testing completed with DPI fingerprint: "
                   f"{fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})")
        
        return results

    async def fingerprint_target(self, 
                                domain: str, 
                                port: int = 443,
                                force_refresh: bool = False) -> Optional[DPIFingerprint]:
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
            LOG.info(f"Starting DPI fingerprinting for {domain}:{port}")
            start_time = time.time()
            
            fingerprint = await self.advanced_fingerprinter.fingerprint_target(
                target=domain,
                port=port,
                force_refresh=force_refresh
            )
            
            analysis_time = time.time() - start_time
            self.fingerprint_stats['fingerprints_created'] += 1
            
            LOG.info(f"DPI fingerprinting completed for {domain}:{port} in {analysis_time:.2f}s")
            LOG.info(f"Detected DPI type: {fingerprint.dpi_type.value} (confidence: {fingerprint.confidence:.2f})")
            
            return fingerprint
            
        except FingerprintingError as e:
            LOG.error(f"Fingerprinting failed for {domain}:{port}: {e}")
            self.fingerprint_stats['fingerprint_failures'] += 1
            return None
        except Exception as e:
            LOG.error(f"Unexpected error during fingerprinting {domain}:{port}: {e}")
            self.fingerprint_stats['fingerprint_failures'] += 1
            return None

    def _adapt_strategies_for_fingerprint(self, 
                                        strategies: List[str], 
                                        fingerprint: DPIFingerprint) -> List[str]:
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
        
        LOG.info(f"Adapting strategies for DPI type: {dpi_type.value} (confidence: {confidence:.2f})")
        
        # Strategy adaptations based on DPI type
        if dpi_type == DPIType.ROSKOMNADZOR_TSPU:
            # TSPU responds quickly to RST injection, prefer fast techniques
            priority_patterns = [
                r'--dpi-desync-ttl=[1-5]',  # Low TTL values
                r'--dpi-desync=fake.*disorder',  # Fake + disorder combinations
                r'--dpi-desync-fooling=badsum',  # Bad checksum fooling
            ]
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
            
        elif dpi_type == DPIType.ROSKOMNADZOR_DPI:
            # Standard DPI, prefer segmentation and fake packets
            priority_patterns = [
                r'--dpi-desync=.*split',  # Segmentation techniques
                r'--dpi-desync-split-pos=midsld',  # Middle of SLD splitting
                r'--dpi-desync=fake',  # Fake packet injection
            ]
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
            
        elif dpi_type == DPIType.COMMERCIAL_DPI:
            # Commercial DPI often has deep inspection, use advanced techniques
            priority_patterns = [
                r'--dpi-desync=multisplit',  # Multiple segmentation
                r'--dpi-desync-split-seqovl',  # Sequence overlap
                r'--dpi-desync-repeats=[2-5]',  # Multiple repeats
            ]
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
            
            # Add specific multisplit strategies for commercial DPI
            adapted_strategies.extend([
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10",
                "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum",
            ])
            
        elif dpi_type == DPIType.FIREWALL_BASED:
            # Firewall-based blocking, prefer simple techniques
            priority_patterns = [
                r'--dpi-desync=disorder',  # Simple disorder
                r'--dpi-desync-ttl=[64,127,128]',  # Standard TTL values
            ]
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
            
        elif dpi_type == DPIType.ISP_TRANSPARENT_PROXY:
            # Transparent proxy, focus on HTTP-level techniques
            priority_patterns = [
                r'--dpi-desync=fake.*disorder',  # Fake + disorder
                r'--dpi-desync-fooling=.*seq',  # Sequence number manipulation
            ]
            adapted_strategies.extend(self._prioritize_strategies(strategies, priority_patterns))
        
        # Add fingerprint-specific strategies based on detected characteristics
        if fingerprint.rst_injection_detected and fingerprint.connection_reset_timing < 100:
            # Fast RST injection detected, add low TTL strategies
            adapted_strategies.extend([
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
            ])
        
        if fingerprint.tcp_window_manipulation:
            # TCP window manipulation detected, use window-aware techniques
            adapted_strategies.extend([
                "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10",
            ])
        
        if fingerprint.http_header_filtering:
            # HTTP header filtering detected, focus on packet-level techniques
            adapted_strategies.extend([
                "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
            ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_strategies = []
        for strategy in adapted_strategies + strategies:
            if strategy not in seen:
                seen.add(strategy)
                unique_strategies.append(strategy)
        
        LOG.info(f"Adapted {len(strategies)} strategies to {len(unique_strategies)} fingerprint-aware strategies")
        return unique_strategies
    
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
        
        # Add advanced fingerprinter stats if available
        if self.advanced_fingerprinter:
            try:
                advanced_stats = self.advanced_fingerprinter.get_stats()
                stats.update({
                    'advanced_' + k: v for k, v in advanced_stats.items()
                })
            except Exception as e:
                LOG.error(f"Failed to get advanced fingerprinter stats: {e}")
        
        return stats

    def cleanup(self):
        """Очистка ресурсов."""
        if self.advanced_fingerprinter and hasattr(self.advanced_fingerprinter, 'executor'):
            try:
                self.advanced_fingerprinter.executor.shutdown(wait=True)
            except Exception as e:
                LOG.error(f"Error shutting down fingerprinter executor: {e}")