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

LOG = logging.getLogger("hybrid_engine")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36"
}

class HybridEngine:
    """
    Гибридный движок, который сочетает:
    1. Парсинг zapret-стратегий.
    2. Реальное тестирование через запущенный BypassEngine с синхронизированным DNS.
    """
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.parser = ZapretStrategyParser()

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
        initial_ttl: Optional[int] = None
    ) -> Tuple[str, int, int, float]:
        """
        Реальное тестирование стратегии с использованием нового BypassEngine.
        """
        parsed_params = self.parser.parse(strategy_str)
        engine_task = self._translate_zapret_to_engine_task(parsed_params)
        if not engine_task:
            return "TRANSLATION_FAILED", 0, len(test_sites), 0.0

        bypass_engine = BypassEngine(debug=self.debug)
        strategy_map = {'default': engine_task}
        bypass_thread = bypass_engine.start(target_ips, strategy_map)
        
        try:
            await asyncio.sleep(1.5)
            # ИСПОЛЬЗУЕМ AIOHTTP ДЛЯ ТЕСТА
            results = await self._test_sites_connectivity(test_sites, dns_cache)
            
            successful_count = sum(1 for status, _, _, _ in results.values() if status == "WORKING")
            successful_latencies = [latency for status, _, latency, _ in results.values() if status == "WORKING"]
            avg_latency = sum(successful_latencies) / len(successful_latencies) if successful_latencies else 0.0
            
            if successful_count == 0: result_status = "NO_SITES_WORKING"
            elif successful_count == len(test_sites): result_status = "ALL_SITES_WORKING"
            else: result_status = "PARTIAL_SUCCESS"
            
            LOG.info(f"Результат реального теста: {successful_count}/{len(test_sites)} сайтов работают, ср. задержка: {avg_latency:.1f}ms")
            return result_status, successful_count, len(test_sites), avg_latency
        except Exception as e:
            LOG.error(f"Ошибка во время реального тестирования: {e}", exc_info=self.debug)
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
        initial_ttl: Optional[int] = None
    ) -> List[Dict]:
        """
        Гибридное тестирование стратегий:
        Проводит реальное тестирование всех кандидатов с помощью BypassEngine.
        """
        results = []
        strategies_to_test = strategies
        
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
            }
            results.append(result_data)
            
            if success_rate > 0:
                LOG.info(f"✓ Успех: {success_rate:.0%} ({successful_count}/{total_count}), задержка: {avg_latency:.1f}ms")
            else:
                LOG.info(f"✗ Провал: ни один сайт не заработал.")
        
        results.sort(key=lambda x: (x['success_rate'], -x['avg_latency_ms']), reverse=True)
        return results

    def cleanup(self):
        """Очистка ресурсов."""
        pass