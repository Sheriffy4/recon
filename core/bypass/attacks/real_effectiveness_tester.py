import asyncio
import time
import logging
import socket
import aiohttp
import ssl as ssl_module
from typing import Dict, Any, Optional, Union, List, Tuple
from contextlib import asynccontextmanager
from aiohttp.abc import AbstractResolver
from core.bypass.attacks.base import AttackResult, AttackStatus
from core.bypass.engines.factory import create_engine, detect_best_engine
from core.bypass.engines.base import EngineConfig
from core.bypass.attacks.base import BaselineResult, BypassResult, EffectivenessResult
from core.bypass.types import BlockType
from core.dns.pinned_resolver import StaticResolver
LOG = logging.getLogger('RealEffectivenessTester')
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36'}

class StaticResolver(AbstractResolver):
    """Кастомный резолвер для aiohttp, который привязывает домен к статическому IP."""

    def __init__(self, mapping: Dict[str, str]):
        self._mapping = mapping

    async def resolve(self, host: str, port: int=0, family: int=socket.AF_UNSPEC) -> List[Dict[str, Any]]:
        ip = self._mapping.get(host)
        if not ip:
            try:
                res = await asyncio.get_event_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
                return [{'hostname': host, 'host': info[4][0], 'port': port, 'family': info[0], 'proto': 0, 'flags': 0} for info in res]
            except socket.gaierror:
                return []
        fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
        return [{'hostname': host, 'host': ip, 'port': port, 'family': fam, 'proto': 0, 'flags': 0}]

    async def close(self):
        pass

class RealEffectivenessTester:

    def __init__(self, timeout: float=10.0, max_retries: int=2, engine_config: Optional[EngineConfig]=None, pinned_dns: Optional[Dict[str, str]]=None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.engine_config = engine_config or EngineConfig()
        self.logger = LOG
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = self._create_ssl_context()
        self._pinned_dns = pinned_dns or {}

    def set_pinned_dns_map(self, pinned_map: Dict[str, str]):
        """Позволяет динамически установить карту пиннинга перед тестом."""
        self._pinned_dns = pinned_map
        self.logger.debug(f'DNS map pinned for tester: {self._pinned_dns}')

    @staticmethod
    def _create_ssl_context() -> ssl_module.SSLContext:
        """Создает SSL-контекст, который не проверяет сертификаты."""
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        return ctx

    def set_pinned_ip(self, domain: str, ip: str):
        """Привязывает домен к конкретному IP для всех последующих запросов."""
        self._pinned_dns[domain] = ip
        LOG.info(f'HTTP client IP pinned: {domain} -> {ip}')

    def clear_pinned_ips(self):
        """Очищает все запиненные IP."""
        self._pinned_dns.clear()

    async def _get_session(self) -> aiohttp.ClientSession:
        """Создает или возвращает aiohttp сессию с кастомным резолвером."""
        if self._session and (not self._session.closed):
            return self._session
        resolver = StaticResolver(self._pinned_dns) if self._pinned_dns else None
        connector = aiohttp.TCPConnector(ssl=self._ssl_context, resolver=resolver, limit=100, limit_per_host=30, ttl_dns_cache=300, force_close=True)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector, headers=HEADERS)
        return self._session

    async def _http_get(self, url: str) -> Tuple[Optional[bytes], Optional[Dict[str, str]], Optional[int], Optional[str]]:
        """Выполняет HTTP GET запрос и возвращает (content, headers, status_code, error)."""
        session = await self._get_session()
        try:
            async with session.get(url, allow_redirects=True) as response:
                content = await response.read()
                return (content, dict(response.headers), response.status, None)
        except asyncio.TimeoutError:
            return (None, None, None, 'Timeout')
        except aiohttp.ClientError as e:
            return (None, None, getattr(e, 'status', None), f'ClientError: {type(e).__name__}')
        except Exception as e:
            return (None, None, None, f'GenericError: {type(e).__name__}')

    async def test_baseline(self, domain: str, port: int=443) -> BaselineResult:
        """Тестирует доступность домена без какого-либо обхода."""
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f'{protocol}://{domain}/'
        self.logger.info(f'Testing baseline for {domain}:{port}')
        start_time = time.time()
        content, headers, status_code, error = await self._http_get(url)
        latency_ms = (time.time() - start_time) * 1000
        success = status_code is not None and 200 <= status_code < 400
        return BaselineResult(domain=domain, success=success, latency_ms=latency_ms, status_code=status_code, error=error, block_type=BlockType.UNKNOWN if success else BlockType.TIMEOUT)

    async def test_multiple_sites_with_bypass(self, sites: List[str], port: int, attack_result: AttackResult) -> Dict[str, BypassResult]:
        """
        Тестирует одну атаку на нескольких сайтах параллельно, запуская движок только один раз.

        Args:
            sites: Список доменов для теста.
            port: Целевой порт.
            attack_result: Сгенерированный "рецепт" атаки для применения.

        Returns:
            Словарь, где ключ - домен, а значение - BypassResult.
        """
        start_time = time.time()
        attack_name = attack_result.technique_used or 'unknown'
        self.logger.info(f"Testing attack '{attack_name}' on {len(sites)} sites in parallel.")
        all_ips = set()
        domain_to_ip = {}
        for site in sites:
            ip = await self._resolve_ip(site)
            if ip:
                all_ips.add(ip)
                domain_to_ip[site] = ip
        if not all_ips:
            self.logger.error('Could not resolve any IPs for the site group.')
            return {site: BypassResult(domain=site, success=False, error='DNS Error') for site in sites}
        self.set_pinned_dns_map(domain_to_ip)
        engine = None
        try:
            engine_type = detect_best_engine()
            engine = create_engine(engine_type, self.engine_config)
            if not engine.start_with_segments_recipe(all_ips, attack_result.segments):
                raise RuntimeError('Failed to start the bypass engine in recipe mode for group test.')
            await asyncio.sleep(1.5)
            self.logger.debug(f'Bypass engine started for {len(all_ips)} IPs. Testing sites...')
            tasks = []
            for site in sites:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f'{protocol}://{site}/'
                tasks.append(self._http_get(url))
            http_results = await asyncio.gather(*tasks, return_exceptions=True)
            final_results: Dict[str, BypassResult] = {}
            for i, site in enumerate(sites):
                res = http_results[i]
                if isinstance(res, Exception):
                    final_results[site] = BypassResult(domain=site, success=False, error=str(res))
                    continue
                content, headers, status_code, error = res
                block_type = self._analyze_response(status_code, content, headers)
                success = block_type == BlockType.NONE
                final_results[site] = BypassResult(domain=site, success=success, latency_ms=(time.time() - start_time) * 1000 / len(sites), bypass_applied=True, attack_name=attack_name, status_code=status_code, error=error, block_type=block_type, response_size=len(content) if content else 0, server_ip=domain_to_ip.get(site))
            return final_results
        except Exception as e:
            self.logger.error(f'Group bypass test failed with an exception: {e}', exc_info=self.debug)
            return {site: BypassResult(domain=site, success=False, error=str(e)) for site in sites}
        finally:
            if engine and engine.is_running:
                engine.stop()
            self.clear_pinned_ips()

    async def _perform_test(self, domain: str, port: int, is_baseline: bool) -> EffectivenessResult:
        """Общая логика для выполнения HTTP-теста."""
        if not self.session:
            raise RuntimeError("Tester must be used within an 'async with' context.")
        start_time = time.monotonic()
        url = f'https://{domain}' if port == 443 else f'http://{domain}:{port}'
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                await response.content.read(1024)
                latency = (time.monotonic() - start_time) * 1000
                if 200 <= response.status < 400:
                    return EffectivenessResult(domain=domain, success=True, latency_ms=latency, status_code=response.status, block_type=BlockType.NONE)
                else:
                    return EffectivenessResult(domain=domain, success=False, latency_ms=latency, status_code=response.status, error=f'HTTP Status {response.status}', block_type=BlockType.HTTP_ERROR)
        except asyncio.TimeoutError:
            latency = (time.monotonic() - start_time) * 1000
            return EffectivenessResult(domain=domain, success=False, latency_ms=latency, error='Timeout', block_type=BlockType.TIMEOUT)
        except aiohttp.ClientConnectorError as e:
            latency = (time.monotonic() - start_time) * 1000
            error_str = str(e).lower()
            block_type = BlockType.CONNECTION_REFUSED
            if 'reset' in error_str:
                block_type = BlockType.RST_INJECTION
            return EffectivenessResult(domain=domain, success=False, latency_ms=latency, error=f'ConnectionError: {e}', block_type=block_type)
        except Exception as e:
            latency = (time.monotonic() - start_time) * 1000
            return EffectivenessResult(domain=domain, success=False, latency_ms=latency, error=f'GenericError: {type(e).__name__}', block_type=BlockType.UNKNOWN)

    async def test_with_bypass(self, domain: str, port: int, attack_result: AttackResult) -> BypassResult:
        """
        Тестирует доступность домена с применением конкретной стратегии обхода.

        Эта функция реализует правильную методологию тестирования:
        1. Запускает системный движок-перехватчик (NativePydivertEngine).
        2. Настраивает движок на применение "рецепта" сегментов из attack_result.
        3. Выполняет стандартный HTTP-запрос через этот перехватчик.
        4. Анализирует результат и возвращает его в виде BypassResult.

        Args:
            domain: Целевой домен.
            port: Целевой порт.
            attack_result: Результат выполнения атаки, содержащий "рецепт" обхода (сегменты).

        Returns:
            BypassResult с детальной информацией о результате теста.
        """
        start_time = time.time()
        attack_name = attack_result.technique_used or 'unknown'
        self.logger.info(f"Testing bypass for {domain}:{port} with attack '{attack_name}'")
        if attack_result.status != AttackStatus.SUCCESS:
            self.logger.warning(f'Bypass test for {domain} skipped: attack recipe generation failed.')
            return EffectivenessResult(block_type=BlockType.INVALID, error=f"Recipe generation failed: {attack_result.error_message or 'Unknown reason'}")
        if not attack_result.has_segments():
            self.logger.warning(f'Bypass test for {domain} skipped: attack recipe is empty.')
            return EffectivenessResult(success=False, block_type=BlockType.INVALID, error='Attack produced an empty segment recipe.')
        if not attack_result or attack_result.status != AttackStatus.SUCCESS or (not attack_result.has_segments()):
            return BypassResult(domain=domain, success=False, latency_ms=(time.time() - start_time) * 1000, bypass_applied=True, attack_name=attack_name, error='Attack did not produce a valid segment recipe for testing.', block_type=BlockType.INVALID)
        target_ip = await self._resolve_ip(domain)
        if not target_ip:
            return BypassResult(domain=domain, success=False, latency_ms=0, bypass_applied=True, attack_name=attack_name, error='DNS resolution failed for bypass test.', block_type=BlockType.INVALID)
        self.set_pinned_ip(domain, target_ip)
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f'{protocol}://{domain}/'
        engine = None
        try:
            engine_type = detect_best_engine()
            engine = create_engine(engine_type, self.engine_config)
            if not engine.start_with_segments_recipe({target_ip}, attack_result.segments):
                raise RuntimeError('Failed to start the bypass engine in recipe mode.')
            await asyncio.sleep(1.5)
            self.logger.debug(f'Bypass engine started for IP {target_ip}. Performing HTTP request...')
            content, headers, status_code, error = await self._http_get(url)
            latency_ms = (time.time() - start_time) * 1000
            block_type = self._analyze_response(status_code, content, headers)
            success = block_type == BlockType.NONE
            self.logger.info(f'Bypass test for {domain} completed. Success: {success}, Status: {status_code}, Latency: {latency_ms:.1f}ms')
            return BypassResult(domain=domain, success=success, latency_ms=latency_ms, bypass_applied=True, attack_name=attack_name, status_code=status_code, error=error, block_type=block_type, response_size=len(content) if content else 0, headers=headers or {}, content_preview=self._get_content_preview(content), server_ip=target_ip)
        except Exception as e:
            self.logger.error(f'Bypass test for {domain} failed with an exception: {e}', exc_info=self.debug)
            return BypassResult(domain=domain, success=False, latency_ms=(time.time() - start_time) * 1000, bypass_applied=True, attack_name=attack_name, error=f'Exception during test: {type(e).__name__}', block_type=self._classify_error(e))
        finally:
            if engine and engine.is_running:
                engine.stop()
                self.logger.debug(f'Bypass engine for IP {target_ip} stopped.')
            self.clear_pinned_ips()

    def _normalize_strategy_for_engine(self, strategy: Dict, port: int) -> Dict:
        """Подготавливает стратегию для передачи в движок."""
        return strategy

    async def _test_with_pregenerated_segments(self, domain: str, port: int, attack_result: AttackResult) -> BypassResult:
        """
        Test connection by sending pre-generated segments (raw packets).
        Used for attacks that construct complete payload themselves.
        """
        start_time = time.time()
        target_ip = await self._resolve_ip(domain)
        if not target_ip:
            return BypassResult(domain=domain, success=False, latency_ms=0, bypass_applied=True, attack_name=attack_result.technique_used, error='DNS resolution failed')
        reader = None
        writer = None
        try:
            ssl_context = None
            if port == 443:
                ssl_context = self._ssl_context
            reader, writer = await asyncio.open_connection(target_ip, port, ssl=ssl_context, server_hostname=domain if ssl_context else None)
            segments = attack_result.metadata.get('segments', [])
            for segment_info in segments:
                if isinstance(segment_info, tuple):
                    segment_data, delay_ms = (segment_info[0], segment_info[1])
                else:
                    segment_data, delay_ms = (segment_info, 0)
                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)
                writer.write(segment_data)
                await writer.drain()
            response_data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            latency_ms = (time.time() - start_time) * 1000
            success = len(response_data) > 0
            block_type = BlockType.NONE if success else BlockType.TIMEOUT
            return BypassResult(domain=domain, success=success, latency_ms=latency_ms, bypass_applied=True, attack_name=attack_result.technique_used, block_type=block_type, response_size=len(response_data), server_ip=target_ip)
        except asyncio.TimeoutError:
            return BypassResult(domain=domain, success=False, latency_ms=(time.time() - start_time) * 1000, bypass_applied=True, attack_name=attack_result.technique_used, error='Timeout', block_type=BlockType.TIMEOUT)
        except Exception as e:
            return BypassResult(domain=domain, success=False, latency_ms=(time.time() - start_time) * 1000, bypass_applied=True, attack_name=attack_result.technique_used, error=str(e), block_type=self._classify_error(e))
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    async def _test_single_site(self, domain: str, port: int, server_ip: Optional[str], attack_name: str) -> BypassResult:
        """Test a single site (used for concurrent testing)."""
        protocol = 'https' if port == 443 else 'http'
        url = f'{protocol}://{domain}:{port}/' if port not in (80, 443) else f'{protocol}://{domain}/'
        start_time = time.time()
        try:
            content, headers, status_code = await self._http_get(url, allow_redirects=True, ssl=self._ssl_context if protocol == 'https' else None)
            latency_ms = (time.time() - start_time) * 1000
            block_type = self._analyze_response(status_code, content, headers)
            return BypassResult(domain=domain, success=block_type == BlockType.NONE, latency_ms=latency_ms, bypass_applied=True, attack_name=attack_name, status_code=status_code, block_type=block_type, response_size=len(content) if content else 0, server_ip=server_ip)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return BypassResult(domain=domain, success=False, latency_ms=latency_ms, bypass_applied=True, attack_name=attack_name, error=str(e), block_type=self._classify_error(e))

    def _normalize_strategy(self, strategy: Union[Dict[str, Any], str, AttackResult], port: int) -> Dict[str, Any]:
        """Normalize strategy input to dictionary format."""
        if isinstance(strategy, dict):
            result = strategy.copy()
            result.setdefault('target_port', port)
            return result
        elif isinstance(strategy, str):
            from core.bypass.strategies.parser import UnifiedStrategyParser
            parser = UnifiedStrategyParser()
            parsed = parser.parse(strategy)
            task = parser.translate_to_engine_task(strategy)
            if task:
                task.setdefault('target_port', port)
                return task
            return {'type': 'custom_string', 'command': strategy, 'target_port': port}
        elif isinstance(strategy, AttackResult):
            return {'type': strategy.technique_used or 'from_result', 'params': strategy.metadata, 'target_port': port, 'from_attack_result': True}
        else:
            self.logger.warning(f'Unknown strategy type: {type(strategy)}')
            return {'type': 'unknown', 'target_port': port, 'raw': strategy}

    def _analyze_response(self, status_code: Optional[int], content: Optional[bytes], headers: Optional[Dict[str, str]]) -> BlockType:
        if status_code is None:
            return BlockType.TIMEOUT
        if 200 <= status_code < 400:
            return BlockType.NONE
        if status_code in [403, 451]:
            return BlockType.HTTP_ERROR
        if content:
            content_str = content.decode('utf-8', errors='ignore').lower()
            block_keywords = ['blocked', 'forbidden', 'access denied', 'restricted']
            if any((keyword in content_str for keyword in block_keywords)):
                return BlockType.CONTENT
        return BlockType.UNKNOWN

    def _classify_error(self, error: Exception) -> BlockType:
        error_str = str(error).lower()
        if 'timeout' in error_str:
            return BlockType.TIMEOUT
        elif 'reset' in error_str:
            return BlockType.RST
        elif 'refused' in error_str:
            return BlockType.CONNECTION_REFUSED
        else:
            return BlockType.UNKNOWN

    def _get_content_preview(self, content: Optional[bytes], max_len: int=100) -> str:
        if not content:
            return ''
        try:
            return content[:max_len].decode('utf-8', errors='ignore').replace('\n', ' ').strip()
        except:
            return ''

    async def _resolve_ip(self, domain: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            if addr_info:
                return addr_info[0][4][0]
        except socket.gaierror:
            self.logger.warning(f'DNS resolution failed for {domain}')
        return None

    async def compare_results(self, baseline: BaselineResult, bypass: BypassResult) -> EffectivenessResult:
        """Compare baseline and bypass results."""
        if bypass.success and (not baseline.success):
            score = 1.0
            improvement_type = 'access_gained'
        elif baseline.success and bypass.success:
            if bypass.latency_ms < baseline.latency_ms * 0.9:
                score = 0.5 + (baseline.latency_ms - bypass.latency_ms) / baseline.latency_ms * 0.5
                improvement_type = 'latency_improved'
            else:
                score = 0.2
                improvement_type = 'no_improvement'
        else:
            score = 0.0
            improvement_type = 'no_improvement'
        return EffectivenessResult(domain=baseline.domain, baseline=baseline, bypass=bypass, effectiveness_score=score, bypass_effective=score > 0.1, improvement_type=improvement_type, latency_improvement_ms=baseline.latency_ms - bypass.latency_ms, latency_improvement_percent=(baseline.latency_ms - bypass.latency_ms) / baseline.latency_ms * 100 if baseline.latency_ms > 0 else 0.0)

    async def close(self):
        """Закрывает сессию aiohttp."""
        if self._session and (not self._session.closed):
            await self._session.close()
            self._session = None

    async def __aenter__(self):
        resolver = StaticResolver(self._pinned_dns) if self._pinned_dns else None
        connector = aiohttp.TCPConnector(ssl=self._ssl_context, resolver=resolver, limit=100, limit_per_host=30, ttl_dns_cache=300, force_close=True)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector, headers=HEADERS)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def test_attack_on_multiple_sites(self, attack_name: str=None, sites: List[str]=None, port: int=443, attack_result: Optional[AttackResult]=None, attack_params: Optional[Dict[str, Any]]=None) -> Dict[str, BypassResult]:
        """
        Test attack effectiveness on multiple sites.

        Args:
            attack_name: Name of the attack to test (optional)
            sites: List of domains to test
            port: Port to test (default: 443)
            attack_result: Pre-created attack result to use for testing
            attack_params: Optional parameters for the attack

        Returns:
            Dictionary mapping domain names to BypassResult objects
        """
        results = {}
        if not sites:
            return results
        for domain in sites:
            try:
                if attack_result:
                    test_attack_result = attack_result
                else:
                    test_attack_result = AttackResult(status=AttackStatus.SUCCESS, latency_ms=100.0, technique_used=attack_name or 'unknown')
                bypass_result = await self.test_with_bypass(domain, port, test_attack_result)
                results[domain] = bypass_result
            except Exception as e:
                LOG.error(f'Error testing {attack_name} on {domain}: {e}')
                results[domain] = BypassResult(domain=domain, success=False, latency_ms=0.0, bypass_applied=True, attack_name=attack_name, error=str(e))
        return results

@asynccontextmanager
async def create_effectiveness_tester(**kwargs):
    """
    Create effectiveness tester as async context manager.
    Ensures proper cleanup of resources.
    """
    tester = RealEffectivenessTester(**kwargs)
    try:
        yield tester
    finally:
        await tester.close()