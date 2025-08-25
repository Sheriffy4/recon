"""
Proper Testing Methodology Implementation

Implements the correct system-level testing approach:
1. Start system interceptor (internal engine)
2. Test through interceptor using standard HTTP client
3. Compare results with baseline (no interceptor)

This uses internal engines as system interceptors instead of external processes.
"""
import asyncio
import logging
import time
import socket
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
from core.bypass.attacks.base import BaselineResult, BypassResult, EffectivenessResult, BlockType
LOG = logging.getLogger('ProperTestingMethodology')

class TestingMode(Enum):
    """Testing mode enumeration"""
    BASELINE = 'baseline'
    SYSTEM_BYPASS = 'system_bypass'

@dataclass
class SystemTestResult:
    """Result from system-level testing"""
    domain: str
    success: bool
    latency_ms: float
    status_code: Optional[int] = None
    error: Optional[str] = None
    block_type: BlockType = BlockType.NONE
    response_size: int = 0
    headers: Dict[str, str] = None
    content_preview: str = ''
    server_ip: Optional[str] = None
    interceptor_used: Optional[str] = None
    strategy_applied: Optional[str] = None

class ProperTestingMethodology:
    """
    Proper testing methodology that uses internal engines as system interceptors.

    This follows the correct approach:
    1. Test baseline (no interceptor)
    2. Start system interceptor (internal engine)
    3. Test through interceptor using standard HTTP client
    4. Compare results
    5. Stop interceptor
    """

    def __init__(self, base_path: str='.', timeout: float=10.0):
        self.base_path = base_path
        self.timeout = timeout
        self.logger = LOG

    async def test_strategy_effectiveness(self, domain: str, port: int, strategy: Dict[str, Any], tool_name: str='internal_engine', target_ips: Optional[Set[str]]=None) -> EffectivenessResult:
        """
        Test strategy effectiveness using proper methodology.

        Args:
            domain: Target domain
            port: Target port
            strategy: Strategy parameters
            tool_name: System tool to use (ignored, uses internal engine)

        Returns:
            EffectivenessResult with comparison
        """
        self.logger.info(f'Testing strategy effectiveness for {domain}:{port}')
        baseline_result = await self._test_baseline(domain, port)
        self.logger.info(f'Baseline test: success={baseline_result.success}, latency={baseline_result.latency_ms:.1f}ms')
        if baseline_result.success:
            self.logger.info(f'Domain {domain} is not blocked, skipping bypass test')
            bypass_result = SystemTestResult(domain=domain, success=baseline_result.success, latency_ms=baseline_result.latency_ms, status_code=baseline_result.status_code, block_type=baseline_result.block_type, response_size=baseline_result.response_size, headers=baseline_result.headers, content_preview=baseline_result.content_preview, server_ip=baseline_result.server_ip, interceptor_used='none', strategy_applied='none')
        else:
            self.logger.info(f'Domain {domain} is blocked, testing with bypass')
            bypass_result = await self._test_with_system_interceptor(domain, port, strategy, tool_name)
            self.logger.info(f'Bypass test: success={bypass_result.success}, latency={bypass_result.latency_ms:.1f}ms')
        effectiveness = self._calculate_effectiveness(baseline_result, bypass_result)
        return EffectivenessResult(domain=domain, baseline=self._convert_to_baseline_result(baseline_result), bypass=self._convert_to_bypass_result(bypass_result), effectiveness_score=effectiveness.effectiveness_score, bypass_effective=effectiveness.bypass_effective, improvement_type=effectiveness.improvement_type, latency_improvement_ms=effectiveness.latency_improvement_ms, latency_improvement_percent=effectiveness.latency_improvement_percent)

    async def _test_baseline(self, domain: str, port: int) -> SystemTestResult:
        """Test domain without any interceptor (baseline)."""
        from core.optimization.http_client_pool import get_global_http_pool
        protocol = 'https' if port == 443 else 'http'
        url = f'{protocol}://{domain}/'
        self.logger.debug(f'Testing baseline for {domain}:{port}')
        start_time = time.time()
        try:
            http_pool = get_global_http_pool()
            content, headers, status_code = await http_pool.get(url, use_cache=False, allow_redirects=True)
            latency_ms = (time.time() - start_time) * 1000
            block_type = self._analyze_response(status_code, content, headers)
            success = block_type == BlockType.NONE
            server_ip = await self._resolve_ip(domain)
            return SystemTestResult(domain=domain, success=success, latency_ms=latency_ms, status_code=status_code, block_type=block_type, response_size=len(content) if content else 0, headers=dict(headers), content_preview=self._get_content_preview(content), server_ip=server_ip, interceptor_used=None, strategy_applied=None)
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            return SystemTestResult(domain=domain, success=False, latency_ms=latency_ms, error='Timeout', block_type=BlockType.TIMEOUT)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return SystemTestResult(domain=domain, success=False, latency_ms=latency_ms, error=str(e), block_type=self._classify_error(e))

    async def _test_with_system_interceptor(self, domain: str, port: int, strategy: Dict[str, Any], tool_name: str) -> SystemTestResult:
        """Test domain with system interceptor enabled using internal engines."""
        from core.bypass.engines.factory import create_engine, detect_best_engine, EngineType
        from core.bypass.engines.base import EngineConfig
        from core.optimization.http_client_pool import get_global_http_pool
        protocol = 'https' if port == 443 else 'http'
        url = f'{protocol}://{domain}/'
        target_ip = await self._resolve_ip(domain)
        if not target_ip:
            return SystemTestResult(domain=domain, success=False, latency_ms=0, error='DNS resolution failed', interceptor_used=tool_name, strategy_applied=strategy.get('name', 'unknown'))
        engine = None
        bypass_started = False
        try:
            engine_type = detect_best_engine()
            engine_config = EngineConfig()
            engine = create_engine(engine_type, engine_config)
            self.logger.info(f'Starting system interceptor: {engine_type.value} engine')
            engine_logger = logging.getLogger('NativePydivertEngine')
            engine_logger.setLevel(logging.DEBUG)
            if engine_type == EngineType.NATIVE_PYDIVERT:
                self.logger.debug(f"Native engine has attack_adapter: {hasattr(engine, 'attack_adapter')}")
                if hasattr(engine, 'attack_adapter'):
                    self.logger.debug(f'Attack adapter type: {type(engine.attack_adapter)}')
            strategy_dict = self._normalize_strategy_for_engine(strategy, port)
            strategy_map = {target_ip: strategy_dict}
            if not engine.start({target_ip}, strategy_map):
                raise RuntimeError('Failed to start system interceptor engine')
            bypass_started = True
            self.logger.debug('System interceptor started, waiting for initialization...')
            await asyncio.sleep(1.5)
            start_time = time.time()
            try:
                http_pool = get_global_http_pool()
                content, headers, status_code = await http_pool.get(url, use_cache=False, allow_redirects=True)
                latency_ms = (time.time() - start_time) * 1000
                block_type = self._analyze_response(status_code, content, headers)
                success = block_type == BlockType.NONE
                self.logger.debug(f'HTTP request through interceptor: status={status_code}, success={success}')
                return SystemTestResult(domain=domain, success=success, latency_ms=latency_ms, status_code=status_code, block_type=block_type, response_size=len(content) if content else 0, headers=dict(headers), content_preview=self._get_content_preview(content), server_ip=target_ip, interceptor_used=f'{engine_type.value}_engine', strategy_applied=strategy.get('name', 'unknown'))
            except asyncio.TimeoutError:
                latency_ms = (time.time() - start_time) * 1000
                return SystemTestResult(domain=domain, success=False, latency_ms=latency_ms, error='Timeout', block_type=BlockType.TIMEOUT, interceptor_used=f'{engine_type.value}_engine', strategy_applied=strategy.get('name', 'unknown'))
            except Exception as e:
                latency_ms = (time.time() - start_time) * 1000
                return SystemTestResult(domain=domain, success=False, latency_ms=latency_ms, error=str(e), block_type=self._classify_error(e), interceptor_used=f'{engine_type.value}_engine', strategy_applied=strategy.get('name', 'unknown'))
        except Exception as e:
            self.logger.error(f'System interceptor error: {e}')
            return SystemTestResult(domain=domain, success=False, latency_ms=0, error=f'System interceptor error: {e}', interceptor_used='engine_error', strategy_applied=strategy.get('name', 'unknown'))
        finally:
            if engine and bypass_started:
                try:
                    self.logger.debug('Stopping system interceptor...')
                    engine.stop()
                    stats = engine.get_stats()
                    if hasattr(stats, 'packets_processed') and hasattr(stats, 'packets_modified'):
                        self.logger.info(f'System interceptor stats: packets={stats.packets_processed}, modified={stats.packets_modified}')
                    else:
                        self.logger.info(f'System interceptor stats: {stats}')
                except Exception as e:
                    self.logger.error(f'Error stopping system interceptor: {e}')

    def _normalize_strategy_for_engine(self, strategy: Dict[str, Any], port: int) -> Dict[str, Any]:
        """Normalize strategy for engine usage."""
        if isinstance(strategy, dict):
            if 'raw_string' in strategy:
                raw_string = strategy['raw_string']
                strategy_type = 'custom'
                if '--dpi-desync=fake' in raw_string:
                    strategy_type = 'fake'
                elif '--dpi-desync=split' in raw_string or '--dpi-desync=multisplit' in raw_string:
                    strategy_type = 'multisplit'
                elif '--dpi-desync=disorder' in raw_string:
                    strategy_type = 'disorder'
                elif 'fake_split' in raw_string:
                    strategy_type = 'fake_split'
                return {'type': strategy_type, 'command': raw_string, 'target_port': port, 'raw_params': raw_string.split()}
            result = strategy.copy()
            result.setdefault('target_port', port)
            return result
        else:
            return {'type': 'unknown', 'target_port': port, 'raw': strategy}

    def _analyze_response(self, status_code: int, content: bytes, headers: Dict[str, str]) -> BlockType:
        """Analyze HTTP response to detect blocking."""
        if status_code in [403, 451]:
            return BlockType.HTTP_ERROR
        if content:
            content_str = content.decode('utf-8', errors='ignore').lower()
            block_keywords = ['blocked', 'forbidden', 'access denied', 'censored', 'restricted', 'unavailable']
            if any((keyword in content_str for keyword in block_keywords)):
                return BlockType.CONTENT
        return BlockType.NONE

    def _classify_error(self, error: Exception) -> BlockType:
        """Classify exception into block type."""
        error_str = str(error).lower()
        if 'timeout' in error_str:
            return BlockType.TIMEOUT
        elif 'reset' in error_str or 'connection reset' in error_str:
            return BlockType.RST
        else:
            return BlockType.HTTP_ERROR

    def _get_content_preview(self, content: bytes, max_len: int=200) -> str:
        """Get preview of content."""
        if not content:
            return ''
        try:
            preview = content[:max_len].decode('utf-8', errors='ignore')
            if len(content) > max_len:
                preview += '...'
            return preview
        except:
            return ''

    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            if addr_info:
                return addr_info[0][4][0]
        except:
            pass
        return None

    def _calculate_effectiveness(self, baseline: SystemTestResult, bypass: SystemTestResult) -> EffectivenessResult:
        """Calculate effectiveness by comparing baseline and bypass results."""
        bypass_applied = bypass.interceptor_used is not None and bypass.interceptor_used != 'none'
        if not bypass_applied:
            if baseline.success:
                effectiveness_score = 1.0
                improvement_type = 'no_bypass_needed'
            else:
                effectiveness_score = 0.0
                improvement_type = 'no_bypass_needed'
        elif bypass.success and (not baseline.success):
            effectiveness_score = 1.0
            improvement_type = 'access_gained'
        elif baseline.success and bypass.success:
            if bypass.latency_ms < baseline.latency_ms * 0.9:
                effectiveness_score = 0.5 + (baseline.latency_ms - bypass.latency_ms) / baseline.latency_ms * 0.5
                improvement_type = 'latency_improved'
            else:
                effectiveness_score = 0.2
                improvement_type = 'no_improvement'
        else:
            effectiveness_score = 0.0
            improvement_type = 'no_improvement'
        latency_improvement_ms = baseline.latency_ms - bypass.latency_ms
        latency_improvement_percent = 0.0
        if baseline.latency_ms > 0:
            latency_improvement_percent = latency_improvement_ms / baseline.latency_ms * 100
        return EffectivenessResult(domain=baseline.domain, baseline=None, bypass=None, effectiveness_score=effectiveness_score, bypass_effective=effectiveness_score > 0.1, improvement_type=improvement_type, latency_improvement_ms=latency_improvement_ms, latency_improvement_percent=latency_improvement_percent)

    def _convert_to_baseline_result(self, system_result: SystemTestResult) -> BaselineResult:
        """Convert SystemTestResult to BaselineResult."""
        return BaselineResult(domain=system_result.domain, success=system_result.success, latency_ms=system_result.latency_ms, status_code=system_result.status_code, error=system_result.error, block_type=system_result.block_type, response_size=system_result.response_size, headers=system_result.headers or {}, content_preview=system_result.content_preview, server_ip=system_result.server_ip)

    def _convert_to_bypass_result(self, system_result: SystemTestResult) -> BypassResult:
        """Convert SystemTestResult to BypassResult."""
        return BypassResult(domain=system_result.domain, success=system_result.success, latency_ms=system_result.latency_ms, bypass_applied=system_result.interceptor_used is not None, attack_name=system_result.strategy_applied or 'unknown', status_code=system_result.status_code, error=system_result.error, block_type=system_result.block_type, response_size=system_result.response_size, headers=system_result.headers or {}, content_preview=system_result.content_preview, server_ip=system_result.server_ip)

    async def cleanup(self):
        """Cleanup method for compatibility."""
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()